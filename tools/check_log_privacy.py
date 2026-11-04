#!/usr/bin/env python3
"""Exercise the production Alloy sanitising block against real Loki, without a network."""
import json
from pathlib import Path
import subprocess
import uuid


def call(*args, check=True): return subprocess.run(args, check=check, text=True, capture_output=True)


if __name__ == "__main__":
    root = Path.cwd()
    images = json.loads((root / "infra/images.lock.json").read_text())
    directory = root / ".state/privacy-lab"; directory.mkdir(parents=True, exist_ok=True)
    marker = "PRIVATE_TEST_MARKER_" + uuid.uuid4().hex
    (directory / "messages.log").write_text(
        "Accepted publickey for fake-admin from 192.0.2.1 " + marker + "\n" +
        "Failed keyboard-interactive for fake-admin " + marker + "\n" +
        "unrecognised test line " + marker + "\n")
    original = (root / ".state/validation/vpn_a/alloy.alloy").read_text()
    block = original.split('loki.process "sanitized" {', 1)[1].split('loki.source.journal "services"', 1)[0]
    config = 'logging { level = "warn" }\nloki.process "sanitized" {' + block
    config += '''
loki.source.file "test" {
  targets = [{__path__ = "/fixtures/messages.log", job = "privacy_test"}]
  forward_to = [loki.process.sanitized.receiver]
}
loki.write "central" {
  endpoint { url = "http://127.0.0.1:3100/loki/api/v1/push" }
}
'''
    (directory / "test.alloy").write_text(config)
    prefix = "vpn-privacy-" + uuid.uuid4().hex[:8]
    names = [prefix + "-loki", prefix + "-alloy"]
    try:
        call("docker", "run", "-d", "--name", names[0], "--network", "none", "--read-only", "--cap-drop", "ALL",
             "--tmpfs", "/loki:uid=10001,gid=10001,size=128m", "--tmpfs", "/tmp:size=32m",
             "-v", f"{root / 'monitoring/loki.yml'}:/etc/loki/config.yml:ro", images["loki"], "-config.file=/etc/loki/config.yml")
        # One helper waits inside the same network namespace, never publishing a host port.
        wait = "import urllib.request,time;\nfor i in range(50):\n try:\n  urllib.request.urlopen('http://127.0.0.1:3100/ready',timeout=1); break\n except Exception: time.sleep(1)\nelse: raise RuntimeError('Loki did not become ready')"
        call("docker", "run", "--rm", "--network", "container:" + names[0], "vpn-service-tools:local", "python", "-c", wait)
        call("docker", "run", "-d", "--name", names[1], "--network", "container:" + names[0], "--read-only", "--cap-drop", "ALL",
             "--tmpfs", "/var/lib/alloy:size=32m", "--tmpfs", "/tmp:size=32m",
             "-v", f"{directory}:/fixtures:ro", images["alloy"], "run", "--server.http.listen-addr=127.0.0.1:12345",
             "--storage.path=/var/lib/alloy", "/fixtures/test.alloy")
        query = '''import urllib.request,urllib.parse,json,time
url='http://127.0.0.1:3100/loki/api/v1/query_range?'+urllib.parse.urlencode({'query':'{job="privacy_test"}'})
for i in range(30):
    data=json.load(urllib.request.urlopen(url,timeout=2))
    lines=[v[1] for stream in data['data']['result'] for v in stream['values']]
    if len(lines)>=2: break
    time.sleep(1)
else: raise RuntimeError('Test events did not arrive')
assert set(lines)=={'Accepted publickey','Failed keyboard-interactive'}, lines
print('PASS: real Alloy→Loki pipeline exports only event categories; original source/IP/private marker and unknown message are absent.')
'''
        result = call("docker", "run", "--rm", "--network", "container:" + names[0], "vpn-service-tools:local", "python", "-c", query)
        print(result.stdout.strip())
    except Exception:
        for name in names:
            logs = call("docker", "logs", name, check=False)
            print(logs.stderr[-2000:] if logs.stderr else logs.stdout[-2000:])
        raise
    finally:
        for name in reversed(names): call("docker", "rm", "-f", name, check=False)
