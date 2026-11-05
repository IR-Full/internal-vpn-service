#!/usr/bin/env python3
"""Smoke-test provisioned Grafana in an ephemeral networkless container. No real secrets."""
import base64
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_fleet.plugins import prepare_plugins


def command(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-5000:])
    return result


if __name__ == "__main__":
    root = Path.cwd()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, default=root / "infra/images.lock.json")
    images = json.loads(parser.parse_args().images.read_text())
    plugins = prepare_plugins(images["grafana_plugins"], root / ".state/grafana-plugins")
    temp = root / ".state/smoke"
    for folder in ["datasources", "dashboards", "alerting"]:
        (temp / "provisioning" / folder).mkdir(parents=True, exist_ok=True)
    for source, dest in [("datasources.yml", "datasources/main.yml"), ("dashboards.yml", "dashboards/main.yml"), ("alerts.yml", "alerting/main.yml")]:
        shutil.copyfile(root / "monitoring" / source, temp / "provisioning" / dest)
    contacts_fixture = root / ".state/validation/vpn_b/contacts.yml"
    if not contacts_fixture.exists():
        raise SystemExit("Run tools/validate_local.py to create explicitly fake contacts first")
    shutil.copyfile(contacts_fixture, temp / "provisioning/alerting/contacts.yml")
    # Only evaluation timing is accelerated; production expressions and condition types are unchanged.
    prepare = '''import pathlib,yaml
p=pathlib.Path('/lab/provisioning/alerting/main.yml')
v=yaml.safe_load(p.read_text())
for g in v['groups']:
    g['interval']='10s'
    for r in g['rules']: r['for']='0s'
p.write_text(yaml.safe_dump(v))
p=pathlib.Path('/lab/provisioning/alerting/contacts.yml')
v=yaml.safe_load(p.read_text())
for policy in v['policies']: policy['group_wait']='1h'
p.write_text(yaml.safe_dump(v))
'''
    command("docker", "run", "--rm", "--network", "none", "-v", f"{temp}:/lab", "vpn-service-tools:local", "python", "-c", prepare)
    (temp / "prometheus.yml").write_text("global:\n  scrape_interval: 1s\nscrape_configs:\n  - job_name: lab\n    static_configs:\n      - targets: ['127.0.0.1:9876']\n")
    name = "vpn-smoke-" + uuid.uuid4().hex[:10]
    names = [name + "-loki", name + "-prometheus", name]
    # Deliberate test-only credentials; no production registry is opened by this test.
    auth = base64.b64encode(b"fleetadmin:smoke-test-only-password").decode()
    try:
        command("docker", "run", "-d", "--name", names[0], "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--tmpfs", "/loki:uid=10001,gid=10001,size=128m", "--tmpfs", "/tmp:size=32m",
                "-v", f"{root / 'monitoring/loki.yml'}:/etc/loki/config.yml:ro", images["loki"], "-config.file=/etc/loki/config.yml")
        command("docker", "run", "-d", "--name", names[1], "--network", "container:" + names[0], "--read-only", "--cap-drop", "ALL",
                "--tmpfs", "/prometheus:uid=65534,gid=65534,size=64m", "--tmpfs", "/tmp:size=32m",
                "-v", f"{temp / 'prometheus.yml'}:/etc/prometheus/prometheus.yml:ro", images["prometheus"],
                "--config.file=/etc/prometheus/prometheus.yml", "--web.listen-address=127.0.0.1:9090", "--storage.tsdb.path=/prometheus")
        command("docker", "run", "-d", "--name", name, "--network", "container:" + names[0], "--read-only",
                          "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                          "--tmpfs", "/var/lib/grafana:uid=472,gid=472,size=128m", "--tmpfs", "/tmp:size=32m",
                          "-e", "GF_SERVER_HTTP_ADDR=127.0.0.1", "-e", "GF_SECURITY_ADMIN_USER=fleetadmin",
                          "-e", "GF_SECURITY_ADMIN_PASSWORD=smoke-test-only-password",
                          "-e", "GF_ANALYTICS_REPORTING_ENABLED=false", "-e", "GF_ANALYTICS_CHECK_FOR_UPDATES=false",
                          "-e", "GF_AUTH_ANONYMOUS_ENABLED=false",
                          "-e", "GF_UNIFIED_ALERTING_MIN_INTERVAL=10s",
                          "-e", "GF_PATHS_PLUGINS=/opt/grafana-plugins",
                          "-e", "GF_PLUGINS_PREINSTALL_DISABLED=true",
                          "-e", "GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false",
                          "-e", "GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false",
                          "-v", f"{plugins}:/opt/grafana-plugins:ro",
                          "-v", f"{temp / 'provisioning'}:/etc/grafana/provisioning:ro",
                          "-v", f"{root / 'monitoring/fleet-dashboard.json'}:/var/lib/grafana/dashboards/fleet.json:ro",
                          images["grafana"])
        for attempt in range(40):
            health = command("docker", "exec", name, "wget", "-q", "-O", "-", "http://127.0.0.1:3000/api/health", check=False)
            if health.returncode == 0: break
            if command("docker", "inspect", "-f", "{{.State.Running}}", name).stdout.strip() != "true":
                raise RuntimeError(command("docker", "logs", name).stdout[-6000:])
            time.sleep(1)
        else: raise RuntimeError("Grafana startup timed out")
        def get(path):
            result = command("docker", "exec", name, "wget", "-q", "-O", "-", "--header", "Authorization: Basic " + auth,
                             "http://127.0.0.1:3000" + path)
            return json.loads(result.stdout)
        assert len(get("/api/datasources")) == 2
        assert get("/api/dashboards/uid/private-vpn-fleet")["dashboard"]["title"].startswith("Private VPN")
        assert len(get("/api/v1/provisioning/alert-rules")) == 12
        contacts = get("/api/v1/provisioning/contact-points")
        assert {item["type"] for item in contacts if item["name"] == "fleet-admin"} == {"email", "telegram"}
        anonymous = command("docker", "exec", name, "wget", "-q", "-O", "-", "http://127.0.0.1:3000/api/datasources", check=False)
        assert anonymous.returncode != 0
        result = command("docker", "run", "--rm", "--network", "container:" + names[0], "-v", f"{root}:/workspace:ro", "-w", "/workspace",
                         "vpn-service-tools:local", "python", "tests/monitoring_probe.py")
        print(result.stdout.strip())
        print("PASS: dashboard, 2 data sources, 12 alert rules, both test contacts; anonymous API denied.")
    except Exception:
        # Test-only containers hold no real credentials. Keep diagnostics short and local.
        for container in names:
            logs = command("docker", "logs", container, check=False)
            print((logs.stderr or logs.stdout)[-1500:])
        raise
    finally:
        for container in reversed(names):
            command("docker", "rm", "-f", container, check=False)
