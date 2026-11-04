#!/usr/bin/env python3
"""Smoke-test provisioned Grafana in an ephemeral networkless container. No real secrets."""
import base64
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid


def command(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)


if __name__ == "__main__":
    root = Path.cwd()
    images = json.loads((root / "infra/images.lock.json").read_text())
    temp = root / ".state/smoke"
    for folder in ["datasources", "dashboards", "alerting"]:
        (temp / "provisioning" / folder).mkdir(parents=True, exist_ok=True)
    for source, dest in [("datasources.yml", "datasources/main.yml"), ("dashboards.yml", "dashboards/main.yml"), ("alerts.yml", "alerting/main.yml")]:
        shutil.copyfile(root / "monitoring" / source, temp / "provisioning" / dest)
    contacts_fixture = root / ".state/validation/vpn_b/contacts.yml"
    if contacts_fixture.exists():
        shutil.copyfile(contacts_fixture, temp / "provisioning/alerting/contacts.yml")
    name = "vpn-smoke-" + uuid.uuid4().hex[:10]
    # Deliberate test-only credentials; no production registry is opened by this test.
    auth = base64.b64encode(b"fleetadmin:smoke-test-only-password").decode()
    try:
        created = command("docker", "run", "-d", "--name", name, "--network", "none", "--read-only",
                          "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                          "--tmpfs", "/var/lib/grafana:uid=472,gid=472,size=128m", "--tmpfs", "/tmp:size=32m",
                          "-e", "GF_SERVER_HTTP_ADDR=127.0.0.1", "-e", "GF_SECURITY_ADMIN_USER=fleetadmin",
                          "-e", "GF_SECURITY_ADMIN_PASSWORD=smoke-test-only-password",
                          "-e", "GF_ANALYTICS_REPORTING_ENABLED=false", "-e", "GF_ANALYTICS_CHECK_FOR_UPDATES=false",
                          "-e", "GF_AUTH_ANONYMOUS_ENABLED=false",
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
        assert len(get("/api/v1/provisioning/alert-rules")) >= 9
        if contacts_fixture.exists():
            contacts = get("/api/v1/provisioning/contact-points")
            assert {item["type"] for item in contacts if item["name"] == "fleet-admin"} == {"email", "telegram"}
        anonymous = command("docker", "exec", name, "wget", "-q", "-O", "-", "http://127.0.0.1:3000/api/datasources", check=False)
        assert anonymous.returncode != 0
        print("PASS: Grafana starts, imports dashboard, 2 data sources, 9+ alerts and configured test contacts; anonymous API access is denied. No notification sent.")
    finally:
        command("docker", "rm", "-f", name, check=False)
