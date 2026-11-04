#!/usr/bin/env python3
"""Render test-only fixtures, parse all configs and run Ansible syntax checks."""
import json
from pathlib import Path
import subprocess
import sys
import yaml
from jinja2 import Environment, StrictUndefined

sys.path.insert(0, "tests")
from test_registry import fleet, PASSWORD
from test_notifications import NotificationTests
from vpn_fleet.registry import create_registry, add_user, add_device
from vpn_fleet.deployment import render
from ansible.parsing.vault import VaultLib, VaultSecret


def fixtures():
    state = create_registry(fleet()); add_user(state, "testuser"); add_device(state, "testuser", "testphone")
    state["alerting"] = NotificationTests().settings()
    output = Path(".state/validation")
    images = json.loads(Path("infra/images.lock.json").read_text())
    render(state, output / "inventory", PASSWORD, images)
    data = json.loads((output / "inventory/inventory.json").read_text())
    vault = VaultLib([("default", VaultSecret(PASSWORD.encode()))])
    private = yaml.safe_load(vault.decrypt((output / "inventory/group_vars/all/vault.yml").read_bytes()))
    env = Environment(undefined=StrictUndefined, keep_trailing_newline=True)
    env.filters["to_nice_json"] = lambda value: json.dumps(value, indent=2)
    for node, variables in data["all"]["children"]["vpn"]["hosts"].items():
        variables = {**data["all"]["vars"], **variables, "inventory_hostname": node,
                     "secrets_for_node": private["node_secrets"][node], "grafana_secrets": private["grafana_secrets"],
                     "alerting_settings": private["alerting_settings"], "alerting_provisioning": private["alerting_provisioning"],
                     "ansible_facts": {"default_ipv4": {"interface": "br0"}}}
        directory = output / node; directory.mkdir(parents=True, exist_ok=True)
        (directory / "contacts.yml").write_text(json.dumps(private["alerting_provisioning"]))
        for source in Path("infra/roles").rglob("*.j2"):
            target = directory / source.name.removesuffix(".j2")
            target.write_text(env.from_string(source.read_text()).render(**variables))
            if target.suffix in (".yml", ".json"):
                (json.loads if target.suffix == ".json" else yaml.safe_load)(target.read_text())
    (output / "vault-password-test-only").write_text(PASSWORD)
    for play in ("site.yml", "peers.yml", "harden-ssh.yml", "backup.yml", "verify.yml"):
        subprocess.run(["ansible-playbook", "-i", str((output / "inventory/inventory.json").resolve()),
                        "--vault-password-file", str((output / "vault-password-test-only").resolve()),
                        "--syntax-check", "infra/" + play], check=True)
    for path in Path("monitoring").glob("*.yml"): yaml.safe_load(path.read_text())
    print("Templates, YAML/JSON and five Ansible playbooks validated; no server contacted.")


if __name__ == "__main__": fixtures()
