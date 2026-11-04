#!/usr/bin/env python3
"""Transactional owned-table firewall with a timed last-good rollback."""
import os
import hashlib
import json
import fcntl
from pathlib import Path
import subprocess
import sys

ROOT = Path("/etc/vpn-service")
STATE = Path("/var/lib/vpn-service")
TABLES = [("inet", "vpn_service"), ("ip", "vpn_nat")]


def load(path):
    prefix = ""
    for family, name in TABLES:
        if subprocess.run(["nft", "list", "table", family, name], capture_output=True).returncode == 0:
            prefix += f"delete table {family} {name}\n"
    data = prefix + path.read_text()
    for command in (["nft", "--check", "-f", "-"], ["nft", "-f", "-"]):
        subprocess.run(command, input=data, text=True, check=True, capture_output=True)


def execute(command):
    STATE.mkdir(mode=0o700, exist_ok=True)
    candidate = ROOT / "firewall.nft"
    good = STATE / "firewall.last-good.nft"
    status_path = STATE / "firewall-status.json"
    digest = lambda: hashlib.sha256(candidate.read_bytes()).hexdigest()
    if command == "apply":
        if not good.exists():
            good.write_text((ROOT / "firewall-rescue.nft").read_text())
        subprocess.run(["systemctl", "stop", "vpn-firewall-rollback.timer"], capture_output=True)
        subprocess.run(["systemd-run", "--collect", "--unit=vpn-firewall-rollback", "--on-active=120s",
                        "/usr/local/sbin/vpn-firewall", "rollback"], check=True, capture_output=True)
        status_path.write_text(json.dumps({"status": "pending", "digest": digest()}))
        load(candidate)
        print("Firewall staged. Confirm through a fresh administrative SSH session within 120 seconds.")
    elif command == "confirm":
        status = json.loads(status_path.read_text()) if status_path.exists() else {}
        if status.get("status") != "pending" or status.get("digest") != digest():
            raise ValueError("No matching staged policy remains; it may have rolled back")
        subprocess.run(["systemctl", "stop", "vpn-firewall-rollback.timer"], check=True)
        good.write_text(candidate.read_text())
        status_path.write_text(json.dumps({"status": "confirmed", "digest": digest()}))
        print("Firewall confirmed")
    elif command == "rollback":
        load(good)
        candidate.write_text(good.read_text())
        status_path.write_text(json.dumps({"status": "rolled_back", "digest": digest()}))
        print("Firewall rolled back")
    elif command == "boot":
        load(good if good.exists() else ROOT / "firewall-rescue.nft")
    elif command == "status":
        print(status_path.read_text() if status_path.exists() else '{"status":"unconfirmed"}')
    else:
        raise SystemExit("Expected apply, confirm, rollback, boot or status")


if __name__ == "__main__":
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE / "firewall.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        execute(sys.argv[1])
