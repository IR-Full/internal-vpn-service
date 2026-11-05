#!/usr/bin/env python3
"""Transactional owned-table firewall with a timed last-good rollback."""
import os
import hashlib
import json
import fcntl
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path("/etc/vpn-service")
STATE = Path("/var/lib/vpn-service")
TABLES = [("inet", "vpn_service"), ("ip", "vpn_nat")]


def atomic_write(path, content):
    """Preserve the previous complete file until the new checkpoint is durable."""
    descriptor, temporary = tempfile.mkstemp(prefix=".firewall-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_policy(content):
    """Enforce the owned-table/default-drop envelope; nft still validates all syntax."""
    if not content.strip() or "\x00" in content:
        raise ValueError("Empty or malformed firewall policy")
    lexer = shlex.shlex(content, posix=True, punctuation_chars="{};")
    lexer.whitespace_split = True
    tokens = []
    for token in lexer:
        tokens.extend(token if set(token) <= set("{};") else [token])
    tables, index = {}, 0
    while index < len(tokens):
        if index + 3 >= len(tokens) or tokens[index] != "table" or tokens[index + 3] != "{":
            raise ValueError("Only complete owned-table declarations are allowed")
        identity = tuple(tokens[index + 1:index + 3])
        if identity not in TABLES or identity in tables:
            raise ValueError("Unexpected or duplicate firewall table")
        start, depth = index + 4, 1
        index = start
        while index < len(tokens) and depth:
            depth += (tokens[index] == "{") - (tokens[index] == "}")
            index += 1
        if depth:
            raise ValueError("Incomplete firewall table")
        tables[identity] = tokens[start:index - 1]
    if set(tables) != set(TABLES):
        raise ValueError("Both owned firewall tables are required")
    body = tables[("inet", "vpn_service")]
    for name in ("input", "forward"):
        header = ["chain", name, "{"]
        matches = [i for i in range(len(body) - 2) if body[i:i + 3] == header]
        if len(matches) != 1:
            raise ValueError("Required firewall filter chain is missing or duplicated")
        start, depth = matches[0] + 3, 1
        end = start
        while end < len(body) and depth:
            depth += (body[end] == "{") - (body[end] == "}")
            end += 1
        chain = body[start:end - 1]
        hook = ["type", "filter", "hook", name, "priority"]
        if not any(chain[i:i + len(hook)] == hook for i in range(len(chain) - len(hook) + 1)):
            raise ValueError("Required base-chain hook is missing")
        if not any(chain[i:i + 3] == ["policy", "drop", ";"] for i in range(len(chain) - 2)):
            raise ValueError("Required default-drop policy is missing")
    return content


def transaction(content):
    validate_policy(content)
    prefix = ""
    for family, name in TABLES:
        if subprocess.run(["nft", "list", "table", family, name], capture_output=True).returncode == 0:
            prefix += f"delete table {family} {name}\n"
    return prefix + content


def load(path):
    content = validate_policy(path.read_text())
    data = transaction(content)
    for command in (["nft", "--check", "-f", "-"], ["nft", "-f", "-"]):
        subprocess.run(command, input=data, text=True, check=True, capture_output=True)
    return content


def load_checkpoint(good):
    try:
        return load(good), False
    except (OSError, ValueError, subprocess.CalledProcessError):
        # Invalid checkpoints must never turn into a deletion-only transaction.
        return load(ROOT / "firewall-rescue.nft"), True


def read_status(path):
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        # Unreadable metadata must not disable a scheduled safety rollback.
        return {}


def execute(command):
    STATE.mkdir(mode=0o700, exist_ok=True)
    candidate = ROOT / "firewall.nft"
    good = STATE / "firewall.last-good.nft"
    status_path = STATE / "firewall-status.json"
    digest = lambda: hashlib.sha256(candidate.read_bytes()).hexdigest()
    if command == "apply":
        policy = validate_policy(candidate.read_text())
        subprocess.run(["nft", "--check", "-f", "-"], input=transaction(policy), text=True, check=True, capture_output=True)
        status = read_status(status_path)
        if status.get("status") == "pending":
            raise ValueError("Confirm or roll back the previous staged firewall before restaging")
        if not good.exists():
            atomic_write(good, validate_policy((ROOT / "firewall-rescue.nft").read_text()))
        subprocess.run(["systemctl", "stop", "vpn-firewall-rollback.timer"], capture_output=True)
        subprocess.run(["systemd-run", "--collect", "--unit=vpn-firewall-rollback", "--on-active=120s",
                        "/usr/local/sbin/vpn-firewall", "rollback"], check=True, capture_output=True)
        atomic_write(status_path, json.dumps({"status": "pending", "digest": digest()}))
        load(candidate)
        print("Firewall staged. Confirm through a fresh administrative SSH session within 120 seconds.")
    elif command == "confirm":
        status = read_status(status_path)
        if status.get("status") != "pending" or status.get("digest") != digest():
            raise ValueError("No matching staged policy remains; it may have rolled back")
        policy = validate_policy(candidate.read_text())
        subprocess.run(["nft", "--check", "-f", "-"], input=transaction(policy), text=True, check=True, capture_output=True)
        # Do not disarm rollback while the last-good checkpoint can still be lost.
        atomic_write(good, policy)
        atomic_write(status_path, json.dumps({"status": "confirmed", "digest": digest()}))
        subprocess.run(["systemctl", "stop", "vpn-firewall-rollback.timer"], check=True)
        print("Firewall confirmed")
    elif command == "rollback":
        status = read_status(status_path)
        if status.get("status") == "confirmed":
            print("No pending firewall rollback remains")
            return
        policy, rescue = load_checkpoint(good)
        atomic_write(candidate, policy)
        atomic_write(status_path, json.dumps({"status": "rolled_back", "digest": digest(), "rescue": rescue}))
        print("Firewall rolled back")
    elif command == "boot":
        policy, rescue = load_checkpoint(good)
        if rescue:
            atomic_write(status_path, json.dumps({"status": "rescue"}))
        elif read_status(status_path).get("status") == "pending":
            # The transient rollback timer does not survive a reboot.
            atomic_write(status_path, json.dumps({"status": "rolled_back",
                                                  "digest": hashlib.sha256(policy.encode()).hexdigest(),
                                                  "rescue": False}))
    elif command == "status":
        status = read_status(status_path) or {"status": "unconfirmed"}
        status["needs_apply"] = status.get("status") != "confirmed" or status.get("digest") != digest()
        print(json.dumps(status))
    else:
        raise SystemExit("Expected apply, confirm, rollback, boot or status")


if __name__ == "__main__":
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE / "firewall.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        execute(sys.argv[1])
