#!/usr/bin/env python3
"""Apply a complete peer set without restarting other devices; reject stale state."""
import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def check_key(value):
    if len(base64.b64decode(value, validate=True)) != 32:
        raise ValueError("invalid key")
    return value


def validate(data):
    if data["backend"] not in ("wireguard", "amneziawg"):
        raise ValueError("invalid backend")
    if not isinstance(data["revision"], int) or data["revision"] < 1:
        raise ValueError("invalid revision")
    if not re.fullmatch(r"[a-f0-9-]{36}", data["fleet_id"]):
        raise ValueError("invalid fleet ID")
    check_key(data["private_key"])
    if not 1024 <= data["port"] <= 65535:
        raise ValueError("invalid port")
    if not 1280 <= data.get("mtu", 1380) <= 1420:
        raise ValueError("invalid MTU")
    net = ipaddress.ip_network(data["network"])
    seen, addresses = set(), set()
    if len(data["peers"]) > 300:
        raise ValueError("too many peers")
    for peer in data["peers"]:
        key = check_key(peer["public_key"])
        check_key(peer["psk"])
        addr = ipaddress.ip_address(peer["ipv4"])
        addr6 = ipaddress.ip_address(peer["ipv6"])
        if key in seen or str(addr) in addresses or addr not in net or int(addr) <= int(net.network_address) + 1 or addr == net.broadcast_address:
            raise ValueError("duplicate key/address or invalid allocation")
        if addr6 not in ipaddress.ip_network(data["ipv6_network"], strict=False):
            raise ValueError("invalid IPv6 allocation")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", peer["id"]):
            raise ValueError("invalid device ID")
        seen.add(key); addresses.add(str(addr))
    allowed = {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"}
    for k, v in data.get("options", {}).items():
        if k not in allowed or any(c in str(v) for c in "\r\n\x00"):
            raise ValueError("unsafe option")
    if data["backend"] == "wireguard" and data.get("options"):
        raise ValueError("Amnezia options on standard WireGuard")
    return data


def configuration(data):
    validate(data)
    lines = ["[Interface]", "PrivateKey = " + data["private_key"], f"ListenPort = {data['port']}"]
    lines.extend(f"{k} = {v}" for k, v in data.get("options", {}).items())
    for peer in data["peers"]:
        lines += ["", "[Peer]", "PublicKey = " + peer["public_key"], "PresharedKey = " + peer["psk"],
                  f"AllowedIPs = {peer['ipv4']}/32, {peer['ipv6']}/128"]
    return "\n".join(lines) + "\n"


def write(path, content):
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as out:
            out.write(content); out.flush(); os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def apply(data, state_dir=Path("/var/lib/vpn-service")):
    validate(data)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state_dir / "apply.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        last_path = state_dir / "applied.json"
        previous = json.loads(last_path.read_text()) if last_path.exists() else None
        canonical = json.dumps(data, sort_keys=True)
        if previous and (previous["fleet_id"] != data["fleet_id"] or
                         previous["revision"] > data["revision"] or
                         (previous["revision"] == data["revision"] and json.dumps(previous, sort_keys=True) != canonical)):
            raise ValueError("stale or conflicting desired state; investigate restore/revision")
        binary = "wg" if data["backend"] == "wireguard" else "awg"
        kind = "wireguard" if binary == "wg" else "amneziawg"
        if previous and previous["backend"] != data["backend"]:
            raise ValueError("backend migration requires a planned interface replacement")
        exists = subprocess.run(["ip", "link", "show", "dev", "vpn0"], capture_output=True).returncode == 0
        if not exists:
            run("ip", "link", "add", "vpn0", "type", kind)
        runtime = Path("/run/vpn-service")
        runtime.mkdir(mode=0o700, exist_ok=True)
        conf = runtime / "vpn0.conf"
        write(conf, configuration(data))
        try:
            run(binary, "syncconf", "vpn0", str(conf))
            run("ip", "address", "replace", data["address"] + "/23", "dev", "vpn0")
            run("ip", "-6", "address", "replace", data["ipv6_address"] + "/64", "dev", "vpn0")
            run("ip", "link", "set", "dev", "vpn0", "mtu", str(data.get("mtu", 1380)), "up")
        except Exception:
            if previous:
                write(conf, configuration(previous))
                run(binary, "syncconf", "vpn0", str(conf))
            else:
                subprocess.run(["ip", "link", "delete", "vpn0"], capture_output=True)
            raise
        finally:
            conf.unlink(missing_ok=True)
        write(last_path, canonical)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        # Readable acknowledgement deliberately excludes peer IDs, endpoints and credentials.
        write(state_dir / "ack.json", json.dumps({"fleet_id": data["fleet_id"], "revision": data["revision"], "digest": digest}))
        event_dir = Path("/var/log/vpn-service")
        event_dir.mkdir(mode=0o750, exist_ok=True)
        if previous != data:
            with (event_dir / "events.jsonl").open("a") as log:
                log.write(json.dumps({"event": "configuration_applied", "revision": data["revision"], "peer_count": len(data["peers"])}) + "\n")
        return previous != data


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        changed = apply(json.loads(args.config.read_text()))
        print(json.dumps({"changed": changed}))
    except Exception:
        print("VPN configuration rejected or failed; no credentials logged", file=sys.stderr)
        raise SystemExit(1)
