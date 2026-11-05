"""Authenticated encrypted storage, device quotas, and credential lifecycle."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

AAD = b"private-vpn-fleet/registry/v1"
ID = re.compile(r"[a-z][a-z0-9_-]{0,39}\Z")


class FleetError(ValueError):
    """An actionable error whose message contains no credential values."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise FleetError("Private directory must not be a symlink")
    if os.name == "nt":
        # Replace the entire DACL: removing inheritance and granting the owner alone
        # would leave pre-existing explicit Everyone/Users grants in place.
        script = """
$ErrorActionPreference = 'Stop'
$target = $env:VPN_FLEET_PRIVATE_PATH
$directory = [IO.DirectoryInfo]::new($target)
if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Private directory must not be a reparse point'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetAccessRuleProtection($true, $false)
$rule = [Security.AccessControl.FileSystemAccessRule]::new(
    $identity, [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow)
$security.AddAccessRule($rule)
$directory.SetAccessControl($security)
$actual = $directory.GetAccessControl()
$rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (-not $actual.AreAccessRulesProtected -or $rules.Count -ne 1 -or
    $rules[0].IdentityReference.Value -ne $identity.Value -or
    $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
    $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
    throw 'Private directory ACL verification failed'
}
"""
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        # Preserve a final junction/reparse point so the helper can reject it.
        environment = {**os.environ, "VPN_FLEET_PRIVATE_PATH": str(path.absolute())}
        try:
            subprocess.run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                            base64.b64encode(script.encode("utf-16-le")).decode()],
                           env=environment, check=True, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise FleetError("Cannot enforce private Windows ACLs; use a local filesystem supporting protected ACLs") from None
    else:
        path.chmod(0o700)


def atomic_write(path: Path, data: bytes, *, replace: bool = True) -> None:
    private_directory(path.parent)
    if path.is_symlink() or (path.exists() and not replace):
        raise FleetError("Destination exists or is a symlink; select a new output path")
    fd, name = tempfile.mkstemp(prefix=".vpn-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(name, path)
        else:
            # Atomic no-clobber publication; unlike exists()+replace(), this is race safe.
            os.link(name, path)
            os.unlink(name)
        if os.name != "nt":
            path.chmod(0o600)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def keypair() -> dict:
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"private": base64.b64encode(raw).decode(), "public": base64.b64encode(public).decode()}


def validate_key(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise FleetError("Invalid WireGuard key encoding") from None
    if len(raw) != 32 or raw == bytes(32):
        raise FleetError("WireGuard keys must contain 32 nonzero bytes")
    return value


def identifier(value: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise FleetError("IDs must be lowercase ASCII identifiers, 1–40 characters")
    return value


def validate_fleet(fleet: dict) -> dict:
    if set(fleet) != {"nodes", "admin_cidrs", "admin_public_key"}:
        raise FleetError("Fleet requires nodes, admin_cidrs and admin_public_key only")
    nodes = fleet["nodes"]
    if len(nodes) != 2 or {n["id"] for n in nodes} != {"vpn_a", "vpn_b"}:
        raise FleetError("Exactly vpn_a and vpn_b are required")
    prefixes = []
    endpoints = []
    for n in nodes:
        identifier(n["id"])
        try:
            endpoint = ipaddress.IPv4Address(n["endpoint"])
            net = ipaddress.IPv4Network(n["network"], strict=True)
        except (ValueError, KeyError):
            raise FleetError("Each node needs a public IPv4 endpoint and a private /23 network") from None
        if not endpoint.is_global or net.prefixlen != 23 or not net.is_private:
            raise FleetError("Endpoint must be global IPv4 and network must be private /23")
        if str(net.network_address).split(".")[0] != "10":
            raise FleetError("User networks must be within 10.0.0.0/8")
        if net.overlaps(ipaddress.ip_network("10.78.0.0/30")):
            raise FleetError("User network overlaps the management network")
        if not isinstance(n.get("port"), int) or not 1024 <= n["port"] <= 65535:
            raise FleetError("VPN UDP port must be between 1024 and 65535")
        if not isinstance(n.get("mtu", 1380), int) or not 1280 <= n.get("mtu", 1380) <= 1420:
            raise FleetError("Use an MTU between 1280 and 1420; default is 1380")
        if n.get("backend", "wireguard") not in ("wireguard", "amneziawg"):
            raise FleetError("Unsupported VPN backend")
        options = n.get("amneziawg_options", {})
        allowed = {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"}
        if any(k not in allowed or not isinstance(v, (str, int)) or
               any(c in str(v) for c in "\r\n\x00") or len(str(v)) > 1024 for k, v in options.items()):
            raise FleetError("Invalid AmneziaWG interface options")
        if n.get("backend") == "amneziawg" and not options:
            raise FleetError("AmneziaWG requires reviewed options compatible with the selected clients")
        prefixes.append(net)
        endpoints.append(endpoint)
    if prefixes[0].overlaps(prefixes[1]) or endpoints[0] == endpoints[1]:
        raise FleetError("Node endpoints and networks must be independent")
    if not fleet["admin_cidrs"]:
        raise FleetError("Specify at least one restricted administrative IPv4 CIDR")
    for entry in fleet["admin_cidrs"]:
        net = ipaddress.IPv4Network(entry, strict=True)
        if net.prefixlen < 24 or not net.network_address.is_global:
            raise FleetError("Administrative CIDRs must be global IPv4 /24 or narrower")
    if not re.fullmatch(r"(?:ssh-ed25519|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/=]+(?: [^\r\n]+)?", fleet["admin_public_key"]):
        raise FleetError("Provide a single Ed25519 administrative PUBLIC key")
    return fleet


def create_registry(fleet: dict) -> dict:
    validate_fleet(fleet)
    return {"schema": 1, "fleet_id": str(uuid.uuid4()), "revision": 1,
            "fleet": fleet, "users": {}, "devices": {}, "audit": [],
            "servers": {n["id"]: {"vpn": keypair(), "management": keypair()}
                        for n in fleet["nodes"]}}


def event(state: dict, action: str, subject: str) -> None:
    state["revision"] += 1
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    state["audit"] = [e for e in state["audit"] if e["at"] >= cutoff]
    state["audit"].append({"at": now(), "action": action, "subject": subject,
                           "revision": state["revision"]})


def add_user(state: dict, user: str) -> None:
    identifier(user)
    if user in state["users"] or len(state["users"]) >= 100:
        raise FleetError("User already exists or 100-user limit reached")
    state["users"][user] = {"created": now()}
    event(state, "user_added", user)


def add_device(state: dict, user: str, device: str) -> None:
    identifier(device)
    if user not in state["users"] or device in state["devices"]:
        raise FleetError("Unknown user or device ID already exists")
    active = [d for d in state["devices"].values() if d["user"] == user and not d["revoked"]]
    if len(active) >= 3:
        raise FleetError("Three active devices per user are allowed")
    # Never reuse a slot while any record retains it; rotation cannot resurrect old keys.
    used = {d["slot"] for d in state["devices"].values()}
    slot = next((s for s in range(2, 511) if s not in used), None)
    if slot is None:
        raise FleetError("Address history pool exhausted; use rotate-device for existing devices or plan a reviewed pool migration")
    state["devices"][device] = {"user": user, "slot": slot, "revoked": False, "created": now(),
                                "keys": {n["id"]: {**keypair(), "psk": base64.b64encode(secrets.token_bytes(32)).decode()}
                                         for n in state["fleet"]["nodes"]}}
    event(state, "device_added", device)


def revoke(state: dict, device: str) -> None:
    if device not in state["devices"]:
        raise FleetError("Unknown device")
    record = state["devices"][device]
    if not record["revoked"]:
        record["revoked"] = True
        record["keys"] = {}  # Secret deletion in current registry, not a claim of SSD erasure.
        event(state, "device_revoked", device)


def rotate_device(state: dict, device: str) -> None:
    record = state["devices"].get(device)
    if not record or record["revoked"]:
        raise FleetError("Only an active device can be rotated")
    record["keys"] = {n["id"]: {**keypair(), "psk": base64.b64encode(secrets.token_bytes(32)).decode()}
                      for n in state["fleet"]["nodes"]}
    event(state, "device_keys_rotated", device)


def client_config(state: dict, device: str, node_id: str) -> str:
    record = state["devices"].get(device)
    if not record or record["revoked"]:
        raise FleetError("Device does not exist or was revoked")
    node = next((n for n in state["fleet"]["nodes"] if n["id"] == node_id), None)
    if not node:
        raise FleetError("Unknown node")
    net = ipaddress.ip_network(node["network"])
    suffix = 1 if node_id == "vpn_a" else 2
    keys = record["keys"][node_id]
    lines = ["[Interface]", f"PrivateKey = {keys['private']}",
             f"Address = {net[record['slot']]}/32, fd77:{suffix}::{record['slot']:x}/128",
             f"DNS = {net[1]}", f"MTU = {node.get('mtu', 1380)}"]
    lines.extend(f"{k} = {v}" for k, v in node.get("amneziawg_options", {}).items())
    lines += ["", "[Peer]", f"PublicKey = {state['servers'][node_id]['vpn']['public']}",
              f"PresharedKey = {keys['psk']}", f"Endpoint = {node['endpoint']}:{node['port']}",
              "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def encrypt(state: dict, password: str) -> bytes:
    if len(password) < 16:
        raise FleetError("Use a passphrase of at least 16 characters")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password.encode())
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(state, separators=(",", ":")).encode(), AAD)
    return json.dumps({"schema": 1, "salt": salt.hex(), "nonce": nonce.hex(),
                       "ciphertext": ciphertext.hex()}).encode()


def decrypt(data: bytes, password: str) -> dict:
    try:
        envelope = json.loads(data)
        if envelope["schema"] != 1:
            raise ValueError
        salt, nonce = bytes.fromhex(envelope["salt"]), bytes.fromhex(envelope["nonce"])
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError
        key = Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password.encode())
        state = json.loads(AESGCM(key).decrypt(nonce, bytes.fromhex(envelope["ciphertext"]), AAD))
        if state["schema"] != 1:
            raise ValueError
        validate_fleet(state["fleet"])
        return state
    except (KeyError, ValueError, TypeError, InvalidTag):
        raise FleetError("Cannot open registry: incorrect passphrase, unsupported format or damaged data") from None


@contextmanager
def locked(path: Path):
    private_directory(path.parent)
    lock = path.with_suffix(path.suffix + ".lock")
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise FleetError("Registry is locked; investigate before removing a stale lock") from None
    os.close(fd)
    try:
        yield
    finally:
        lock.unlink()
