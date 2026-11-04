"""Render public inventory and Ansible Vault credentials; never plaintext secrets."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import yaml

from .registry import FleetError, atomic_write, private_directory
from .image_policy import validate_scan


def validate_images(images: dict) -> None:
    try:
        validate_scan(images)
    except (ValueError, TypeError, KeyError) as exc:
        raise FleetError(str(exc) if type(exc) is ValueError else "Invalid image scan evidence") from None


def pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def make_pki() -> dict:
    current = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vpn-fleet-telemetry-ca")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(current - timedelta(minutes=5)).not_valid_after(current + timedelta(days=730))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    result = {"ca": ca.public_bytes(serialization.Encoding.PEM).decode(), "nodes": {}}
    # CA signing key is deliberately discarded after issuance. Renew by replacing this PKI.
    for node_id, addr in [("vpn_a", "10.78.0.1"), ("vpn_b", "10.78.0.2")]:
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
                .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(current - timedelta(minutes=5)).not_valid_after(current + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(addr))]), False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .sign(ca_key, hashes.SHA256()))
        result["nodes"][node_id] = {"key": pem(key), "cert": cert.public_bytes(serialization.Encoding.PEM).decode()}
    return result


def prepare_credentials(state: dict) -> None:
    if "pki" not in state:
        state["pki"] = make_pki()
    if "grafana" not in state:
        state["grafana"] = {"password": secrets.token_urlsafe(32), "secret_key": secrets.token_urlsafe(48)}


def render(state: dict, output: Path, password: str, images: dict) -> None:
    try:
        from ansible.parsing.vault import VaultLib, VaultSecret
    except ImportError:
        raise FleetError("Rendering requires the deploy extra in a Linux controller or tooling container") from None
    prepare_credentials(state)
    private_directory(output)
    hostvars, node_secrets = {}, {}
    for node in state["fleet"]["nodes"]:
        node_id = node["id"]
        peer = next(n for n in state["fleet"]["nodes"] if n["id"] != node_id)
        index = 1 if node_id == "vpn_a" else 2
        net = ipaddress.ip_network(node["network"])
        peers = []
        for device, d in state["devices"].items():
            if not d["revoked"]:
                keys = d["keys"][node_id]
                peers.append({"id": device, "public_key": keys["public"], "psk": keys["psk"],
                              "ipv4": str(net[d["slot"]]), "ipv6": f"fd77:{index}::{d['slot']:x}"})
        # PSKs and all private keys exist ONLY inside Ansible Vault output.
        node_secrets[node_id] = {"vpn_key": state["servers"][node_id]["vpn"]["private"],
                                "mgmt_key": state["servers"][node_id]["management"]["private"],
                                "tls": state["pki"]["nodes"][node_id], "peers": peers}
        hostvars[node_id] = {"ansible_host": node["endpoint"], "vpn_port": node["port"],
                            "vpn_network": node["network"], "vpn_address": str(net[1]),
                            "vpn_ipv6": f"fd77:{index}::1", "vpn_backend": node.get("backend", "wireguard"),
                            "amneziawg_options": node.get("amneziawg_options", {}), "vpn_mtu": node.get("mtu", 1380),
                            "mgmt_address": f"10.78.0.{index}", "mgmt_peer_address": "10.78.0.2" if index == 1 else "10.78.0.1",
                            "mgmt_peer_endpoint": peer["endpoint"],
                            "mgmt_peer_public_key": state["servers"][peer["id"]]["management"]["public"],
                            "monitoring_node": node_id == "vpn_b"}
    inventory = {"all": {"children": {"vpn": {"hosts": hostvars}},
                         "vars": {"fleet_id": state["fleet_id"], "fleet_revision": state["revision"],
                                  "admin_cidrs": state["fleet"]["admin_cidrs"],
                                  "admin_public_key": state["fleet"]["admin_public_key"],
                                  "telemetry_ca": state["pki"]["ca"], "images": images}}}
    vault = VaultLib([("default", VaultSecret(password.encode()))])
    from .notifications import provisioning
    settings = state.get("alerting", {})
    encrypted = vault.encrypt(yaml.safe_dump({"node_secrets": node_secrets,
                                              "grafana_secrets": state["grafana"],
                                              "alerting_settings": settings,
                                              "alerting_provisioning": provisioning(settings) if settings else {}}).encode())
    # Publish credentials first, inventory last. Subsequent renders preserve credentials.
    atomic_write(output / "group_vars" / "all" / "vault.yml", encrypted)
    atomic_write(output / "inventory.json", json.dumps(inventory, indent=2).encode())
