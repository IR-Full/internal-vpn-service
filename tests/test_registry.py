import copy
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ansible.parsing.vault import VaultLib, VaultSecret

from vpn_fleet import registry as r
from vpn_fleet.deployment import render

PASSWORD = "test-only random passphrase 9b7c704d"


def fleet():
    key = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return {"admin_cidrs": ["8.8.4.4/32"], "admin_public_key": key, "nodes": [
        {"id": "vpn_a", "endpoint": "8.8.8.8", "port": 51820, "network": "10.77.0.0/23", "backend": "wireguard"},
        {"id": "vpn_b", "endpoint": "1.1.1.1", "port": 51820, "network": "10.77.2.0/23", "backend": "wireguard"}]}


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.state = r.create_registry(fleet())
        r.add_user(self.state, "u001")

    def test_registry_authentication_and_ciphertext_tamper(self):
        blob = r.encrypt(self.state, PASSWORD)
        self.assertNotIn(self.state["servers"]["vpn_a"]["vpn"]["private"].encode(), blob)
        self.assertEqual(r.decrypt(blob, PASSWORD), self.state)
        with self.assertRaises(r.FleetError): r.decrypt(blob, "incorrect password")
        data = json.loads(blob); data["ciphertext"] = f"{int(data['ciphertext'][:2], 16) ^ 1:02x}" + data["ciphertext"][2:]
        with self.assertRaises(r.FleetError): r.decrypt(json.dumps(data).encode(), PASSWORD)

    def test_100_users_300_devices_unique_addresses_and_keys(self):
        for i in range(2, 101): r.add_user(self.state, f"u{i:03}")
        for i in range(1, 101):
            for j in range(3): r.add_device(self.state, f"u{i:03}", f"d{i:03}_{j}")
        self.assertEqual(len(self.state["devices"]), 300)
        self.assertEqual(len({d["slot"] for d in self.state["devices"].values()}), 300)
        keys = [k["public"] for d in self.state["devices"].values() for k in d["keys"].values()]
        self.assertEqual(len(set(keys)), 600)
        with self.assertRaises(r.FleetError): r.add_device(self.state, "u001", "fourth")
        with self.assertRaises(r.FleetError): r.add_user(self.state, "u101")

    def test_revocation_erases_current_secret_and_releases_quota(self):
        for i in range(3): r.add_device(self.state, "u001", f"device{i}")
        old = self.state["devices"]["device0"]["keys"]["vpn_a"]["private"]
        r.revoke(self.state, "device0")
        self.assertNotIn(old, json.dumps(self.state))
        with self.assertRaises(r.FleetError): r.client_config(self.state, "device0", "vpn_a")
        r.add_device(self.state, "u001", "replacement")
        self.assertNotEqual(self.state["devices"]["replacement"]["slot"], self.state["devices"]["device0"]["slot"])

    def test_profiles_capture_both_ip_families_and_dns(self):
        r.add_device(self.state, "u001", "phone")
        a = r.client_config(self.state, "phone", "vpn_a")
        b = r.client_config(self.state, "phone", "vpn_b")
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", a)
        self.assertIn("DNS = 10.77.0.1", a)
        self.assertIn("DNS = 10.77.2.1", b)
        self.assertNotEqual(a, b)
        self.assertNotIn("PostUp", a)

    def test_rotation_replaces_keys_without_reusing_old_secret_or_consuming_slot(self):
        r.add_device(self.state, "u001", "phone")
        old = copy.deepcopy(self.state["devices"]["phone"])
        r.rotate_device(self.state, "phone")
        self.assertEqual(self.state["devices"]["phone"]["slot"], old["slot"])
        for node_id, keys in old["keys"].items():
            self.assertNotIn(keys["private"], json.dumps(self.state))
            self.assertNotEqual(keys["public"], self.state["devices"]["phone"]["keys"][node_id]["public"])

    def test_input_injection_and_unsafe_networks_rejected(self):
        with self.assertRaises(r.FleetError): r.add_user(self.state, "../secret")
        for cidr in ["0.0.0.0/0", "10.0.0.0/24"]:
            data = fleet(); data["admin_cidrs"] = [cidr]
            with self.assertRaises(r.FleetError): r.validate_fleet(data)
        data = fleet(); data["nodes"][1]["network"] = data["nodes"][0]["network"]
        with self.assertRaises(r.FleetError): r.validate_fleet(data)
        data = fleet(); data["nodes"][0]["amneziawg_options"] = {"PostUp": "arbitrary shell"}
        with self.assertRaises(r.FleetError): r.validate_fleet(data)
        with self.assertRaises(r.FleetError): r.validate_fleet(json.loads(Path("examples/fleet.json").read_text()))

    def test_inventory_is_public_vault_is_encrypted_and_revocation_changes_both_nodes(self):
        r.add_device(self.state, "u001", "phone")
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "deployment"
            render(self.state, output, PASSWORD, {})
            inv = (output / "inventory.json").read_text()
            secret = self.state["devices"]["phone"]["keys"]["vpn_a"]
            for value in (secret["private"], secret["psk"], self.state["servers"]["vpn_a"]["vpn"]["private"]):
                self.assertNotIn(value, inv)
                self.assertNotIn(value, (output / "group_vars/all/vault.yml").read_text())
            vault = VaultLib([("default", VaultSecret(PASSWORD.encode()))])
            import yaml
            plaintext = yaml.safe_load(vault.decrypt((output / "group_vars/all/vault.yml").read_bytes()))
            self.assertEqual(len(plaintext["node_secrets"]["vpn_a"]["peers"]), 1)
            r.revoke(self.state, "phone")
            render(self.state, output, PASSWORD, {})
            plaintext = yaml.safe_load(vault.decrypt((output / "group_vars/all/vault.yml").read_bytes()))
            self.assertEqual(plaintext["node_secrets"]["vpn_a"]["peers"], [])
            self.assertEqual(plaintext["node_secrets"]["vpn_b"]["peers"], [])

    def test_no_clobber_and_lock_exclusion(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private" / "file"
            r.atomic_write(path, b"original", replace=False)
            with self.assertRaises(r.FleetError): r.atomic_write(path, b"replacement", replace=False)
            self.assertEqual(path.read_bytes(), b"original")
            with r.locked(path):
                with self.assertRaises(r.FleetError):
                    with r.locked(path): pass


if __name__ == "__main__": unittest.main()
