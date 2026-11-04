import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("node_apply", "server/node_apply.py")
node = importlib.util.module_from_spec(spec); spec.loader.exec_module(node)
from vpn_fleet.registry import keypair


def desired():
    return {"backend": "wireguard", "revision": 4, "fleet_id": "b9b1a0de-8af2-4779-9abd-2d8752b953fd",
            "private_key": keypair()["private"], "port": 51820, "network": "10.77.0.0/23",
            "address": "10.77.0.1", "ipv6_network": "fd77:1::/64", "ipv6_address": "fd77:1::1",
            "options": {}, "peers": [{"id": "phone", "public_key": keypair()["public"], "psk": keypair()["private"], "ipv4": "10.77.0.2", "ipv6": "fd77:1::2"}]}


class NodeTests(unittest.TestCase):
    def test_only_exact_peer_routes(self):
        data = desired()
        self.assertIn("AllowedIPs = 10.77.0.2/32, fd77:1::2/128", node.configuration(data))
        self.assertNotIn("0.0.0.0/0", node.configuration(data))

    def test_duplicate_peer_and_outside_network_rejected(self):
        data = desired(); data["peers"].append(copy.deepcopy(data["peers"][0]))
        with self.assertRaises(ValueError): node.validate(data)
        data = desired(); data["peers"][0]["ipv4"] = "169.254.169.254"
        with self.assertRaises(ValueError): node.validate(data)
        data = desired(); data["options"] = {"PrivateKey": "injected"}
        with self.assertRaises(ValueError): node.validate(data)
