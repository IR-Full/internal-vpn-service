import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("firewall", "server/firewall.py")
firewall = importlib.util.module_from_spec(spec); spec.loader.exec_module(firewall)


class FirewallGuardTests(unittest.TestCase):
    def test_timeout_is_not_misreported_as_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "etc"; root.mkdir()
            state = Path(directory) / "state"
            (root / "firewall.nft").write_text("new policy")
            (root / "firewall-rescue.nft").write_text("rescue policy")
            with patch.object(firewall, "ROOT", root), patch.object(firewall, "STATE", state), patch.object(firewall, "load"), patch.object(firewall.subprocess, "run"):
                firewall.execute("apply")
                firewall.execute("rollback")
                with self.assertRaises(ValueError): firewall.execute("confirm")
                self.assertEqual(json.loads((state / "firewall-status.json").read_text())["status"], "rolled_back")

    def test_modified_candidate_cannot_be_confirmed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "etc"; root.mkdir()
            state = Path(directory) / "state"
            (root / "firewall.nft").write_text("new policy")
            (root / "firewall-rescue.nft").write_text("rescue policy")
            with patch.object(firewall, "ROOT", root), patch.object(firewall, "STATE", state), patch.object(firewall, "load"), patch.object(firewall.subprocess, "run"):
                firewall.execute("apply")
                (root / "firewall.nft").write_text("different policy")
                with self.assertRaises(ValueError): firewall.execute("confirm")
