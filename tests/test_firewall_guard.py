import importlib.util
from contextlib import contextmanager
from io import StringIO
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from jinja2 import Environment, StrictUndefined

spec = importlib.util.spec_from_file_location("firewall", "server/firewall.py")
firewall = importlib.util.module_from_spec(spec); spec.loader.exec_module(firewall)


# Real nft syntax, including the protected base chains. No external network is used.
RESCUE = """table inet vpn_service {
 chain input { type filter hook input priority filter; policy drop; iifname "lo" accept }
 chain forward { type filter hook forward priority filter; policy drop; }
}
table ip vpn_nat { }
"""
CANDIDATE = RESCUE.replace('iifname "lo" accept', 'iifname "lo" accept; ip saddr 192.0.2.1 tcp dport 22 accept')
OTHER = RESCUE.replace('iifname "lo" accept', 'iifname "lo" accept; ip saddr 192.0.2.2 tcp dport 22 accept')


class FirewallGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "etc"; self.root.mkdir()
        self.state = Path(self.directory.name) / "state"; self.state.mkdir()
        self.candidate = self.root / "firewall.nft"; self.candidate.write_text(CANDIDATE)
        (self.root / "firewall-rescue.nft").write_text(RESCUE)
        self.good = self.state / "firewall.last-good.nft"
        self.status = self.state / "firewall-status.json"
        self.transactions = []
        self.commands = []
        def command(argv, **kwargs):
            self.commands.append(argv)
            if argv[:2] == ["nft", "list"]:
                return SimpleNamespace(returncode=0)
            if argv[0] == "nft":
                self.transactions.append(kwargs["input"])
            return SimpleNamespace(returncode=0)
        for item in (patch.object(firewall, "ROOT", self.root), patch.object(firewall, "STATE", self.state),
                     patch.object(firewall.subprocess, "run", side_effect=command)):
            item.start(); self.addCleanup(item.stop)

    def stage(self):
        firewall.execute("apply")
        self.assertEqual(json.loads(self.status.read_text())["status"], "pending")

    def test_timeout_is_not_misreported_as_confirmation(self):
        self.stage()
        firewall.execute("rollback")
        with self.assertRaises(ValueError): firewall.execute("confirm")
        self.assertEqual(json.loads(self.status.read_text())["status"], "rolled_back")
        self.assertEqual(self.candidate.read_text(), RESCUE)

    def test_boot_rejects_confirmation_of_candidate_that_is_no_longer_running(self):
        self.stage()
        firewall.execute("boot")
        with self.assertRaises(ValueError):
            firewall.execute("confirm")
        with patch("sys.stdout", new_callable=StringIO) as output:
            firewall.execute("status")
        status = json.loads(output.getvalue())
        self.assertEqual(status["status"], "rolled_back")
        self.assertTrue(status["needs_apply"])
        self.stage()
        firewall.execute("confirm")
        self.candidate.write_text(OTHER)
        with patch("sys.stdout", new_callable=StringIO) as output:
            firewall.execute("status")
        self.assertTrue(json.loads(output.getvalue())["needs_apply"])

    def test_modified_candidate_cannot_be_confirmed(self):
        self.stage(); self.candidate.write_text(OTHER)
        with self.assertRaises(ValueError): firewall.execute("confirm")
        self.assertEqual(self.good.read_text(), RESCUE)

    def test_write_sync_or_replace_failure_preserves_complete_previous_checkpoint_and_timer(self):
        self.stage()
        stop = ["systemctl", "stop", "vpn-firewall-rollback.timer"]
        for name in ("fsync", "replace"):
            with self.subTest(failure=name):
                self.commands.clear()
                with patch.object(firewall.os, name, side_effect=OSError("synthetic disk failure")):
                    with self.assertRaises(OSError): firewall.execute("confirm")
                self.assertEqual(self.good.read_text(), RESCUE)
                self.assertEqual(json.loads(self.status.read_text())["status"], "pending")
                self.assertNotIn(stop, self.commands)
                self.assertFalse(list(self.state.glob(".firewall-*")))

    def test_partial_write_never_truncates_the_existing_checkpoint(self):
        self.good.write_text(RESCUE)
        open_stream = firewall.os.fdopen
        @contextmanager
        def partial_write(descriptor, mode):
            with open_stream(descriptor, mode) as stream:
                class FaultyWriter:
                    def write(self, content):
                        stream.write(content[:12]); stream.flush()
                        raise OSError("synthetic short write")
                yield FaultyWriter()
        with patch.object(firewall.os, "fdopen", side_effect=partial_write):
            with self.assertRaises(OSError): firewall.atomic_write(self.good, CANDIDATE)
        self.assertEqual(self.good.read_text(), RESCUE)
        self.assertFalse(list(self.state.glob(".firewall-*")))

    def test_confirmation_state_must_be_durable_before_timer_is_disarmed(self):
        self.stage(); self.commands.clear()
        atomic = firewall.atomic_write
        def fail_status(path, content):
            if path == self.status: raise OSError("synthetic metadata disk failure")
            return atomic(path, content)
        with patch.object(firewall, "atomic_write", side_effect=fail_status):
            with self.assertRaises(OSError): firewall.execute("confirm")
        self.assertEqual(self.good.read_text(), CANDIDATE)
        self.assertEqual(json.loads(self.status.read_text())["status"], "pending")
        self.assertNotIn(["systemctl", "stop", "vpn-firewall-rollback.timer"], self.commands)

    def test_corrupt_checkpoints_boot_to_rescue_and_never_delete_only(self):
        for invalid in ("", "# lost policy", "table inet vpn_service {", "table inet vpn_service {}\ntable ip vpn_nat {}",
                        RESCUE.replace("policy drop", "policy accept"), "flush ruleset\n" + RESCUE):
            with self.subTest(invalid=invalid):
                self.good.write_text(invalid); self.transactions.clear()
                firewall.execute("boot")
                self.assertEqual(json.loads(self.status.read_text())["status"], "rescue")
                self.assertTrue(self.transactions)
                self.assertTrue(all(RESCUE in tx for tx in self.transactions))

    def test_nft_syntax_rejection_of_checkpoint_falls_back_without_applying_it(self):
        self.good.write_text(CANDIDATE)
        command = firewall.subprocess.run.side_effect
        applied = []
        def reject(argv, **kwargs):
            if argv[:2] == ["nft", "--check"] and CANDIDATE in kwargs.get("input", ""):
                raise subprocess.CalledProcessError(1, argv)
            if argv[:2] == ["nft", "-f"]: applied.append(kwargs["input"])
            return command(argv, **kwargs)
        with patch.object(firewall.subprocess, "run", side_effect=reject): firewall.execute("boot")
        self.assertEqual(len(applied), 1)
        self.assertIn(RESCUE, applied[0])

    def test_queued_late_rollback_does_not_clobber_a_confirmed_policy(self):
        self.stage(); firewall.execute("confirm")
        self.transactions.clear()
        firewall.execute("rollback")
        self.assertEqual(self.transactions, [])
        self.assertEqual(self.good.read_text(), CANDIDATE)
        self.assertEqual(json.loads(self.status.read_text())["status"], "confirmed")

    def test_corrupt_status_does_not_prevent_safety_rollback(self):
        self.good.write_text(RESCUE); self.status.write_text("{truncated")
        firewall.execute("rollback")
        self.assertEqual(self.candidate.read_text(), RESCUE)
        self.assertEqual(json.loads(self.status.read_text())["status"], "rolled_back")

    def test_pending_policy_cannot_be_replaced_by_another_staging(self):
        self.stage()
        self.candidate.write_text(OTHER)
        with self.assertRaises(ValueError): firewall.execute("apply")
        self.assertEqual(self.good.read_text(), RESCUE)

    def test_plaintext_last_good_policy_remains_compatible(self):
        self.good.write_text(CANDIDATE)
        firewall.execute("boot")
        self.assertTrue(self.transactions)
        self.assertTrue(all(CANDIDATE in tx for tx in self.transactions))

    def test_current_production_and_rescue_templates_fit_the_guard_envelope(self):
        variables = {"admin_cidrs": ["192.0.2.1/32"], "vpn_network": "10.77.0.0/23", "vpn_address": "10.77.0.1",
                     "vpn_port": 51820, "mgmt_peer_endpoint": "198.51.100.2", "mgmt_peer_address": "10.78.0.2",
                     "ansible_facts": {"default_ipv4": {"interface": "eth0"}}}
        environment = Environment(undefined=StrictUndefined)
        for name in ("firewall.nft.j2", "rescue.nft.j2"):
            with self.subTest(template=name):
                source = Path("infra/roles/node/templates") / name
                policy = environment.from_string(source.read_text()).render(**variables)
                self.assertEqual(firewall.validate_policy(policy), policy)
