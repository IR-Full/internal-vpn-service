import importlib.util
from pathlib import Path
import tempfile
import unittest
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from vpn_fleet.deployment import make_pki

spec = importlib.util.spec_from_file_location("vpn_metrics", "server/metrics.py")
metrics = importlib.util.module_from_spec(spec); spec.loader.exec_module(metrics)


class CertificateMetricsTests(unittest.TestCase):
    def collected(self, failed=None, link_flags="0x81"):
        def run(argv, **kwargs):
            source = argv[0]
            if source == failed:
                raise subprocess.TimeoutExpired(source, 5)
            output = {"wg": "synthetic-public-key 1700000000\n", "journalctl": "",
                      "nft": json.dumps({"nftables": [{"counter": {"name": n, "packets": 0}}
                                         for n in ("input_drops", "forward_drops")]})}[source]
            return SimpleNamespace(stdout=output)
        def read(path, **kwargs):
            if path.name == "ack.json":
                return "{}" if failed == "ack" else json.dumps({"revision": 4})
            if path == Path("/sys/class/net/vpn0/flags"):
                if failed == "link_flags":
                    raise OSError("test-only unavailable link status")
                return link_flags
            return "1700000000"
        with patch.object(metrics, "certificate_expiry", return_value=2000000000), \
                patch.object(metrics.subprocess, "run", side_effect=run), \
                patch.object(metrics.Path, "read_text", read), \
                patch.object(metrics.shutil, "disk_usage", return_value=SimpleNamespace(free=50, total=100)), \
                patch.object(metrics.urllib.request, "urlopen", side_effect=OSError("test-only disconnected telemetry")):
            return metrics.collect({"node": "vpn_a", "backend": "wireguard"})

    def test_wireguard_peer_output_does_not_imply_link_is_up(self):
        self.assertEqual(self.collected()["vpn_interface_up"], 1)
        down = self.collected(link_flags="0x80")
        self.assertEqual(down["vpn_interface_up"], 0)
        self.assertEqual(down["vpn_peers_configured"], 1)
        self.assertEqual(self.collected(failed="link_flags")["vpn_interface_up"], 0)

    def test_security_probe_requires_readable_log_firewall_and_revision(self):
        healthy = self.collected()
        self.assertEqual(healthy["vpn_admin_auth_failures_5m"], 0)
        self.assertEqual(healthy["vpn_security_probe_up"], 1)
        for failure in ("journalctl", "nft", "ack"):
            with self.subTest(failure=failure):
                observed = self.collected(failure)
                self.assertEqual(observed["vpn_security_probe_up"], 0)
                self.assertGreater(observed["vpn_probe_timestamp_seconds"], 0)

    def test_real_certificate_expiry_and_invalid_certificate_are_not_treated_as_healthy(self):
        import time
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test-cert.pem"
            path.write_text(make_pki()["nodes"]["vpn_a"]["cert"])
            self.assertAlmostEqual((metrics.certificate_expiry(path) - time.time()) / 86400, 365, delta=0.01)
            path.write_text("invalid public certificate")
            self.assertEqual(metrics.certificate_expiry(path), 0)
            path.unlink()
            self.assertEqual(metrics.certificate_expiry(path), 0)
