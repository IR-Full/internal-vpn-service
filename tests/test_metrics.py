import importlib.util
from pathlib import Path
import tempfile
import unittest

from vpn_fleet.deployment import make_pki

spec = importlib.util.spec_from_file_location("vpn_metrics", "server/metrics.py")
metrics = importlib.util.module_from_spec(spec); spec.loader.exec_module(metrics)


class CertificateMetricsTests(unittest.TestCase):
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
