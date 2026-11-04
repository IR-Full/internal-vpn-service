import time
import unittest
from vpn_fleet.deployment import validate_images
from vpn_fleet.registry import FleetError
from vpn_fleet.image_policy import SCAN_POLICY, PLATFORM
from vpn_fleet.image_policy import image_hash, artifacts
from vpn_fleet.plugins import plugin_hash


class ImageGateTests(unittest.TestCase):
    def images(self):
        data = {"grafana": "grafana/grafana@sha256:" + "a" * 64, "loki": "grafana/loki@sha256:" + "b" * 64,
                "alloy": "grafana/alloy@sha256:" + "c" * 64, "prometheus": "prom/prometheus@sha256:" + "d" * 64}
        data["grafana_plugins"] = {k: {"version": "13.2.5", "sha256": str(i) * 64,
            "url": f"https://grafana.com/api/plugins/{k}/versions/13.2.5/download?os=linux&arch=amd64"}
            for i, k in enumerate(("loki", "prometheus"), 1)}
        data["grafana_plugins_sha256"] = plugin_hash(data["grafana_plugins"])
        data["scanned_images_sha256"] = image_hash(data)
        data["images_sha256"] = data["scanned_images_sha256"]
        data.update(scan_status="passed", scanned_epoch=int(time.time()), scan_policy=SCAN_POLICY, scan_platform=PLATFORM,
                    scanner="aquasec/trivy@sha256:" + "f" * 64)
        data["scan_reports"] = {k: {"artifact": v, "status": "passed", "findings": 0, "sha256": "1" * 64}
                                for k, v in artifacts(data).items()}
        return data

    def test_failed_stale_and_changed_image_set_are_rejected(self):
        validate_images(self.images())
        data = self.images(); data["scan_status"] = "failed"
        with self.assertRaises(FleetError): validate_images(data)
        data = self.images(); data["scanned_epoch"] -= 8 * 86400
        with self.assertRaises(FleetError): validate_images(data)
        data = self.images(); data["grafana"] = "grafana/grafana@sha256:" + "e" * 64
        with self.assertRaises(FleetError): validate_images(data)

    def test_future_partial_legacy_and_mismatched_evidence_are_rejected(self):
        for change in (
            lambda d: d.update(scanned_epoch=int(time.time()) + 3600),
            lambda d: d.update(scan_policy="ignore-unfixed"),
            lambda d: d.update(scan_platform="linux/arm64"),
            lambda d: d["scan_reports"].pop("loki"),
            lambda d: d["scan_reports"]["loki"].update(findings=1),
            lambda d: d["scan_reports"]["loki"].update(artifact=d["grafana"]),
            lambda d: d["scan_reports"]["loki"].update(status="error"),
            lambda d: d.update(images_sha256="0" * 64),
            lambda d: d.update(scanned_epoch=True),
            lambda d: d["grafana_plugins"]["loki"].update(sha256="0" * 64),
            lambda d: d["scan_reports"].pop("plugin_loki"),
            lambda d: d["scan_reports"]["plugin_loki"].update(findings=False),
        ):
            with self.subTest(change=change):
                data = self.images(); change(data)
                with self.assertRaises(FleetError): validate_images(data)
