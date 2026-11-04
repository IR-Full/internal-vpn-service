import hashlib
import json
import time
import unittest
from vpn_fleet.deployment import validate_images
from vpn_fleet.registry import FleetError


class ImageGateTests(unittest.TestCase):
    def images(self):
        data = {"grafana": "grafana/grafana@sha256:" + "a" * 64, "loki": "grafana/loki@sha256:" + "b" * 64,
                "alloy": "grafana/alloy@sha256:" + "c" * 64, "prometheus": "prom/prometheus@sha256:" + "d" * 64}
        data["scanned_images_sha256"] = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        data.update(scan_status="passed", scanned_epoch=int(time.time()))
        return data

    def test_failed_stale_and_changed_image_set_are_rejected(self):
        validate_images(self.images())
        data = self.images(); data["scan_status"] = "failed"
        with self.assertRaises(FleetError): validate_images(data)
        data = self.images(); data["scanned_epoch"] -= 8 * 86400
        with self.assertRaises(FleetError): validate_images(data)
        data = self.images(); data["grafana"] = "grafana/grafana@sha256:" + "e" * 64
        with self.assertRaises(FleetError): validate_images(data)
