import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from vpn_fleet.plugins import fetch_archive, unpack, validate_plugins


class PluginArchiveTests(unittest.TestCase):
    def archive(self, target, extra=None, version="13.2.5"):
        with zipfile.ZipFile(target, "w") as out:
            out.writestr("loki/plugin.json", json.dumps({"id": "loki", "info": {"version": version}}))
            out.writestr("loki/MANIFEST.txt", "synthetic manifest; real signatures are checked by Grafana")
            if extra is not None: out.writestr(extra, "not executable")

    def test_traversal_links_duplicates_and_version_mismatch_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); archive = root / "plugin.zip"
            link = zipfile.ZipInfo("loki/escape")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            for index, entry in enumerate(("../escape", "loki/../../escape", "/escape", "loki\\escape", link, "loki/plugin.json")):
                with self.subTest(entry=str(entry)):
                    self.archive(archive, entry)
                    directory = root / str(index); directory.mkdir()
                    with self.assertRaises(ValueError): unpack(archive, directory, "loki", "13.2.5")
                    self.assertFalse((root / "escape").exists())
            self.archive(archive, version="13.2.4")
            with self.assertRaises(ValueError): unpack(archive, root / "wrong-version", "loki", "13.2.5")

    def test_download_checksum_mismatch_is_not_published(self):
        class Response(io.BytesIO):
            def geturl(self): return "https://grafana.com/test-only"
        lock = {"url": "https://grafana.com/test-only", "sha256": hashlib.sha256(b"expected").hexdigest()}
        with tempfile.TemporaryDirectory() as temp, patch("urllib.request.urlopen", return_value=Response(b"tampered")):
            target = Path(temp) / "archive.zip"
            with self.assertRaises(ValueError): fetch_archive(lock, target)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix(".download").exists())

    def test_arbitrary_plugin_hosts_and_extra_plugins_are_not_allowed(self):
        from test_image_gate import ImageGateTests
        pins = ImageGateTests().images()["grafana_plugins"]
        validate_plugins(pins)
        pins["loki"]["url"] = "https://example.invalid/plugin.zip"
        with self.assertRaises(ValueError): validate_plugins(pins)
