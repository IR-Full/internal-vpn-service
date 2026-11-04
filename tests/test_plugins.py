import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import shutil
import errno

from vpn_fleet.plugins import fetch_archive, unpack, validate_plugins, prepare_plugins


class PluginArchiveTests(unittest.TestCase):
    def cached_plugins(self, root):
        pins = {}
        (root / "archives").mkdir(parents=True)
        for plugin_id in ("loki", "prometheus"):
            archive = root / (plugin_id + ".zip")
            with zipfile.ZipFile(archive, "w") as out:
                out.writestr(plugin_id + "/plugin.json", json.dumps({"id": plugin_id, "info": {"version": "13.2.5"}}))
                out.writestr(plugin_id + "/MANIFEST.txt", "synthetic test manifest, never used by a live Grafana")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            shutil.move(archive, root / "archives" / (plugin_id + "-" + digest + ".zip"))
            pins[plugin_id] = {"version": "13.2.5", "sha256": digest,
                "url": f"https://grafana.com/api/plugins/{plugin_id}/versions/13.2.5/download?os=linux&arch=amd64"}
        return pins

    def test_published_public_plugin_set_is_readable_without_opening_private_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "private"; root.mkdir(mode=0o700)
            pins = self.cached_plugins(root)
            destination = prepare_plugins(pins, root)
            if os.name == "posix":
                self.assertEqual(root.stat().st_mode & 0o777, 0o700)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
            destination.chmod(0o700)
            self.assertEqual(prepare_plugins(pins, root), destination)
            if os.name == "posix": self.assertEqual(destination.stat().st_mode & 0o777, 0o755)

    def test_concurrent_first_publish_accepts_only_an_identical_tree(self):
        for different in (False, True):
            with self.subTest(different=different), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); pins = self.cached_plugins(root)
                rename = os.rename
                def competitor(source, destination):
                    shutil.copytree(source, destination)
                    if different: (destination / "loki/plugin.json").write_text("changed competitor content")
                    # Linux returns ENOTEMPTY for this race; Windows may return EEXIST.
                    try: rename(source, destination)
                    except OSError as exc:
                        self.assertIn(exc.errno, (errno.EEXIST, errno.ENOTEMPTY))
                        raise
                with patch("vpn_fleet.plugins.os.rename", side_effect=competitor):
                    if different:
                        with self.assertRaises(ValueError): prepare_plugins(pins, root)
                    else:
                        self.assertTrue(prepare_plugins(pins, root).is_dir())

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
