from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vpn_fleet.cli import main
from vpn_fleet.registry import decrypt
from test_registry import fleet, PASSWORD


class CliTests(unittest.TestCase):
    def test_real_cli_lifecycle_exports_only_to_explicit_private_files(self):
        with tempfile.TemporaryDirectory() as directory, patch("getpass.getpass", return_value=PASSWORD):
            root = Path(directory)
            config = root / "fleet.json"; config.write_text(json.dumps(fleet()))
            registry = root / "private" / "registry.enc"
            common = ["--registry", str(registry)]
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                self.assertEqual(main(common + ["init", "--fleet", str(config)]), 0)
                self.assertEqual(main(common + ["add-user", "u001"]), 0)
                self.assertEqual(main(common + ["add-device", "u001", "phone"]), 0)
                state = decrypt(registry.read_bytes(), PASSWORD)
                key = state["devices"]["phone"]["keys"]["vpn_a"]["private"]
                self.assertEqual(main(common + ["export", "phone", "--out", str(root / "exports")]), 0)
                self.assertIn(key, (root / "exports/phone-vpn_a.conf").read_text())
                self.assertNotIn(key, output.getvalue())
                self.assertEqual(main(common + ["backup", "--out", str(root / "backups/registry.enc")]), 0)
                self.assertEqual(main(common + ["revoke", "phone"]), 0)
                self.assertEqual(main(common + ["export", "phone", "--out", str(root / "forbidden")]), 2)
                self.assertEqual(main(common + ["delete-user", "u001"]), 0)
            self.assertEqual(decrypt(registry.read_bytes(), PASSWORD)["users"], {})
