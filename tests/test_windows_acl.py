"""Native Windows regression; no real credentials are used by these tests."""
import base64
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vpn_fleet import registry as r


@unittest.skipUnless(os.name == "nt", "Requires native Windows NTFS ACL enforcement")
class WindowsPrivacyTests(unittest.TestCase):
    def test_failed_acl_enforcement_prevents_secret_file_creation(self):
        root = Path(".state/security-audit-acl").resolve(); root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temp:
            directory = Path(temp).resolve(); self.assertIn(root, directory.parents)
            target = directory / "must-not-exist.txt"
            with patch("vpn_fleet.registry.subprocess.run", side_effect=subprocess.CalledProcessError(1, ["acl-helper"])):
                with self.assertRaises(r.FleetError): r.atomic_write(target, b"synthetic secret")
            self.assertFalse(target.exists())

    def acl(self, path):
        script = """
$ErrorActionPreference = 'Stop'
$target = $env:VPN_FLEET_ACL_TEST_PATH
if ([IO.Directory]::Exists($target)) { $item = [IO.DirectoryInfo]::new($target) }
else { $item = [IO.FileInfo]::new($target) }
$acl = $item.GetAccessControl()
[Console]::WriteLine('owner_sid=' + $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)
[Console]::WriteLine('protected=' + $acl.AreAccessRulesProtected)
foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    [Console]::WriteLine(('{0}|{1}|{2}|{3}' -f $rule.IdentityReference.Value,
        [int]$rule.FileSystemRights, $rule.IsInherited, ($rule.AccessControlType -eq 'Allow')))
}
"""
        executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                                 base64.b64encode(script.encode("utf-16-le")).decode()],
                                env={**os.environ, "VPN_FLEET_ACL_TEST_PATH": str(path.resolve())},
                                check=True, capture_output=True, text=True, timeout=30)
        lines = result.stdout.splitlines()
        rules = []
        for line in lines[2:]:
            sid, rights, inherited, allow = line.split("|")
            rules.append({"sid": sid, "rights": int(rights), "inherited": inherited.lower() == "true", "allow": allow.lower() == "true"})
        return {"owner_sid": lines[0].split("=", 1)[1], "protected": lines[1].split("=", 1)[1].lower() == "true", "rules": rules}

    def test_explicit_other_user_grants_are_removed_before_atomic_secret_write(self):
        root = Path(".state/security-audit-acl").resolve(); root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temp:
            directory = Path(temp).resolve()
            self.assertIn(root, directory.parents)
            subprocess.run(["icacls", str(directory), "/grant:r",
                            "*S-1-1-0:(OI)(CI)RX", "*S-1-5-32-545:(OI)(CI)RX"],
                           check=True, capture_output=True, timeout=30)
            self.assertTrue(any(a["sid"] == "S-1-1-0" for a in self.acl(directory)["rules"]))
            target = directory / "synthetic-secret.txt"
            r.atomic_write(target, b"synthetic test value; never a production credential")
            for path in (directory, target):
                acl = self.acl(path)
                self.assertEqual(len(acl["rules"]), 1)
                self.assertEqual(acl["rules"][0]["sid"], acl["owner_sid"])
                self.assertTrue(acl["rules"][0]["allow"])
            self.assertTrue(self.acl(directory)["protected"])
            # Replacement also inherits only the repaired private directory ACL.
            r.atomic_write(target, b"replacement synthetic test value")
            self.assertEqual({a["sid"] for a in self.acl(target)["rules"]}, {self.acl(directory)["owner_sid"]})

    def test_new_directory_and_path_metacharacters_remain_private(self):
        root = Path(".state/security-audit-acl").resolve(); root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temp:
            directory = Path(temp).resolve() / "private [test] ' value; $safe"
            self.assertIn(root, directory.parents)
            r.atomic_write(directory / "synthetic.txt", b"synthetic fixture")
            for path in (directory, directory / "synthetic.txt"):
                acl = self.acl(path)
                self.assertEqual({a["sid"] for a in acl["rules"]}, {acl["owner_sid"]})
