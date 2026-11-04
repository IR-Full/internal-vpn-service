import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path("tools").resolve()))
from scan_images import check_report, check_plugin_report

IMAGE = "grafana/grafana@sha256:" + "a" * 64


class ScanEvidenceTests(unittest.TestCase):
    def test_plugin_scan_must_actually_analyse_its_go_binary(self):
        lock = {"sha256": "b" * 64}
        report = {"SchemaVersion": 2, "ArtifactType": "filesystem", "ArtifactName": "/plugins/loki",
                  "Results": [{"Type": "gobinary", "Packages": [{"Name": "stdlib", "Version": "v1.27.3"}]}]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plugin.json"
            path.write_text(json.dumps(report))
            self.assertEqual(check_plugin_report(path, "loki", lock, 0)["status"], "passed")
            report["Results"][0]["Packages"] = []
            path.write_text(json.dumps(report))
            with self.assertRaises(ValueError): check_plugin_report(path, "loki", lock, 0)
            report.pop("Results"); path.write_text(json.dumps(report))
            with self.assertRaises(ValueError): check_plugin_report(path, "loki", lock, 0)

    def test_actual_findings_exit_errors_wrong_artifact_and_partial_reports_fail_closed(self):
        clean = {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": IMAGE,
                 "Metadata": {"RepoDigests": [IMAGE], "ImageConfig": {"architecture": "amd64"}, "OS": {}},
                 "Results": [{"Type": "gobinary"}]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(clean))
            self.assertEqual(check_report(path, IMAGE, 0)["status"], "passed")
            self.assertEqual(check_report(path, IMAGE, 2)["status"], "failed")
            # Even an inconsistent zero exit cannot make an unfixed HIGH disappear.
            high = copy.deepcopy(clean)
            high["Results"][0]["Vulnerabilities"] = [{"Severity": "HIGH", "FixedVersion": ""}]
            path.write_text(json.dumps(high))
            self.assertEqual(check_report(path, IMAGE, 0)["findings"], 1)
            self.assertEqual(check_report(path, IMAGE, 0)["status"], "failed")
            for change in (
                lambda r: r.update(ArtifactName="wrong image"),
                lambda r: r.update(Results=[]),
                lambda r: r["Metadata"]["ImageConfig"].update(architecture="arm64"),
                lambda r: r["Metadata"].update(RepoDigests=[]),
                lambda r: r["Metadata"]["OS"].update(EOSL=True),
            ):
                report = copy.deepcopy(clean); change(report); path.write_text(json.dumps(report))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    check_report(path, IMAGE, 0)
