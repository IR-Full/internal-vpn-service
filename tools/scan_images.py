#!/usr/bin/env python3
"""Scan exact runtime images; an unfinished/failed scan never produces a pass."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

from lock_images import image_hash, digest
from vpn_fleet.image_policy import PLATFORM, REPOSITORIES, SCAN_POLICY, validate_references
from vpn_fleet.plugins import prepare_plugins, plugin_artifact


def check_report(path, image, returncode):
    """A process exit alone is not proof that the requested image was scanned."""
    raw = path.read_bytes()
    report = json.loads(raw)
    if (report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image"
            or report.get("ArtifactName") != image
            or image not in report.get("Metadata", {}).get("RepoDigests", [])
            or report.get("Metadata", {}).get("ImageConfig", {}).get("architecture") != "amd64"
            or not isinstance(report.get("Results"), list) or not report["Results"]):
        raise ValueError("Incomplete scan or artifact/platform mismatch")
    if report.get("Metadata", {}).get("OS", {}).get("EOSL"):
        raise ValueError("Image distribution is end of life")
    return report_outcome(raw, report, image, returncode)


def report_outcome(raw, report, artifact, returncode):
    findings = []
    for result in report["Results"]:
        if not isinstance(result, dict) or not result.get("Type"):
            raise ValueError("Malformed scanner result")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Malformed vulnerability list")
        findings.extend(v for v in vulnerabilities if v["Severity"] in ("HIGH", "CRITICAL"))
    passed = returncode == 0 and not findings
    return {"artifact": artifact, "sha256": hashlib.sha256(raw).hexdigest(),
            "status": "passed" if passed else "failed", "findings": len(findings)}


def print_public_findings(path):
    """Keep CI failures diagnosable without dumping image metadata or full reports."""
    report = json.loads(path.read_bytes())
    details = {(v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"], v.get("FixedVersion", ""), v["Severity"])
               for result in report.get("Results", []) for v in result.get("Vulnerabilities") or []
               if v["Severity"] in ("HIGH", "CRITICAL")}
    for vulnerability, package, installed, fixed, severity in sorted(details):
        print(json.dumps({"id": vulnerability, "package": package, "installed": installed,
                          "fixed": fixed or None, "severity": severity}), flush=True)


def check_plugin_report(path, plugin_id, lock, returncode):
    raw = path.read_bytes(); report = json.loads(raw)
    if (report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "filesystem"
            or report.get("ArtifactName") != "/plugins/" + plugin_id
            or not isinstance(report.get("Results"), list) or not report["Results"]):
        raise ValueError("Incomplete plugin scan or artifact mismatch")
    binaries = [r for r in report["Results"] if r.get("Type") == "gobinary"]
    if not binaries or not any(p.get("Name") == "stdlib" for result in binaries for p in result.get("Packages", [])):
        raise ValueError("Plugin Go binary and standard library were not analysed")
    return report_outcome(raw, report, plugin_artifact(plugin_id, lock), returncode)

if __name__ == "__main__":
    path = Path("infra/images.lock.json")
    data = json.loads(path.read_text())
    data["scan_status"] = "not_scanned"
    data.pop("scan_reports", None)
    path.write_text(json.dumps(data, indent=2) + "\n")
    pending = path.read_bytes()
    validate_references(data)
    plugins_dir = prepare_plugins(data["grafana_plugins"], Path(".state/grafana-plugins"))
    # Resolve scanner from its upstream release; persist the immutable scanner identity.
    import urllib.request
    request = urllib.request.Request("https://api.github.com/repos/aquasecurity/trivy/releases/latest", headers={"User-Agent": "private-vpn-fleet"})
    release = json.load(urllib.request.urlopen(request, timeout=30))["tag_name"].removeprefix("v")
    scanner = "aquasec/trivy@" + digest("aquasec/trivy", release)
    out = Path(".state/scans"); out.mkdir(parents=True, exist_ok=True)
    cache = Path(".state/trivy-cache"); cache.mkdir(parents=True, exist_ok=True)
    passed = True
    reports = {}
    for key in REPOSITORIES:
        report_path = out / f"{key}.json"
        report_path.unlink(missing_ok=True)
        # No Docker socket mount. Scanner fetches public registry images remotely.
        result = subprocess.run(["docker", "run", "--rm", "-v", f"{out.resolve()}:/reports", "-v", f"{cache.resolve()}:/root/.cache/trivy",
                                 scanner, "image", "--quiet", "--timeout", "15m", "--platform", PLATFORM, "--image-src", "remote", "--scanners", "vuln",
                                 "--severity", "HIGH,CRITICAL", "--exit-code", "1",
                                 "--format", "json", "--output", f"/reports/{key}.json", data[key]])
        try:
            reports[key] = check_report(report_path, data[key], result.returncode)
        except (OSError, ValueError, KeyError, TypeError):
            reports[key] = {"artifact": data[key], "status": "error"}
        passed = passed and reports[key]["status"] == "passed"
        print(f"{key}: {reports[key]['status']}; HIGH/CRITICAL: {reports[key].get('findings', 'unknown')}", flush=True)
        if reports[key]["status"] == "failed": print_public_findings(report_path)
    for plugin_id, lock in data["grafana_plugins"].items():
        key = "plugin_" + plugin_id
        report_path = out / f"{key}.json"; report_path.unlink(missing_ok=True)
        result = subprocess.run(["docker", "run", "--rm", "-v", f"{out.resolve()}:/reports",
                                 "-v", f"{cache.resolve()}:/root/.cache/trivy", "-v", f"{plugins_dir.resolve()}:/plugins:ro",
                                 scanner, "rootfs", "--quiet", "--list-all-pkgs", "--timeout", "15m", "--scanners", "vuln",
                                 "--severity", "HIGH,CRITICAL", "--exit-code", "1", "--format", "json",
                                 "--output", f"/reports/{key}.json", "/plugins/" + plugin_id])
        try:
            reports[key] = check_plugin_report(report_path, plugin_id, lock, result.returncode)
        except (OSError, ValueError, KeyError, TypeError):
            reports[key] = {"artifact": plugin_artifact(plugin_id, lock), "status": "error"}
        passed = passed and reports[key]["status"] == "passed"
        print(f"{key}: {reports[key]['status']}; HIGH/CRITICAL: {reports[key].get('findings', 'unknown')}", flush=True)
        if reports[key]["status"] == "failed": print_public_findings(report_path)
    data["scan_status"] = "passed" if passed else "failed"
    data["scanner"] = scanner
    data["scan_platform"] = PLATFORM
    data["scan_policy"] = SCAN_POLICY
    data["scan_reports"] = reports
    data["scanned_images_sha256"] = image_hash(data)
    data["scanned_at"] = datetime.now(timezone.utc).isoformat()
    data["scanned_epoch"] = int(datetime.now(timezone.utc).timestamp())
    if path.read_bytes() != pending:
        raise SystemExit("Image lock changed during scan; refusing to overwrite it")
    path.write_text(json.dumps(data, indent=2) + "\n")
    raise SystemExit(0 if passed else 1)
