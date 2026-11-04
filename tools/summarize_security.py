"""Persist a small reviewable inventory of actual scanner findings; no waiver."""
import json
from pathlib import Path
import hashlib
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_fleet.image_policy import artifacts, validate_scan

lock = json.loads(Path("infra/images.lock.json").read_text())
validate_scan(lock)
summary = {"scanned_at": lock["scanned_at"], "scanner": lock["scanner"],
           "status": lock["scan_status"], "platform": lock["scan_platform"], "policy": lock["scan_policy"],
           "criterion": "All HIGH/CRITICAL, including unfixed; lower severity is outside this gate", "images": []}
for name, artifact in artifacts(lock).items():
    raw = Path(f".state/scans/{name}.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock["scan_reports"][name]["sha256"]:
        raise SystemExit("Report changed since the recorded scan; run the scan again")
    report = json.loads(raw)
    findings = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            findings.append({"component": result.get("Target"), "id": vuln["VulnerabilityID"], "package": vuln["PkgName"],
                             "installed": vuln["InstalledVersion"], "fixed": vuln.get("FixedVersion"),
                             "severity": vuln["Severity"], "source": vuln.get("PrimaryURL")})
    runtime = sorted({p["Version"] for result in report.get("Results", []) for p in result.get("Packages", []) if p["Name"] == "stdlib"})
    summary["images"].append({"name": name, "image": artifact, "report_sha256": lock["scan_reports"][name]["sha256"],
                             "go_versions": runtime, "findings_count": len(findings), "findings": findings})
out = Path("security/image-audit.json"); out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(summary, indent=2) + "\n")
print("Recorded actual image audit findings. No finding was suppressed or waived.")
