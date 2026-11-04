"""Persist a small reviewable inventory of actual scanner findings; no waiver."""
import json
from pathlib import Path

lock = json.loads(Path("infra/images.lock.json").read_text())
summary = {"scanned_at": lock["scanned_at"], "scanner": lock["scanner"],
           "criterion": "HIGH/CRITICAL with published fixes; unfixed and lower severity are excluded from this gate", "images": []}
for name in ("grafana", "loki", "alloy", "prometheus"):
    report = json.loads(Path(f".state/scans/{name}.json").read_text())
    findings = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            findings.append({"component": result.get("Target"), "id": vuln["VulnerabilityID"], "package": vuln["PkgName"],
                             "installed": vuln["InstalledVersion"], "fixed": vuln.get("FixedVersion"),
                             "severity": vuln["Severity"], "source": vuln.get("PrimaryURL")})
    summary["images"].append({"name": name, "image": lock[name], "findings_count": len(findings), "findings": findings})
out = Path("security/image-audit.json"); out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(summary, indent=2) + "\n")
print("Recorded actual image audit findings. No finding was suppressed or waived.")
