#!/usr/bin/env python3
"""Scan exact runtime images; an unfinished/failed scan never produces a pass."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from lock_images import image_hash, digest

if __name__ == "__main__":
    path = Path("infra/images.lock.json")
    data = json.loads(path.read_text())
    data["scan_status"] = "not_scanned"
    path.write_text(json.dumps(data, indent=2) + "\n")
    # Resolve scanner from its upstream release; persist the immutable scanner identity.
    import urllib.request
    request = urllib.request.Request("https://api.github.com/repos/aquasecurity/trivy/releases/latest", headers={"User-Agent": "private-vpn-fleet"})
    release = json.load(urllib.request.urlopen(request, timeout=30))["tag_name"].removeprefix("v")
    scanner = "aquasec/trivy@" + digest("aquasec/trivy", release)
    out = Path(".state/scans"); out.mkdir(parents=True, exist_ok=True)
    cache = Path(".state/trivy-cache"); cache.mkdir(parents=True, exist_ok=True)
    passed = True
    for key in ("grafana", "loki", "alloy", "prometheus"):
        # No Docker socket mount. Scanner fetches public registry images remotely.
        result = subprocess.run(["docker", "run", "--rm", "-v", f"{out.resolve()}:/reports", "-v", f"{cache.resolve()}:/root/.cache/trivy",
                                 scanner, "image", "--image-src", "remote", "--scanners", "vuln",
                                 "--severity", "HIGH,CRITICAL", "--ignore-unfixed", "--exit-code", "1",
                                 "--format", "json", "--output", f"/reports/{key}.json", data[key]])
        passed = passed and result.returncode == 0
    data["scan_status"] = "passed" if passed else "failed"
    data["scanner"] = scanner
    data["scanned_images_sha256"] = image_hash(data)
    data["scanned_at"] = datetime.now(timezone.utc).isoformat()
    data["scanned_epoch"] = int(datetime.now(timezone.utc).timestamp())
    path.write_text(json.dumps(data, indent=2) + "\n")
    raise SystemExit(0 if passed else 1)
