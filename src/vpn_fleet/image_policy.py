"""Shared, dependency-free policy for the exact runtime image set."""
import hashlib
import json
import re
import time
from .plugins import validate_plugins, plugin_artifact, plugin_hash

REPOSITORIES = {"grafana": "grafana/grafana", "loki": "grafana/loki", "alloy": "grafana/alloy", "prometheus": "prom/prometheus"}
SCAN_POLICY = "all-high-critical-v1"
PLATFORM = "linux/amd64"


def image_hash(images):
    payload = {k: images[k] for k in sorted(REPOSITORIES)}
    payload["grafana_plugins"] = images["grafana_plugins"]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def artifacts(images):
    return {**{k: images[k] for k in REPOSITORIES},
            **{"plugin_" + k: plugin_artifact(k, v) for k, v in images["grafana_plugins"].items()}}


def validate_references(images):
    validate_plugins(images.get("grafana_plugins"))
    if images.get("grafana_plugins_sha256") != plugin_hash(images["grafana_plugins"]):
        raise ValueError("Plugin set hash differs from its actual lock")
    for name, repository in REPOSITORIES.items():
        if not isinstance(images.get(name), str) or not re.fullmatch(re.escape(repository) + r"@sha256:[a-f0-9]{64}", images[name]):
            raise ValueError("Runtime images must use reviewed official repositories and immutable digests")
    if images.get("images_sha256") != image_hash(images):
        raise ValueError("Image lock hash does not match its actual references")


def validate_scan(images, current_time=None):
    validate_references(images)
    if images.get("scan_status") != "passed" or images.get("scanned_images_sha256") != image_hash(images):
        raise ValueError("Image security scan is missing/failed or does not match this exact image set")
    if images.get("scan_policy") != SCAN_POLICY or images.get("scan_platform") != PLATFORM:
        raise ValueError("Rescan all HIGH/CRITICAL findings for linux/amd64, including unfixed findings")
    if not re.fullmatch(r"aquasec/trivy@sha256:[a-f0-9]{64}", images.get("scanner", "")):
        raise ValueError("Missing immutable scanner identity")
    timestamp = images.get("scanned_epoch")
    if type(timestamp) is not int or not 0 <= (time.time() if current_time is None else current_time) - timestamp <= 7 * 86400:
        raise ValueError("Image scan is stale or has an invalid/future timestamp")
    reports = images.get("scan_reports", {})
    expected = artifacts(images)
    if not isinstance(reports, dict) or set(reports) != set(expected):
        raise ValueError("Missing per-image scan evidence")
    for name, report in reports.items():
        if (not isinstance(report, dict) or report.get("artifact") != expected[name]
                or report.get("status") != "passed" or report.get("findings") != 0
                or type(report.get("findings")) is not int
                or not re.fullmatch(r"[a-f0-9]{64}", report.get("sha256", ""))):
            raise ValueError("Incomplete or mismatched per-image scan evidence")
