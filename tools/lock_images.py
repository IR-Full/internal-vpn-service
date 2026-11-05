#!/usr/bin/env python3
"""Resolve selected upstream releases to immutable registry digests; no image executes."""
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import urllib.request
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_fleet.image_policy import image_hash
from vpn_fleet.plugins import plugin_hash

RELEASES = {
    "grafana": ("grafana/grafana", "grafana/grafana", "13.3.0-slim"),
    "loki": ("grafana/loki", "grafana/loki", "3.7.9"),
    "alloy": ("grafana/alloy", "grafana/alloy", "v1.21.3-distroless"),
    "prometheus": ("prometheus/prometheus", "prom/prometheus", "v3.15.1"),
}


def request(url, headers=None):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "private-vpn-fleet", **(headers or {})}), timeout=60)


def digest(repository, tag):
    url = "https://auth.docker.io/token?" + urllib.parse.urlencode({"service": "registry.docker.io", "scope": f"repository:{repository}:pull"})
    token = json.load(request(url))["token"]
    accept = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                        "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
    with request(f"https://registry-1.docker.io/v2/{repository}/manifests/{tag}",
                 {"Authorization": "Bearer " + token, "Accept": accept}) as response:
        content = response.read()
        result = response.headers["Docker-Content-Digest"]
        if result != "sha256:" + hashlib.sha256(content).hexdigest():
            raise ValueError("Registry digest mismatch")
        return result


if __name__ == "__main__":
    result = {}
    for key, (upstream, repository, tag) in RELEASES.items():
        result[key] = f"{repository}@{digest(repository, tag)}"
        print(key + ": digest verified")
    result["grafana_plugins"] = {}
    for plugin_id in ("loki", "prometheus"):
        version = "13.2.5"
        metadata = json.load(request(f"https://grafana.com/api/plugins/{plugin_id}/versions/{version}"))
        if metadata["version"] != version or metadata["signatureType"] != "grafana":
            raise ValueError("Unexpected plugin release identity/signature publisher")
        package = metadata["packages"]["linux-amd64"]
        result["grafana_plugins"][plugin_id] = {"version": version, "sha256": package["sha256"],
            "url": f"https://grafana.com/api/plugins/{plugin_id}/versions/{version}/download?os=linux&arch=amd64"}
    result["grafana_plugins_sha256"] = plugin_hash(result["grafana_plugins"])
    result["images_sha256"] = image_hash(result)
    result["scan_status"] = "not_scanned"
    Path("infra/images.lock.json").write_text(json.dumps(result, indent=2) + "\n")
