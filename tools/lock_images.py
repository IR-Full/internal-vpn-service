#!/usr/bin/env python3
"""Resolve selected upstream releases to immutable registry digests; no image executes."""
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import urllib.request

RELEASES = {
    "grafana": ("grafana/grafana", "grafana/grafana", "13.3.0"),
    "loki": ("grafana/loki", "grafana/loki", "3.7.9"),
    "alloy": ("grafana/alloy", "grafana/alloy", "v1.21.3"),
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


def image_hash(data):
    return hashlib.sha256(json.dumps({k: data[k] for k in sorted(RELEASES)}, sort_keys=True).encode()).hexdigest()


if __name__ == "__main__":
    result = {}
    for key, (upstream, repository, tag) in RELEASES.items():
        result[key] = f"{repository}@{digest(repository, tag)}"
        print(key + ": digest verified")
    result["images_sha256"] = image_hash(result)
    result["scan_status"] = "not_scanned"
    Path("infra/images.lock.json").write_text(json.dumps(result, indent=2) + "\n")
