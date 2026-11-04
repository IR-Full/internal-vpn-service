#!/usr/bin/env python3
"""Resolve official Ubuntu Noble PPA key fingerprint and explicit package versions."""
import gzip
import hashlib
import json
import lzma
from pathlib import Path
import re
import subprocess
import urllib.request


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "private-vpn-fleet"})
    with urllib.request.urlopen(request, timeout=40) as response: return response.read()


if __name__ == "__main__":
    archive = json.loads(fetch("https://api.launchpad.net/1.0/~amnezia/+archive/ubuntu/ppa"))
    fingerprint = archive["signing_key_fingerprint"]
    if not re.fullmatch(r"[A-Fa-f0-9]{40,64}", fingerprint): raise ValueError("Invalid PPA fingerprint")
    url = "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x" + fingerprint
    key = fetch(url)
    source = "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/noble/main/binary-amd64/Packages"
    try: packages = lzma.decompress(fetch(source + ".xz")).decode()
    except urllib.error.HTTPError: packages = gzip.decompress(fetch(source + ".gz")).decode()
    names = {"amneziawg": "amnezia_package_version", "amneziawg-tools": "amnezia_tools_version", "amneziawg-dkms": "amnezia_dkms_version"}
    result = {"amnezia_ppa_key_url": url, "amnezia_ppa_key_sha256": hashlib.sha256(key).hexdigest(),
              "amnezia_ppa_fingerprint": fingerprint}
    for block in packages.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(" "))
        if fields.get("Package") in names:
            variable = names[fields["Package"]]
            version = fields["Version"]
            if variable not in result or subprocess.run(["dpkg", "--compare-versions", version, "gt", result[variable]]).returncode == 0:
                result[variable] = version
    if not all(variable in result for variable in names.values()):
        raise RuntimeError("Official Noble repository lacks required packages; do not silently use another OS repository")
    output = Path(".state/amnezia-lock.json"); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print("Official PPA fingerprint/checksum and three package versions recorded. Review before installation; running-kernel DKMS and client compatibility still need a VPS pilot.")
