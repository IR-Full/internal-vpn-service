#!/usr/bin/env python3
"""Ansible delegates the same image gate as vpnctl to its trusted controller."""
import json
from pathlib import Path
import sys
import argparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from vpn_fleet.image_policy import validate_scan
from vpn_fleet.plugins import prepare_plugins

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--prepare-plugins", action="store_true")
        args = parser.parse_args()
        images = json.load(sys.stdin)
        validate_scan(images)
        if args.prepare_plugins:
            prepare_plugins(images["grafana_plugins"], Path(__file__).resolve().parents[1] / ".state/grafana-plugins")
    except (ValueError, TypeError, KeyError):
        raise SystemExit("Image admission rejected; run the full exact-image security scan")
    print("Exact image references, evidence, policy, platform and scan freshness verified")
