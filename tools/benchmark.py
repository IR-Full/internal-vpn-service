#!/usr/bin/env python3
"""Capture one controlled iperf3 baseline; parallel flows are NOT distinct VPN users."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target", required=True, help="IP of your own authorised iperf3 server beyond the VPN")
parser.add_argument("--port", type=int, default=5201)
parser.add_argument("--seconds", type=int, default=30)
parser.add_argument("--flows", type=int, default=4)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
ipaddress.ip_address(args.target)
if not (1 <= args.flows <= 32 and 10 <= args.seconds <= 3600 and 1024 <= args.port <= 65535):
    parser.error("Use 1–32 flows, 10–3600 seconds and an unprivileged target port")
results = {"started_at": datetime.now(timezone.utc).isoformat(), "target": args.target,
           "parallel_flows": args.flows, "distinct_vpn_users": "not measured by this script", "directions": {}}
for direction in ("upload", "download"):
    cmd = ["iperf3", "-c", args.target, "-p", str(args.port), "-t", str(args.seconds), "-P", str(args.flows), "-J"]
    if direction == "download": cmd.append("-R")
    test = subprocess.run(cmd, capture_output=True, text=True, timeout=args.seconds + 30, check=True)
    results["directions"][direction] = json.loads(test.stdout)
args.out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
args.out.write_text(json.dumps(results, indent=2))
print("Saved real iperf3 measurements. Repeat without VPN on the same path and load profile for comparison.")
