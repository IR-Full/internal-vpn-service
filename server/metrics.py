#!/usr/bin/env python3
"""Local aggregate-only metrics. Never emit peer keys, endpoints, or destinations."""
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import time
import urllib.request


def certificate_expiry(path):
    try:
        result = subprocess.run(["openssl", "x509", "-in", str(path), "-noout", "-enddate"],
                                check=True, capture_output=True, text=True, timeout=5)
        return ssl.cert_time_to_seconds(result.stdout.strip().removeprefix("notAfter="))
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


def collect(config):
    metrics = {"vpn_probe_timestamp_seconds": time.time()}
    security_checks = {"revision": False, "firewall": False, "auth_log": False}
    # An unreadable/malformed certificate produces zero, which must alert immediately.
    metrics["vpn_telemetry_certificate_expiry_timestamp_seconds"] = min(
        certificate_expiry(Path("/etc/vpn-service") / name)
        for name in ("telemetry-ca.pem", "telemetry-cert.pem"))
    tool = "wg" if config["backend"] == "wireguard" else "awg"
    try:
        result = subprocess.run([tool, "show", "vpn0", "latest-handshakes"], capture_output=True, text=True, check=True, timeout=5)
        timestamps = [int(line.split()[1]) for line in result.stdout.splitlines() if line.strip()]
        metrics["vpn_peers_configured"] = len(timestamps)
        metrics["vpn_peers_recent_handshake"] = sum(0 < time.time() - t < 180 for t in timestamps)
        metrics["vpn_interface_up"] = 1
    except Exception:
        metrics["vpn_interface_up"] = 0
    try:
        ack = json.loads(Path("/var/lib/vpn-service/ack.json").read_text())
        if type(ack["revision"]) is not int or ack["revision"] < 1:
            raise ValueError("Invalid acknowledgement revision")
        metrics["vpn_fleet_revision"] = ack["revision"]
        security_checks["revision"] = True
    except Exception:
        metrics["vpn_fleet_revision"] = 0
    usage = shutil.disk_usage("/")
    metrics["vpn_root_disk_free_ratio"] = usage.free / usage.total
    try:
        metrics["vpn_backup_success_timestamp_seconds"] = int(Path("/var/lib/vpn-service/backup-success").read_text())
    except (OSError, ValueError):
        metrics["vpn_backup_success_timestamp_seconds"] = 0
    try:
        counters = subprocess.run(["nft", "-j", "list", "counters", "table", "inet", "vpn_service"],
                                  check=True, text=True, capture_output=True, timeout=5)
        found = set()
        for entry in json.loads(counters.stdout)["nftables"]:
            counter = entry.get("counter", {})
            if counter.get("name") in ("input_drops", "forward_drops"):
                metrics["vpn_firewall_" + counter["name"] + "_total"] = counter["packets"]
                found.add(counter["name"])
        security_checks["firewall"] = found == {"input_drops", "forward_drops"}
    except Exception:
        pass
    try:
        journal = subprocess.run(["journalctl", "-u", "ssh.service", "--since=-5min", "-n", "1000", "-o", "cat", "--no-pager"],
                                 check=True, text=True, capture_output=True, timeout=5)
        metrics["vpn_admin_auth_failures_5m"] = sum(any(event in line for event in
            ("Failed publickey", "Failed keyboard-interactive", "authentication failure", "Invalid user"))
            for line in journal.stdout.splitlines())
        security_checks["auth_log"] = True
    except Exception:
        metrics["vpn_admin_auth_failures_5m"] = 0
    # Zero failed logins is meaningful only if the log could actually be read.
    metrics["vpn_security_probe_up"] = int(all(security_checks.values()))
    try:
        context = ssl.create_default_context(cafile="/etc/vpn-service/telemetry-ca.pem")
        context.load_cert_chain("/etc/vpn-service/telemetry-cert.pem", "/etc/vpn-service/telemetry-key.pem")
        start = time.monotonic()
        with urllib.request.urlopen("https://10.78.0.2:8443/healthz", context=context, timeout=5) as response:
            metrics["vpn_telemetry_reachable"] = int(response.status == 200)
        metrics["vpn_management_rtt_seconds"] = time.monotonic() - start
    except Exception:
        metrics["vpn_telemetry_reachable"] = 0
    # Protect the host from a logging/metrics disk exhaustion incident.
    if usage.free / usage.total < 0.10 and config["node"] == "vpn_b":
        subprocess.run(["docker", "compose", "-f", "/opt/vpn-monitoring/compose.yml", "stop", "loki"], capture_output=True, timeout=30)
    return metrics


if __name__ == "__main__":
    os.umask(0o077)
    config = json.loads(Path("/etc/vpn-service/metrics.json").read_text())
    result = collect(config)
    target = Path("/var/lib/vpn-service/metrics/fleet.prom")
    temporary = target.with_suffix(".tmp")
    temporary.write_text("".join(f"{key} {value}\n" for key, value in sorted(result.items())))
    os.replace(temporary, target)
