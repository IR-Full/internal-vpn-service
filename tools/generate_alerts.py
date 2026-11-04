"""Generate Grafana-managed rules without a notification credential in the repo."""
from pathlib import Path
import yaml

RULES = [
    ("stale", "Node telemetry is stale or missing", '(max by(node)(time() - vpn_probe_timestamp_seconds) > bool 120) or on(node) absent(vpn_probe_timestamp_seconds{node="vpn_a"}) or on(node) absent(vpn_probe_timestamp_seconds{node="vpn_b"})', 0, "1m"),
    ("interface", "VPN interface is down", "1 - vpn_interface_up", 0, "1m"),
    ("cpu", "CPU saturation", '100 * (1 - avg by(node)(rate(node_cpu_seconds_total{mode="idle"}[2m])))', 85, "5m"),
    ("memory", "Memory pressure", "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)", 85, "5m"),
    ("disk", "Low host disk space", "1 - vpn_root_disk_free_ratio", 0.8, "2m"),
    ("telemetry", "Telemetry ingestion gateway unavailable", "1 - vpn_telemetry_reachable", 0, "1m"),
    ("backup", "Backup missing or older than 26 hours", "time() - vpn_backup_success_timestamp_seconds", 93600, "5m"),
    ("certificate", "Telemetry certificate expires within 30 days or cannot be read", "30 * 86400 - (vpn_telemetry_certificate_expiry_timestamp_seconds - time())", 0, "5m"),
    ("revision", "VPN nodes have different configuration revisions", "max(vpn_fleet_revision) - min(vpn_fleet_revision)", 0, "5m"),
    ("auth", "Repeated administrative authentication failures", "vpn_admin_auth_failures_5m", 10, "1m"),
    ("ddos", "Possible flood: high packet rate and firewall drops", '(sum by(node)(rate(node_network_receive_packets_total{device!~"lo|vpn0|wg-mgmt|docker.*|veth.*|br-.*"}[2m])) > bool 200000) * (sum by(node)(rate(vpn_firewall_input_drops_total[2m])) > bool 10000)', 0, "1m"),
]
rules = []
for uid, title, expression, threshold, duration in RULES:
    rules.append({"uid": "vpn-" + uid, "title": title, "condition": "B", "for": duration,
                  "noDataState": "Alerting", "execErrState": "Alerting", "isPaused": False,
                  "labels": {"service": "private-vpn"},
                  "annotations": {"summary": title, "description": 'Node: {{ $labels.node }}; see dashboard for fleet-wide alerts.',
                                  "runbook_url": "https://github.com/IR-Full/internal-vpn-service/blob/main/docs/runbooks.md"},
                  "data": [
                      {"refId": "A", "relativeTimeRange": {"from": 300, "to": 0}, "datasourceUid": "prometheus",
                       "model": {"refId": "A", "expr": expression, "instant": True, "intervalMs": 20000, "maxDataPoints": 43200}},
                      {"refId": "B", "relativeTimeRange": {"from": 0, "to": 0}, "datasourceUid": "__expr__",
                       "model": {"refId": "B", "type": "math", "expression": f"$A > {threshold}"}}]})
Path("monitoring/alerts.yml").write_text(yaml.safe_dump({"apiVersion": 1, "groups": [
    {"orgId": 1, "name": "private-vpn", "folder": "Private VPN", "interval": "20s", "rules": rules}]}, sort_keys=False))
