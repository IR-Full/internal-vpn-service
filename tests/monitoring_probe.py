"""Real monitoring queries and alert evaluation inside a networkless test namespace."""
import base64
import http.server
import json
from pathlib import Path
import threading
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import yaml

PHASE = "healthy"
LAST_ALERT_STATE = {}
AUTH = "Basic " + base64.b64encode(b"fleetadmin:smoke-test-only-password").decode()


def metrics():
    lines = []
    for node in ("vpn_a", "vpn_b"):
        if node == "vpn_a" and PHASE == "missing-a":
            continue
        now = time.time()
        values = {"vpn_probe_timestamp_seconds": now - (600 if PHASE == "stale-a" and node == "vpn_a" else 0),
                  "vpn_interface_up": 1, "vpn_peers_configured": 2, "vpn_root_disk_free_ratio": 0.8,
                  "vpn_telemetry_reachable": 1, "vpn_backup_success_timestamp_seconds": now,
                  "vpn_telemetry_certificate_expiry_timestamp_seconds": now + (86400 if PHASE == "certificate-a" and node == "vpn_a" else 100 * 86400),
                  "vpn_admin_auth_failures_5m": 0, "vpn_fleet_revision": 4,
                  "node_memory_MemAvailable_bytes": 8e9, "node_memory_MemTotal_bytes": 12e9,
                  "vpn_firewall_input_drops_total": 0}
        lines.extend(f'{key}{{node="{node}"}} {value}\n' for key, value in values.items())
        lines.append(f'node_cpu_seconds_total{{node="{node}",cpu="0",mode="idle"}} {now * 0.9}\n')
        lines.append(f'node_network_receive_packets_total{{node="{node}",device="eth0"}} {now * 100}\n')
    return "".join(lines).encode()


class Exporter(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = metrics()
        self.send_response(200); self.send_header("Content-Type", "text/plain; version=0.0.4"); self.end_headers(); self.wfile.write(data)
    def log_message(self, *_):
        pass


def request(url, data=None, grafana=False):
    headers = {"Content-Type": "application/json"}
    if grafana: headers["Authorization"] = AUTH
    with urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                                    headers=headers), timeout=5) as response:
        content = response.read()
        return json.loads(content) if content else None


def eventually(check, description, seconds=60):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            if check(): return
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError, AssertionError) as exc:
            last = type(exc).__name__
        time.sleep(1)
    raise AssertionError(f"Timed out: {description}; last error type: {last}")


def query(expression):
    return request("http://127.0.0.1:9090/api/v1/query?" + urllib.parse.urlencode({"query": expression}))["data"]["result"]


def alert_states(title):
    groups = request("http://127.0.0.1:3000/api/prometheus/grafana/api/v1/rules", grafana=True)["data"]["groups"]
    rule = next(rule for group in groups for rule in group["rules"] if rule["name"] == title)
    # Emit only this synthetic test rule if evaluation enters an unexpected state.
    if rule.get("lastError"):
        raise AssertionError("Grafana evaluation error: " + rule["lastError"])
    states = {alert["labels"].get("node"): alert["state"] for alert in rule.get("alerts", [])}
    diagnostic = {"phase": PHASE, "title": title, "state": rule.get("state"), "health": rule.get("health"),
                  "instances": states}
    if LAST_ALERT_STATE.get(title) != diagnostic:
        print(json.dumps(diagnostic), file=sys.stderr, flush=True)
        LAST_ALERT_STATE[title] = diagnostic
    return states


def run():
    global PHASE
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 9876), Exporter)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    eventually(lambda: len(query("vpn_probe_timestamp_seconds")) == 2, "both nodes scraped")
    for uid in ("prometheus", "loki"):
        eventually(lambda: request(f"http://127.0.0.1:3000/api/datasources/uid/{uid}/health", grafana=True)["status"] == "OK",
                   f"working {uid} backend plugin")
        installed = request(f"http://127.0.0.1:3000/api/plugins/{uid}/settings", grafana=True)
        assert installed["signature"] == "valid", installed
    prom = request("http://127.0.0.1:3000/api/ds/query", {"from": "now-5m", "to": "now", "queries": [
        {"refId": "A", "datasource": {"type": "prometheus", "uid": "prometheus"}, "expr": "sum(vpn_peers_configured)", "instant": True, "range": False}]}, grafana=True)
    assert prom["results"]["A"]["frames"][0]["data"]["values"][1] == [4], prom
    event = "Accepted publickey"
    request("http://127.0.0.1:3100/loki/api/v1/push", {"streams": [{"stream": {"job": "admin_auth"}, "values": [[str(time.time_ns()), event]]}]})
    def logs_work():
        result = request("http://127.0.0.1:3000/api/ds/query", {"from": "now-5m", "to": "now", "queries": [
            {"refId": "A", "datasource": {"type": "loki", "uid": "loki"}, "expr": '{job="admin_auth"}', "queryType": "range", "maxLines": 10}]}, grafana=True)
        return event in json.dumps(result["results"]["A"]["frames"])
    eventually(logs_work, "actual logs through Grafana Loki datasource")
    rules = yaml.safe_load(Path("/workspace/monitoring/alerts.yml").read_text())["groups"][0]["rules"]
    # Exercise every production PromQL expression with real Prometheus, including rate-based ones.
    time.sleep(3)
    for rule in rules:
        expression = rule["data"][0]["model"]["expr"]
        assert query(expression), f"No result for {rule['uid']}"
    stale = next(r for r in rules if r["uid"] == "vpn-stale")
    def values(): return {r["metric"]["node"]: float(r["value"][1]) for r in query(stale["data"][0]["model"]["expr"])}
    eventually(lambda: values() == {"vpn_a": 0, "vpn_b": 0}, "healthy negative control")
    PHASE = "missing-a"
    eventually(lambda: values() == {"vpn_a": 1, "vpn_b": 0}, "missing node still alerts after stale markers")
    eventually(lambda: alert_states(stale["title"]) == {"vpn_a": "Alerting", "vpn_b": "Normal"},
               "Grafana fires only for missing node, retaining its label")
    PHASE = "healthy"
    eventually(lambda: values() == {"vpn_a": 0, "vpn_b": 0}, "recovery samples")
    eventually(lambda: alert_states(stale["title"]) == {"vpn_a": "Normal", "vpn_b": "Normal"}, "Grafana resolves recovered node")
    PHASE = "stale-a"
    eventually(lambda: values() == {"vpn_a": 1, "vpn_b": 0}, "old collector timestamp")
    PHASE = "certificate-a"
    certificate = next(r for r in rules if r["uid"] == "vpn-certificate")
    eventually(lambda: alert_states(certificate["title"]) == {"vpn_a": "Alerting", "vpn_b": "Normal"},
               "certificate expiry alert with healthy second node")
    server.shutdown()
    print("PASS: real Prometheus and Loki queries through Grafana; all alert expressions; missing/stale node, per-node firing/recovery and certificate expiry. No external network or notification delivery.")


if __name__ == "__main__": run()
