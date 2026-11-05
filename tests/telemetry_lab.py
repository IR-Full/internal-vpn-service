#!/usr/bin/env python3
"""Exercise the production nginx mTLS gateway and certificate reload without a network."""
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

from vpn_fleet.deployment import make_pki


def write_pki(directory, pki):
    directory.mkdir(exist_ok=True)
    for name, value in {
        "ca.pem": pki["ca"], "server.pem": pki["nodes"]["vpn_b"]["cert"],
        "server.key": pki["nodes"]["vpn_b"]["key"], "client.pem": pki["nodes"]["vpn_a"]["cert"],
        "client.key": pki["nodes"]["vpn_a"]["key"],
    }.items():
        path = directory / name
        path.write_text(value)
        path.chmod(0o600)


def context(ca, client=None):
    result = ssl.create_default_context(cafile=str(ca))
    if client is not None:
        result.load_cert_chain(str(client / "client.pem"), str(client / "client.key"))
    return result


def request(port, tls, path="/healthz"):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        # Production certificates contain this management IP. Transport is loopback only.
        with tls.wrap_socket(raw, server_hostname="10.78.0.2") as connection:
            connection.sendall(f"GET {path} HTTP/1.1\r\nHost: 10.78.0.2\r\nConnection: close\r\n\r\n".encode())
            status = connection.makefile("rb").readline(4096)
            if not status.startswith(b"HTTP/1."):
                raise AssertionError("Gateway did not return an HTTP response")
            return int(status.split()[1])


def rejected(port, tls):
    try:
        status = request(port, tls)
    except ssl.SSLError:
        return True
    return status in (400, 401, 403)


def eventually(check, message):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if check(): return
        except (OSError, AssertionError):
            pass
        time.sleep(0.1)
    raise AssertionError(message)


def run():
    with tempfile.TemporaryDirectory(prefix="vpn-tls-lab-") as temporary:
        root = Path(temporary)
        old, new, foreign = (root / name for name in ("old", "new", "foreign"))
        for directory in (old, new, foreign): write_pki(directory, make_pki())
        active = root / "active"
        active.mkdir()
        def activate(directory):
            for name in ("ca.pem", "server.pem", "server.key"):
                (active / name).write_bytes((directory / name).read_bytes())
                (active / name).chmod(0o600)
        activate(old)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0)); port = reservation.getsockname()[1]
        server = Path("infra/roles/monitoring/templates/telemetry-nginx.conf.j2").read_text()
        replacements = {
            "10.78.0.2:8443": f"127.0.0.1:{port}",
            "/etc/vpn-service/telemetry-cert.pem": str(active / "server.pem"),
            "/etc/vpn-service/telemetry-key.pem": str(active / "server.key"),
            "/etc/vpn-service/telemetry-ca.pem": str(active / "ca.pem"),
            "/var/log/nginx/vpn-telemetry-error.log": str(root / "gateway-error.log"),
        }
        for source, target in replacements.items():
            if source not in server: raise AssertionError("Production gateway template changed; review lab adaptation")
            server = server.replace(source, target)
        configuration = root / "nginx.conf"
        configuration.write_text(
            f"daemon off;\npid {root / 'nginx.pid'};\nerror_log {root / 'error.log'} warn;\n"
            "worker_processes 1;\nevents { worker_connections 32; }\nhttp {\n"
            f"client_body_temp_path {root / 'client-temp'};\nproxy_temp_path {root / 'proxy-temp'};\n"
            f"fastcgi_temp_path {root / 'fastcgi-temp'};\nuwsgi_temp_path {root / 'uwsgi-temp'};\n"
            f"scgi_temp_path {root / 'scgi-temp'};\n"
            + server + "\n}\n")
        command = ["nginx", "-p", str(root) + "/", "-c", str(configuration)]
        checked = subprocess.run(command + ["-t"], capture_output=True, text=True, timeout=5)
        if checked.returncode:
            raise RuntimeError("Isolated nginx configuration rejected: " + checked.stderr[-2000:])
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            old_good = context(old / "ca.pem", old)
            new_good = context(new / "ca.pem", new)
            eventually(lambda: request(port, old_good) == 200, "Initial valid client failed")
            assert rejected(port, context(old / "ca.pem")), "Missing client certificate was accepted"
            assert rejected(port, context(old / "ca.pem", foreign)), "Foreign client certificate was accepted"
            assert request(port, old_good, "/api/v1/write") == 403, "GET bypassed the POST-only ingestion gate"
            assert request(port, old_good, "/loki/api/v1/push") == 403, "GET bypassed the POST-only log gate"
            assert request(port, old_good, "/unexpected") == 404, "Unexpected path was exposed"
            activate(new)
            assert request(port, old_good) == 200, "Test expected nginx to retain its loaded old credentials before reload"
            try:
                request(port, new_good)
            except ssl.SSLCertVerificationError:
                pass
            else:
                raise AssertionError("New-only trust unexpectedly worked before nginx reloaded")
            subprocess.run(command + ["-s", "reload"], check=True, capture_output=True, timeout=5)
            eventually(lambda: request(port, new_good) == 200, "New client failed after actual nginx reload")
            # Trust the new SERVER, but present the OLD client: proves server-side client rejection.
            eventually(lambda: rejected(port, context(new / "ca.pem", old)), "Old client still accepted after reload")
            assert rejected(port, context(new / "ca.pem")), "Missing client accepted after reload"
            assert rejected(port, context(new / "ca.pem", foreign)), "Foreign client accepted after reload"
            assert request(port, new_good) == 200, "Gateway became unavailable during negative checks"
            print("PASS: real production nginx mTLS configuration rejects missing/foreign clients and disallowed routes; file replacement alone retains old TLS state; actual reload activates new credentials and rejects old clients. Loopback-only, no external network.")
        finally:
            process.terminate()
            try: process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate(timeout=5)


if __name__ == "__main__": run()
