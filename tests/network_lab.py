#!/usr/bin/env python3
"""Isolated no-internet network test: real kernel WireGuard, nftables and revocation."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, "tests")
from test_node_apply import desired, node
from vpn_fleet.registry import keypair


def run(*args, ok=True, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True)
    if ok and result.returncode:
        raise RuntimeError("Lab command failed: " + " ".join(args[:4]) + "\n" + result.stderr)
    return result


def ns(name, *args, **kwargs): return run("ip", "netns", "exec", name, *args, **kwargs)


def ping(name, address, expected=True):
    result = ns(name, "ping", "-n", "-c", "1", "-W", "2", address, ok=False)
    if (result.returncode == 0) != expected:
        raise AssertionError(f"Unexpected routing result in {name}, expected reachable={expected}")


if __name__ == "__main__":
    processes = []
    names = ["client1", "client2", "internet"]
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        try:
            run("ip", "link", "add", "br0", "type", "bridge")
            run("ip", "address", "add", "198.51.100.1/24", "dev", "br0")
            run("ip", "link", "set", "br0", "up")
            for i, name in enumerate(names, 2):
                run("ip", "netns", "add", name)
                run("ip", "link", "add", f"port{i}", "type", "veth", "peer", "name", "eth0", "netns", name)
                run("ip", "link", "set", f"port{i}", "master", "br0")
                run("ip", "link", "set", f"port{i}", "up")
                ns(name, "ip", "link", "set", "lo", "up")
                ns(name, "ip", "link", "set", "eth0", "up")
                ns(name, "ip", "address", "add", f"198.51.100.{i}/24", "dev", "eth0")
            # Docker supplies these per-network-namespace sysctls; /proc/sys stays read-only.
            assert Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
            data = desired(); data["peers"] = []
            private = []
            for i in (2, 3):
                keys = keypair(); private.append(keys)
                data["peers"].append({"id": f"device{i}", "public_key": keys["public"], "psk": keypair()["private"],
                                      "ipv4": f"10.77.0.{i}", "ipv6": f"fd77:1::{i}"})
            node.apply(data, temp / "server-state")
            pub = run("wg", "show", "vpn0", "public-key").stdout.strip()
            for i, name in enumerate(names[:2], 2):
                ns(name, "ip", "link", "add", "clientwg", "type", "wireguard")
                config = temp / f"{name}.conf"
                config.write_text(f"[Interface]\nPrivateKey = {private[i-2]['private']}\n[Peer]\nPublicKey = {pub}\nPresharedKey = {data['peers'][i-2]['psk']}\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n")
                ns(name, "wg", "setconf", "clientwg", str(config))
                ns(name, "ip", "address", "add", f"10.77.0.{i}/32", "dev", "clientwg")
                ns(name, "ip", "-6", "address", "add", f"fd77:1::{i}/128", "dev", "clientwg")
                ns(name, "ip", "link", "set", "clientwg", "up")
                for route in ["10.77.0.0/23", "198.51.100.4/32", "169.254.169.254/32"]:
                    ns(name, "ip", "route", "add", route, "dev", "clientwg")
                ns(name, "ip", "-6", "route", "add", "default", "dev", "clientwg")
            # Map the rendered management peer endpoint to the isolated upstream namespace.
            policy = Path(".state/validation/vpn_a/firewall.nft").read_text().replace("1.1.1.1", "198.51.100.4")
            run("nft", "-f", "-", input=policy)
            run("ip", "route", "add", "169.254.169.254/32", "via", "198.51.100.4")
            ns("internet", "ip", "address", "add", "169.254.169.254/32", "dev", "lo")
            ping("client1", "10.77.0.1")
            ping("client2", "10.77.0.1")
            resolver = temp / "resolver.conf"
            resolver.write_text('server:\n interface: 10.77.0.1\n username: ""\n chroot: ""\n pidfile: ""\n use-syslog: no\n access-control: 10.77.0.0/23 allow\n local-zone: "lab.invalid." static\n local-data: "lab.invalid. 60 IN A 198.51.100.4"\n')
            processes.append(subprocess.Popen(["unbound", "-d", "-c", str(resolver)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            time.sleep(0.5)
            query = "import socket,struct; q=struct.pack('!HHHHHH',123,256,1,0,0,0)+b'\\x03lab\\x07invalid\\x00'+struct.pack('!HH',1,1); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(q,('10.77.0.1',53)); a=s.recv(512); assert a[:2]==q[:2] and b'\\xc6\\x33\\x64\\x04' in a"
            ns("client1", "python", "-c", query)
            ping("client1", "198.51.100.4")  # NAT path, not a direct /24 shortcut.
            def forward_drops():
                counters = json.loads(run("nft", "-j", "list", "counter", "inet", "vpn_service", "forward_drops").stdout)
                return next(entry["counter"]["packets"] for entry in counters["nftables"] if "counter" in entry)

            before = forward_drops()
            ns("client1", "python", "-c", "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'lab', ('198.51.100.4', 51821))")
            assert forward_drops() > before, "Client can reach the peer management UDP listener via NAT"
            ping("client1", "10.77.0.3", expected=False)
            ping("client1", "169.254.169.254", expected=False)
            result = ns("client1", "ping", "-6", "-n", "-c", "1", "-W", "1", "2606:4700:4700::1111", ok=False)
            assert result.returncode != 0
            assert "clientwg" in ns("client1", "ip", "-6", "route", "get", "2606:4700:4700::1111").stdout
            older = copy.deepcopy(data)
            data["revision"] += 1; data["peers"] = data["peers"][1:]
            node.apply(data, temp / "server-state")
            ping("client1", "10.77.0.1", expected=False)
            ping("client2", "10.77.0.1")
            try:
                node.apply(older, temp / "server-state")
                raise AssertionError("Stale revision resurrected revoked peer")
            except ValueError:
                pass
            stale_config = temp / "tunnel.json"
            stale_config.write_text(json.dumps(older))
            run("ip", "link", "delete", "dev", "vpn0")
            node.apply(None, temp / "server-state", boot_fallback=stale_config)
            assert run("wg", "show", "vpn0", "peers").stdout.split() == [data["peers"][0]["public_key"]]
            ping("client1", "10.77.0.1", expected=False)
            # The surviving client may still be using its pre-restart session keys.
            for _ in range(25):
                if ns("client2", "ping", "-n", "-c", "1", "-W", "1", "10.77.0.1", ok=False).returncode == 0:
                    break
            else:
                raise AssertionError("Surviving peer could not establish a new session after restart")
            ack = json.loads((temp / "server-state" / "ack.json").read_text())
            assert ack["revision"] == data["revision"]
            print("PASS: encrypted handshake, private DNS, routed IPv4/NAT, client isolation, metadata protection, IPv6 capture, selective revocation and restart after stale-state rejection.")
        finally:
            for process in processes: process.terminate()
            for name in names: run("ip", "netns", "delete", name, ok=False)
