from __future__ import annotations
import argparse
import getpass
import hashlib
import json
from pathlib import Path
import sys

from . import registry as r


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Private administrator-only VPN device registry")
    parser.add_argument("--registry", type=Path, default=Path(".state/registry.enc"))
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--fleet", type=Path, required=True)
    update = sub.add_parser("set-fleet"); update.add_argument("--fleet", type=Path, required=True)
    user = sub.add_parser("add-user"); user.add_argument("user")
    device = sub.add_parser("add-device"); device.add_argument("user"); device.add_argument("device")
    revoke = sub.add_parser("revoke"); revoke.add_argument("device")
    rotate = sub.add_parser("rotate-device"); rotate.add_argument("device")
    rotate_server = sub.add_parser("rotate-server"); rotate_server.add_argument("node", choices=["vpn_a", "vpn_b"])
    sub.add_parser("renew-telemetry")
    purge = sub.add_parser("delete-user"); purge.add_argument("user")
    sub.add_parser("list")
    sub.add_parser("configure-alerting", help="Enroll BOTH private Telegram and email locally; never sends a message")
    export = sub.add_parser("export"); export.add_argument("device"); export.add_argument("--out", type=Path, required=True)
    render = sub.add_parser("render"); render.add_argument("--out", type=Path, default=Path(".state/deploy"))
    render.add_argument("--images", type=Path, default=Path("infra/images.lock.json"))
    backup = sub.add_parser("backup"); backup.add_argument("--out", type=Path, required=True)
    credential = sub.add_parser("grafana-password"); credential.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        password = getpass.getpass("Registry passphrase: ")
        with r.locked(args.registry):
            if args.command == "init":
                if args.registry.exists():
                    raise r.FleetError("Registry already exists")
                if password != getpass.getpass("Repeat passphrase: "):
                    raise r.FleetError("Passphrases differ")
                state = r.create_registry(json.loads(args.fleet.read_text(encoding="utf-8")))
            else:
                state = r.decrypt(args.registry.read_bytes(), password)
            if args.command == "configure-alerting":
                from .notifications import validate
                settings = {"enabled": True, "email": input("Recipient email: ").strip(),
                            "telegram": {"chat_id": input("Your Telegram chat ID: ").strip(),
                                         "token": getpass.getpass("Telegram bot token (hidden): ")},
                            "smtp": {"host": input("SMTP host:587: ").strip(),
                                     "user": input("SMTP user: ").strip(),
                                     "password": getpass.getpass("SMTP app password (hidden): "),
                                     "from_address": input("SMTP sender email: ").strip()}}
                state["alerting"] = validate(settings)
                r.event(state, "notification_settings_updated", "administrator")
            elif args.command == "set-fleet":
                fleet = r.validate_fleet(json.loads(args.fleet.read_text(encoding="utf-8")))
                old = {n["id"]: n for n in state["fleet"]["nodes"]}
                if any(n["network"] != old[n["id"]]["network"] or n.get("backend", "wireguard") != old[n["id"]].get("backend", "wireguard") for n in fleet["nodes"]):
                    raise r.FleetError("Network/backend migration requires a planned replacement; do not change it in place")
                state["fleet"] = fleet
                r.event(state, "fleet_updated", "fleet")
            elif args.command == "add-user":
                r.add_user(state, args.user)
            elif args.command == "add-device":
                r.add_device(state, args.user, args.device)
            elif args.command == "rotate-device":
                r.rotate_device(state, args.device)
            elif args.command == "rotate-server":
                state["servers"][args.node] = {"vpn": r.keypair(), "management": r.keypair()}
                r.event(state, "server_keys_rotated", args.node)
            elif args.command == "renew-telemetry":
                from .deployment import make_pki
                state["pki"] = make_pki()
                r.event(state, "telemetry_pki_renewed", "fleet")
            elif args.command == "revoke":
                r.revoke(state, args.device)
            elif args.command == "delete-user":
                if args.user not in state["users"]:
                    raise r.FleetError("Unknown user")
                for d in list(state["devices"]):
                    if state["devices"][d]["user"] == args.user:
                        r.revoke(state, d)
                        del state["devices"][d]
                del state["users"][args.user]
                r.event(state, "user_deleted", args.user)
            elif args.command == "list":
                print(json.dumps({"revision": state["revision"], "users": len(state["users"]),
                                  "devices": [{"id": k, "user": d["user"], "revoked": d["revoked"]}
                                              for k, d in state["devices"].items()]}, indent=2))
                return 0
            elif args.command == "export":
                r.validate_fleet(state["fleet"])
                # A new private directory is required, so two-profile export cannot mix credentials.
                if args.out.exists():
                    raise r.FleetError("Choose a NEW private output directory")
                r.private_directory(args.out)
                for node in state["fleet"]["nodes"]:
                    r.atomic_write(args.out / f"{args.device}-{node['id']}.conf",
                                   r.client_config(state, args.device, node["id"]).encode(), replace=False)
                print("Two sensitive profiles written; transfer securely and remove the export afterwards.")
                return 0
            elif args.command == "render":
                from .deployment import render
                images = json.loads(args.images.read_text())
                from .deployment import validate_images
                validate_images(images)
                render(state, args.out, password, images)
            elif args.command == "grafana-password":
                if "grafana" not in state:
                    raise r.FleetError("Render deployment first")
                r.atomic_write(args.out, state["grafana"]["password"].encode(), replace=False)
                return 0
            elif args.command == "backup":
                r.atomic_write(args.out, args.registry.read_bytes(), replace=False)
                # Verify backup is decryptable, without printing any plaintext.
                r.decrypt(args.out.read_bytes(), password)
                print("Encrypted backup verified. Keep its passphrase separately.")
                return 0
            r.atomic_write(args.registry, r.encrypt(state, password))
            print(f"OK. Desired configuration revision: {state['revision']}. Apply to BOTH nodes and verify acknowledgements.")
            return 0
    except (r.FleetError, OSError, ValueError, KeyError) as exc:
        # Avoid reflecting untrusted JSON, credentials, or subprocess output.
        print(str(exc) if isinstance(exc, r.FleetError) else "Operation failed; check paths and configuration format.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
