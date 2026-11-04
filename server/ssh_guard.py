#!/usr/bin/env python3
"""Stage MFA-only SSH with an independently scheduled 180-second rollback."""
import os
import pwd
import fcntl
from pathlib import Path
import shutil
import subprocess
import sys

STATE = Path("/var/lib/vpn-service/ssh-rollback")
PAM = Path("/etc/pam.d/sshd")
DROPIN = Path("/etc/ssh/sshd_config.d/00-vpn-service.conf")
CONFIRMED = Path("/var/lib/vpn-service/ssh-mfa-confirmed")


def restart():
    subprocess.run(["/usr/sbin/sshd", "-t"], check=True, capture_output=True)
    subprocess.run(["systemctl", "reload", "ssh"], check=True)


def execute(command):
    if command == "stage":
        if STATE.exists():
            raise SystemExit("Previous SSH change is pending; confirm or roll back first")
        secret = Path("/home/vpnadmin/.google_authenticator")
        if not secret.is_file() or secret.stat().st_mode & 0o077 or secret.stat().st_uid != pwd.getpwnam("vpnadmin").pw_uid:
            raise SystemExit("Enroll vpnadmin TOTP first; secret file must be private")
        if "@include common-auth" not in PAM.read_text():
            raise SystemExit("Unsupported PAM layout; refusing a blind replacement")
        STATE.mkdir(mode=0o700)
        CONFIRMED.unlink(missing_ok=True)
        shutil.copyfile(PAM, STATE / "pam")
        if DROPIN.exists(): shutil.copyfile(DROPIN, STATE / "dropin")
        subprocess.run(["systemd-run", "--collect", "--unit=vpn-ssh-rollback", "--on-active=180s",
                        "/usr/local/sbin/vpn-ssh-guard", "rollback"], check=True, capture_output=True)
        DROPIN.write_text("\n".join([
            "PermitRootLogin no", "PubkeyAuthentication yes", "PasswordAuthentication no",
            "KbdInteractiveAuthentication yes", "AuthenticationMethods publickey,keyboard-interactive:pam",
            "UsePAM yes", "PermitEmptyPasswords no", "AllowUsers vpnadmin", "MaxAuthTries 3",
            "LoginGraceTime 30", "X11Forwarding no", "AllowAgentForwarding no", "LogLevel VERBOSE", ""]))
        PAM.write_text(PAM.read_text().replace("@include common-auth", "auth required pam_google_authenticator.so"))
        try:
            restart()
            effective = subprocess.run(["/usr/sbin/sshd", "-T"], check=True, capture_output=True, text=True).stdout
            if "authenticationmethods publickey,keyboard-interactive:pam" not in effective:
                raise ValueError("Another SSH setting overrides mandatory MFA")
        except Exception:
            execute("rollback")
            raise
        print("Open a NEW SSH connection and validate MFA, then confirm within 180 seconds")
    elif command == "confirm":
        if not STATE.exists():
            raise SystemExit("No staged SSH change remains; it may already have rolled back")
        subprocess.run(["systemctl", "stop", "vpn-ssh-rollback.timer"], check=True)
        CONFIRMED.write_text("key-plus-totp verified by operator\n")
        if STATE.exists(): shutil.rmtree(STATE)
        print("MFA-only SSH confirmed")
    elif command == "rollback":
        CONFIRMED.unlink(missing_ok=True)
        if STATE.exists():
            shutil.copyfile(STATE / "pam", PAM)
            if (STATE / "dropin").exists(): shutil.copyfile(STATE / "dropin", DROPIN)
            else: DROPIN.unlink(missing_ok=True)
            restart()
            shutil.rmtree(STATE)
        print("SSH configuration restored")
    else:
        raise SystemExit("Expected stage, confirm or rollback")


if __name__ == "__main__":
    os.umask(0o077)
    with Path("/var/lib/vpn-service/ssh-guard.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        execute(sys.argv[1])
