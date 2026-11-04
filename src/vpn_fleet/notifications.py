"""Local-only notification enrollment; sending is left to deployed Grafana."""
import re
from .registry import FleetError


def validate(settings):
    smtp = settings["smtp"]
    if not re.fullmatch(r"[A-Za-z0-9.-]+:587", smtp["host"]):
        raise FleetError("Use a valid SMTP hostname on port 587 with mandatory STARTTLS")
    for address in (settings["email"], smtp["from_address"]):
        if not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", address):
            raise FleetError("Invalid notification email address")
    for value in (smtp["user"], smtp["password"], settings["telegram"]["token"]):
        if not value or any(c in value for c in "\r\n\x00"):
            raise FleetError("Notification credentials must be nonempty single-line values")
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", settings["telegram"]["token"]):
        raise FleetError("Invalid Telegram bot token format")
    if not re.fullmatch(r"-?[0-9]+", settings["telegram"]["chat_id"]):
        raise FleetError("Telegram chat ID must be numeric")
    return settings


def provisioning(settings):
    validate(settings)
    return {
        "apiVersion": 1,
        "contactPoints": [{"orgId": 1, "name": "fleet-admin", "receivers": [
            {"uid": "fleet-telegram", "type": "telegram", "disableResolveMessage": False,
             "settings": {"bottoken": settings["telegram"]["token"], "chatid": settings["telegram"]["chat_id"],
                          "disable_web_page_preview": True, "protect_content": True}},
            {"uid": "fleet-email", "type": "email", "disableResolveMessage": False,
             "settings": {"addresses": settings["email"], "singleEmail": True}}]}],
        "policies": [{"orgId": 1, "receiver": "fleet-admin", "group_by": ["grafana_folder", "alertname"],
                      "group_wait": "30s", "group_interval": "5m", "repeat_interval": "4h"}],
    }
