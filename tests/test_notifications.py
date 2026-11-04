import copy
import unittest
from vpn_fleet.notifications import validate, provisioning
from vpn_fleet.registry import FleetError


class NotificationTests(unittest.TestCase):
    def settings(self):
        return {"enabled": True, "email": "admin@example.invalid", "telegram": {"token": "123456:test_only_not_a_real_token", "chat_id": "123456"},
                "smtp": {"host": "smtp.example.invalid:587", "user": "test-admin", "password": "test-only-placeholder", "from_address": "vpn@example.invalid"}}

    def test_both_contacts_and_deduplicated_policy(self):
        config = provisioning(self.settings())
        self.assertEqual({r["type"] for r in config["contactPoints"][0]["receivers"]}, {"email", "telegram"})
        self.assertEqual(config["policies"][0]["repeat_interval"], "4h")

    def test_tls_downgrade_and_line_injection_rejected(self):
        settings = self.settings(); settings["smtp"]["host"] = "smtp.example.invalid:25"
        with self.assertRaises(FleetError): validate(settings)
        settings = self.settings(); settings["email"] += "\nBcc: other@example.invalid"
        with self.assertRaises(FleetError): validate(settings)
