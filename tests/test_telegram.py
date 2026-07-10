from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from octra_recon.telegram import load_telegram_settings, notify_telegram, send_telegram_message


class TelegramTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self.temp_dir.name) / "telegram.env"
        self.environment = {
            "OCTRA_TELEGRAM_CONFIG": str(self.config_path),
            "OCTRA_TELEGRAM_BOT_TOKEN": "123456:example_token",
            "OCTRA_TELEGRAM_CHAT_ID": "-1001234567890",
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_missing_settings_are_disabled(self) -> None:
        self.assertIsNone(load_telegram_settings({"OCTRA_TELEGRAM_CONFIG": str(self.config_path)}))

    def test_message_delivery_uses_standard_bot_api(self) -> None:
        settings = load_telegram_settings(self.environment)
        self.assertIsNotNone(settings)
        response = MagicMock()
        response.read.return_value = b'{"ok": true}'
        with patch("octra_recon.telegram.urlopen") as opener:
            opener.return_value.__enter__.return_value = response
            result = send_telegram_message(settings, "Inventory completed")

        request = opener.call_args.args[0]
        self.assertEqual({"channel": "telegram", "status": "sent"}, result)
        self.assertIn("sendMessage", request.full_url)
        self.assertIn("chat_id=-1001234567890", request.data.decode("utf-8"))

    def test_optional_delivery_failure_is_sanitized(self) -> None:
        with patch.dict(os.environ, self.environment, clear=True):
            with patch("octra_recon.telegram.urlopen", side_effect=URLError("network unavailable")):
                result = notify_telegram("Inventory completed")

        self.assertEqual("failed", result["status"])
        self.assertNotIn("123456:example_token", result["error"])
