from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from octra_recon.social_watch import _priority_for_text, social_telegram_messages, social_watch
from octra_recon.workspace import init_workspace


class SocialWatchTests(unittest.TestCase):
    def test_priority(self) -> None:
        self.assertEqual(_priority_for_text("we recovered the mnemonic"), "critical")
        self.assertEqual(_priority_for_text("new LPN sample drop"), "high")
        self.assertEqual(_priority_for_text("hello world"), "normal")

    def test_telegram_messages_order(self) -> None:
        report = {
            "critical": [{"source": "x_tweet", "text": "solved", "url": "https://x.com/i/web/status/1", "priority": "critical"}],
            "high": [{"source": "github_commit", "repo": "a/b", "message": "add lpn", "priority": "high"}],
            "actionable": [],
        }
        msgs = social_telegram_messages(report, max_messages=2)
        self.assertEqual(len(msgs), 2)
        self.assertIn("CRITICAL", msgs[0])

    def test_social_watch_handles_network_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            init_workspace(ws)
            with patch("octra_recon.social_watch._http_json", side_effect=TimeoutError):
                report = social_watch(ws)
            self.assertIn("alert_count", report)
            self.assertTrue((ws / "logs" / "social_watch.json").is_file())


if __name__ == "__main__":
    unittest.main()
