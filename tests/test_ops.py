"""Tests for unlock scan and ops helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from octra_recon.ops import heartbeat, process_candidates
from octra_recon.unlock_scan import scan_tree
from octra_recon.workspace import init_workspace


class UnlockScanTests(unittest.TestCase):
    def test_flags_rku_named_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "harmless.txt").write_text("hello", encoding="utf-8")
            (root / "challenge_rku.bin").write_bytes(b"\x00\x01Rku\x02")
            report = scan_tree(root, label="t")
            self.assertGreaterEqual(report["critical_count"], 1)
            self.assertTrue(report["unlock_signal"])


class OpsTests(unittest.TestCase):
    def test_process_candidates_empty_inbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            init_workspace(ws)
            report = process_candidates(ws)
            self.assertEqual(report["processed"], 0)
            self.assertEqual(report["hits"], 0)

    def test_heartbeat_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "workspace"
            base = Path(tmp)
            init_workspace(ws)
            report = heartbeat(ws, base=base)
            self.assertIn("message", report)
            self.assertIn("disk", report)


if __name__ == "__main__":
    unittest.main()
