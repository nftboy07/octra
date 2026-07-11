"""Tests for deep LPN audit helpers (synthetic small instance)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from octra_recon.lpn_audit import HEXROW, N, _add_rank, _z_balance, deep_audit
from octra_recon.workspace import init_workspace, write_json


class LpnAuditUnitTests(unittest.TestCase):
    def test_rank_full_identity(self) -> None:
        pivots: dict[int, int] = {}
        for i in range(8):
            _add_rank(pivots, 1 << i)
        self.assertEqual(len(pivots), 8)

    def test_z_balance_zero(self) -> None:
        self.assertAlmostEqual(_z_balance(50, 100), 0.0)

    def test_hexrow_width(self) -> None:
        # 1024 hex chars for 512 bytes
        self.assertTrue(HEXROW.fullmatch("0" * 1024))
        self.assertFalse(HEXROW.fullmatch("0" * 10))


if __name__ == "__main__":
    unittest.main()
