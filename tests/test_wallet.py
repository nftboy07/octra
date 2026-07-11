"""Wallet derivation smoke tests (stdlib-only)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from octra_recon.hypotheses import run_hypotheses
from octra_recon.wallet import (
    TARGET_ADDRESS,
    check_mnemonic_against_target,
    mnemonic_from_entropy,
    validate_mnemonic,
)
from octra_recon.workspace import init_workspace


class WalletTests(unittest.TestCase):
    def test_bip39_abandon_vector(self) -> None:
        mnemonic = mnemonic_from_entropy(bytes(16))
        self.assertEqual(
            mnemonic,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        validate_mnemonic(mnemonic)

    def test_check_does_not_match_target_for_abandon(self) -> None:
        row = check_mnemonic_against_target(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            target=TARGET_ADDRESS,
        )
        self.assertFalse(row["match"])
        self.assertTrue(str(row["address"]).startswith("oct"))
        self.assertEqual(len(row["public_key_hex"]), 64)

    def test_hypotheses_run_zero_hits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            init_workspace(root)
            summary = run_hypotheses(root, include_file_hashes=False)
            self.assertGreater(summary["tested"], 50)
            self.assertEqual(summary["hits"], 0)


if __name__ == "__main__":
    unittest.main()
