"""Wire parser + mask/rng/stack smoke tests."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from octra_recon.mask_diff import dual_mask_model, run_mask_diff
from octra_recon.rng_audit import audit_wallet_gen_source, run_rng_audit
from octra_recon.wire_audit import audit_secret_ct, parse_bundle
from octra_recon.workspace import init_workspace


# tests/ -> toolkit/ -> octra-investigation/
ROOT = Path(__file__).resolve().parents[2]
SECRET = ROOT / "hfhe-challenge" / "secret.ct"
if not SECRET.is_file():
    SECRET = Path(r"C:\Users\91907\dev\octra-investigation\hfhe-challenge\secret.ct")


class WireStackTests(unittest.TestCase):
    def test_parse_real_secret_ct_if_present(self) -> None:
        if not SECRET.is_file():
            self.skipTest("secret.ct not in tree")
        report = audit_secret_ct(SECRET)
        self.assertTrue(report["bundle"]["parse_complete"])
        self.assertEqual(report["bundle"]["cipher_count"], 22)
        self.assertEqual(report["bundle"]["total_base_layers"], 44)
        self.assertEqual(report["bundle"]["total_prod_layers"], 0)
        self.assertEqual(report["bundle"]["dual_base_cipher_count"], 22)
        self.assertEqual(report["bundle"]["total_edges"], 1829)
        pl = report["plaintext_length"]
        self.assertEqual(pl["plaintext_bytes_min"], 301)
        self.assertEqual(pl["plaintext_bytes_max"], 315)
        self.assertTrue(pl["matches_smoke_ui_22"])
        self.assertFalse(report["alert"])

    def test_bad_magic(self) -> None:
        with self.assertRaises(Exception):
            parse_bundle(b"NOT-A-BUNDLE" + b"\x00" * 32)

    def test_dual_mask_model_static(self) -> None:
        m = dual_mask_model()
        self.assertIn("N0 = R0 * (v + m)", m["equations"])
        self.assertTrue(any(s["id"] == "prf_k" for s in m["secrets_required"]))

    def test_rng_wallet_gen_if_present(self) -> None:
        wg = ROOT / "wallet-gen" / "src" / "server.ts"
        if not wg.is_file():
            self.skipTest("wallet-gen source missing")
        r = audit_wallet_gen_source(wg)
        self.assertTrue(r["has_crypto_randomBytes"])
        self.assertTrue(r["has_Octra_seed_hmac"])
        self.assertTrue(r["csprng_shaped"])
        self.assertFalse(r["has_Math_random"])

    def test_mask_diff_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            init_workspace(ws)
            # copy secret if available for richer run
            if SECRET.is_file():
                (ws / "artifacts").mkdir(exist_ok=True)
                shutil.copy(SECRET, ws / "artifacts" / "secret.ct")
            report = run_mask_diff(ws)
            self.assertIn("decision_matrix", report)
            self.assertIn("model", report)

    def test_rng_audit_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            init_workspace(ws)
            report = run_rng_audit(ws)
            self.assertIn("checked_at", report)
            self.assertIn("bounty_seed_note", report)


if __name__ == "__main__":
    unittest.main()
