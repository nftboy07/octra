"""Unit tests for LPN sample inventory helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from octra_recon.lpn import estimate_lpn_hardness, inventory_lpn_samples
from octra_recon.workspace import init_workspace, write_json


class LpnTests(unittest.TestCase):
    def test_hardness_estimate_shape(self) -> None:
        report = estimate_lpn_hardness()
        self.assertEqual(report["n"], 4096)
        self.assertIn("ballpark", report)
        joined = " ".join(report["notes"]).lower()
        self.assertIn("prf_k", joined)

    def test_inventory_synthetic_samples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            init_workspace(root)
            lpn = root / "artifacts" / "lpn_samples"
            lpn.mkdir(parents=True)
            meta = {
                "format": "octra-bounty-target-seed-lpn-ay-v1",
                "cipher_index": 0,
                "layer_id": 0,
                "slot": 0,
                "dom": "pvac.prf.r.1",
                "n": 4096,
                "t": 3,
                "tau_num": 1,
                "tau_den": 8,
                "row_words": 64,
                "seed_ztag": 1,
                "nonce_lo_hex": "00",
                "nonce_hi_hex": "00",
                "public_T_hex": "aa",
            }
            # One synthetic file (inventory still runs; file_count_ok will be false).
            path = lpn / "ct00_l0_s0_pvac_prf_r_1.jsonl"
            with path.open("w", encoding="utf-8") as handle:
                handle.write(json.dumps(meta) + "\n")
                for i in range(3):
                    handle.write(json.dumps({"i": i, "y": i % 2, "a": "00"}) + "\n")
            report = inventory_lpn_samples(root, scan_y_bits=True)
            self.assertEqual(report["file_count"], 1)
            self.assertEqual(report["files"][0]["sample_rows"], 3)
            self.assertFalse(report["file_count_ok"])
            self.assertTrue((root / "logs" / "lpn_inventory.json").is_file())


if __name__ == "__main__":
    unittest.main()
