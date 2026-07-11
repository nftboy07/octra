from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from octra_recon.race.bkw_sweep import plain_bkw_estimate, run_bkw_sweep
from octra_recon.race.planted import generate_planted, gaussian_solve_noiseless, run_planted_suite
from octra_recon.race.residual import _dot_parity, parse_s_bits
from octra_recon.workspace import init_workspace


class RaceTests(unittest.TestCase):
    def test_noiseless_recover(self) -> None:
        s, rows = generate_planted(32, 64, 0.0, seed=1)
        got = gaussian_solve_noiseless(rows, 32)
        self.assertEqual(got, s)

    def test_dot_parity_matches_planted(self) -> None:
        s, rows = generate_planted(40, 20, 0.0, seed=2)
        for a, y in rows:
            self.assertEqual(_dot_parity(a, s), y)

    def test_parse_bits(self) -> None:
        bits = parse_s_bits("01" * 20, n=40)
        self.assertEqual(len(bits), 40)

    def test_bkw_has_frontier(self) -> None:
        est = plain_bkw_estimate()
        self.assertIn("rows", est)
        self.assertTrue(len(est["rows"]) > 5)

    def test_planted_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            init_workspace(ws)
            report = run_planted_suite(ws)
            self.assertTrue(report["ok"])
            run_bkw_sweep(ws)


if __name__ == "__main__":
    unittest.main()
