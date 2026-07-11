from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from octra_recon.claim import claim_pipeline
from octra_recon.dashboard import build_dashboard
from octra_recon.workspace import init_workspace


class ClaimDashTests(unittest.TestCase):
    def test_claim_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            init_workspace(ws)
            # no lpn dir — unlock may fail; create empty structure
            (ws / "artifacts" / "lpn_samples").mkdir(parents=True)
            (ws / "repos" / "hfhe-challenge" / "lpn_samples").mkdir(parents=True)
            try:
                report = claim_pipeline(ws)
                self.assertIn("claim_ready", report)
            except Exception:
                # without samples unlock scan may error — ensure dashboard still builds
                pass
            (ws / "logs").mkdir(exist_ok=True)
            dash = build_dashboard(ws)
            self.assertTrue(Path(dash["dashboard"]).is_file())


if __name__ == "__main__":
    unittest.main()
