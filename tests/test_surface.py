from __future__ import annotations

import unittest

from octra_recon.surface import open_surface_status


class SurfaceTests(unittest.TestCase):
    def test_status_has_fury_and_sources(self) -> None:
        report = open_surface_status()
        self.assertIn("fury_applicability", report)
        self.assertEqual(report["fury_applicability"]["rku_in_public_package"], False)
        ids = {s["id"] for s in report["public_sources"]}
        self.assertIn("tempest_blog", ids)
        self.assertIn("lambda_lpn_drop", ids)
        self.assertIn("smoke_ui_assessment", ids)


if __name__ == "__main__":
    unittest.main()
