from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from octra_recon.artifacts import detect_repeated_blocks, extract_params, verify_checksums
from octra_recon.sources import ReconError
from octra_recon.workspace import init_workspace


class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name) / "workspace"
        init_workspace(self.workspace)
        self.artifacts = self.workspace / "artifacts"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_checksum_manifest_is_verified(self) -> None:
        payload = b"approved artifact"
        (self.artifacts / "pk.bin").write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        (self.artifacts / "SHA256SUMS").write_text(f"{digest}  pk.bin\n", encoding="utf-8")

        report = verify_checksums(self.workspace)

        self.assertTrue(report["ok"])
        self.assertEqual("ok", report["files"][0]["status"])
        self.assertTrue((self.workspace / "logs" / "checksum_report.json").is_file())

    def test_checksum_manifest_rejects_parent_paths(self) -> None:
        (self.artifacts / "SHA256SUMS").write_text("0" * 64 + "  ../secret\n", encoding="utf-8")

        with self.assertRaises(ReconError):
            verify_checksums(self.workspace)

    def test_params_report_writes_powg_dump(self) -> None:
        (self.artifacts / "params.json").write_text(
            json.dumps({"powg_B": [7, 11], "mode": "test"}), encoding="utf-8"
        )

        report = extract_params(self.workspace)

        self.assertEqual(2, report["powg_B_count"])
        self.assertEqual("0: 7\n1: 11\n", (self.artifacts / "powg_B_dump.txt").read_text(encoding="utf-8"))

    def test_repeated_blocks_are_reported_without_raw_values(self) -> None:
        (self.artifacts / "seed.ct").write_bytes(b"ABCDABCDWXYZ")

        report = detect_repeated_blocks(self.workspace, block_size=4)

        self.assertEqual(3, report["complete_blocks"])
        self.assertEqual(1, len(report["repeated_blocks"]))
        self.assertIn("block_sha256", report["repeated_blocks"][0])

    def test_block_scan_rejects_parent_paths(self) -> None:
        with self.assertRaisesRegex(ReconError, "Unsafe manifest path"):
            detect_repeated_blocks(self.workspace, "../outside.bin")
