from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from octra_recon.workspace import WORKSPACE_DIRECTORIES, init_workspace, require_workspace


class WorkspaceTests(unittest.TestCase):
    def test_init_creates_marker_and_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "investigation"

            result = init_workspace(workspace)

            self.assertEqual("ready", result["status"])
            self.assertTrue((workspace / "workspace.json").is_file())
            self.assertTrue(all((workspace / name).is_dir() for name in WORKSPACE_DIRECTORIES))
            self.assertEqual(workspace.resolve(), require_workspace(workspace))
