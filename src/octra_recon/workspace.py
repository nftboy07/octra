"""Workspace creation and static local evidence utilities."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from .sources import ReconError


WORKSPACE_FILE = "workspace.json"
WORKSPACE_DIRECTORIES = ("repos", "artifacts", "logs", "notes", "timeline", "reports")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ReconError(f"Invalid JSON in {path}: {error}") from error


def init_workspace(path: Path) -> dict[str, str]:
    path = path.resolve()
    path.mkdir(parents=True, exist_ok=True)
    for directory in WORKSPACE_DIRECTORIES:
        (path / directory).mkdir(exist_ok=True)
    marker = path / WORKSPACE_FILE
    if not marker.exists():
        write_json(
            marker,
            {
                "created_at": _now(),
                "format": 1,
                "purpose": "non-executing Octra source and artifact reconnaissance",
            },
        )
    return {"workspace": str(path), "status": "ready"}


def require_workspace(path: Path) -> Path:
    path = path.resolve()
    if not (path / WORKSPACE_FILE).is_file():
        raise ReconError(f"{path} is not an initialized workspace. Run 'octra-recon init' first.")
    return path


def safe_relative_path(value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ReconError(f"Unsafe manifest path: {value!r}")
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_sources(workspace: Path) -> dict[str, Any]:
    repos_dir = workspace / "repos"
    if not repos_dir.is_dir():
        raise ReconError(f"Repository directory is missing: {repos_dir}")
    files: list[dict[str, Any]] = []
    for path in sorted(repos_dir.rglob("*")):
        relative = path.relative_to(repos_dir)
        if not path.is_file() or path.is_symlink() or ".git" in relative.parts:
            continue
        files.append(
            {
                "path": relative.as_posix(),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    return {"file_count": len(files), "files": files}
