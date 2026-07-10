"""Declared public source repositories and safe Git synchronization helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import subprocess
from typing import Any


class ReconError(RuntimeError):
    """Raised when a local reconnaissance operation cannot continue."""


@dataclass(frozen=True)
class SourceSpec:
    name: str
    url: str
    revision: str | None = None
    before: str | None = None


SOURCES: tuple[SourceSpec, ...] = (
    SourceSpec(
        name="pvac_hfhe_cpp",
        url="https://github.com/octra-labs/pvac_hfhe_cpp.git",
        revision="071b0e9",
    ),
    SourceSpec(
        name="hfhe-challenge",
        url="https://github.com/octra-labs/hfhe-challenge.git",
        revision="v2_fix",
    ),
    SourceSpec(
        name="wallet-gen",
        url="https://github.com/octra-labs/wallet-gen.git",
    ),
    SourceSpec(
        name="lite_node",
        url="https://github.com/octra-labs/lite_node.git",
    ),
)


def _run_git(args: list[str], cwd: Path | None = None) -> str:
    command = ["git", "-c", "protocol.file.allow=never", *args]
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        details = completed.stderr.strip() or completed.stdout.strip()
        raise ReconError(f"Git command failed: {' '.join(command)}\n{details}")
    return completed.stdout.strip()


def _is_git_repository(path: Path) -> bool:
    return (path / ".git").exists()


def _remote_url(repo: Path) -> str:
    return _run_git(["remote", "get-url", "origin"], repo)


def _default_ref(repo: Path) -> str:
    try:
        return _run_git(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], repo)
    except ReconError:
        branches = _run_git(
            ["for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"], repo
        )
        candidates = [line for line in branches.splitlines() if line != "origin/HEAD"]
        if not candidates:
            raise ReconError(f"No remote branch is available for {repo.name}.")
        return candidates[0]


def _resolve_revision(repo: Path, spec: SourceSpec) -> str:
    if spec.revision:
        try:
            return _run_git(["rev-parse", "--verify", f"{spec.revision}^{{commit}}"], repo)
        except ReconError as error:
            raise ReconError(
                f"Declared revision {spec.revision!r} for {spec.name} cannot be resolved. "
                "The source manifest was not changed automatically."
            ) from error

    default_ref = _default_ref(repo)
    if spec.before:
        try:
            before = datetime.fromisoformat(spec.before.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError as error:
            raise ReconError(f"Invalid before date for {spec.name}: {spec.before}") from error
        commit = _run_git(["rev-list", "-1", f"--before={before.isoformat()}", default_ref], repo)
        if not commit:
            raise ReconError(f"No commit before {spec.before} is available for {spec.name}.")
        return commit
    return _run_git(["rev-parse", "--verify", f"{default_ref}^{{commit}}"], repo)


def _revision_policy(spec: SourceSpec) -> str:
    if spec.revision:
        return spec.revision
    if spec.before:
        return f"before {spec.before}"
    return "default branch"


def sync_sources(workspace: Path) -> dict[str, Any]:
    repos_dir = workspace / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, str]] = []

    for spec in SOURCES:
        repo = repos_dir / spec.name
        if repo.exists() and not _is_git_repository(repo):
            raise ReconError(f"Refusing to overwrite non-Git path: {repo}")
        if not repo.exists():
            _run_git(["clone", "--filter=blob:none", "--no-checkout", spec.url, str(repo)])
        elif _remote_url(repo) != spec.url:
            raise ReconError(f"Origin URL mismatch for {repo}; refusing to fetch a different source.")

        _run_git(["fetch", "--prune", "--tags", "origin"], repo)
        commit = _resolve_revision(repo, spec)
        _run_git(["checkout", "--detach", "--no-recurse-submodules", commit], repo)
        _run_git(["config", "--local", "submodule.recurse", "false"], repo)
        records.append(
            {
                "name": spec.name,
                "url": spec.url,
                "commit": commit,
                "revision_policy": _revision_policy(spec),
            }
        )
    return {"sources": records, "warning": "No cloned source code was executed."}


def source_status(workspace: Path) -> dict[str, Any]:
    records: list[dict[str, str]] = []
    for spec in SOURCES:
        repo = workspace / "repos" / spec.name
        if not _is_git_repository(repo):
            records.append({"name": spec.name, "status": "not cloned"})
            continue
        records.append(
            {
                "name": spec.name,
                "status": "present",
                "commit": _run_git(["rev-parse", "HEAD"], repo),
                "origin": _remote_url(repo),
            }
        )
    return {"sources": records}
