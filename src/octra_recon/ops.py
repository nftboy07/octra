"""24x7 operations: integrity, heartbeat, GitHub poll, candidates, archive."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .lpn import summarize_lpn, verify_lpn_checksums
from .social_watch import social_telegram_messages, social_watch
from .sources import ReconError
from .unlock_scan import scan_challenge_workspace, telegram_blurb
from .wallet import TARGET_ADDRESS, check_mnemonic_against_target
from .workspace import sha256_file, write_json

CORE_ARTIFACTS = (
    "secret.ct",
    "pk.bin",
    "params.json",
    "manifest.json",
    "pvac_commit.txt",
    "SHA256SUMS",
)

GITHUB_REPOS = (
    ("octra-labs", "hfhe-challenge"),
    ("octra-labs", "pvac_hfhe_cpp"),
    ("smoke-ui", "octra-hfhe-v2-security-assessment"),
    ("nftboy07", "octra"),
)

COMMIT_KEYWORDS = ("lpn", "rku", "sample", "sk", "prf", "bounty", "secret", "mask", "recrypt")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _git(args: list[str], cwd: Path | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def integrity_check(workspace: Path) -> dict[str, Any]:
    """Daily integrity: core artifact hashes + LPN checksums + unlock scan."""
    artifacts = workspace / "artifacts"
    core: list[dict[str, Any]] = []
    for name in CORE_ARTIFACTS:
        path = artifacts / name
        if not path.is_file():
            core.append({"file": name, "status": "missing"})
            continue
        core.append(
            {
                "file": name,
                "status": "ok",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    lpn_ok = None
    lpn_error = None
    try:
        lpn = verify_lpn_checksums(workspace)
        lpn_ok = lpn.get("ok")
    except ReconError as error:
        lpn_error = str(error)

    scan = scan_challenge_workspace(workspace)

    # compare secret.ct to known bounty hash if present in SHA256SUMS
    expected_secret = None
    sums = artifacts / "SHA256SUMS"
    if sums.is_file():
        for line in sums.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.endswith("secret.ct"):
                expected_secret = line.split()[0].lower()
                break
    secret_row = next((r for r in core if r["file"] == "secret.ct"), None)
    secret_match = None
    if secret_row and secret_row.get("sha256") and expected_secret:
        secret_match = secret_row["sha256"].lower() == expected_secret

    report = {
        "checked_at": _now(),
        "core": core,
        "secret_ct_matches_manifest": secret_match,
        "lpn_checksums_ok": lpn_ok,
        "lpn_error": lpn_error,
        "unlock_scan": {
            "unlock_signal": scan.get("unlock_signal"),
            "new_file_count": scan.get("new_file_count"),
            "critical_count": sum(t.get("critical_count", 0) for t in scan.get("trees", [])),
        },
        "ok": (
            all(r.get("status") == "ok" for r in core if r["file"] != "SHA256SUMS" or r.get("status") == "ok")
            and (lpn_ok is True or lpn_ok is None)
            and secret_match is not False
        ),
        "telegram": telegram_blurb(scan) if scan.get("unlock_signal") else None,
    }
    # tighten ok
    report["ok"] = all(
        [
            all(r.get("status") == "ok" for r in core),
            lpn_ok is True,
            secret_match is not False,
        ]
    )
    write_json(workspace / "logs" / "integrity_report.json", report)
    return report


def heartbeat(workspace: Path, base: Path | None = None) -> dict[str, Any]:
    base = base or workspace.parent
    repos = {
        "hfhe-challenge": base / "repos" / "hfhe-challenge",
        "pvac_hfhe_cpp": base / "repos" / "pvac_hfhe_cpp",
        "smoke-ui": base / "repos" / "smoke-ui",
        "octra-recon": base / "repos" / "octra-recon",
    }
    heads = {}
    for name, path in repos.items():
        if (path / ".git").exists():
            heads[name] = _git(["log", "-1", "--format=%h %s"], path) or "unknown"
        else:
            heads[name] = "missing"

    disk = shutil.disk_usage(str(base if base.exists() else workspace))
    report = {
        "checked_at": _now(),
        "target": TARGET_ADDRESS,
        "heads": heads,
        "disk": {
            "total_gb": round(disk.total / (1024**3), 2),
            "used_gb": round(disk.used / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
        },
        "message": (
            f"HEARTBEAT alive. challenge={heads.get('hfhe-challenge', '?')[:7]} "
            f"toolkit={heads.get('octra-recon', '?')[:7]} "
            f"disk_free_gb={round(disk.free / (1024**3), 1)}. "
            f"Goal blocked without unlock. hits pending unlock only."
        ),
    }
    write_json(workspace / "logs" / "heartbeat.json", report)
    return report


def github_poll(workspace: Path) -> dict[str, Any]:
    """Poll GitHub commits API (unauthenticated, rate-limited) for keyword alerts."""
    state_path = workspace / "logs" / "github_poll_state.json"
    state: dict[str, Any] = {}
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            state = {}

    alerts: list[dict[str, Any]] = []
    snapshots: dict[str, str] = {}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("OCTRA_GITHUB_TOKEN")

    for owner, repo in GITHUB_REPOS:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=5"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "octra-recon-watchdog/1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            alerts.append({"repo": f"{owner}/{repo}", "error": type(error).__name__})
            continue

        if not isinstance(payload, list) or not payload:
            continue
        latest_sha = payload[0].get("sha", "")
        key = f"{owner}/{repo}"
        snapshots[key] = latest_sha
        prev = (state.get("shas") or {}).get(key)
        if prev and prev != latest_sha:
            for commit in payload:
                sha = commit.get("sha", "")
                if sha == prev:
                    break
                msg = ((commit.get("commit") or {}).get("message") or "").split("\n")[0]
                lower = msg.lower()
                kw = [k for k in COMMIT_KEYWORDS if k in lower]
                alerts.append(
                    {
                        "repo": key,
                        "sha": sha[:10],
                        "message": msg[:160],
                        "keywords": kw,
                        "priority": "high" if kw else "normal",
                    }
                )

    new_state = {"shas": snapshots, "checked_at": _now()}
    write_json(state_path, new_state)
    report = {
        "checked_at": _now(),
        "repos": snapshots,
        "alerts": alerts,
        "alert_count": len([a for a in alerts if "sha" in a]),
        "high_priority": [a for a in alerts if a.get("priority") == "high"],
    }
    write_json(workspace / "logs" / "github_poll.json", report)
    return report


def process_candidates(workspace: Path, target: str = TARGET_ADDRESS) -> dict[str, Any]:
    """Process drop-folder mnemonics/keys; move handled files."""
    drop = workspace / "candidates" / "inbox"
    done = workspace / "candidates" / "processed"
    hits_dir = workspace / "candidates" / "hits"
    drop.mkdir(parents=True, exist_ok=True)
    done.mkdir(parents=True, exist_ok=True)
    hits_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []

    for path in sorted(drop.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        # first non-empty line as mnemonic or ignore comments
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if not lines:
            dest = done / path.name
            path.replace(dest)
            results.append({"file": path.name, "status": "empty"})
            continue
        mnemonic = lines[0]
        try:
            check = check_mnemonic_against_target(mnemonic, target=target)
            entry = {
                "file": path.name,
                "status": "checked",
                "match": check["match"],
                "address": check["address"],
            }
            if check["match"]:
                entry["mnemonic_words"] = check["mnemonic_words"]
                hits.append(entry)
                # preserve hit material privately
                (hits_dir / path.name).write_text(
                    f"# MATCH {target}\n# address {check['address']}\n{mnemonic}\n",
                    encoding="utf-8",
                )
                path.replace(done / path.name)
            else:
                path.replace(done / path.name)
            results.append(entry)
        except ReconError as error:
            path.replace(done / f"error_{path.name}")
            results.append({"file": path.name, "status": "error", "error": str(error)})

    report = {
        "checked_at": _now(),
        "processed": len(results),
        "hits": len(hits),
        "hit_details": hits,
        "results": results,
        "inbox": str(drop),
        "note": "Drop one mnemonic per file in candidates/inbox/. Hits copied to candidates/hits/.",
    }
    write_json(workspace / "logs" / "candidates_report.json", report)
    return report


def create_archive(workspace: Path, base: Path | None = None) -> dict[str, Any]:
    """Monthly-style snapshot of pins, logs, reports (no full LPN blobs)."""
    base = base or workspace.parent
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = base / "archives"
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_path = out_dir / f"octra-investigation-{stamp}.tar.gz"

    include_dirs = [
        workspace / "logs",
        workspace / "reports",
        base / "reports",
    ]
    include_files = [
        workspace / "artifacts" / "SHA256SUMS",
        workspace / "artifacts" / "params.json",
        workspace / "artifacts" / "manifest.json",
        workspace / "artifacts" / "pvac_commit.txt",
        base / "reports" / "OPEN_SURFACE.md",
        base / "reports" / "UNLOCK_RUNBOOK.md",
    ]

    # pin file
    pins = {}
    for name in ("hfhe-challenge", "pvac_hfhe_cpp", "smoke-ui", "octra-recon"):
        repo = base / "repos" / name
        if (repo / ".git").exists():
            pins[name] = _git(["rev-parse", "HEAD"], repo)
    pins_path = workspace / "logs" / f"pins_{stamp}.json"
    write_json(pins_path, {"checked_at": _now(), "pins": pins})

    with tarfile.open(archive_path, "w:gz") as tar:
        for path in include_files:
            if path.is_file():
                tar.add(path, arcname=f"snapshot/{path.name}")
        for directory in include_dirs:
            if directory.is_dir():
                for path in directory.rglob("*"):
                    if path.is_file() and path.stat().st_size < 5_000_000:
                        arc = f"snapshot/{directory.name}/{path.relative_to(directory).as_posix()}"
                        tar.add(path, arcname=arc)
        tar.add(pins_path, arcname="snapshot/pins.json")

    report = {
        "archive": str(archive_path),
        "size_bytes": archive_path.stat().st_size,
        "pins": pins,
        "created_at": _now(),
    }
    write_json(workspace / "logs" / "archive_latest.json", report)
    return report


def full_ops_cycle(workspace: Path, base: Path | None = None) -> dict[str, Any]:
    """One-shot: integrity + unlock scan + github/x social + candidates."""
    base = base or workspace.parent
    integrity = integrity_check(workspace)
    github = github_poll(workspace)
    social = social_watch(workspace)
    candidates = process_candidates(workspace)
    beat = heartbeat(workspace, base=base)
    cycle = {
        "checked_at": _now(),
        "integrity_ok": integrity.get("ok"),
        "unlock_signal": (integrity.get("unlock_scan") or {}).get("unlock_signal"),
        "github_alerts": github.get("alert_count"),
        "github_high": len(github.get("high_priority") or []),
        "social_alerts": social.get("alert_count"),
        "social_critical": social.get("critical_count"),
        "social_high": social.get("high_count"),
        "social_x_mode": social.get("x_mode"),
        "candidate_hits": candidates.get("hits"),
        "heartbeat": beat.get("message"),
        "social_messages": social_telegram_messages(social),
        "details": {
            "integrity": str(workspace / "logs" / "integrity_report.json"),
            "github": str(workspace / "logs" / "github_poll.json"),
            "social": str(workspace / "logs" / "social_watch.json"),
            "candidates": str(workspace / "logs" / "candidates_report.json"),
        },
    }
    write_json(workspace / "logs" / "ops_cycle.json", cycle)
    return cycle
