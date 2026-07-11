"""Scan challenge trees for unlock-relevant artifacts (Rku, sk, new bins, keywords)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .sources import ReconError
from .workspace import sha256_file, write_json

# Filenames / path fragments that raise unlock priority
UNLOCK_NAME_PATTERNS = (
    re.compile(r"rku", re.I),
    re.compile(r"recrypt", re.I),
    re.compile(r"(^|[/\\])sk(\.|_|$)", re.I),
    re.compile(r"seckey|secret[_-]?key|master[_-]?key", re.I),
    re.compile(r"prf[_-]?k", re.I),
    re.compile(r"bootstrapp", re.I),
    re.compile(r"mnemonic|seed\.txt|wallet", re.I),
)

UNLOCK_EXTENSIONS = {".bin", ".ct", ".json", ".jsonl", ".hex", ".key", ".pem", ".txt", ".dat"}

# Substrings in file *content* (small files only)
CONTENT_NEEDLES = (
    b"Rku",
    b"rku",
    b"make_rku",
    b"prf_k",
    b"OCTRA-HFHE",
    b"mnemonic",
)


@dataclass(frozen=True)
class ScanHit:
    path: str
    reason: str
    size: int
    sha256: str | None
    severity: str  # critical | high | info


def _iter_files(root: Path, max_files: int = 50_000) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*"):
        if count >= max_files:
            break
        rel = path.relative_to(root)
        if ".git" in rel.parts:
            continue
        if not path.is_file() or path.is_symlink():
            continue
        count += 1
        yield path


def _name_reasons(rel: str) -> list[str]:
    reasons: list[str] = []
    for pat in UNLOCK_NAME_PATTERNS:
        if pat.search(rel):
            reasons.append(f"name_match:{pat.pattern}")
    return reasons


def _content_scan(path: Path, max_bytes: int = 256_000) -> list[str]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size == 0 or size > max_bytes:
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    hits: list[str] = []
    for needle in CONTENT_NEEDLES:
        if needle in data:
            hits.append(f"content:{needle.decode('latin-1')}")
    return hits


def scan_tree(root: Path, label: str = "tree") -> dict[str, Any]:
    if not root.is_dir():
        raise ReconError(f"Scan root missing: {root}")

    hits: list[dict[str, Any]] = []
    inventory: list[dict[str, Any]] = []
    for path in sorted(_iter_files(root)):
        rel = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            continue
        digest = None
        # hash only modest files or unlock-named ones
        name_hits = _name_reasons(rel)
        content_hits: list[str] = []
        if name_hits or path.suffix.lower() in UNLOCK_EXTENSIONS:
            if size <= 8 * 1024 * 1024:
                try:
                    digest = sha256_file(path)
                except OSError:
                    digest = None
            if size <= 256_000:
                content_hits = _content_scan(path)

        reasons = name_hits + content_hits
        inventory.append({"path": rel, "size": size, "sha256": digest})

        # known public bounty names are not unlock signals by themselves
        base_name = Path(rel).name
        expected_names = {
            "secret.ct",
            "pk.bin",
            "params.json",
            "manifest.json",
            "SHA256SUMS",
            "pvac_commit.txt",
            "README.md",
        }
        if not reasons:
            if (
                path.suffix.lower() in {".bin", ".ct", ".key"}
                and size > 0
                and base_name not in expected_names
                and "lpn_samples/" not in rel
            ):
                reasons = ["unexpected_binary_artifact"]
            else:
                continue

        severity = "info"
        joined = " ".join(reasons).lower()
        if any(k in joined for k in ("rku", "seckey", "prf_k", "prf-k", "secret_key", "master_key")):
            severity = "critical"
        elif "sk" in joined and "lpn_samples" not in rel:
            # avoid flagging unrelated paths; name patterns already filtered
            if "name_match" in joined:
                severity = "critical"
        elif "unexpected_binary" in joined or "recrypt" in joined:
            severity = "high"

        hits.append(
            {
                "path": rel,
                "reasons": reasons,
                "size": size,
                "sha256": digest,
                "severity": severity,
                "tree": label,
            }
        )

    critical = [h for h in hits if h["severity"] == "critical"]
    high = [h for h in hits if h["severity"] == "high"]
    return {
        "root": str(root),
        "label": label,
        "file_count": len(inventory),
        "hit_count": len(hits),
        "critical_count": len(critical),
        "high_count": len(high),
        "unlock_signal": len(critical) > 0 or any(
            "rku" in " ".join(h["reasons"]).lower() for h in hits
        ),
        "hits": hits,
        "critical_hits": critical,
        "high_hits": high,
    }


def scan_challenge_workspace(workspace: Path) -> dict[str, Any]:
    """Scan challenge repo + artifacts for unlock material."""
    roots: list[tuple[str, Path]] = []
    challenge = workspace / "repos" / "hfhe-challenge"
    artifacts = workspace / "artifacts"
    if challenge.is_dir():
        roots.append(("hfhe-challenge", challenge))
    if artifacts.is_dir():
        roots.append(("artifacts", artifacts))

    # also absolute common VPS layout
    for label, path in (
        ("vps-challenge", Path("/home/ubuntu/octra_investigation/repos/hfhe-challenge")),
    ):
        if path.is_dir() and not any(p == path for _, p in roots):
            roots.append((label, path))

    if not roots:
        raise ReconError("No challenge/artifacts paths found to scan.")

    reports = []
    any_signal = False
    for label, root in roots:
        rep = scan_tree(root, label=label)
        reports.append(rep)
        any_signal = any_signal or bool(rep.get("unlock_signal"))

    # baseline expected files (not unlock by themselves)
    expected = {
        "secret.ct",
        "pk.bin",
        "params.json",
        "manifest.json",
        "SHA256SUMS",
        "pvac_commit.txt",
        "README.md",
    }
    # flag NEW non-lpn files vs previous snapshot
    state_path = workspace / "logs" / "unlock_file_index.json"
    previous: dict[str, Any] = {}
    if state_path.is_file():
        try:
            previous = json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous = {}

    current_index: dict[str, str] = {}
    new_files: list[str] = []
    for rep in reports:
        root = Path(rep["root"])
        for path in _iter_files(root):
            rel = f"{rep['label']}:{path.relative_to(root).as_posix()}"
            try:
                current_index[rel] = f"{path.stat().st_size}"
            except OSError:
                continue
            if previous and rel not in previous.get("files", {}):
                # ignore pure lpn sample churn unless brand new dir
                if "lpn_samples/" in rel and rel.endswith(".jsonl"):
                    if "lpn_samples" in str(previous.get("files", {})):
                        continue
                new_files.append(rel)

    write_json(state_path, {"files": current_index})

    summary = {
        "unlock_signal": any_signal or bool(new_files),
        "new_files": new_files[:100],
        "new_file_count": len(new_files),
        "trees": reports,
        "expected_public_core": sorted(expected),
        "guidance": [
            "critical: possible Rku/sk/prf material — run UNLOCK_RUNBOOK immediately",
            "high: new binary artifacts — inspect and re-hash",
            "If only lpn_samples changed: re-run lpn summary + binding",
            "If Rku present: FURY-class research may apply (confirm PRF path at pin)",
        ],
    }
    write_json(workspace / "logs" / "unlock_scan.json", summary)
    return summary


def telegram_blurb(summary: dict[str, Any]) -> str:
    parts = [
        f"UNLOCK SCAN: signal={summary.get('unlock_signal')}",
        f"new_files={summary.get('new_file_count', 0)}",
    ]
    crit = []
    for tree in summary.get("trees", []):
        for h in tree.get("critical_hits", [])[:5]:
            crit.append(h.get("path", "?"))
    if crit:
        parts.append("CRITICAL: " + ", ".join(crit)[:200])
    news = summary.get("new_files") or []
    if news:
        parts.append("NEW: " + ", ".join(news[:8])[:220])
    return " | ".join(parts)[:900]
