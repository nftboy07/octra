"""Auto-digest competitor research repos (smoke-ui, etc.) — no human paste required."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .workspace import write_json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _git(args: list[str], cwd: Path) -> str:
    r = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return (r.stdout or "").strip()


def _extract_result_lines(text: str, limit: int = 12) -> list[str]:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if any(
            k in low
            for k in (
                "result",
                "no demonstrated",
                "no practical",
                "no tested",
                "null",
                "surviving signal",
                "does not",
                "finding",
                "verdict",
                "blocked",
                "recover",
                "plaintext",
                "prf_k",
                "möbius",
                "mobius",
                "lpn",
            )
        ):
            # strip markdown noise
            line = re.sub(r"^#+\s*", "", line)
            line = re.sub(r"\*+", "", line)
            lines.append(line[:220])
        if len(lines) >= limit:
            break
    return lines


def digest_repo(repo: Path, name: str, state: dict[str, Any]) -> dict[str, Any] | None:
    """If HEAD advanced, build digest of new commits + key research md files."""
    if not (repo / ".git").exists():
        return None
    head = _git(["rev-parse", "HEAD"], repo)
    prev = (state.get("heads") or {}).get(name)
    if not head:
        return None
    if prev == head:
        return None

    # commits since prev
    if prev:
        log = _git(["log", "--oneline", f"{prev}..{head}"], repo)
    else:
        log = _git(["log", "-3", "--oneline"], repo)

    subjects = [ln for ln in log.splitlines() if ln.strip()][:8]
    research_hits: list[dict[str, str]] = []
    research_dir = repo / "research"
    if research_dir.is_dir():
        # newest research md by mtime among changed files if possible
        changed = _git(["diff", "--name-only", f"{prev}..{head}"], repo) if prev else ""
        files = [x for x in changed.splitlines() if x.startswith("research/") and x.endswith(".md")]
        if not files:
            files = sorted(
                [str(p.relative_to(repo)) for p in research_dir.glob("*.md")],
                key=lambda p: (repo / p).stat().st_mtime,
                reverse=True,
            )[:2]
        for rel in files[:4]:
            path = repo / rel
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")[:8000]
            research_hits.append(
                {
                    "file": rel,
                    "highlights": " | ".join(_extract_result_lines(text, limit=6)),
                }
            )

    # README result line
    readme_note = ""
    readme = repo / "README.md"
    if readme.is_file():
        for ln in readme.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
            if "result" in ln.lower() or "no public" in ln.lower() or "not broken" in ln.lower():
                readme_note = ln.strip()[:200]
                break

    digest = {
        "name": name,
        "prev": prev,
        "head": head,
        "commits": subjects,
        "research": research_hits,
        "readme_note": readme_note,
        "checked_at": _now(),
        "bounty_path_changed": _bounty_changed(subjects, research_hits),
    }
    return digest


def _bounty_changed(commits: list[str], research: list[dict[str, str]]) -> bool:
    blob = " ".join(commits).lower() + " " + " ".join(r.get("highlights", "") for r in research).lower()
    # positive break language
    positives = ("recovered", "plaintext found", "mnemonic", "private key", "broke the", "successful recovery")
    if any(p in blob for p in positives) and "no " not in blob[:80]:
        # crude; prefer explicit no-
        if "no demonstrated" in blob or "no practical" in blob or "no tested" in blob:
            return False
        return True
    return False


def digest_all(workspace: Path, base: Path | None = None) -> dict[str, Any]:
    base = base or workspace.parent
    state_path = workspace / "logs" / "intel_digest_state.json"
    state: dict[str, Any] = {}
    if state_path.is_file():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            state = {}

    repos = {
        "smoke-ui": base / "repos" / "smoke-ui",
        "intel-smoke-ui": base / "repos" / "intel" / "smoke-ui",
        "hfhe-challenge": base / "repos" / "hfhe-challenge",
        "pvac_hfhe_cpp": base / "repos" / "pvac_hfhe_cpp",
    }

    digests = []
    heads = dict(state.get("heads") or {})
    for name, path in repos.items():
        d = digest_repo(path, name, state)
        if d:
            digests.append(d)
            heads[name] = d["head"]
        elif path.is_dir() and (path / ".git").exists():
            heads[name] = _git(["rev-parse", "HEAD"], path)

    write_json(state_path, {"heads": heads, "checked_at": _now()})

    report = {
        "checked_at": _now(),
        "new_digests": digests,
        "count": len(digests),
        "any_bounty_path_change": any(d.get("bounty_path_changed") for d in digests),
    }
    write_json(workspace / "logs" / "intel_digest.json", report)

    # human log
    if digests:
        md_lines = [f"# Intel digest {_now()}", ""]
        for d in digests:
            md_lines.append(f"## {d['name']} `{d.get('prev','?')[:7]}` → `{d['head'][:7]}`")
            for c in d.get("commits") or []:
                md_lines.append(f"- commit: {c}")
            for r in d.get("research") or []:
                md_lines.append(f"- research `{r['file']}`: {r.get('highlights','')[:300]}")
            if d.get("readme_note"):
                md_lines.append(f"- readme: {d['readme_note']}")
            md_lines.append(f"- bounty_path_changed: **{d.get('bounty_path_changed')}**")
            md_lines.append("")
        out = workspace / "logs" / "intel_digest_latest.md"
        out.write_text("\n".join(md_lines), encoding="utf-8")
        report["markdown"] = str(out)

    return report


def telegram_messages(report: dict[str, Any], max_n: int = 4) -> list[str]:
    msgs = []
    for d in report.get("new_digests") or []:
        name = d.get("name")
        # skip noisy self-mirror if named nftboy
        if "nftboy" in name:
            continue
        commits = d.get("commits") or []
        subj = commits[0] if commits else d.get("head", "")[:10]
        highlights = ""
        if d.get("research"):
            highlights = (d["research"][0].get("highlights") or "")[:180]
        flag = "BREAK?" if d.get("bounty_path_changed") else "null/no-break"
        msg = (
            f"INTEL DIGEST [{flag}] {name} {d.get('prev','')[:7]}->{d.get('head','')[:7]} | "
            f"{subj[:100]} | {highlights}"
        )
        msgs.append(" ".join(msg.split())[:900])
        if len(msgs) >= max_n:
            break
    return msgs
