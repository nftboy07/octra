"""Claim-first pipeline: react in order when unlock material or candidates appear."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .race.residual import score_candidate_s
from .sources import ReconError
from .unlock_scan import scan_challenge_workspace
from .wallet import TARGET_ADDRESS, check_mnemonic_against_target
from .workspace import write_json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def claim_pipeline(workspace: Path, target: str = TARGET_ADDRESS) -> dict[str, Any]:
    """
    One-shot claim race:
      1) unlock scan (Rku/sk/new bins)
      2) score all S candidates in s_inbox (with rotating holdout)
      3) check all mnemonics in candidates/inbox
      4) emit ordered next actions
    """
    steps: list[dict[str, Any]] = []
    critical: list[str] = []

    try:
        unlock = scan_challenge_workspace(workspace)
        steps.append({
            "step": "unlock_scan",
            "unlock_signal": unlock.get("unlock_signal"),
            "new_file_count": unlock.get("new_file_count"),
        })
        if unlock.get("unlock_signal"):
            critical.append("UNLOCK_SIGNAL: inspect new Rku/sk/bin files immediately")
    except ReconError as error:
        unlock = {"unlock_signal": False}
        steps.append({"step": "unlock_scan", "error": str(error)})

    # S candidates
    s_inbox = workspace / "candidates" / "s_inbox"
    s_inbox.mkdir(parents=True, exist_ok=True)
    s_hits = []
    holdout = _rotating_holdout(workspace)
    for path in sorted(s_inbox.glob("*")):
        if not path.is_file() or path.name.startswith("."):
            continue
        try:
            # holdout only if file exists in samples
            score = score_candidate_s(workspace, str(path), holdout=holdout)
            entry = {"file": path.name, "verdict": score.get("verdict"), "mean": score.get("mean_residual_rate"), "holdout": holdout}
            if score.get("verdict") == "LIKELY_TRUE_SHARED_S":
                s_hits.append(entry)
                critical.append(f"TRUE_S_CANDIDATE: {path.name}")
                dest = workspace / "candidates" / "hits" / f"S_{path.name}"
                dest.write_text(path.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
            steps.append({"step": "score_s", **entry})
        except ReconError as error:
            steps.append({"step": "score_s", "file": path.name, "error": str(error)})

    # mnemonics
    inbox = workspace / "candidates" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    m_hits = []
    for path in sorted(inbox.glob("*")):
        if not path.is_file() or path.name.startswith("."):
            continue
        lines = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
                 if ln.strip() and not ln.startswith("#")]
        if not lines:
            continue
        try:
            check = check_mnemonic_against_target(lines[0], target=target)
            entry = {"file": path.name, "match": check["match"], "address": check["address"]}
            if check["match"]:
                m_hits.append(entry)
                critical.append(f"WALLET_MATCH: {path.name} -> {check['address']}")
                (workspace / "candidates" / "hits" / path.name).write_text(
                    f"# MATCH {target}\n{lines[0]}\n", encoding="utf-8"
                )
            steps.append({"step": "wallet_check", **entry})
        except ReconError as error:
            steps.append({"step": "wallet_check", "file": path.name, "error": str(error)})

    actions = []
    if any("WALLET_MATCH" in c for c in critical):
        actions = [
            "1. Offline re-run: octra-recon wallet check --mnemonic \"...\"",
            "2. Use Octra web client with recovered instructions",
            "3. Contact dev@octra.org for second 500k",
            "4. DO NOT post mnemonic publicly",
        ]
    elif any("TRUE_S" in c for c in critical):
        actions = [
            "1. Preserve S bits offline",
            "2. Composition still needs prf_k / R — do not claim wallet yet",
            "3. Race: search for Rku/prf material; publish residual tables",
        ]
    elif unlock.get("unlock_signal"):
        actions = [
            "1. ls new files under hfhe-challenge",
            "2. octra-recon unlock scan",
            "3. If Rku: FURY-class research; if sk: deserialize attempt",
        ]
    else:
        actions = ["No claim material. Keep sensors online."]

    report = {
        "checked_at": _now(),
        "target": target,
        "critical": critical,
        "s_hits": s_hits,
        "mnemonic_hits": m_hits,
        "holdout_file": holdout,
        "next_actions": actions,
        "steps": steps,
        "claim_ready": bool(m_hits),
    }
    write_json(workspace / "logs" / "claim_pipeline.json", report)
    return report


def _rotating_holdout(workspace: Path) -> str:
    """Deterministic daily holdout among 44 files for scientific scoring."""
    day = datetime.now(timezone.utc).timetuple().tm_yday
    # ctXX_lY pattern
    ct = day % 22
    layer = (day // 22) % 2
    return f"ct{ct:02d}_l{layer}_s0_pvac_prf_r_1.jsonl"


def claim_telegram_blurb(report: dict[str, Any]) -> str | None:
    if report.get("claim_ready"):
        return f"CLAIM READY: mnemonic hit x{len(report.get('mnemonic_hits') or [])}. Follow runbook NOW."
    if report.get("s_hits"):
        return f"RACE S HIT: {len(report['s_hits'])} candidate(s) LIKELY_TRUE_SHARED_S. prf_k still needed."
    if report.get("critical"):
        return "CLAIM PIPELINE: " + "; ".join(report["critical"])[:400]
    return None
