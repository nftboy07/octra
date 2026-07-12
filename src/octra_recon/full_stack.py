"""Run every implementable public-surface check in one shot."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .claim import claim_pipeline, claim_telegram_blurb
from .github_lexicon import lexicon_telegram_blurb, run_github_lexicon
from .hypotheses import run_hypotheses
from .mask_diff import mask_diff_telegram_blurb, run_mask_diff
from .race.suite import run_race_suite
from .rng_audit import rng_telegram_blurb, run_rng_audit
from .surface import open_surface_status
from .wire_audit import run_wire_audit, wire_telegram_blurb
from .workspace import write_json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_full_stack(
    workspace: Path,
    *,
    include_lexicon: bool = True,
    lexicon_max: int = 2000,
    include_race: bool = True,
    skip_full_audit: bool = True,
) -> dict[str, Any]:
    """
    Everything we can run on public data without claiming a 2^128 break.

    Order: unlock/claim → wire → mask → rng → hypotheses → lexicon (bounded)
           → race suite (optional) → surface brief.
    """
    parts: dict[str, Any] = {}
    alerts: list[str] = []

    parts["claim"] = claim_pipeline(workspace)
    blurb = claim_telegram_blurb(parts["claim"])
    if blurb:
        alerts.append(blurb)

    parts["wire"] = run_wire_audit(workspace)
    blurb = wire_telegram_blurb(parts["wire"])
    if blurb:
        alerts.append(blurb)

    parts["mask_diff"] = run_mask_diff(workspace)
    blurb = mask_diff_telegram_blurb(parts["mask_diff"])
    if blurb:
        alerts.append(blurb)

    parts["rng"] = run_rng_audit(workspace)
    blurb = rng_telegram_blurb(parts["rng"])
    if blurb:
        alerts.append(blurb)

    parts["hypotheses"] = run_hypotheses(workspace, include_file_hashes=True)
    if parts["hypotheses"].get("hits"):
        alerts.append(f"HYPOTHESES HIT count={parts['hypotheses']['hits']}")

    if include_lexicon:
        parts["lexicon"] = run_github_lexicon(
            workspace,
            base=workspace.parent,
            max_candidates=lexicon_max,
            deep=False,
            skip_tested=True,
        )
        blurb = lexicon_telegram_blurb(parts["lexicon"])
        if blurb:
            alerts.append(blurb)

    if include_race:
        parts["race"] = run_race_suite(workspace, skip_full_audit=skip_full_audit)

    parts["surface"] = open_surface_status(workspace)

    claim_ready = bool(parts["claim"].get("claim_ready"))
    s_hits = len(parts["claim"].get("s_hits") or [])
    unlock = bool((parts["mask_diff"].get("unlock") or {}).get("unlock_signal"))

    report = {
        "checked_at": _now(),
        "claim_ready": claim_ready,
        "s_hits": s_hits,
        "unlock_signal": unlock,
        "wire_parse_ok": (parts.get("wire") or {}).get("summary", {}).get("parse_ok"),
        "rng_ok": (parts.get("rng") or {}).get("ok"),
        "alerts": alerts,
        "parts_keys": sorted(parts.keys()),
        "parts": {
            # keep nested summaries small in top-level log
            "claim": {
                "claim_ready": parts["claim"].get("claim_ready"),
                "critical": parts["claim"].get("critical"),
                "s_hits": parts["claim"].get("s_hits"),
                "mnemonic_hits": parts["claim"].get("mnemonic_hits"),
            },
            "wire_summary": (parts.get("wire") or {}).get("summary"),
            "mask_status": (parts.get("mask_diff") or {}).get("status"),
            "rng_ok": (parts.get("rng") or {}).get("ok"),
            "hypotheses_hits": (parts.get("hypotheses") or {}).get("hits"),
            "lexicon_hits": (parts.get("lexicon") or {}).get("hits") if include_lexicon else None,
            "race_scorecard": ((parts.get("race") or {}).get("scorecard_vs_smoke_ui") if include_race else None),
        },
        "logs": {
            "wire": str(workspace / "logs" / "wire_audit.json"),
            "mask": str(workspace / "logs" / "mask_diff.json"),
            "rng": str(workspace / "logs" / "rng_audit.json"),
            "claim": str(workspace / "logs" / "claim_pipeline.json"),
            "full": str(workspace / "logs" / "full_stack.json"),
        },
        "note": (
            "Full public-surface stack. No module claims a 2^128 LPN/BIP39 break. "
            "Decrypt still requires unlock material (Rku/sk/prf) or a true structural bug."
        ),
    }
    # store full parts separately (large)
    write_json(workspace / "logs" / "full_stack_parts.json", {k: _slim(v) for k, v in parts.items()})
    write_json(workspace / "logs" / "full_stack.json", report)

    md = workspace / "reports" / "FULL_STACK.md"
    md.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Full stack run",
        "",
        f"Generated: {report['checked_at']}",
        "",
        f"- claim_ready: **{claim_ready}**",
        f"- s_hits: **{s_hits}**",
        f"- unlock_signal: **{unlock}**",
        f"- wire_parse_ok: **{report['wire_parse_ok']}**",
        f"- rng_ok: **{report['rng_ok']}**",
        "",
        "## Alerts",
        "",
    ]
    if alerts:
        lines.extend(f"- {a}" for a in alerts)
    else:
        lines.append("- (none — sensors only; bounty still blocked)")
    lines += [
        "",
        "## Commands",
        "",
        "```bash",
        "octra-recon stack run --workspace $W",
        "octra-recon wire audit --workspace $W",
        "octra-recon mask diff --workspace $W",
        "octra-recon rng audit --workspace $W",
        "```",
        "",
    ]
    md.write_text("\n".join(lines), encoding="utf-8")
    report["markdown"] = str(md)
    return report


def _slim(obj: Any, depth: int = 0) -> Any:
    """Avoid multi-MB full_stack_parts from embedding every cipher edge."""
    if depth > 4:
        return "..."
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("ciphers", "edges", "layers", "pc_full", "results", "keys") and depth > 0:
                if isinstance(v, list):
                    out[k] = f"<{len(v)} items>"
                else:
                    out[k] = "<omitted>"
            else:
                out[k] = _slim(v, depth + 1)
        return out
    if isinstance(obj, list):
        if len(obj) > 40:
            return [_slim(x, depth + 1) for x in obj[:20]] + [f"... +{len(obj)-20} more"]
        return [_slim(x, depth + 1) for x in obj]
    return obj


def full_stack_telegram_blurb(report: dict[str, Any]) -> str | None:
    alerts = report.get("alerts") or []
    if report.get("claim_ready"):
        return "STACK CRITICAL: claim_ready — mnemonic hit"
    if alerts:
        return "STACK: " + alerts[0][:400]
    return (
        f"STACK ok wire={report.get('wire_parse_ok')} rng={report.get('rng_ok')} "
        f"unlock={report.get('unlock_signal')} s_hits={report.get('s_hits')} claim=0"
    )
