"""Official challenge day log (lambda0xE / octra public updates).

Tracks day-by-day PASS/FAIL research notes so the lab does not re-chase
closed paths (e.g. Day 3 timing constancy).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .workspace import write_json

# Curated, source-backed day log (extend when new official posts land)
DAY_LOG: list[dict[str, Any]] = [
    {
        "day": 3,
        "date": "2026-07-12",
        "author": "lambda0xE",
        "source": "https://x.com/lambda0xE/status/2076417278543835438",
        "title": "Timing / constancy probes on Apple Silicon",
        "status": "DAY3_PASS",
        "severity": "info",  # info = closed negative; not an unlock
        "unlock_signal": False,
        "summary": (
            "Built pvac on Apple Silicon (-march=armv8-a+crypto). "
            "Benchmarks: prf_R ~15.3 ms; enc_value ~43.4 ms (2 layers / 37 edges). "
            "Constancy (independent keys, 7 runs): skA 44.07 ms vs skB 41.90 ms "
            "statistically equal → no sk-dependent timing branch. "
            "No remote-relevant leak. No exploit path from timing."
        ),
        "numbers": {
            "prf_R_ms": 15.3,
            "enc_value_ms": 43.4,
            "enc_layers": 2,
            "enc_edges": 37,
            "skA_ms": 44.07,
            "skB_ms": 41.90,
            "constancy_runs_each": 7,
        },
        "closed_paths": [
            "sk-dependent timing side channel (Apple Silicon build / this probe)",
            "remote-relevant timing exploit from these constancy results",
        ],
        "next": [
            "Day 4–5 algebraic / reduced-params notes",
            "Day 7 freeze if nothing simplifies",
        ],
        "lab_action": (
            "Do NOT spend VPS time on timing attacks against public package. "
            "Keep unlock sensors + wire/mask/LPN/lexicon. Watch Day 4–5 algebra posts."
        ),
    },
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def challenge_day_status(workspace: Path | None = None) -> dict[str, Any]:
    """Emit day log + latest status for dashboard / TG / surface."""
    latest = DAY_LOG[-1] if DAY_LOG else None
    report = {
        "checked_at": _now(),
        "day_count": len(DAY_LOG),
        "latest": latest,
        "days": DAY_LOG,
        "bounty_impact": {
            "decrypt_path_opened": False,
            "timing_side_channel": "closed_for_day3_probe",
            "still_blocked_by": [
                "dual independent masks R0,R1",
                "no Rku in public package",
                "LPN only pvac.prf.r.1; S alone ≠ R",
                "BIP39 128-bit CSPRNG seed",
            ],
        },
        "note": (
            "Official day log is passive intel. DAY3_PASS means their timing probes "
            "found nothing exploitable — not that the bounty was solved."
        ),
    }
    if workspace is not None:
        write_json(workspace / "logs" / "challenge_days.json", report)
        md = workspace / "reports" / "CHALLENGE_DAYS.md"
        md.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Challenge day log",
            "",
            f"Generated: {report['checked_at']}",
            "",
        ]
        for d in DAY_LOG:
            lines += [
                f"## Day {d['day']} — {d['status']}",
                "",
                f"- date: {d.get('date')}",
                f"- author: {d.get('author')}",
                f"- source: {d.get('source')}",
                f"- title: {d.get('title')}",
                f"- unlock_signal: **{d.get('unlock_signal')}**",
                "",
                d.get("summary", ""),
                "",
                "**Closed paths:**",
                "",
                *[f"- {c}" for c in (d.get("closed_paths") or [])],
                "",
                "**Next:**",
                "",
                *[f"- {n}" for n in (d.get("next") or [])],
                "",
                f"**Lab action:** {d.get('lab_action')}",
                "",
            ]
        md.write_text("\n".join(lines), encoding="utf-8")
        report["markdown"] = str(md)
    return report


def day_telegram_blurb(report: dict[str, Any] | None = None) -> str:
    latest = (report or {}).get("latest") or (DAY_LOG[-1] if DAY_LOG else None)
    if not latest:
        return "DAY LOG empty"
    return (
        f"DAY {latest['day']} {latest['status']}: {latest.get('title')}\n"
        f"unlock={latest.get('unlock_signal')}\n"
        f"{(latest.get('summary') or '')[:280]}\n"
        f"lab: {latest.get('lab_action')}"
    )[:900]
