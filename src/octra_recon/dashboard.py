"""Generate a local HTML status dashboard (no network server required)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def build_dashboard(workspace: Path) -> dict[str, str]:
    logs = workspace / "logs"
    items = {
        "integrity": _load(logs / "integrity_report.json"),
        "lpn_audit": _load(logs / "lpn_deep_audit_summary.json"),
        "race": _load(logs / "race_suite.json"),
        "claim": _load(logs / "claim_pipeline.json"),
        "social": _load(logs / "social_watch.json"),
        "body_bind": _load(logs / "race_body_bind.json"),
        "heartbeat": _load(logs / "heartbeat.json"),
    }
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    def row(name: str, ok: Any, detail: str) -> str:
        color = "#1a7f37" if ok else ("#cf222e" if ok is False else "#9a6700")
        label = "OK" if ok is True else ("FAIL" if ok is False else "n/a")
        return f"<tr><td><b>{name}</b></td><td style='color:{color}'>{label}</td><td><code>{detail}</code></td></tr>"

    rows = []
    integ = items["integrity"] or {}
    rows.append(row("integrity", integ.get("ok"), f"lpn={integ.get('lpn_checksums_ok')}"))
    audit = items["lpn_audit"] or {}
    rows.append(row("lpn_deep_audit", audit.get("ok"), f"rows={audit.get('rows')}"))
    race = items["race"] or {}
    sc = (race.get("scorecard_vs_smoke_ui") or {}) if race else {}
    rows.append(row("race_suite", sc.get("planted_controls"), f"body={sc.get('equation_body_commitment')}"))
    claim = items["claim"] or {}
    rows.append(row("claim_ready", claim.get("claim_ready"), f"critical={len(claim.get('critical') or [])}"))
    body = items["body_bind"] or {}
    rows.append(row("body_bind", body.get("ok"), (body.get("root_body_commitment") or "")[:16] + "…"))
    social = items["social"] or {}
    rows.append(row("social", None, f"alerts={social.get('alert_count')} x={social.get('x_mode')}"))

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Octra Race Dashboard</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#0d1117;color:#e6edf3}}
table{{border-collapse:collapse;width:100%;max-width:960px}}
td,th{{border:1px solid #30363d;padding:.5rem .75rem;text-align:left}}
th{{background:#161b22}}
code{{font-size:12px;color:#79c0ff}}
h1{{font-size:1.4rem}}
.meta{{color:#8b949e;margin-bottom:1rem}}
a{{color:#58a6ff}}
</style></head><body>
<h1>Octra HFHE Race Dashboard</h1>
<p class="meta">Generated {now} · workspace {workspace}</p>
<p class="meta">Target wallet: <code>octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ</code></p>
<table>
<tr><th>Component</th><th>Status</th><th>Detail</th></tr>
{''.join(rows)}
</table>
<p class="meta">Open this file locally. Do not expose publicly (may summarize paths).</p>
</body></html>
"""
    out = workspace / "reports" / "dashboard.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return {"dashboard": str(out), "generated_at": now}
