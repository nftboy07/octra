"""Wallet-gen + artifact RNG static audit (no execution of remote code).

Checks:
  * wallet-gen server.ts uses crypto.randomBytes for entropy
  * strength domain is standard BIP39 bit lengths
  * HMAC key is 'Octra seed' (matches our wallet.py)
  * challenge artifact entropy looks high (not all-zero / low unique bytes)
  * no obvious weak CSPRNG patterns in public TS sources

Does not prove the bounty seed was generated correctly — only that the
published generator path is CSPRNG-shaped.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import math
import re
from pathlib import Path
from typing import Any

from .workspace import write_json

OCTRA_HMAC = "Octra seed"
RANDOM_BYTES_RE = re.compile(r"crypto\.randomBytes\s*\(\s*([^)]+)\)")
MATH_RANDOM_RE = re.compile(r"Math\.random\s*\(")
DATE_NOW_RE = re.compile(r"Date\.now\s*\(")
STRENGTH_RE = re.compile(r"strength\s*[:=]\s*(\d+)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    c = Counter(data)
    return -sum((k / n) * math.log2(k / n) for k in c.values())


def _find_wallet_gen_sources(workspace: Path) -> list[Path]:
    base = workspace.parent
    candidates = [
        base / "repos" / "wallet-gen" / "src" / "server.ts",
        base / "repos" / "intel" / "wallet-gen" / "src" / "server.ts",
        base / "wallet-gen" / "src" / "server.ts",
        workspace / "repos" / "wallet-gen" / "src" / "server.ts",
        # local investigation tree sibling
        Path(__file__).resolve().parents[3] / "wallet-gen" / "src" / "server.ts",
    ]
    out = []
    seen = set()
    for p in candidates:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if key in seen:
            continue
        if p.is_file():
            seen.add(key)
            out.append(p)
    # also rglob once under repos
    for root in (base / "repos", base / "repos" / "intel"):
        if not root.is_dir():
            continue
        for p in root.rglob("server.ts"):
            if "wallet" in str(p).lower() or "wallet-gen" in p.parts:
                try:
                    key = str(p.resolve())
                except OSError:
                    key = str(p)
                if key not in seen and p.is_file():
                    seen.add(key)
                    out.append(p)
    return out


def audit_wallet_gen_source(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    findings: list[dict[str, str]] = []
    rb = RANDOM_BYTES_RE.findall(text)
    has_random_bytes = bool(rb)
    has_math_random = bool(MATH_RANDOM_RE.search(text))
    has_date_now_entropy = bool(DATE_NOW_RE.search(text)) and "randomBytes" not in text
    has_octra_seed = OCTRA_HMAC in text
    has_bip39 = "bip39" in text.lower()
    strength_vals = [int(x) for x in STRENGTH_RE.findall(text) if x.isdigit()]

    if has_random_bytes:
        findings.append({
            "id": "CSPRNG_RANDOM_BYTES",
            "severity": "info",
            "detail": f"crypto.randomBytes used ({len(rb)} call site(s)).",
        })
    else:
        findings.append({
            "id": "NO_RANDOM_BYTES",
            "severity": "high",
            "detail": "No crypto.randomBytes found — investigate entropy source.",
        })
    if has_math_random:
        findings.append({
            "id": "MATH_RANDOM",
            "severity": "critical",
            "detail": "Math.random() present — weak if used for keys.",
        })
    if has_octra_seed:
        findings.append({
            "id": "OCTRA_HMAC_KEY",
            "severity": "info",
            "detail": "HMAC key string 'Octra seed' present (matches bounty path).",
        })
    else:
        findings.append({
            "id": "HMAC_KEY_MISSING",
            "severity": "high",
            "detail": "Did not find 'Octra seed' HMAC label in this file.",
        })
    if has_bip39:
        findings.append({"id": "BIP39_IMPORT", "severity": "info", "detail": "bip39 library referenced."})
    if strength_vals and all(s in (128, 160, 192, 224, 256) for s in strength_vals):
        findings.append({
            "id": "STRENGTH_STANDARD",
            "severity": "info",
            "detail": f"BIP39 strengths mentioned: {sorted(set(strength_vals))}",
        })

    # generateEntropy default 128
    default_128 = "generateEntropy" in text and ("128" in text)
    if default_128:
        findings.append({
            "id": "DEFAULT_128",
            "severity": "info",
            "detail": "Generator path references 128-bit entropy default.",
        })

    ok = has_random_bytes and not has_math_random and has_octra_seed
    return {
        "file": str(path),
        "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        "has_crypto_randomBytes": has_random_bytes,
        "has_Math_random": has_math_random,
        "has_Octra_seed_hmac": has_octra_seed,
        "has_bip39": has_bip39,
        "randomBytes_call_sites": len(rb),
        "strength_literals": sorted(set(strength_vals)),
        "findings": findings,
        "csprng_shaped": ok,
    }


def audit_artifact_entropy(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        return {"file": label, "error": "missing"}
    data = path.read_bytes()
    if not data:
        return {"file": label, "error": "empty"}
    unique = len(set(data))
    H = _shannon(data)
    findings = []
    if unique < 16 and len(data) > 64:
        findings.append({"id": "LOW_UNIQUE_BYTES", "severity": "high", "detail": f"only {unique} distinct bytes"})
    if data == bytes(len(data)):
        findings.append({"id": "ALL_ZERO", "severity": "critical", "detail": "artifact is all zeros"})
    if H < 4.0 and len(data) > 64:
        findings.append({"id": "LOW_SHANNON", "severity": "high", "detail": f"H={H:.3f}"})
    else:
        findings.append({"id": "HIGH_ENTROPY_SHAPE", "severity": "info", "detail": f"H≈{H:.3f}, unique={unique}"})
    return {
        "file": label,
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "unique_bytes": unique,
        "shannon": round(H, 4),
        "findings": findings,
    }


def run_rng_audit(workspace: Path) -> dict[str, Any]:
    sources = _find_wallet_gen_sources(workspace)
    source_reports = [audit_wallet_gen_source(p) for p in sources]

    artifacts = workspace / "artifacts"
    art_reports = []
    for name in ("secret.ct", "pk.bin", "params.json", "pvac_commit.txt"):
        p = artifacts / name
        if p.is_file():
            art_reports.append(audit_artifact_entropy(p, name))
        else:
            alt = workspace / "repos" / "hfhe-challenge" / name
            if alt.is_file():
                art_reports.append(audit_artifact_entropy(alt, name))

    critical = []
    for r in source_reports:
        for f in r.get("findings") or []:
            if f.get("severity") in ("critical", "high"):
                critical.append(f"{r['file']}: {f['id']}")
    for r in art_reports:
        for f in r.get("findings") or []:
            if f.get("severity") in ("critical", "high"):
                critical.append(f"{r.get('file')}: {f['id']}")

    report = {
        "checked_at": _now(),
        "wallet_gen_sources_found": len(sources),
        "wallet_gen": source_reports,
        "artifacts": art_reports,
        "critical_or_high": critical,
        "bounty_seed_note": (
            "Bounty wallet entropy is claimed CSPRNG 128-bit. Public wallet-gen source "
            "uses crypto.randomBytes when present. This audit cannot recover the seed "
            "and does not justify BIP39 brute force."
        ),
        "ok": len(critical) == 0 and (not sources or any(r.get("csprng_shaped") for r in source_reports)),
    }
    write_json(workspace / "logs" / "rng_audit.json", report)

    md = workspace / "reports" / "RNG_AUDIT.md"
    md.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# RNG / wallet-gen audit",
        "",
        f"Generated: {report['checked_at']}",
        f"Sources found: {len(sources)}",
        f"ok: **{report['ok']}**",
        "",
    ]
    for r in source_reports:
        lines.append(f"## `{r['file']}`")
        lines.append(f"- csprng_shaped: **{r.get('csprng_shaped')}**")
        for f in r.get("findings") or []:
            lines.append(f"- {f['id']}: {f['detail']}")
        lines.append("")
    lines.append("## Artifacts")
    for r in art_reports:
        lines.append(f"- {r.get('file')}: H={r.get('shannon')} unique={r.get('unique_bytes')}")
    lines += ["", report["bounty_seed_note"], ""]
    md.write_text("\n".join(lines), encoding="utf-8")
    report["markdown"] = str(md)
    return report


def rng_telegram_blurb(report: dict[str, Any]) -> str | None:
    crit = [c for c in (report.get("critical_or_high") or []) if "CRITICAL" in c.upper() or "MATH_RANDOM" in c or "ALL_ZERO" in c]
    if crit:
        return "RNG ALERT: " + "; ".join(crit)[:350]
    high = report.get("critical_or_high") or []
    if high:
        return "RNG HIGH: " + "; ".join(high)[:350]
    return None
