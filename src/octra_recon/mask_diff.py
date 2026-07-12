"""Dual-mask differential checklist + automatic invariant probes.

Documents the wrapped text model:
  N0 = R0 * (v + m)
  N1 = R1 * (-m)
  v  = N0/R0 + N1/R1

Public wire has neither R0 nor R1 nor m. This module:
  * records what would break if each asset appeared
  * probes LPN domain coverage (r.1 only)
  * flags any new public material that changes the composition
  * produces a claim-race decision matrix
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .lpn import inventory_lpn_samples
from .sources import ReconError
from .unlock_scan import scan_challenge_workspace
from .workspace import write_json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def dual_mask_model() -> dict[str, Any]:
    return {
        "encoding": "pvac-text-wrapped",
        "equations": [
            "N0 = R0 * (v + m)",
            "N1 = R1 * (-m)",
            "v  = N0/R0 + N1/R1",
        ],
        "public_observables": [
            "edge aggregates related to N_l (masked)",
            "layer seeds/nonces (public)",
            "Pedersen PC commitments (hiding)",
            "LPN samples for domain pvac.prf.r.1 only",
        ],
        "secrets_required": [
            {"id": "R0", "role": "layer-0 mask", "public": False},
            {"id": "R1", "role": "layer-1 mask", "public": False},
            {"id": "m", "role": "plaintext blinding", "public": False},
            {"id": "S", "role": "LPN secret (r.1 path)", "public": "only via hard LPN"},
            {"id": "prf_k", "role": "PRF AES/Toeplitz key", "public": False},
            {"id": "r2_r3", "role": "other PRF domains for full R", "public": False},
            {"id": "Rku", "role": "FURY-class prf_k recovery", "public": False},
        ],
        "closed_attacks": [
            "R_com offline candidate check (v2 removed)",
            "single-mask cancel (independent R0,R1)",
            "S alone → R (needs prf_k for r2/r3/Toeplitz)",
            "FURY without Rku",
            "BIP39 2^128 brute force",
        ],
    }


def _lpn_domain_probe(workspace: Path) -> dict[str, Any]:
    try:
        inv = inventory_lpn_samples(workspace)
    except ReconError as err:
        return {"ok": False, "error": str(err)}
    domains = set()
    files = inv.get("files") or inv.get("samples") or []
    # inventory shape may vary
    if isinstance(files, list):
        for f in files:
            if isinstance(f, dict):
                dom = f.get("dom") or f.get("domain")
                if dom:
                    domains.add(dom)
    # fallback: scan filenames
    lpn_dir = workspace / "artifacts" / "lpn_samples"
    if not lpn_dir.is_dir():
        lpn_dir = workspace / "repos" / "hfhe-challenge" / "lpn_samples"
    name_domains = set()
    if lpn_dir.is_dir():
        for p in lpn_dir.glob("*.jsonl"):
            # ctXX_lY_s0_pvac_prf_r_1.jsonl
            if "pvac_prf_r_1" in p.name or "pvac.prf.r.1" in p.name:
                name_domains.add("pvac.prf.r.1")
            if "pvac_prf_r_2" in p.name:
                name_domains.add("pvac.prf.r.2")
            if "pvac_prf_r_3" in p.name:
                name_domains.add("pvac.prf.r.3")
    all_doms = sorted(domains | name_domains)
    return {
        "ok": True,
        "domains_seen": all_doms,
        "only_r1": all_doms == ["pvac.prf.r.1"] or (len(all_doms) == 1 and "r.1" in all_doms[0]),
        "missing_for_full_R": [d for d in ("pvac.prf.r.2", "pvac.prf.r.3") if d not in all_doms],
        "file_count": inv.get("file_count") or inv.get("count"),
        "inventory_ok": inv.get("ok"),
    }


def decision_matrix(unlock_signal: bool, has_rku: bool, has_sk: bool, has_r2: bool, s_hit: bool) -> list[dict[str, str]]:
    rows = []
    if has_rku:
        rows.append({"if": "Rku present", "then": "FURY-class prf_k research NOW", "priority": "P0"})
    if has_sk:
        rows.append({"if": "sk.bin present", "then": "deserialize sk → S + prf_k → decrypt path", "priority": "P0"})
    if has_r2:
        rows.append({"if": "r2/r3 LPN samples", "then": "extend residual S scoring to new domains", "priority": "P0"})
    if s_hit:
        rows.append({"if": "TRUE S candidate", "then": "preserve S; still need prf_k for R", "priority": "P1"})
    if unlock_signal:
        rows.append({"if": "unlock_signal", "then": "unlock scan + claim pipeline", "priority": "P0"})
    if not rows:
        rows.append({
            "if": "public package only",
            "then": "sensors only; no decrypt path",
            "priority": "P3",
        })
    return rows


def run_mask_diff(workspace: Path) -> dict[str, Any]:
    unlock = {}
    try:
        unlock = scan_challenge_workspace(workspace)
    except ReconError as err:
        unlock = {"error": str(err), "unlock_signal": False}

    # scan tree names for rku/sk
    trees = unlock.get("trees") or []
    names = []
    for t in trees:
        for h in t.get("hits") or []:
            names.append(str(h.get("path") or h.get("reason") or "").lower())
    blob = " ".join(names)
    has_rku = "rku" in blob or "recrypt" in blob
    has_sk = any(x in blob for x in ("sk.bin", "seckey", "secret_key", "/sk.", "\\sk."))
    lpn = _lpn_domain_probe(workspace)
    has_r2 = bool(lpn.get("missing_for_full_R") == []) or ("pvac.prf.r.2" in (lpn.get("domains_seen") or []))

    # S hits from claim log if present
    s_hit = False
    claim_path = workspace / "logs" / "claim_pipeline.json"
    if claim_path.is_file():
        try:
            claim = json.loads(claim_path.read_text(encoding="utf-8"))
            s_hit = bool(claim.get("s_hits"))
        except json.JSONDecodeError:
            pass

    report = {
        "checked_at": _now(),
        "model": dual_mask_model(),
        "lpn_domains": lpn,
        "unlock": {
            "unlock_signal": unlock.get("unlock_signal"),
            "new_file_count": unlock.get("new_file_count"),
            "has_rku_hint": has_rku,
            "has_sk_hint": has_sk,
        },
        "what_breaks_if": {
            "R0_or_R1_leaked": "single layer opens; dual still needs both for clean v, but one may shrink space",
            "both_R0_R1": "immediate plaintext recovery via v = N0/R0 + N1/R1",
            "m_leaked": "still need R masks unless combined algebraically",
            "S_only": "does NOT decrypt; need prf_k for full R composition",
            "prf_k_only": "can rebuild PRF streams if seeds known; still need S for LPN side",
            "Rku": "FURY may recover prf_k depending on PRF path at pin",
            "sk_bin": "full decrypt possible",
            "second_ct_same_key": "potential multi-CT algebra / related-key research",
        },
        "decision_matrix": decision_matrix(
            bool(unlock.get("unlock_signal")),
            has_rku,
            has_sk,
            has_r2,
            s_hit,
        ),
        "status": "blocked_public_only" if not unlock.get("unlock_signal") else "unlock_attention",
        "note": (
            "No public linear cancel of dual masks is known. This report re-validates domain "
            "coverage and unlock hints each run for claim-race speed."
        ),
    }
    write_json(workspace / "logs" / "mask_diff.json", report)

    md = workspace / "reports" / "MASK_DIFF.md"
    md.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Dual-mask differential",
        "",
        f"Generated: {report['checked_at']}",
        "",
        f"Status: **{report['status']}**",
        "",
        "## Model",
        "",
        "```",
        *report["model"]["equations"],
        "```",
        "",
        "## LPN domains",
        "",
        f"- seen: `{lpn.get('domains_seen')}`",
        f"- missing for full R: `{lpn.get('missing_for_full_R')}`",
        "",
        "## Decision matrix",
        "",
    ]
    for row in report["decision_matrix"]:
        lines.append(f"- **{row['priority']}** if {row['if']} → {row['then']}")
    lines += ["", report["note"], ""]
    md.write_text("\n".join(lines), encoding="utf-8")
    report["markdown"] = str(md)
    return report


def mask_diff_telegram_blurb(report: dict[str, Any]) -> str | None:
    if report.get("status") == "unlock_attention":
        return "MASK/UNLOCK: unlock_signal set — run claim + inspect Rku/sk NOW"
    u = report.get("unlock") or {}
    if u.get("has_rku_hint") or u.get("has_sk_hint"):
        return "MASK/UNLOCK: Rku/sk name hint in scan — inspect immediately"
    return None
