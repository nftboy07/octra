"""Score a candidate LPN secret S against published sample files (held-out ready)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from ..lpn import _lpn_dir
from ..sources import ReconError
from ..workspace import write_json

N_DEFAULT = 4096


def parse_s_bits(spec: str | Path, n: int = N_DEFAULT) -> list[int]:
    """
    Parse candidate S from:
      - path to file with hex (512 hex chars for n=4096) or 0/1 bitstring
      - raw hex string
      - 0/1 bitstring
    Returns list of 0/1 length n (little-endian bit order within hex bytes).
    """
    text = str(spec)
    path = Path(text)
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        # allow first non-comment line
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        text = lines[0] if lines else ""

    text = text.replace(" ", "").replace("\n", "").lower()
    if text.startswith("0x"):
        text = text[2:]

    bits: list[int] = []
    if all(c in "01" for c in text) and len(text) >= n:
        bits = [1 if c == "1" else 0 for c in text[:n]]
    elif all(c in "0123456789abcdef" for c in text):
        raw = bytes.fromhex(text)
        # little-endian bits like audit int.from_bytes(..., 'little')
        val = int.from_bytes(raw, "little")
        bits = [(val >> i) & 1 for i in range(n)]
    else:
        raise ReconError("S must be hex or 0/1 bitstring (file or literal)")

    if len(bits) < n:
        raise ReconError(f"S has {len(bits)} bits, need {n}")
    return bits[:n]


def _dot_parity(a_bytes: bytes, s_bits: list[int]) -> int:
    """Parity of <A,S> over GF(2); A little-endian packed bits."""
    n = len(s_bits)
    acc = 0
    for wi in range((n + 63) // 64):
        start = wi * 8
        chunk = a_bytes[start : start + 8]
        if len(chunk) < 8:
            chunk = chunk + b"\x00" * (8 - len(chunk))
        word = int.from_bytes(chunk, "little")
        s_word = 0
        for b in range(64):
            idx = wi * 64 + b
            if idx < n and s_bits[idx]:
                s_word |= 1 << b
        acc ^= word & s_word
    acc ^= acc >> 32
    acc ^= acc >> 16
    acc ^= acc >> 8
    acc ^= acc >> 4
    acc ^= acc >> 2
    acc ^= acc >> 1
    return acc & 1


def score_file(path: Path, s_bits: list[int], max_rows: int | None = None) -> dict[str, Any]:
    n = len(s_bits)
    mismatches = 0
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.readline()  # meta
        for line in handle:
            if max_rows is not None and total >= max_rows:
                break
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            a = bytes.fromhex(row["a"])
            y = int(row["y"])
            pred = _dot_parity(a, s_bits)
            if pred != y:
                mismatches += 1
            total += 1
    rate = (mismatches / total) if total else None
    return {
        "file": path.name,
        "rows": total,
        "mismatches": mismatches,
        "residual_rate": rate,
        "consistent_with_tau_1_8": rate is not None and 0.10 <= rate <= 0.16,
        "looks_random_half": rate is not None and 0.45 <= rate <= 0.55,
    }


def score_candidate_s(
    workspace: Path,
    s_spec: str,
    *,
    holdout: str | None = None,
    max_rows_per_file: int | None = None,
    n: int = N_DEFAULT,
) -> dict[str, Any]:
    """
    Score S on all LPN files. Optional holdout=filename trains interpretation:
      - if holdout set, also report that file separately as test.
    """
    s_bits = parse_s_bits(s_spec, n=n)
    lpn_dir = _lpn_dir(workspace)
    paths = sorted(lpn_dir.glob("*.jsonl"))
    if not paths:
        raise ReconError("no LPN samples")

    per = []
    for path in paths:
        per.append(score_file(path, s_bits, max_rows=max_rows_per_file))

    rates = [p["residual_rate"] for p in per if p["residual_rate"] is not None]
    mean_rate = sum(rates) / len(rates) if rates else None
    holdout_row = None
    train_rates = []
    for p in per:
        if holdout and p["file"] == holdout:
            holdout_row = p
        else:
            if p["residual_rate"] is not None:
                train_rates.append(p["residual_rate"])

    report = {
        "n": n,
        "files_scored": len(per),
        "mean_residual_rate": mean_rate,
        "min_residual_rate": min(rates) if rates else None,
        "max_residual_rate": max(rates) if rates else None,
        "files_near_tau_1_8": sum(1 for p in per if p.get("consistent_with_tau_1_8")),
        "files_near_half": sum(1 for p in per if p.get("looks_random_half")),
        "verdict": _verdict(mean_rate, sum(1 for p in per if p.get("consistent_with_tau_1_8")), len(per)),
        "holdout": holdout_row,
        "train_mean_residual": (sum(train_rates) / len(train_rates)) if train_rates else None,
        "per_file": per,
        "note": (
            "True shared S should yield residual ≈ 1/8 on every file. "
            "Wrong S or separate secrets ≈ 1/2. This does not recover S; it verifies candidates instantly."
        ),
    }
    write_json(workspace / "logs" / "lpn_s_score.json", report)
    return report


def _verdict(mean: float | None, near_tau: int, nfiles: int) -> str:
    if mean is None:
        return "no_data"
    if near_tau >= max(1, nfiles - 2) and mean < 0.20:
        return "LIKELY_TRUE_SHARED_S"
    if mean > 0.40:
        return "LIKELY_WRONG_S"
    return "INCONCLUSIVE"
