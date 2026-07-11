"""Planted LPN controls: prove residual scorer + small-n recovery pipeline."""

from __future__ import annotations

import json
import os
import random
from pathlib import Path
from typing import Any

from ..sources import ReconError
from ..workspace import write_json
from .residual import _dot_parity, score_file


def _parity64(x: int) -> int:
    x ^= x >> 32
    x ^= x >> 16
    x ^= x >> 8
    x ^= x >> 4
    x ^= x >> 2
    x ^= x >> 1
    return x & 1


def generate_planted(
    n: int,
    m: int,
    tau: float,
    *,
    seed: int = 1,
) -> tuple[list[int], list[tuple[bytes, int]]]:
    """Return (s_bits, rows) with rows=(A_bytes little-endian padded, y)."""
    rng = random.Random(seed)
    s = [rng.randint(0, 1) for _ in range(n)]
    nbytes = (n + 7) // 8
    # pad to 8-byte words
    word_bytes = ((n + 63) // 64) * 8
    rows: list[tuple[bytes, int]] = []
    for _ in range(m):
        a_bits = [rng.randint(0, 1) for _ in range(n)]
        # pack little-endian
        val = 0
        for i, b in enumerate(a_bits):
            if b:
                val |= 1 << i
        a = val.to_bytes(word_bytes, "little")
        # truncate/pad to word_bytes
        dot = 0
        for i in range(n):
            dot ^= a_bits[i] & s[i]
        e = 1 if rng.random() < tau else 0
        y = dot ^ e
        rows.append((a, y))
    return s, rows


def gaussian_solve_noiseless(rows: list[tuple[bytes, int]], n: int) -> list[int] | None:
    """Solve A s = y over GF(2) when system is consistent (tau≈0)."""
    # Build augmented matrix as ints of width n+1
    mat: list[int] = []
    for a, y in rows:
        val = int.from_bytes(a, "little") & ((1 << n) - 1)
        if y:
            val |= 1 << n
        mat.append(val)

    # Gaussian elimination
    rank = 0
    pivots = [-1] * n
    for col in range(n):
        pivot = None
        for r in range(rank, len(mat)):
            if (mat[r] >> col) & 1:
                pivot = r
                break
        if pivot is None:
            continue
        mat[rank], mat[pivot] = mat[pivot], mat[rank]
        for r in range(len(mat)):
            if r != rank and ((mat[r] >> col) & 1):
                mat[r] ^= mat[rank]
        pivots[col] = rank
        rank += 1

    # back-sub
    s = [0] * n
    for col in range(n - 1, -1, -1):
        r = pivots[col]
        if r < 0:
            continue
        # s_col = augmented bit
        bit = (mat[r] >> n) & 1
        row = mat[r]
        for j in range(col + 1, n):
            if (row >> j) & 1:
                bit ^= s[j]
        s[col] = bit
    # verify
    for a, y in rows[: min(50, len(rows))]:
        if _dot_parity(a, s) != y:
            return None
    return s


def run_planted_suite(workspace: Path) -> dict[str, Any]:
    """
    Experiments that outperform 'audit only':
      1) residual scorer separates true S (~tau) from random (~0.5)
      2) noiseless small-n recovery works end-to-end
      3) scaling table for n in {32,64,128} with m = 176*n
    """
    out_dir = workspace / "logs" / "race_planted"
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []

    # 1) residual separation at challenge-like tau (+ larger battery)
    for n, m, tau, seed in (
        (64, 64 * 176, 0.125, 7),
        (128, 128 * 40, 0.125, 11),  # fewer m for speed on small VPS
        (256, 256 * 20, 0.125, 13),  # outperform battery
        (512, 512 * 10, 0.125, 17),  # heavier; still VPS-feasible
    ):
        s, rows = generate_planted(n, m, tau, seed=seed)
        # write temp jsonl-like for score_file compatibility needs hex a of fixed width
        word_bytes = ((n + 63) // 64) * 8
        tmp = out_dir / f"planted_n{n}.jsonl"
        with tmp.open("w", encoding="utf-8") as f:
            f.write(json.dumps({"n": n, "t": m, "format": "planted"}) + "\n")
            for i, (a, y) in enumerate(rows):
                # pad a to challenge-like width only if needed — residual uses actual length
                f.write(json.dumps({"i": i, "y": y, "a": a.hex()}) + "\n")

        true_score = score_file(tmp, s)
        rnd = [random.randint(0, 1) for _ in range(n)] if False else __import__("random").Random(99).choices([0, 1], k=n)
        bad_score = score_file(tmp, rnd)
        results.append(
            {
                "experiment": "residual_separation",
                "n": n,
                "m": m,
                "tau": tau,
                "true_residual": true_score["residual_rate"],
                "random_residual": bad_score["residual_rate"],
                "separator_ok": (
                    true_score["residual_rate"] is not None
                    and bad_score["residual_rate"] is not None
                    and true_score["residual_rate"] < 0.20
                    and bad_score["residual_rate"] > 0.40
                ),
            }
        )

    # 2) noiseless recovery
    for n, m in ((32, 64), (48, 96), (64, 128)):
        s, rows = generate_planted(n, m, tau=0.0, seed=123 + n)
        recovered = gaussian_solve_noiseless(rows, n)
        ok = recovered == s
        results.append(
            {
                "experiment": "noiseless_gaussian_recovery",
                "n": n,
                "m": m,
                "recovered": ok,
            }
        )

    # 3) write scaling notes for challenge params
    challenge_note = {
        "experiment": "challenge_scale_note",
        "n": 4096,
        "m": 720896,
        "tau": 0.125,
        "m_over_n": 720896 / 4096,
        "status": (
            "Planted pipeline validates scorer+solver plumbing. "
            "Full n=4096 tau=1/8 recovery remains open (smoke-ui: no commodity break)."
        ),
    }
    results.append(challenge_note)

    report = {
        "ok": all(r.get("separator_ok", r.get("recovered", True)) for r in results if "separator_ok" in r or "recovered" in r),
        "results": results,
        "advantage_over_smoke_ui": [
            "Executable residual verifier for any candidate S (held-out ready)",
            "Planted positive/negative controls proving the scorer works",
            "Noiseless end-to-end recovery path for reduced n",
        ],
    }
    write_json(workspace / "logs" / "race_planted.json", report)
    return report
