"""Read-only LPN sample inventory and hardness estimates for HFHE challenge v2."""

from __future__ import annotations

from collections import Counter
import json
import math
from pathlib import Path
from typing import Any

from .artifacts import SHA256_LINE
from .sources import ReconError
from .workspace import safe_relative_path, sha256_file, write_json


EXPECTED_DOM = "pvac.prf.r.1"
EXPECTED_N = 4096
EXPECTED_T = 16384
EXPECTED_TAU = (1, 8)
EXPECTED_ROW_WORDS = 64
EXPECTED_FILE_COUNT = 44  # 22 ciphers * 2 base layers


def _lpn_dir(workspace: Path) -> Path:
    candidates = [
        workspace / "artifacts" / "lpn_samples",
        workspace / "repos" / "hfhe-challenge" / "lpn_samples",
    ]
    for path in candidates:
        if path.is_dir():
            return path
    raise ReconError(
        "lpn_samples directory not found under artifacts/lpn_samples or "
        "repos/hfhe-challenge/lpn_samples"
    )


def _parse_meta_line(line: str) -> dict[str, Any]:
    try:
        meta = json.loads(line)
    except json.JSONDecodeError as error:
        raise ReconError(f"Invalid LPN meta JSON: {error}") from error
    if not isinstance(meta, dict):
        raise ReconError("LPN meta line must be a JSON object")
    return meta


def _count_sample_rows(path: Path) -> int:
    """Count sample rows (lines after meta). Streams; does not load full file."""
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        first = handle.readline()
        if not first:
            return 0
        for _ in handle:
            count += 1
    return count


def _y_bit_stats(path: Path, max_rows: int | None = None) -> dict[str, Any]:
    """Stream y bits and report empirical noise-related stats (y is A·s ⊕ e)."""
    ones = 0
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.readline()  # meta
        for line in handle:
            if max_rows is not None and total >= max_rows:
                break
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            y = row.get("y")
            if y in (0, 1):
                ones += int(y)
                total += 1
    zeros = total - ones
    return {
        "rows_scanned": total,
        "y_ones": ones,
        "y_zeros": zeros,
        "y_one_fraction": (ones / total) if total else None,
    }


def estimate_lpn_hardness(n: int = EXPECTED_N, tau: float = 0.125) -> dict[str, Any]:
    """
    Ballpark classical hardness notes for LPN(n, tau).

    These are order-of-magnitude references (not tight concrete security claims):
    - BKW-style: roughly n / log2(n) in the exponent for certain regimes
    - ISD / Gauss needing ~n noise-free equations is vastly larger at tau=1/8
    Independent assessments place best known solvers far above 2^128 for n=4096, tau=1/8.
    """
    log2_n = math.log2(n) if n > 1 else 0.0
    bkw_exp = n / log2_n if log2_n else None
    # Information-theoretic: need ~n / (1-h2(tau)) samples roughly; we have many more.
    # Binary entropy of Bernoulli(tau)
    if 0 < tau < 1:
        h2 = -tau * math.log2(tau) - (1 - tau) * math.log2(1 - tau)
    else:
        h2 = None
    return {
        "n": n,
        "tau": tau,
        "notes": [
            "Recovering S from published (A,y) for domain pvac.prf.r.1 is a side target.",
            "Even full recovery of S does not decrypt: mask R = r1*r2*r3 and r2,r3 need sk.prf_k.",
            "Public samples cover only r1 (dom pvac.prf.r.1).",
        ],
        "ballpark": {
            "bkw_style_exponent_log2": bkw_exp,
            "binary_entropy_h2_tau": h2,
            "consensus_floor": ">> 2^128 classical work for n=4096, tau=1/8 (see eienel / smoke-ui)",
        },
        "references": [
            "https://eienel.github.io/hfhe-challenge-eienel/",
            "https://github.com/smoke-ui/octra-hfhe-v2-security-assessment",
            "https://github.com/octra-labs/hfhe-challenge/commit/d9d29d505e2840c0028d7a91a2a8ba59e163b9a4",
        ],
    }


def inventory_lpn_samples(workspace: Path, scan_y_bits: bool = False) -> dict[str, Any]:
    """Inventory all LPN sample files: meta consistency, row counts, uniqueness."""
    lpn_dir = _lpn_dir(workspace)
    files = sorted(lpn_dir.glob("*.jsonl"))
    if not files:
        raise ReconError(f"No .jsonl samples in {lpn_dir}")

    records: list[dict[str, Any]] = []
    seed_tags: list[int] = []
    public_ts: list[str] = []
    issues: list[str] = []

    for path in files:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            meta_line = handle.readline()
        if not meta_line:
            issues.append(f"{path.name}: empty file")
            continue
        meta = _parse_meta_line(meta_line)
        row_count = _count_sample_rows(path)
        size = path.stat().st_size
        digest = sha256_file(path)

        n = meta.get("n")
        t = meta.get("t")
        tau_num = meta.get("tau_num")
        tau_den = meta.get("tau_den")
        dom = meta.get("dom")
        row_words = meta.get("row_words")

        local_issues: list[str] = []
        if dom != EXPECTED_DOM:
            local_issues.append(f"unexpected dom {dom!r}")
        if n != EXPECTED_N:
            local_issues.append(f"unexpected n={n}")
        if t != EXPECTED_T:
            local_issues.append(f"unexpected t={t}")
        if (tau_num, tau_den) != EXPECTED_TAU:
            local_issues.append(f"unexpected tau={tau_num}/{tau_den}")
        if row_words != EXPECTED_ROW_WORDS:
            local_issues.append(f"unexpected row_words={row_words}")
        if row_count != EXPECTED_T and t == EXPECTED_T:
            local_issues.append(f"row_count={row_count} != t={t}")

        seed = meta.get("seed_ztag")
        pub_t = meta.get("public_T_hex")
        if isinstance(seed, int):
            seed_tags.append(seed)
        if isinstance(pub_t, str):
            public_ts.append(pub_t)

        record: dict[str, Any] = {
            "file": path.name,
            "sha256": digest,
            "size_bytes": size,
            "cipher_index": meta.get("cipher_index"),
            "layer_id": meta.get("layer_id"),
            "slot": meta.get("slot"),
            "dom": dom,
            "n": n,
            "t": t,
            "tau": f"{tau_num}/{tau_den}",
            "seed_ztag": seed,
            "nonce_lo_hex": meta.get("nonce_lo_hex"),
            "nonce_hi_hex": meta.get("nonce_hi_hex"),
            "public_T_hex": pub_t,
            "sample_rows": row_count,
            "issues": local_issues,
        }
        if scan_y_bits:
            record["y_stats"] = _y_bit_stats(path)
        records.append(record)
        issues.extend(f"{path.name}: {msg}" for msg in local_issues)

    seed_counts = Counter(seed_tags)
    t_counts = Counter(public_ts)
    duplicate_seeds = [s for s, c in seed_counts.items() if c > 1]
    duplicate_ts = [t for t, c in t_counts.items() if c > 1]

    total_samples = sum(r["sample_rows"] for r in records)
    report: dict[str, Any] = {
        "lpn_dir": str(lpn_dir),
        "file_count": len(records),
        "expected_file_count": EXPECTED_FILE_COUNT,
        "file_count_ok": len(records) == EXPECTED_FILE_COUNT,
        "total_sample_rows": total_samples,
        "unique_seed_ztag": len(seed_counts),
        "unique_public_T": len(t_counts),
        "duplicate_seed_ztag": duplicate_seeds,
        "duplicate_public_T": duplicate_ts,
        "all_seeds_distinct": len(duplicate_seeds) == 0,
        "all_public_T_distinct": len(duplicate_ts) == 0,
        "issues": issues,
        "ok": len(issues) == 0 and len(records) == EXPECTED_FILE_COUNT and not duplicate_seeds,
        "hardness": estimate_lpn_hardness(),
        "decrypt_blocker": {
            "published_domain": EXPECTED_DOM,
            "mask_structure": "R = r1 * r2 * r3",
            "missing_for_decrypt": [
                "sk.prf_k (independent 256-bit secret)",
                "r2 / r3 LPN domains and Toeplitz keys derived from prf_k",
            ],
            "consequence": "Solving S from these samples does not yield a usable mask R.",
        },
        "files": records,
    }
    write_json(workspace / "logs" / "lpn_inventory.json", report)
    return report


def verify_lpn_checksums(workspace: Path) -> dict[str, Any]:
    """
    Verify lpn_samples/* hashes listed in artifacts/SHA256SUMS (or challenge root).
    Does not require compiling the C++ binding tool.
    """
    manifest_candidates = [
        workspace / "artifacts" / "SHA256SUMS",
        workspace / "repos" / "hfhe-challenge" / "SHA256SUMS",
    ]
    manifest = next((p for p in manifest_candidates if p.is_file()), None)
    if manifest is None:
        raise ReconError("SHA256SUMS not found for LPN verification")

    lpn_dir = _lpn_dir(workspace)
    results: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = SHA256_LINE.match(line)
        if not match:
            continue
        expected, filename = match.groups()
        filename = filename.lstrip("*")
        if not filename.startswith("lpn_samples/"):
            continue
        rel = safe_relative_path(filename)
        # Prefer lpn_dir + basename if artifacts/lpn_samples is the root
        target = workspace / "artifacts" / rel
        if not target.is_file():
            target = lpn_dir / Path(filename).name
        if not target.is_file():
            results.append(
                {"file": filename, "expected": expected.lower(), "actual": None, "status": "missing"}
            )
            continue
        actual = sha256_file(target)
        status = "ok" if actual.lower() == expected.lower() else "mismatch"
        results.append(
            {"file": filename, "expected": expected.lower(), "actual": actual, "status": status}
        )

    report: dict[str, Any] = {
        "manifest": str(manifest),
        "checked": len(results),
        "ok": bool(results) and all(r["status"] == "ok" for r in results),
        "files": results,
        "note": (
            "Metadata binding of (seed_ztag, nonce, public_T) to secret.ct requires "
            "source/tools/verify_lpn_sample_binding.cpp against compiled pvac_hfhe_cpp. "
            "This command only verifies published SHA-256 digests."
        ),
    }
    write_json(workspace / "logs" / "lpn_checksum_report.json", report)
    return report


def summarize_lpn(workspace: Path) -> dict[str, Any]:
    """Compact summary: inventory + checksums without optional y-bit scan."""
    inv = inventory_lpn_samples(workspace, scan_y_bits=False)
    sums = verify_lpn_checksums(workspace)
    summary = {
        "inventory_ok": inv["ok"],
        "checksums_ok": sums["ok"],
        "file_count": inv["file_count"],
        "total_sample_rows": inv["total_sample_rows"],
        "all_seeds_distinct": inv["all_seeds_distinct"],
        "hardness_consensus": inv["hardness"]["ballpark"]["consensus_floor"],
        "decrypt_blocker": inv["decrypt_blocker"]["consequence"],
        "reports": {
            "inventory": str(workspace / "logs" / "lpn_inventory.json"),
            "checksums": str(workspace / "logs" / "lpn_checksum_report.json"),
        },
    }
    write_json(workspace / "logs" / "lpn_summary.json", summary)
    return summary
