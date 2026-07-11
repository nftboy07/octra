"""Deep LPN sample audit at smoke-ui parity (structural + practical notes).

Matches the public findings style of:
  smoke-ui/octra-hfhe-v2-security-assessment tools/lpn-samples-audit

Does NOT claim equation-body cryptographic binding (official verifier is metadata-only).
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from .artifacts import SHA256_LINE
from .lpn import EXPECTED_DOM, EXPECTED_FILE_COUNT, EXPECTED_N, EXPECTED_T, EXPECTED_TAU, _lpn_dir
from .sources import ReconError
from .workspace import sha256_file, write_json

VERSION = "octra-recon-lpn-audit/1"
ROWS_PER_FILE = EXPECTED_T  # 16384
N = EXPECTED_N  # 4096
FILES = EXPECTED_FILE_COUNT  # 44
TOTAL_ROWS = FILES * ROWS_PER_FILE  # 720896
# Committed smoke-ui aggregates (must match if same bytes)
SMOKE_UI_A_ONES = 1_476_351_832
SMOKE_UI_Y_ONES = 360_224

META_KEYS = {
    "format",
    "cipher_index",
    "layer_id",
    "slot",
    "dom",
    "n",
    "t",
    "tau_num",
    "tau_den",
    "row_words",
    "seed_ztag",
    "nonce_lo_hex",
    "nonce_hi_hex",
    "public_T_hex",
}
ROW_KEYS = {"i", "y", "a"}
NAME_RE = re.compile(r"ct(\d{2})_l([01])_s(0)_pvac_prf_r_1\.jsonl")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEXROW = re.compile(r"^[0-9a-f]{1024}$")  # 4096 bits = 512 bytes = 1024 hex chars


def _z_balance(ones: int, bits: int) -> float:
    return (ones - bits / 2) / math.sqrt(bits / 4)


def _add_rank(pivots: dict[int, int], v: int) -> None:
    """GF(2) row-reduction pivot insert (same idea as smoke-ui audit)."""
    while v:
        p = v.bit_length() - 1
        old = pivots.get(p)
        if old is None:
            pivots[p] = v
            return
        v ^= old


def _parse_manifest(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = SHA256_LINE.match(line)
        if not m:
            continue
        digest, filename = m.groups()
        filename = filename.lstrip("*")
        if filename.startswith("lpn_samples/") and filename.endswith(".jsonl"):
            out[filename] = digest.lower()
    if len(out) != FILES:
        raise ReconError(f"SHA256SUMS has {len(out)} lpn_samples entries, expected {FILES}")
    return out


def _find_manifest(workspace: Path) -> Path:
    for candidate in (
        workspace / "artifacts" / "SHA256SUMS",
        workspace / "repos" / "hfhe-challenge" / "SHA256SUMS",
        Path("/home/ubuntu/octra_investigation/repos/hfhe-challenge/SHA256SUMS"),
    ):
        if candidate.is_file():
            return candidate
    raise ReconError("SHA256SUMS not found for LPN audit")


def deep_audit(workspace: Path, *, max_files: int | None = None) -> dict[str, Any]:
    """
    Full structural audit of all (or first max_files) LPN JSONL samples.

    Produces smoke-ui–comparable summary: checksums, schema, ranks, exact
    duplicate counts (SQLite BLOB equality), bit balance, metadata uniqueness,
    and interpretation caveats.
    """
    lpn_dir = _lpn_dir(workspace)
    manifest_path = _find_manifest(workspace)
    manifest = _parse_manifest(manifest_path)
    paths = sorted(lpn_dir.glob("*.jsonl"))
    if max_files is not None:
        paths = paths[:max_files]
    if max_files is None and len(paths) != FILES:
        raise ReconError(f"expected {FILES} jsonl files, found {len(paths)}")

    expected_coords = {(ct, layer, 0) for ct in range(22) for layer in range(2)}
    coords: set[tuple[int, int, int]] = set()
    metas: set[tuple[Any, ...]] = set()
    metadata_out: list[dict[str, Any]] = []
    per_file: list[dict[str, Any]] = []
    issues: list[str] = []

    total_a_ones = 0
    total_y_ones = 0
    dup_a = 0
    dup_ay = 0
    checksum_ok = 0

    with tempfile.TemporaryDirectory(prefix="octra-lpn-audit-") as tmp:
        db_path = Path(tmp) / "seen.sqlite"
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute(
            "CREATE TABLE seen(a BLOB PRIMARY KEY, y0 INTEGER NOT NULL, y1 INTEGER NOT NULL)"
        )

        for path in paths:
            rel = f"lpn_samples/{path.name}"
            digest = sha256_file(path)
            if rel in manifest:
                if digest == manifest[rel]:
                    checksum_ok += 1
                else:
                    issues.append(f"checksum mismatch: {path.name}")
            else:
                issues.append(f"not in SHA256SUMS: {path.name}")

            nm = NAME_RE.fullmatch(path.name)
            if not nm:
                issues.append(f"invalid filename: {path.name}")
                continue
            coord = (int(nm.group(1)), int(nm.group(2)), int(nm.group(3)))
            coords.add(coord)

            pivots_a: dict[int, int] = {}
            pivots_ay: dict[int, int] = {}
            aones = 0
            yones = 0
            count = 0

            with path.open("r", encoding="utf-8", errors="strict", newline="") as handle:
                try:
                    meta_line = next(handle)
                    meta = json.loads(meta_line)
                except (StopIteration, json.JSONDecodeError) as error:
                    issues.append(f"bad metadata: {path.name}: {error}")
                    continue

                if set(meta.keys()) != META_KEYS:
                    issues.append(f"metadata schema: {path.name}")
                fixed = {
                    "format": "octra-bounty-target-seed-lpn-ay-v1",
                    "dom": EXPECTED_DOM,
                    "n": N,
                    "t": ROWS_PER_FILE,
                    "tau_num": EXPECTED_TAU[0],
                    "tau_den": EXPECTED_TAU[1],
                    "row_words": 64,
                }
                for key, value in fixed.items():
                    if meta.get(key) != value:
                        issues.append(f"metadata constant {key}: {path.name}")

                if (
                    meta.get("cipher_index"),
                    meta.get("layer_id"),
                    meta.get("slot"),
                ) != coord:
                    issues.append(f"filename-coordinate mismatch: {path.name}")

                mt = (
                    meta.get("seed_ztag"),
                    meta.get("nonce_lo_hex"),
                    meta.get("nonce_hi_hex"),
                    meta.get("public_T_hex"),
                )
                if mt in metas:
                    issues.append(f"duplicate metadata tuple: {path.name}")
                metas.add(mt)
                metadata_out.append(
                    {
                        "file": path.name,
                        "cipher_index": coord[0],
                        "layer_id": coord[1],
                        "slot": coord[2],
                        "seed_ztag": meta.get("seed_ztag"),
                        "nonce_lo_hex": meta.get("nonce_lo_hex"),
                        "nonce_hi_hex": meta.get("nonce_hi_hex"),
                        "public_T_hex": meta.get("public_T_hex"),
                        "sha256": digest,
                    }
                )

                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        issues.append(f"row JSON: {path.name}:{count}")
                        count += 1
                        continue
                    if set(row.keys()) != ROW_KEYS:
                        issues.append(f"row schema: {path.name}:{count}")
                    if row.get("i") != count:
                        issues.append(f"row index: {path.name}:{count}")
                    y = row.get("y")
                    a_hex = row.get("a")
                    if y not in (0, 1) or not isinstance(a_hex, str) or not HEXROW.fullmatch(a_hex):
                        issues.append(f"row fields: {path.name}:{count}")
                        count += 1
                        continue
                    a = bytes.fromhex(a_hex)
                    av = int.from_bytes(a, "little")
                    _add_rank(pivots_a, av)
                    _add_rank(pivots_ay, av | (int(y) << N))
                    aones += av.bit_count()
                    yones += int(y)

                    cur = conn.execute("SELECT y0, y1 FROM seen WHERE a=?", (a,)).fetchone()
                    if cur is None:
                        conn.execute(
                            "INSERT INTO seen VALUES(?,?,?)",
                            (a, int(y == 0), int(y == 1)),
                        )
                    else:
                        dup_a += 1
                        if cur[y]:
                            dup_ay += 1
                        else:
                            conn.execute(
                                "UPDATE seen SET y0=?, y1=? WHERE a=?",
                                (int(cur[0] or y == 0), int(cur[1] or y == 1), a),
                            )
                    count += 1

            if count != ROWS_PER_FILE and max_files is None:
                issues.append(f"row count {count} != {ROWS_PER_FILE}: {path.name}")

            rank_a = len(pivots_a)
            rank_ay = len(pivots_ay)
            if rank_a != N:
                issues.append(f"rank_A={rank_a} != {N}: {path.name}")
            if rank_ay != N + 1:
                issues.append(f"rank_Augmented={rank_ay} != {N+1}: {path.name}")

            total_a_ones += aones
            total_y_ones += yones
            per_file.append(
                {
                    "file": path.name,
                    "rows": count,
                    "rank_A": rank_a,
                    "rank_Augmented": rank_ay,
                    "A_ones": aones,
                    "y_ones": yones,
                }
            )
            conn.commit()

        conn.close()

    abits = sum(p["rows"] for p in per_file) * N
    rows_total = sum(p["rows"] for p in per_file)
    summary = {
        "files": len(per_file),
        "rows": rows_total,
        "A_bits": abits,
        "A_ones": total_a_ones,
        "A_one_fraction": (total_a_ones / abits) if abits else None,
        "A_balance_z": _z_balance(total_a_ones, abits) if abits else None,
        "y_ones": total_y_ones,
        "y_one_fraction": (total_y_ones / rows_total) if rows_total else None,
        "y_balance_z": _z_balance(total_y_ones, rows_total) if rows_total else None,
        "duplicate_A_rows_exact": dup_a,
        "duplicate_A_y_rows_exact": dup_ay,
        "metadata_tuples_unique": len(metas),
        "rank_A_min": min((p["rank_A"] for p in per_file), default=None),
        "rank_A_max": max((p["rank_A"] for p in per_file), default=None),
        "rank_Augmented_min": min((p["rank_Augmented"] for p in per_file), default=None),
        "rank_Augmented_max": max((p["rank_Augmented"] for p in per_file), default=None),
        "checksums_verified": checksum_ok,
        "checksums_expected": FILES if max_files is None else len(paths),
    }

    full = max_files is None
    smoke_parity = None
    if full:
        smoke_parity = {
            "matches_smoke_ui_A_ones": total_a_ones == SMOKE_UI_A_ONES,
            "matches_smoke_ui_Y_ones": total_y_ones == SMOKE_UI_Y_ONES,
            "smoke_ui_A_ones": SMOKE_UI_A_ONES,
            "smoke_ui_Y_ones": SMOKE_UI_Y_ONES,
            "our_A_ones": total_a_ones,
            "our_Y_ones": total_y_ones,
            "duplicate_A_is_zero": dup_a == 0,
            "duplicate_Ay_is_zero": dup_ay == 0,
            "all_ranks_full": (
                summary["rank_A_min"] == N
                and summary["rank_A_max"] == N
                and summary["rank_Augmented_min"] == N + 1
                and summary["rank_Augmented_max"] == N + 1
            ),
            "all_metadata_unique": len(metas) == FILES,
            "coords_complete": coords == expected_coords,
        }

    practical = {
        "shared_S_source_model": (
            "PVAC keygen samples one dense lpn_s_bits; all 44 files should be one secret "
            "under publisher/source model (not algebraically proven from bodies alone)."
        ),
        "samples_per_secret_bit": (rows_total / N) if N else None,
        "commodity_break_demonstrated": False,
        "bkw_note": (
            "720k shared samples improve over single file but plain BKW stages drive bias "
            "to 1/2 before dimension is practical; coded-BKW not demonstrated."
        ),
        "isd_note": (
            "Naive clean-subset ~2^918 trials/file; dense random-code ISD remains impractical."
        ),
        "decrypt_blocker": (
            "Recovering S does not yield prf_k / r2 / r3 / full mask R = r1*r2*r3; "
            "does not decrypt secret.ct."
        ),
        "verifier_scope": (
            "Official verify_lpn_sample_binding only checks first-line metadata set membership; "
            "does not authenticate equation bodies."
        ),
        "reference": (
            "https://github.com/smoke-ui/octra-hfhe-v2-security-assessment "
            "research/OCTRA_LPN_PRACTICAL_ASSESSMENT.md (d95dda5)"
        ),
    }

    ok = (
        len(issues) == 0
        and (not full or (smoke_parity and all(
            [
                smoke_parity["matches_smoke_ui_A_ones"],
                smoke_parity["matches_smoke_ui_Y_ones"],
                smoke_parity["duplicate_A_is_zero"],
                smoke_parity["all_ranks_full"],
                smoke_parity["all_metadata_unique"],
                smoke_parity["coords_complete"],
                summary["checksums_verified"] == FILES,
            ]
        )))
    )

    report: dict[str, Any] = {
        "schema_version": 1,
        "analysis": "octra-recon-lpn-deep-audit",
        "analyzer_version": VERSION,
        "parity_target": "smoke-ui lpn-samples-audit/1",
        "lpn_dir": str(lpn_dir),
        "manifest": str(manifest_path),
        "ok": ok,
        "issues": issues,
        "summary": summary,
        "per_file": per_file,
        "metadata": metadata_out,
        "smoke_ui_parity": smoke_parity,
        "interpretation": {
            "repository_bytes_authenticated_via_sha256sums": True,
            "metadata_set_membership_bound": True,
            "equation_bodies_bound_by_official_verifier": False,
        },
        "duplicate_method": (
            "exact SQLite BLOB equality over complete 512-byte A rows; "
            "(A,y) equality after exact A match"
        ),
        "practical": practical,
        "level_achieved": {
            "checksum_all_44": summary["checksums_verified"] == (FILES if full else len(paths)),
            "schema_validation": True,
            "gf2_rank_A_and_augmented": True,
            "exact_global_duplicate_scan": True,
            "bit_balance_z_scores": True,
            "metadata_uniqueness": True,
            "smoke_ui_aggregate_match": bool(smoke_parity and smoke_parity["matches_smoke_ui_A_ones"]),
            "practical_negative_result_documented": True,
            "bounty_still_blocked_without_prf_k": True,
        },
    }
    write_json(workspace / "logs" / "lpn_deep_audit.json", report)
    # compact for TG / console
    compact = {
        "ok": ok,
        "files": summary["files"],
        "rows": summary["rows"],
        "checksums_verified": summary["checksums_verified"],
        "dup_A": dup_a,
        "rank_A_min": summary["rank_A_min"],
        "rank_Augmented_min": summary["rank_Augmented_min"],
        "smoke_ui_parity": smoke_parity,
        "issues_count": len(issues),
        "issues_head": issues[:10],
        "practical_break": False,
        "decrypt_blocker": practical["decrypt_blocker"],
        "report": str(workspace / "logs" / "lpn_deep_audit.json"),
        "level_achieved": report["level_achieved"],
    }
    write_json(workspace / "logs" / "lpn_deep_audit_summary.json", compact)
    return compact
