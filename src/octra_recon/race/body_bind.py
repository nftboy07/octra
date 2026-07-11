"""Equation-body binding: hash every row body (smoke-ui noted official tool skips this)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..lpn import _lpn_dir
from ..sources import ReconError
from ..workspace import write_json


def hash_file_bodies(path: Path) -> dict[str, Any]:
    """Stream all sample rows; commit to SHA-256 of canonical body stream."""
    h = hashlib.sha256()
    count = 0
    y_ones = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        meta = handle.readline()
        h.update(b"META:")
        h.update(meta.encode("utf-8"))
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            # canonical body bytes: i|y|a
            body = f"{row.get('i')}|{row.get('y')}|{row.get('a')}".encode("ascii")
            h.update(body)
            count += 1
            y_ones += int(row.get("y") or 0)
    return {
        "file": path.name,
        "rows": count,
        "body_sha256": h.hexdigest(),
        "y_ones": y_ones,
    }


def body_binding_audit(workspace: Path) -> dict[str, Any]:
    """
    Produce per-file body commitments + root hash over all files.
    Outperforms official metadata-only verifier for integrity of equation bodies.
    """
    lpn_dir = _lpn_dir(workspace)
    paths = sorted(lpn_dir.glob("*.jsonl"))
    if not paths:
        raise ReconError("no LPN samples")

    per = [hash_file_bodies(p) for p in paths]
    root = hashlib.sha256()
    for row in per:
        root.update(row["body_sha256"].encode("ascii"))
        root.update(b"|")
    report = {
        "ok": len(per) == 44 and all(r["rows"] == 16384 for r in per),
        "files": len(per),
        "root_body_commitment": root.hexdigest(),
        "per_file": per,
        "advantage": (
            "Official verify_lpn_sample_binding does not hash/authenticate equation bodies. "
            "This commitment detects any row-body mutation even if metadata headers stay valid."
        ),
        "note": "Does not prove bodies came from sk; proves byte integrity of published bodies.",
    }
    write_json(workspace / "logs" / "race_body_bind.json", report)
    return {
        "ok": report["ok"],
        "files": report["files"],
        "root_body_commitment": report["root_body_commitment"],
        "advantage": report["advantage"],
        "report": str(workspace / "logs" / "race_body_bind.json"),
    }
