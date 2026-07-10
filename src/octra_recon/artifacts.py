"""Read-only artifact integrity and metadata checks."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .sources import ReconError
from .workspace import safe_relative_path, sha256_file, write_json


SHA256_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+)$")


def verify_checksums(workspace: Path, manifest_name: str = "SHA256SUMS") -> dict[str, Any]:
    artifacts = workspace / "artifacts"
    manifest = artifacts / manifest_name
    if not manifest.is_file():
        raise ReconError(f"Checksum manifest is missing: {manifest}")
    results: list[dict[str, str | None]] = []
    for line_number, raw_line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = SHA256_LINE.match(line)
        if not match:
            raise ReconError(f"Invalid checksum manifest line {line_number}: {raw_line.rstrip()}")
        expected, filename = match.groups()
        target = artifacts / safe_relative_path(filename)
        if target.is_symlink():
            raise ReconError(f"Refusing to hash symlinked artifact: {filename}")
        if not target.is_file():
            actual = None
            status = "missing"
        else:
            actual = sha256_file(target)
            status = "ok" if actual.lower() == expected.lower() else "mismatch"
        results.append({"file": filename, "expected": expected.lower(), "actual": actual, "status": status})
    report: dict[str, Any] = {
        "manifest": manifest_name,
        "files": results,
        "ok": all(row["status"] == "ok" for row in results),
    }
    write_json(workspace / "logs" / "checksum_report.json", report)
    return report


def extract_params(workspace: Path, name: str = "params.json") -> dict[str, Any]:
    source = workspace / "artifacts" / safe_relative_path(name)
    if not source.is_file() or source.is_symlink():
        raise ReconError(f"Parameters file is missing or unsafe: {source}")
    try:
        params = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ReconError(f"Invalid JSON in {source}: {error}") from error
    if not isinstance(params, dict):
        raise ReconError(f"Parameters file must contain a JSON object: {source}")
    powg_b = params.get("powg_B")
    report: dict[str, Any] = {"file": name, "keys": sorted(params), "powg_B_count": None}
    if isinstance(powg_b, list):
        dump = workspace / "artifacts" / "powg_B_dump.txt"
        dump.write_text("".join(f"{index}: {value}\n" for index, value in enumerate(powg_b)), encoding="utf-8")
        report["powg_B_count"] = len(powg_b)
        report["powg_B_dump"] = str(dump)
    write_json(workspace / "logs" / "params_report.json", report)
    return report


def detect_repeated_blocks(workspace: Path, name: str = "seed.ct", block_size: int = 16) -> dict[str, Any]:
    if block_size < 1 or block_size > 1024 * 1024:
        raise ReconError("Block size must be between 1 and 1048576 bytes.")
    source = workspace / "artifacts" / safe_relative_path(name)
    if not source.is_file() or source.is_symlink():
        raise ReconError(f"Artifact is missing or unsafe: {source}")
    data = source.read_bytes()
    blocks = [data[index : index + block_size] for index in range(0, len(data) - block_size + 1, block_size)]
    hashes = Counter(hashlib.sha256(block).hexdigest() for block in blocks)
    duplicates = [
        {"block_sha256": block_hash, "count": count}
        for block_hash, count in sorted(hashes.items())
        if count > 1
    ]
    report: dict[str, Any] = {
        "file": name,
        "block_size": block_size,
        "complete_blocks": len(blocks),
        "trailing_bytes": len(data) % block_size,
        "repeated_blocks": duplicates,
        "warning": "This is a generic block-duplicate heuristic, not a protocol-aware nonce parser.",
    }
    write_json(workspace / "logs" / "block_duplicate_report.json", report)
    return report
