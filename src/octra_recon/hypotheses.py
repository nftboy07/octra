"""Small, logged hypothesis set for wallet entropy (not 2^128 brute force)."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Iterable

from .sources import ReconError
from .wallet import (
    TARGET_ADDRESS,
    address_from_entropy,
    check_mnemonic_against_target,
    mnemonic_from_entropy,
)
from .workspace import write_json


HypothesisFn = Callable[[], Iterable[tuple[str, bytes | str]]]


def _entropy_candidates() -> list[tuple[str, bytes]]:
    """Deterministic low-entropy / public-string derived 128-bit candidates."""
    strings = [
        b"",
        b"octra",
        b"OCTRA",
        b"hfhe",
        b"HFHE",
        b"hfhe-challenge",
        b"octra-labs",
        b"lambda0xE",
        b"pvac",
        b"secret.ct",
        b"071b0e9",
        b"071b0e909c119de815e284b347c4bd979cb59ef3",
        b"octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ",
        b"OCTRA_PVAC_MASTER_V1",
        b"OCTRA_PVAC_TAG",
        b"1 million OCT",
        b"1000000",
        b"500000",
        b"2026-07-09",
        b"2026-07-11",
        b"d9d29d505e2840c0028d7a91a2a8ba59e163b9a4",
        b"challenge v2",
        b"bounty",
    ]
    out: list[tuple[str, bytes]] = []
    out.append(("all_zero_16", bytes(16)))
    out.append(("all_ff_16", bytes([0xFF] * 16)))
    out.append(("all_01_16", bytes([0x01] * 16)))
    out.append(("counter_0_15", bytes(range(16))))
    for s in strings:
        digest = sha256(s).digest()[:16]
        out.append((f"sha25616:{s.decode('utf-8', 'replace')}", digest))
        digest2 = sha256(sha256(s).digest()).digest()[:16]
        out.append((f"dbl_sha25616:{s.decode('utf-8', 'replace')}", digest2))
    # bit flips of all-zero
    for i in range(16):
        buf = bytearray(16)
        buf[i] = 0x01
        out.append((f"single_bit_byte{i}", bytes(buf)))
    return out


def _bip39_test_vector_mnemonics() -> list[tuple[str, str]]:
    """Well-known BIP39 test vectors and trivial phrases (checksum-valid only)."""
    # Official BIP39 test vector (12 words) — NOT expected to match Octra target
    vectors = [
        (
            "bip39_tv_00000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            "bip39_tv_7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "bip39_tv_80808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "bip39_tv_ffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
    ]
    return vectors


def run_hypotheses(
    workspace: Path,
    target: str = TARGET_ADDRESS,
    include_file_hashes: bool = True,
) -> dict[str, Any]:
    """Test a few hundred cheap candidates; log all results; alert only on match."""
    results: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []

    # entropy-based
    for label, entropy in _entropy_candidates():
        try:
            row = address_from_entropy(entropy)
            entry = {
                "class": "entropy",
                "label": label,
                "address": row["address"],
                "match": row["address"] == target,
            }
            if entry["match"]:
                entry["mnemonic"] = row["mnemonic"]
                hits.append(entry)
            results.append(entry)
        except ReconError as error:
            results.append({"class": "entropy", "label": label, "error": str(error)})

    # known mnemonics
    for label, mnemonic in _bip39_test_vector_mnemonics():
        try:
            row = check_mnemonic_against_target(mnemonic, target=target)
            entry = {
                "class": "mnemonic",
                "label": label,
                "address": row["address"],
                "match": row["match"],
            }
            if row["match"]:
                entry["mnemonic"] = mnemonic
                hits.append(entry)
            results.append(entry)
        except ReconError as error:
            results.append({"class": "mnemonic", "label": label, "error": str(error)})

    # optional: hash of local challenge artifacts as entropy
    if include_file_hashes:
        artifacts = workspace / "artifacts"
        for name in ("secret.ct", "pk.bin", "params.json", "manifest.json", "pvac_commit.txt"):
            path = artifacts / name
            if not path.is_file():
                continue
            digest = sha256(path.read_bytes()).digest()[:16]
            label = f"artifact_sha25616:{name}"
            try:
                row = address_from_entropy(digest)
                entry = {
                    "class": "artifact_hash",
                    "label": label,
                    "address": row["address"],
                    "match": row["address"] == target,
                }
                if entry["match"]:
                    entry["mnemonic"] = row["mnemonic"]
                    hits.append(entry)
                results.append(entry)
            except ReconError as error:
                results.append({"class": "artifact_hash", "label": label, "error": str(error)})

    report = {
        "target": target,
        "tested": len(results),
        "hits": len(hits),
        "hit_details": hits,
        "note": (
            "This is a cheap hypothesis screen (~hundreds of candidates), not a 2^128 search. "
            "Expected hits: 0. A hit would be extraordinary and should be verified offline."
        ),
        "results": results,
    }
    write_json(workspace / "logs" / "hypotheses_report.json", report)
    # compact summary without full result dump for console
    summary = {
        "target": target,
        "tested": report["tested"],
        "hits": report["hits"],
        "hit_details": hits,
        "report": str(workspace / "logs" / "hypotheses_report.json"),
        "note": report["note"],
    }
    write_json(workspace / "logs" / "hypotheses_summary.json", summary)
    return summary
