"""Exhaustive public-intel candidate hunt (bounded, not 2^128).

Uses every public string/clue gathered in this investigation:
  tweets, circle OCaml type fields, mintlify/docs, repo names, day3 numbers,
  challenge constants, wallet path labels, octra-sqlite / fheOS language.

Tests each as:
  * brainwallet hashes → 128-bit BIP39 entropy → Octra address
  * BIP39 passphrase on abandon/zero and known vectors (empty default already)
  * direct mnemonic if 12 BIP39 words with valid checksum

Expected hits for honest CSPRNG seed: 0.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256, sha512
import itertools
import re
from pathlib import Path
from typing import Any

from .sources import ReconError
from .wallet import (
    TARGET_ADDRESS,
    address_from_entropy,
    check_mnemonic_against_target,
    validate_mnemonic,
)
from .workspace import write_json

# ---------------------------------------------------------------------------
# Every clue string from user-provided intel (explicit list, no secrets)
# ---------------------------------------------------------------------------

TWEET_PHRASES = (
    "unbothered. moisturized. happy. in my lane. focused. flourishing.",
    "unbothered moisturized happy in my lane focused flourishing",
    "unbothered. moisturized. happy. in my lane. focused. flourishing",
    "unbothered moisturized happy focused flourishing",
    "in my lane",
    "moisturized",
    "flourishing",
    "an ephemeral instance with its own code, persistent state, keys, access control, encrypted state and no permanent host",
    "ephemeral instance with its own code persistent state keys access control encrypted state and no permanent host",
    "ephemeral instance",
    "no permanent host",
    "distributed fheOS",
    "fheOS",
    "a circle is not a vm running on someones computer",
    "a circle is the computer with a distributed fheOS installed",
    "what you see: a circle",
    "what i see: an ephemeral instance",
)

CIRCLE_FIELDS = (
    "circle_info",
    "circle_id",
    "runtime",
    "version",
    "owner",
    "code_hash",
    "stable_root",
    "assets_root",
    "privacy_class",
    "browser_mode",
    "resource_mode",
    "policy_hash",
    "members_root",
    "export_policy",
    "limits",
    "wasm_v1",
    "OSR1",
    "OSW1",
    "octra_circleView",
)

DAY3 = (
    "DAY3 PASS",
    "DAY3_PASS",
    "Day 3",
    "DAY3",
    "15.3",
    "43.4",
    "44.07",
    "41.90",
    "prf_R",
    "enc_value",
    "Apple Silicon",
    "armv8-a+crypto",
    "statistically equal",
    "no sk-dependent timing",
)

CHALLENGE = (
    "octra",
    "OCTRA",
    "hfhe",
    "HFHE",
    "hfhe-challenge",
    "octra-labs",
    "lambda0xE",
    "pvac",
    "pvac_hfhe_cpp",
    "pvac-hfhe",
    "PVAC-HFHE",
    "secret.ct",
    "071b0e9",
    "071b0e909c119de815e284b347c4bd979cb59ef3",
    "019380c",
    "octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ",
    "OCTRA_PVAC_MASTER_V1",
    "OCTRA_PVAC_TAG",
    "1 million OCT",
    "1000000",
    "500000",
    "2026-07-09",
    "2026-07-11",
    "2026-07-12",
    "2026-07-13",
    "challenge v2",
    "bounty",
    "Octra seed",
    "octra seed",
    "mnemonic",
    "pvac.prf.r.1",
    "pvac.prf.r.2",
    "pvac.prf.r.3",
    "Rku",
    "prf_k",
    "lpn_s_bits",
    "dev@octra.org",
    "wallet.octra.org",
    "docs.octra.org",
    "https://x.com/lambda0xE/status/2076417278543835438",
    "https://x.com/octra/status/2075336875322032268",
    "https://github.com/octra-labs/hfhe-challenge",
    "https://github.com/octra-labs/pvac_hfhe_cpp",
    "https://octra-labs-pvac_hfhe_cpp.mintlify.app/introduction",
    "https://github.com/tomismeta/octra-sqlite",
    "tomismeta",
    "octra-sqlite",
    "mintlify",
    "MIPT",
    "2^127 - 1",
    "2^127-1",
    "127-bit",
    "n=4096",
    "tau=1/8",
    "301-315",
    "OCTRA-HFHE-BTY02",
    "smoke-ui",
    "eienel",
    "FURY",
    "R_com",
    "dual-mask",
    "wrapped",
    "enc_text",
    "dec_text",
    "keygen",
)

PRODUCT = (
    "circle",
    "circles",
    "Circle",
    "fheOS",
    "FHE OS",
    "ephemeral",
    "persistent state",
    "encrypted state",
    "access control",
    "privacy_class",
    "sealed",
    "public-read",
    "oct://devnet/",
    "lite_node",
    "webcli",
    "wallet-gen",
    "program-examples",
    "circle_examples",
    "ocs01-test",
    "svm-fhe",
    "octra-groth16-bn254",
    "groth16",
    "ocaml",
    "OCaml",
)


def _all_base_phrases() -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for group in (TWEET_PHRASES, CIRCLE_FIELDS, DAY3, CHALLENGE, PRODUCT):
        for p in group:
            if p not in seen:
                seen.add(p)
                out.append(p)
    # combinations of the famous 6-word tweet
    six = ["unbothered", "moisturized", "happy", "focused", "flourishing"]
    # "in my lane" as unit
    units = six + ["in my lane", "in_my_lane", "inmylane"]
    for a, b in itertools.combinations(units[:8], 2):
        for form in (f"{a} {b}", f"{a}.{b}", f"{a}_{b}", f"{a}{b}"):
            if form not in seen:
                seen.add(form)
                out.append(form)
    # ordered full six without "in my lane"
    full = " ".join(six)
    if full not in seen:
        out.append(full)
    # BIP39-ish reordering: only hash forms, not full perm
    return out


def _hash_variants(payload: bytes) -> list[tuple[str, bytes]]:
    d1 = sha256(payload).digest()
    d2 = sha256(d1).digest()
    d5 = sha512(payload).digest()
    return [
        ("sha256_16", d1[:16]),
        ("dbl_sha256_16", d2[:16]),
        ("sha512_16", d5[:16]),
        ("sha512_mid16", d5[16:32]),
        ("sha256_last16", d1[16:32]),
    ]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_intel_exhaust(
    workspace: Path,
    *,
    target: str = TARGET_ADDRESS,
    also_passphrases: bool = True,
) -> dict[str, Any]:
    """Test all intel phrases; write hits to candidates/hits/."""
    phrases = _all_base_phrases()
    # variants: lower, strip punctuation, no spaces
    expanded: list[str] = []
    for p in phrases:
        expanded.append(p)
        low = p.lower().strip()
        if low and low not in expanded:
            expanded.append(low)
        nopunct = re.sub(r"[^A-Za-z0-9 ]+", "", p).strip()
        if nopunct and nopunct not in expanded:
            expanded.append(nopunct)
        compact = re.sub(r"\s+", "", nopunct.lower())
        if compact and compact not in expanded:
            expanded.append(compact)

    # de-dupe preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for p in expanded:
        if p not in seen:
            seen.add(p)
            uniq.append(p)

    hits: list[dict[str, Any]] = []
    tested = 0
    errors = 0
    sample: list[dict[str, str]] = []

    for phrase in uniq:
        raw = phrase.encode("utf-8", errors="replace")
        for tag, ent in _hash_variants(raw):
            try:
                row = address_from_entropy(ent)
                tested += 1
                match = row["address"] == target
                if len(sample) < 3:
                    sample.append({"label": f"{tag}:{phrase[:40]}", "address": str(row["address"])})
                if match:
                    entry = {
                        "class": "intel_brainwallet",
                        "label": f"{tag}:{phrase[:120]}",
                        "address": row["address"],
                        "mnemonic": row["mnemonic"],
                        "match": True,
                    }
                    hits.append(entry)
                    _write_hit(workspace, entry, target)
            except ReconError:
                errors += 1

        # try phrase as BIP39 mnemonic if right shape
        words = phrase.lower().split()
        if len(words) in (12, 15, 18, 21, 24):
            try:
                validate_mnemonic(" ".join(words))
                row = check_mnemonic_against_target(" ".join(words), target=target)
                tested += 1
                if row["match"]:
                    entry = {
                        "class": "intel_mnemonic",
                        "label": phrase[:120],
                        "address": row["address"],
                        "mnemonic": " ".join(words),
                        "match": True,
                    }
                    hits.append(entry)
                    _write_hit(workspace, entry, target)
            except ReconError:
                errors += 1

    # passphrase variants on zero-entropy mnemonic (common brainwallet mistake)
    if also_passphrases:
        zero_m = (
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about"
        )
        for phrase in uniq[:80]:  # cap PBKDF2 cost
            try:
                row = check_mnemonic_against_target(zero_m, target=target, passphrase=phrase)
                tested += 1
                if row["match"]:
                    entry = {
                        "class": "intel_passphrase_on_zero",
                        "label": phrase[:120],
                        "address": row["address"],
                        "mnemonic": zero_m,
                        "passphrase": phrase,
                        "match": True,
                    }
                    hits.append(entry)
                    _write_hit(workspace, entry, target)
            except ReconError:
                errors += 1

    report = {
        "checked_at": _now(),
        "target": target,
        "phrases_base": len(phrases),
        "phrases_expanded": len(uniq),
        "tested": tested,
        "errors": errors,
        "hits": len(hits),
        "hit_details": hits,
        "sample_addresses": sample,
        "note": (
            "Exhaustive public-intel brainwallet/passphrase screen over all provided clues. "
            "Not a 2^128 BIP39 search. Expected hits: 0 for CSPRNG seed."
        ),
        "sources_covered": [
            "tweet six-word meme + ephemeral circle definition",
            "circle_info OCaml field names",
            "Day3 timing numbers/labels",
            "challenge constants + pins + wallet path",
            "mintlify/sqlite/docs URLs and product words",
        ],
    }
    write_json(workspace / "logs" / "intel_exhaust_report.json", report)
    summary = {
        "checked_at": report["checked_at"],
        "target": target,
        "phrases_expanded": len(uniq),
        "tested": tested,
        "hits": len(hits),
        "hit_details": hits,
        "report": str(workspace / "logs" / "intel_exhaust_report.json"),
        "note": report["note"],
    }
    write_json(workspace / "logs" / "intel_exhaust_summary.json", summary)
    return summary


def _write_hit(workspace: Path, entry: dict[str, Any], target: str) -> None:
    hits_dir = workspace / "candidates" / "hits"
    hits_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = hits_dir / f"INTEL_EXHAUST_{stamp}.txt"
    path.write_text(
        f"# MATCH {target}\n# {entry}\n{entry.get('mnemonic', '')}\n"
        f"# passphrase={entry.get('passphrase', '')}\n",
        encoding="utf-8",
    )


def exhaust_telegram_blurb(summary: dict[str, Any]) -> str | None:
    if summary.get("hits"):
        return (
            f"CRITICAL INTEL-EXHAUST HIT count={summary['hits']} — "
            f"candidates/hits/ VERIFY AND CLAIM NOW"
        )
    return None
