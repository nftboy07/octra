"""GitHub-lexicon wallet hunter (bounded, not 2^128 BIP39 brute force).

Mines text from local clones of challenge-related GitHub repos, extracts:

  * tokens ∩ BIP39 English wordlist
  * natural phrases / commit subjects / README lines
  * hex/base58-looking blobs
  * consecutive BIP39 words (checksum-valid 12-word windows)

Then derives candidate mnemonics via:

  * brainwallet hashes (sha256 / dbl-sha256 / sha512 → 128-bit entropy)
  * direct BIP39 checksum-valid phrases found in text
  * bounded combos of high-frequency BIP39 tokens from the corpus
  * passphrase variants on a small seed set

A hit is extraordinary. Expected hits under honest CSPRNG seed: 0.
This is NOT enumerating 2048^12; it only tests material present in
(or derived from) public GitHub text we already clone.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256, sha512
import itertools
import re
from pathlib import Path
from typing import Any, Iterable, Iterator

from .sources import ReconError
from .wallet import (
    TARGET_ADDRESS,
    address_from_entropy,
    check_mnemonic_against_target,
    mnemonic_from_entropy,
    validate_mnemonic,
)
from .workspace import write_json

# Text-ish extensions only (skip binaries, lockfiles, huge assets)
_TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".rst",
    ".py",
    ".js",
    ".ts",
    ".mjs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".rs",
    ".go",
    ".java",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".bash",
    ".ps1",
    ".html",
    ".css",
    ".svg",
    ".csv",
    ".log",
    ".env",
    ".example",
    ".gitignore",
    ".dockerignore",
    ".makefile",
    "",
}

_SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "target",
    "dist",
    "build",
    ".tox",
    "lpn_samples",  # huge JSONL — not passphrase material
}

# Challenge / brand seed phrases always tested (even without local clones)
_SEED_PHRASES = (
    "",
    "octra",
    "OCTRA",
    "hfhe",
    "HFHE",
    "hfhe-challenge",
    "octra-labs",
    "lambda0xE",
    "pvac",
    "secret.ct",
    "071b0e9",
    "071b0e909c119de815e284b347c4bd979cb59ef3",
    "octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ",
    "OCTRA_PVAC_MASTER_V1",
    "OCTRA_PVAC_TAG",
    "1 million OCT",
    "1000000",
    "500000",
    "2026-07-09",
    "2026-07-11",
    "challenge v2",
    "bounty",
    "pvac_hfhe_cpp",
    "wallet-gen",
    "bip39",
    "mnemonic",
    "octra seed",
    "Octra seed",
    "dev@octra.org",
    "Rku",
    "prf_k",
    "LPN",
    "smoke-ui",
    "nftboy07",
    # user-provided tweet / circle intel
    "unbothered. moisturized. happy. in my lane. focused. flourishing.",
    "unbothered moisturized happy in my lane focused flourishing",
    "ephemeral instance",
    "distributed fheOS",
    "fheOS",
    "circle_info",
    "no permanent host",
    "tomismeta",
    "octra-sqlite",
    "DAY3_PASS",
    "wasm_v1",
)

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z']{1,24}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,128}\b")
_B58_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,64}\b")
_MNEMONIC_LINE_RE = re.compile(
    r"(?:^|[^a-z])((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})(?:[^a-z]|$)",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_bip39_set() -> set[str]:
    from .wallet import _load_wordlist

    return set(_load_wordlist())


def discover_scan_roots(workspace: Path, base: Path | None = None) -> list[Path]:
    """Locate local GitHub clones and text surfaces to mine."""
    base = base or workspace.parent
    roots: list[Path] = []
    candidates = [
        base / "repos",
        base / "repos" / "intel",
        workspace / "repos",
        workspace / "artifacts",
        workspace / "notes",
        workspace / "reports",
        base / "reports",
    ]
    # also walk one level under repos/ for named clones
    for parent in (base / "repos", base / "repos" / "intel", workspace / "repos"):
        if parent.is_dir():
            for child in parent.iterdir():
                if child.is_dir() and not child.name.startswith("."):
                    candidates.append(child)
    seen: set[str] = set()
    for path in candidates:
        try:
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        if path.exists():
            seen.add(key)
            roots.append(path)
    return roots


def _should_skip_dir(name: str) -> bool:
    return name in _SKIP_DIR_NAMES or name.startswith(".")


def iter_text_files(
    roots: Iterable[Path],
    *,
    max_files: int = 8000,
    max_file_bytes: int = 512_000,
) -> Iterator[Path]:
    count = 0
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            if root.stat().st_size <= max_file_bytes:
                yield root
                count += 1
            continue
        for path in root.rglob("*"):
            if count >= max_files:
                return
            if not path.is_file():
                continue
            # skip nested .git and other dirs
            parts = set(path.parts)
            if parts & _SKIP_DIR_NAMES:
                continue
            if any(_should_skip_dir(p) for p in path.parts):
                continue
            suffix = path.suffix.lower()
            # allow no-suffix common names
            name_l = path.name.lower()
            if suffix not in _TEXT_SUFFIXES and name_l not in (
                "readme",
                "license",
                "makefile",
                "dockerfile",
                "changelog",
                "authors",
                "copying",
            ):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0 or size > max_file_bytes:
                continue
            yield path
            count += 1


def extract_corpus(
    roots: Iterable[Path],
    bip39: set[str],
    *,
    max_files: int = 8000,
    max_file_bytes: int = 512_000,
) -> dict[str, Any]:
    """Build lexicon stats from local GitHub trees."""
    bip39_counts: Counter[str] = Counter()
    phrase_set: set[str] = set()
    hex_blobs: set[str] = set()
    b58_blobs: set[str] = set()
    mnemonic_candidates: set[str] = set()
    files_read = 0
    bytes_read = 0

    for path in iter_text_files(roots, max_files=max_files, max_file_bytes=max_file_bytes):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_read += 1
        bytes_read += len(text)

        # lines as phrases (short)
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#") and len(s) < 4:
                continue
            # strip common markdown/list noise
            s = re.sub(r"^[-*+>\s#]+", "", s).strip()
            if 3 <= len(s) <= 120:
                phrase_set.add(s)
            # mnemonic-looking lines
            for m in _MNEMONIC_LINE_RE.finditer(s + " "):
                cand = " ".join(m.group(1).lower().split())
                words = cand.split()
                if len(words) in (12, 15, 18, 21, 24):
                    if all(w in bip39 for w in words):
                        mnemonic_candidates.add(cand)

        # tokens
        for tok in _WORD_RE.findall(text):
            low = tok.lower()
            if low in bip39:
                bip39_counts[low] += 1

        for h in _HEX_RE.findall(text):
            if len(h) in (32, 40, 64, 128):
                hex_blobs.add(h.lower())
            elif 32 < len(h) < 128:
                hex_blobs.add(h.lower()[:64])  # truncated probes

        for b in _B58_RE.findall(text):
            if b.startswith("oct"):
                continue  # addresses, not seeds
            b58_blobs.add(b)

    # always include seed phrases
    for p in _SEED_PHRASES:
        if p:
            phrase_set.add(p)

    return {
        "files_read": files_read,
        "bytes_read": bytes_read,
        "bip39_token_counts": bip39_counts,
        "phrases": phrase_set,
        "hex_blobs": hex_blobs,
        "b58_blobs": b58_blobs,
        "mnemonic_candidates": mnemonic_candidates,
        "bip39_unique": len(bip39_counts),
    }


def _hash_entropy_variants(payload: bytes) -> list[tuple[str, bytes]]:
    """Map arbitrary bytes to 128-bit entropy via common brainwallet hashes."""
    out: list[tuple[str, bytes]] = []
    d1 = sha256(payload).digest()
    out.append(("sha25616", d1[:16]))
    out.append(("sha25632trunc", d1[:16]))  # same 16; label kept for clarity
    d2 = sha256(d1).digest()
    out.append(("dbl_sha25616", d2[:16]))
    d5 = sha512(payload).digest()
    out.append(("sha51216", d5[:16]))
    out.append(("sha512_mid16", d5[16:32]))
    # utf-8 normalized lower
    return out


def _generate_candidates(
    corpus: dict[str, Any],
    bip39: set[str],
    *,
    max_candidates: int = 80_000,
    top_bip39: int = 64,
    combo_pairs: bool = True,
    combo_triples: bool = False,
    deep: bool = False,
) -> list[tuple[str, str, Any]]:
    """
    Return list of (class, label, payload) where payload is either:
      - ("entropy", bytes16)
      - ("mnemonic", str)
    """
    candidates: list[tuple[str, str, Any]] = []
    seen_entropy: set[bytes] = set()
    seen_mnemonic: set[str] = set()

    def add_entropy(cls: str, label: str, ent: bytes) -> None:
        if len(candidates) >= max_candidates:
            return
        if len(ent) != 16:
            return
        if ent in seen_entropy:
            return
        seen_entropy.add(ent)
        candidates.append((cls, label[:180], ("entropy", ent)))

    def add_mnemonic(cls: str, label: str, mnemonic: str) -> None:
        if len(candidates) >= max_candidates:
            return
        norm = " ".join(mnemonic.strip().lower().split())
        if norm in seen_mnemonic:
            return
        try:
            validate_mnemonic(norm)
        except ReconError:
            return
        seen_mnemonic.add(norm)
        candidates.append((cls, label[:180], ("mnemonic", norm)))

    # 0) Fixed / test patterns first (always present; used by unit tests + low-entropy screen)
    for label, ent in (
        ("all_zero", bytes(16)),
        ("all_ff", bytes([0xFF] * 16)),
        ("counter", bytes(range(16))),
        ("all_01", bytes([0x01] * 16)),
    ):
        add_entropy("fixed", label, ent)

    # 1) Direct BIP39 phrases found in text
    for m in corpus.get("mnemonic_candidates") or []:
        add_mnemonic("found_mnemonic", f"text:{m[:60]}", m)

    # 2) Seed + mined phrases as brainwallets
    phrases: set[str] = set(corpus.get("phrases") or set())
    # rank short phrases first; cap phrase count
    ranked_phrases = sorted(phrases, key=lambda s: (len(s), s))[: (20_000 if deep else 8_000)]
    for phrase in ranked_phrases:
        if len(candidates) >= max_candidates:
            break
        raw = phrase.encode("utf-8", errors="replace")
        for tag, ent in _hash_entropy_variants(raw):
            add_entropy("brainwallet", f"{tag}:{phrase[:80]}", ent)
        # also try lowercased / stripped punctuation variants
        low = phrase.lower().strip()
        if low != phrase and low:
            for tag, ent in _hash_entropy_variants(low.encode("utf-8")):
                add_entropy("brainwallet", f"{tag}:low:{low[:80]}", ent)

    # 3) Hex blobs → entropy (first 16 bytes)
    for hx in list(corpus.get("hex_blobs") or [])[:5000]:
        if len(candidates) >= max_candidates:
            break
        try:
            raw = bytes.fromhex(hx[:32] if len(hx) >= 32 else hx)
        except ValueError:
            continue
        if len(raw) >= 16:
            add_entropy("hex_blob", f"hex16:{hx[:32]}", raw[:16])
        # also hash the full hex string
        for tag, ent in _hash_entropy_variants(hx.encode("ascii")):
            add_entropy("hex_hash", f"{tag}:hx:{hx[:40]}", ent)

    # 4) Base58-looking strings as brainwallet
    for b in list(corpus.get("b58_blobs") or [])[:3000]:
        if len(candidates) >= max_candidates:
            break
        for tag, ent in _hash_entropy_variants(b.encode("ascii")):
            add_entropy("b58_hash", f"{tag}:b58:{b[:40]}", ent)

    # 5) High-frequency BIP39 tokens alone + combos
    counts: Counter[str] = corpus.get("bip39_token_counts") or Counter()
    top = [w for w, _ in counts.most_common(top_bip39)]
    if not top:
        # fallback common BIP39 subset if corpus empty
        top = [
            "abandon",
            "ability",
            "able",
            "about",
            "above",
            "absent",
            "absorb",
            "abstract",
            "absurd",
            "abuse",
            "access",
            "accident",
            "account",
            "accuse",
            "achieve",
            "acid",
            "acoustic",
            "acquire",
            "across",
            "act",
            "action",
            "actor",
            "actress",
            "actual",
            "adapt",
            "add",
            "addict",
            "address",
            "adjust",
            "admit",
            "adult",
            "advance",
            "advice",
            "aerobic",
            "affair",
            "afford",
            "afraid",
            "again",
            "age",
            "agent",
            "agree",
            "ahead",
            "aim",
            "air",
            "airport",
            "aisle",
            "alarm",
            "album",
            "alcohol",
            "alert",
            "alien",
            "all",
            "alley",
            "allow",
            "almost",
            "alone",
            "alpha",
            "already",
            "also",
            "alter",
            "always",
            "amateur",
            "amazing",
            "among",
        ][:top_bip39]

    for w in top:
        if len(candidates) >= max_candidates:
            break
        for tag, ent in _hash_entropy_variants(w.encode("utf-8")):
            add_entropy("bip39_token", f"{tag}:word:{w}", ent)

    if combo_pairs:
        # pairs of top words (space and concat)
        limit_pair = top[: min(40, len(top))] if deep else top[: min(24, len(top))]
        for a, b in itertools.combinations(limit_pair, 2):
            if len(candidates) >= max_candidates:
                break
            for form in (f"{a} {b}", f"{a}{b}", f"{a}-{b}", f"{b} {a}"):
                for tag, ent in _hash_entropy_variants(form.encode("utf-8")):
                    add_entropy("bip39_pair", f"{tag}:{form}", ent)

    if combo_triples or deep:
        limit_t = top[: min(16, len(top))]
        for a, b, c in itertools.combinations(limit_t, 3):
            if len(candidates) >= max_candidates:
                break
            form = f"{a} {b} {c}"
            for tag, ent in _hash_entropy_variants(form.encode("utf-8")):
                add_entropy("bip39_triple", f"{tag}:{form}", ent)

    # 6) Sliding windows of top BIP39 tokens into 12-word candidates (checksum filter)
    #    Only when we have enough tokens; this catches accidental dump of wordlists.
    if len(top) >= 12 and deep:
        # also use all unique bip39 tokens sorted by frequency as a stream
        stream = [w for w, _ in counts.most_common(500)]
        for i in range(0, max(0, len(stream) - 11)):
            if len(candidates) >= max_candidates:
                break
            window = " ".join(stream[i : i + 12])
            add_mnemonic("bip39_window", f"window:{i}", window)

    return candidates


def _candidate_key(kind: str, value: Any) -> str:
    if kind == "entropy":
        return "e:" + value.hex()
    return "m:" + " ".join(str(value).strip().lower().split())


def _load_tested_cache(workspace: Path) -> set[str]:
    path = workspace / "logs" / "github_lexicon_tested.json"
    if not path.is_file():
        return set()
    try:
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
        keys = data.get("keys") or []
        return set(keys) if isinstance(keys, list) else set()
    except (OSError, ValueError, TypeError):
        return set()


def _save_tested_cache(workspace: Path, keys: set[str], *, max_keys: int = 500_000) -> None:
    # keep newest-ish by truncating arbitrarily if huge
    ordered = list(keys)
    if len(ordered) > max_keys:
        ordered = ordered[-max_keys:]
    write_json(
        workspace / "logs" / "github_lexicon_tested.json",
        {"count": len(ordered), "keys": ordered, "updated_at": _now()},
    )


def run_github_lexicon(
    workspace: Path,
    *,
    target: str = TARGET_ADDRESS,
    base: Path | None = None,
    max_candidates: int = 8_000,
    max_files: int = 8000,
    deep: bool = False,
    roots: list[Path] | None = None,
    skip_tested: bool = True,
) -> dict[str, Any]:
    """Mine local GitHub clones and test brainwallet / BIP39 candidates against target.

    Pure-Python Ed25519 is ~100ms/candidate, so defaults stay modest:
      standard ≈ 8k (~15 min), deep ≈ 25k (~45 min). Across runs a tested-cache
      skips already-checked entropy so the frontier advances over days/weeks.
    """
    base = base or workspace.parent
    bip39 = _load_bip39_set()
    scan_roots = roots if roots is not None else discover_scan_roots(workspace, base)

    corpus = extract_corpus(
        scan_roots,
        bip39,
        max_files=max_files,
        max_file_bytes=512_000 if not deep else 1_500_000,
    )

    top_n = 96 if deep else 48
    gen_cap = max_candidates if not deep else max(max_candidates, 40_000)
    candidates = _generate_candidates(
        corpus,
        bip39,
        max_candidates=gen_cap,
        top_bip39=top_n,
        combo_pairs=True,
        combo_triples=deep,
        deep=deep,
    )

    tested_cache = _load_tested_cache(workspace) if skip_tested else set()
    hits: list[dict[str, Any]] = []
    tested = 0
    skipped = 0
    errors = 0
    sample_addresses: list[dict[str, str]] = []
    new_keys: set[str] = set()

    for cls, label, payload in candidates:
        kind, value = payload
        key = _candidate_key(kind, value)
        if key in tested_cache:
            skipped += 1
            continue
        if tested >= max_candidates:
            break
        try:
            if kind == "entropy":
                row = address_from_entropy(value)
                match = row["address"] == target
                entry = {
                    "class": cls,
                    "label": label,
                    "address": row["address"],
                    "match": match,
                }
                if match:
                    entry["mnemonic"] = row["mnemonic"]
                    hits.append(entry)
                    _write_hit(workspace, entry, target)
            else:
                row = check_mnemonic_against_target(value, target=target)
                match = bool(row["match"])
                entry = {
                    "class": cls,
                    "label": label,
                    "address": row["address"],
                    "match": match,
                }
                if match:
                    entry["mnemonic"] = value
                    hits.append(entry)
                    _write_hit(workspace, entry, target)
            tested += 1
            new_keys.add(key)
            if len(sample_addresses) < 5:
                sample_addresses.append({"label": label, "address": str(entry["address"])})
        except ReconError:
            errors += 1
            new_keys.add(key)  # don't retry broken forever
            continue

    if skip_tested and new_keys:
        tested_cache |= new_keys
        _save_tested_cache(workspace, tested_cache)

    report = {
        "checked_at": _now(),
        "target": target,
        "mode": "deep" if deep else "standard",
        "scan_roots": [str(p) for p in scan_roots],
        "files_read": corpus["files_read"],
        "bytes_read": corpus["bytes_read"],
        "bip39_unique_in_corpus": corpus["bip39_unique"],
        "phrases_mined": len(corpus["phrases"]),
        "hex_blobs": len(corpus["hex_blobs"]),
        "b58_blobs": len(corpus["b58_blobs"]),
        "found_mnemonics_in_text": len(corpus["mnemonic_candidates"]),
        "top_bip39": [w for w, _ in (corpus["bip39_token_counts"] or Counter()).most_common(30)],
        "candidates_generated": len(candidates),
        "tested": tested,
        "skipped_already_tested": skipped,
        "cache_size": len(tested_cache),
        "errors": errors,
        "hits": len(hits),
        "hit_details": hits,
        "sample_addresses": sample_addresses,
        "note": (
            "Bounded GitHub-lexicon hunter. Uses words/phrases from local clones of "
            "challenge-related GitHub repos + brainwallet hashes + BIP39-valid windows. "
            "Does NOT brute-force 2048^12. Expected hits: 0 for honest CSPRNG seed. "
            "Across runs a tested-cache advances the frontier without redoing work."
        ),
    }
    write_json(workspace / "logs" / "github_lexicon_report.json", report)
    summary = {
        "checked_at": report["checked_at"],
        "target": target,
        "mode": report["mode"],
        "files_read": report["files_read"],
        "bip39_unique_in_corpus": report["bip39_unique_in_corpus"],
        "candidates_generated": report["candidates_generated"],
        "tested": tested,
        "skipped_already_tested": skipped,
        "cache_size": report["cache_size"],
        "hits": len(hits),
        "hit_details": hits,
        "top_bip39": report["top_bip39"],
        "report": str(workspace / "logs" / "github_lexicon_report.json"),
        "note": report["note"],
    }
    write_json(workspace / "logs" / "github_lexicon_summary.json", summary)
    return summary


def _write_hit(workspace: Path, entry: dict[str, Any], target: str) -> None:
    hits_dir = workspace / "candidates" / "hits"
    hits_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", entry.get("label", "hit"))[:60]
    path = hits_dir / f"LEXICON_{stamp}_{safe}.txt"
    mnemonic = entry.get("mnemonic", "")
    path.write_text(
        f"# MATCH {target}\n"
        f"# class={entry.get('class')} label={entry.get('label')}\n"
        f"# address={entry.get('address')}\n"
        f"{mnemonic}\n",
        encoding="utf-8",
    )


def lexicon_telegram_blurb(summary: dict[str, Any]) -> str | None:
    if summary.get("hits"):
        return (
            f"CRITICAL LEXICON HIT count={summary['hits']} — "
            f"mnemonic in candidates/hits/. VERIFY OFFLINE AND CLAIM NOW."
        )
    return None
