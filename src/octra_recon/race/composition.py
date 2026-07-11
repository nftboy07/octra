"""Composition map: what recovering S still leaves (source-backed)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..workspace import write_json


def composition_map(workspace: Path | None = None) -> dict[str, Any]:
    """
    Document exact dependency chain from PVAC source (pin 071b0e9):
      prf_k -> AES key for LPN rows AND Toeplitz
      lpn_s_bits (S) -> only the secret in y = <A,S> xor e
      R = f(r1,r2,r3) needs S and prf_k domains
    """
    report = {
        "pvac_pin": "071b0e909c119de815e284b347c4bd979cb59ef3",
        "chain": [
            {
                "asset": "S = sk.lpn_s_bits",
                "bits": 4096,
                "public_via": "lpn_samples (A,y) for domain pvac.prf.r.1 only",
                "recovery_status": "open / impractical at published params (smoke-ui + our audit)",
            },
            {
                "asset": "sk.prf_k[4] u64",
                "bits": 256,
                "public_via": "NOT published; no Rku in bounty package",
                "used_for": [
                    "derive_aes_key for LPN row PRG (with seed+domain)",
                    "derive_aes_key for Toeplitz compression (Dom::TOEP)",
                    "native recrypt PRF path (separate)",
                ],
            },
            {
                "asset": "r1 from domain pvac.prf.r.1",
                "depends_on": ["S", "prf_k", "per-layer seed"],
                "note": "Even with S, regenerating rows needs prf_k to rebuild A streams; samples give A public but R compression still needs prf_k Toeplitz keys.",
            },
            {
                "asset": "r2, r3 other PRF domains",
                "depends_on": ["S", "prf_k", "seeds"],
                "public_via": "no LPN sample files for these domains",
            },
            {
                "asset": "R = r1 * r2 * r3 (field)",
                "depends_on": ["r1", "r2", "r3"],
                "decrypt": "mask inverse in decryption sum",
            },
            {
                "asset": "wallet mnemonic plaintext",
                "depends_on": ["all layer R inverses", "wrapped fuse structure"],
                "bits_entropy": 128,
            },
        ],
        "if_S_recovered_tomorrow": {
            "still_missing": ["prf_k (256)", "r2/r3 domain material", "full R per layer"],
            "does_not_alone_decrypt": True,
            "next_race": "prf_k / Rku / second CT under same key",
        },
        "outperform_angle": (
            "Smoke-ui states the blocker; we encode it as an operational checklist "
            "for claim racing the moment any missing piece appears."
        ),
    }
    if workspace is not None:
        write_json(workspace / "logs" / "race_composition.json", report)
    return report
