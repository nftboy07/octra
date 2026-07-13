"""Document attack surface status including LPN drop and FURY applicability."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .wallet import TARGET_ADDRESS
from .workspace import write_json


def open_surface_status(workspace: Path | None = None) -> dict[str, Any]:
    """Machine-readable open-surface brief incorporating public research."""
    report: dict[str, Any] = {
        "goal": {
            "wallet": TARGET_ADDRESS,
            "reward_oct_total": 1_000_000,
            "source_post": "https://x.com/octra/status/2075336875322032268",
        },
        "public_sources": [
            {
                "id": "lambda_lpn_drop",
                "url": "https://x.com/lambda0xE/status/2075787279197508060",
                "summary": (
                    "Official-side note: LPN samples derived from sk.bin published for "
                    "cryptanalysis (would not happen in real deployments unless leaked)."
                ),
            },
            {
                "id": "smoke_ui_assessment",
                "url": "https://github.com/smoke-ui/octra-hfhe-v2-security-assessment",
                "summary": (
                    "Independent negative result: no public plaintext recovery; v2 closes "
                    "R_com oracle; LPN/PRF path requires prf_k; length 301-315 bytes."
                ),
            },
            {
                "id": "tempest_blog",
                "url": "https://te.mpe.st/blog/20260628-octra.html",
                "summary": (
                    "OSINT + crypto critique. Describes FURY: recovery of prf_k from public "
                    "Rku via broken quadratic native PRF on multi-slot recrypt keys. "
                    "Also claims LPN→FHE reduction unproven and project-level red flags."
                ),
            },
            {
                "id": "eienel",
                "url": "https://eienel.github.io/hfhe-challenge-eienel/",
                "summary": "LPN drop insufficient for decrypt without independent prf_k.",
            },
            {
                "id": "lambda_day3_timing",
                "url": "https://x.com/lambda0xE/status/2076417278543835438",
                "date": "2026-07-12",
                "summary": (
                    "DAY3 PASS: Apple Silicon pvac build; prf_R~15.3ms enc_value~43.4ms; "
                    "skA vs skB constancy statistically equal → no sk-dependent timing leak, "
                    "no remote exploit path. Next Day 4–5 algebra; Day 7 freeze if no simplify."
                ),
            },
        ],
        "challenge_day_log": {
            "latest_day": 3,
            "latest_status": "DAY3_PASS",
            "timing_side_channel": "closed_for_published_probe",
            "see": "octra-recon days status",
        },
        "pillars_blocking_bounty": [
            {
                "id": "no_r_com",
                "status": "closed",
                "detail": "v2 does not serialize R_com; offline plaintext guess check dead.",
            },
            {
                "id": "independent_dual_masks",
                "status": "closed",
                "detail": "Wrapped fuse(Enc(v+m), Enc(-m)) with independent R0,R1.",
            },
            {
                "id": "lpn_only_r1",
                "status": "open_as_side_target",
                "detail": (
                    "July 11 lpn_samples expose (A,y) for pvac.prf.r.1 only; n=4096 tau=1/8; "
                    "hardness >> 2^128; even S does not build R without prf_k for r2/r3."
                ),
            },
            {
                "id": "bip39_128",
                "status": "closed_to_brute_force",
                "detail": "Uniform 128-bit BIP39; dictionary/GPU folklore does not apply.",
            },
        ],
        "fury_applicability": {
            "claim": (
                "FURY recovers prf_k from public Rku when native PRF is the quadratic "
                "form a = h0 + sum ki*hi and Rku encrypts each prf_k[i] under that PRF."
            ),
            "challenge_public_files": ["secret.ct", "pk.bin", "params.json", "lpn_samples/*"],
            "rku_in_public_package": False,
            "note_on_pin_071b0e9": (
                "At pinned pvac commit 071b0e9, ru_affine hashes seed+slot+prf_k via SHA-256 "
                "into a field element (not the linear combination described for older commits "
                "in the te.mpe.st writeup). Challenge generation writes only pk + ciphertext "
                "bundle publicly; sk.bin stays private. No Rku object is shipped in the bounty "
                "package. Therefore FURY as published does not currently apply to public "
                "challenge artifacts alone."
            ),
            "what_would_enable_fury": [
                "Publication of Rku / recrypt key for the challenge keypair",
                "Or a wire path that embeds the broken quadratic PRF material",
                "Plus confirmation the vulnerable PRF path is the one used for that key",
            ],
            "status": "not_applicable_to_current_public_package",
        },
        "unlock_events": [
            "Second ciphertext under same key",
            "Leak/publication of prf_k or r2/r3 samples",
            "Rku or other bootstrapping material for challenge key",
            "Implementation bug putting mask material on the wire",
            "Feasible LPN break AND path to prf_k (still need both)",
        ],
        "lab_capabilities": [
            "artifact integrity + LPN inventory/checksums/binding",
            "wallet address verifier (BIP39→Octra address)",
            "cheap hypothesis screen + GitHub-lexicon brainwallet hunter",
            "secret.ct PVAC wire parser (bundle + dual BASE layers + length interval)",
            "dual-mask differential + LPN domain decision matrix",
            "wallet-gen RNG static audit",
            "S residual scorer + claim pipeline",
            "git/TG watchdog for new material",
            "full stack: octra-recon stack run",
        ],
    }
    if workspace is not None:
        write_json(workspace / "logs" / "open_surface_status.json", report)
    return report
