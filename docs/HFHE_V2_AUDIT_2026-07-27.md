# HFHE Challenge v2 — Independent 64-Agent Audit

**Date:** 2026-07-27
**Target wallet:** `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`
**Challenge:** https://github.com/octra-labs/hfhe-challenge
**Implementation reviewed:** `octra-labs/pvac_hfhe_cpp` @ `071b0e9`

## Result

**The private key / plaintext was NOT recovered. No key was fabricated.**

An independent adversarial audit (56 completed sub-agents across all 44 source
files plus 12 targeted cryptanalysis angles, with an adversarial verify stage)
reconfirmed the conclusion already recorded in
[`HFHE_V2_STATUS.md`](./HFHE_V2_STATUS.md): HFHE Challenge v2 meets its ~128-bit
design target on every attack surface examined. Recovery from public artifacts
is cryptographically infeasible on any realistic hardware.

## Artifact verification (genuine files confirmed by hash)

| File | SHA-256 | Match |
|------|---------|-------|
| `secret.ct` | `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab` | ✅ |
| `pk.bin` | `1e788edff9dea19a782defae053f3757ccf5edd41cd3e24ae44e1496045e9410` | ✅ |

`secret.ct` structure: magic `OCTRA-HFHE-BTY02` + count **22** + 22
length-prefixed `Cipher` blobs, fully consumed, **0 trailing bytes**. The bundle
contains exactly 22 serialized `Cipher` objects and nothing else — no
`sha256_hidden_trace` proof material is present in the public artifact.

## Concrete cryptographic barrier

Two independent hard problems both stand. Decryption requires `prf_k`
regardless, so even a free LPN/syndrome solution does not decrypt `secret.ct`.

### Side LPN instance — `n=4096`, `tau=1/8`, `t=16384` (= 4n samples)
- Prange / Pooled-Gauss: **~2^918** (single file), **~2^791** (all 44 files pooled).
- Information-theoretic floor pooling cannot lower: `(1-tau)^-n = (8/7)^4096 = ` **2^789**.
- Advanced ISD (MMT/BJMM/May-Ozerov): constant-factor only; even a 50% exponent cut leaves **~2^395**.
- BKW / coded-BKW: cannot start — needs ~2^341 samples, only ~2^14–2^19.5 exist. The `t = 4n` budget is deliberately BKW-hostile.

### Main syndrome instance — `H` 8192×16384, col wt 192, secret wt 128, err wt 128, over `Fp = 2^127−1`
- Prange hard floor: **~2^128.7 iterations (~2^154.7 field-ops)** for `x` alone; **~2^435** for `(x,e)` jointly.
- Idealized F2 Stern (over-optimistic): still **~2^132**.
- Over a 2^127-size field, the birthday/representation collisions that power
  Stern/BJMM/MMT/May-Ozerov effectively never occur (prob ~`q^-ℓ`), so those
  speedups collapse to Prange — published sub-2^128 *binary* exponents do **not** transfer to Fp.
- Compressed-sensing (L1/OMP undefined over Fp) and LDPC belief-propagation shortcuts checked and refuted.

**Compute reality:** a 64-core VPS ≈ 2^61 ops/year; all of humanity for a
century ≈ 2^95. No known algorithm closes a ~300-order-of-magnitude gap.

## Attack surfaces ruled out

- **RNG replay:** the random `keygen` path draws `prf_k` from the unseeded OS
  CSPRNG (`getrandom`/`BCryptGenRandom`/`arc4random`). No seed exists to recover
  or replay. The deterministic `AesCtr256` `SeedableRng` is used only by
  `keygen_from_seed`, which the bounty does not invoke.
- **`pk.bin` leak:** `serialize_pubkey` emits only public / re-derivable data
  (params, `canon_tag`, `H`, `ubk`, `H_digest`, `omega_B`, `powg_B`). Secrets
  (`prf_k`, `lpn_s_bits`) live only in the unpublished `TAG_SECKEY` blob.
- **`R_com` offline oracle (v1 bug):** genuinely defanged at `071b0e9` —
  `compute_R_com_base` hashes only public metadata (`canon_tag`, `ztag`,
  `nonce.lo/hi`, `R_slots.size()`), never secret `R` or plaintext.
- **Toeplitz `toep_127` truncation:** real (drops bit 127+), but sits between
  AES-CTR (keyed by `SHA256(prf_k||…)`) and `hash_to_fp_nonzero` + three Fp
  mults — cannot be linearized.
- **Dual-mask algebra:** 44 equations vs 88 unknowns; every layer uses a fresh
  nonce, so the blocks never assemble into a solvable system.
- **Wallet / on-chain angle:** address = `oct + base58(SHA256(pubkey))`;
  privkey is a fresh random key sealed in the ciphertext, not a brainwallet.
  No public-only path independent of breaking `secret.ct`.

## Findings worth reporting to octra (responsible disclosure)

These are real code observations. **Neither recovers the bounty key.**

1. **`pvac_hfhe_cpp/include/pvac/ops/sha256_hidden_trace.hpp` — degenerate
   MPC-in-the-head randomness (severity: high).** The 3-branch replicated
   sharing that hides the SHA-256 input uses a single top-level `(base_a,
   base_b)` pair as its entire randomness; gate builders discard their random
   args (`(void)a;(void)b;`). Opening 2 of 3 branches recovers the preimage in
   O(1) algebra, falsifying `message_hidden=true`. **Not exploitable against
   this bounty** — the construct is not part of the serialized `Cipher`/`Layer`
   struct and (confirmed above) is absent from `secret.ct`. Latent defect worth
   fixing before any future feature relies on it.
2. **`pvac_hfhe_cpp/bounty2_data/sk.bin` is publicly committed** — a valid full
   secret key, but for an independent homomorphic-add unit-test keypair
   (`a=1`, `b=2`), generated by a separate fresh `keygen()`. It cannot decrypt
   `secret.ct`. Hygiene issue; recommend removal.

## The only theoretical paths that could ever unlock it

1. A `sha256_hidden_trace` proof serialized into a future public artifact.
2. A reintroduced offline oracle (any public value made to depend on secret `R`
   / plaintext / mask).
3. A different build routing `prf_k` through the deterministic
   `keygen_from_seed` path.
4. A genuine algorithmic breakthrough below the LPN floor of 2^789 or making
   Fp-syndrome decoding collision-friendly despite `q = 2^127` — a field-wide
   result, not a bug in this scheme.

## Reproduction

- Audit method: 44 per-file adversarial source reviews + 12 targeted angles
  (RNG determinism, `pk.bin` leak, LPN feasibility, syndrome feasibility,
  Toeplitz leverage, oracle removal, dual-mask algebra, key-reuse history,
  plaintext format, wallet angle, ristretto nonce, field inversion) +
  adversarial verify stage + synthesis.
- Artifacts fetched from `raw.githubusercontent.com/octra-labs/hfhe-challenge`
  and verified against the hashes above.
- No live-network interaction, no key material generated, no claim submitted.
