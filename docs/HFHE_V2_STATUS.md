# HFHE Challenge v2 Status

Checked: 2026-07-18

Target payout address:

`octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`

## Result

The target wallet key and the v2 plaintext were not recovered from the current
public artifacts. No claim, transaction, or issue submission was performed.

The active v2 README describes the plaintext as a private key plus metadata for
the target address. The public generator does not define the private plaintext;
it reads that value from a private `challenge_private/plaintext.txt` file before
encryption.

## Verified artifacts

- Challenge commit: `019380c` (`clarify lpn samples`)
- PVAC commit: `071b0e9` (`public matrix sampling`)
- Ciphertext SHA-256: `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab`
- Public key SHA-256: `1e788edff9dea19a782480f5d7f668dcce998a0f657eaae2c4c61433c9993dc82`
- Ciphertext structure: 22 wrapped objects, 44 BASE layers, 1,829 edges
- Public length interval: 301-315 bytes, from the 22-object framing
- Current VPS LPN inventory: 44 files and 720,896 sample rows

## Structural findings

The current PRF computes three independent masks per base layer. Each wrapped
block is formed from `enc(v + m)` and `enc(-m)` using independent layers, so a
known plaintext gives one equation with two unknown masks:

```text
v = N0 / R0 + N1 / R1
```

The `toep_127` implementation returns only convolution bits 0 through 126.
Consequently, bits at index 127 and above of the LPN vector do not affect one
PRF output. This is a real truncation, but the first 127 bits still depend on
AES streams keyed by the hidden `prf_k`; it does not expose a wallet key or
make the public ciphertext decryptable by itself.

The 44 published LPN files expose `A,y` for `pvac.prf.r.1` only. Recovering
`S` would still not provide `prf_k`, the r2/r3 domains, or the Toeplitz mask
stream needed for the full `R`. The public cryptanalysis PR and independent
assessment both report no practical public-only recovery route.

## Bounded validation

Built and ran on the VPS against the pinned public source:

- `test_prf`: PASS
- `test_rcomless_fold`: PASS
- `bounty_r2_attack`: PASS, 402 pairs tested, 0 leaks
- Active wire audit: PASS, 22 dual-mask ciphers, 0 duplicate seeds/nonces/PCs
- Public-fork screen: 33 forks, no `sk.bin`, `plaintext.txt`, mnemonic, or private-artifact path
- Cheap active-artifact hypotheses: 75 tested, 0 hits
- Read-only `unlock scan`: no new critical/high material
- Read-only `surface status`: no Rku, second ciphertext, wire leak, or key material
- Derived PRF-nonce audit: 264 values across six PRF domains, 0 collisions
- Full public Git history audit: no private artifact path, unreachable object, or
  reusable active key material

The active generator calls the random `keygen` path. It samples four fresh
`csprng_u64()` words for `prf_k`; the wallet-seeded `keygen_from_seed` path is
not used by the challenge generator. Historical v2 commits also contain
different public-key blobs, so an older public artifact does not reuse the
active HFHE secret state.

The current blocker is therefore cryptographic recovery of the hidden PRF
material, not deployment or repository synchronization. The next actionable
unlock would be a newly published second same-key ciphertext, `prf_k`/R2-R3,
Rku, a wire leak, or a feasible LPN break connected to the PRF key path.
