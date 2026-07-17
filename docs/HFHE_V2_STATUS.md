# HFHE Challenge v2 Status

Checked: 2026-07-17

Target payout address:

`octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`

## Result

The target wallet key and the v2 plaintext were not recovered from the current
public artifacts. No claim, transaction, or issue submission was performed.

The published v2 bundle is an encrypted email plus a random 32-byte secret,
not an encrypted Octra wallet mnemonic. The payout address is separate from
that plaintext.

## Verified artifacts

- Challenge commit: `08bf879` (`v2_fix`)
- PVAC commit: `071b0e9` (`public matrix sampling`)
- Ciphertext SHA-256: `8f38ed7706cca15fa5208de905cf3ee445faf6c3c72068d26ea46ac7b6fa3300`
- Public key SHA-256: `ad5f2ecab6d71ffaaf1e363ed3b6aefc7ac1de4156a6189f8ff9ee720305a865`
- Plaintext format: 110 bytes, 9 wrapped 15-byte ciphertext blocks
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

## Bounded validation

Built and ran on the VPS against the pinned public source:

- `test_prf`: PASS
- `test_rcomless_fold`: PASS
- `bounty_r2_attack`: PASS, 402 pairs tested, 0 leaks
- Read-only `unlock scan`: no new critical/high material
- Read-only `surface status`: no Rku, second ciphertext, wire leak, or key material

The current blocker is therefore cryptographic recovery of the hidden PRF
material, not deployment or repository synchronization. The next actionable
unlock would be a newly published second same-key ciphertext, `prf_k`/R2-R3,
Rku, a wire leak, or a feasible LPN break connected to the PRF key path.
