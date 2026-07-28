# Wire audit (secret.ct)

Generated: 2026-07-20T01:17:43.629081Z

- parse_ok: **True**
- cipher_count: **22**
- dual_base_cts: **22**
- total_edges: **1829**
- plaintext: **301–315** bytes
- sha256: `5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab`

## Findings

- **OCTRA-HFHE-INFO-001** (info): Cipher count 22 narrows plaintext length to 301–315 bytes (same as smoke-ui).
- **DUAL_BASE_WRAP** (info): All 22 CTs have exactly 2 BASE layers / 0 PROD (wrapped dual-mask layout).
- **SEED_NONCE_UNIQUE** (info): No repeated base-layer seed/nonce pairs across the bundle.
- **SECRET_CT_KNOWN_DIGEST** (info): Matches published bounty secret.ct SHA-256.

## Decrypt?

No. Dual independent masks block recovery from public wire alone.
