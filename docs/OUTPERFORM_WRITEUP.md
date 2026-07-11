# Outperforming public HFHE v2 audits

## Position

Independent public work (smoke-ui, eienel) established that OCTRA HFHE Challenge v2
has no known practical public-only plaintext recovery path. We match their LPN
structural results and extend the stack for **claim racing** and **next-experiment
science**.

## Parity (matched)

- 44 LPN files, 720,896 equations, full GF(2) ranks, zero exact A-row duplicates  
- Aggregate A/y ones-counts identical to smoke-ui published figures  
- Metadata binding 44/44; official verifier is metadata-only  

## Extensions (ahead of audit-only repos)

| Extension | Why it matters |
|-----------|----------------|
| Residual S scorer + daily holdout | Instant verification if anyone publishes S bits |
| Planted controls n=32…128 (+256/512 battery) | Proves scorer/solver plumbing |
| Restricted-sample BKW grid | Quantitative sample-vs-bias under exact M |
| Equation-body root commitment | Detects body mutation official tool misses |
| Composition checklist | S alone never decrypts without prf_k |
| 24×7 TG + social + fork tracking | Time-to-aware measured in minutes |
| Claim pipeline + bot commands | First-to-verify / first-to-claim path |

## What still wins the bounty

Only recovery of wallet material (or equivalent control). Missing public pieces:

- `prf_k` / Rku / r2–r3 samples / second CT / real wire leak  

## Repro

```bash
octra-recon lpn audit --workspace $W
octra-recon race run --workspace $W
octra-recon claim run --workspace $W
octra-recon dashboard build --workspace $W
```

## Ethics / scope

Public challenge artifacts only. No unauthorized access, no phishing.
