# Unlock runbook (24×7 lab)

Goal wallet: `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`  
VPS root: `/home/ubuntu/octra_investigation`

## When Telegram says unlock / challenge moved

```bash
export BASE=/home/ubuntu/octra_investigation
export RECON=$BASE/repos/octra-recon/.venv/bin/octra-recon
export W=$BASE/workspace

bash $BASE/scripts/sync-to-vps.sh
$RECON unlock scan --workspace $W
$RECON ops integrity --workspace $W
$RECON lpn summary --workspace $W
$RECON surface status --workspace $W
```

### Decision tree

| Finding | Action |
|---------|--------|
| New `rku` / recrypt / `sk*.bin` | **CRITICAL** — FURY-class research; do not sleep on this |
| New `lpn_samples` only | Re-bind all samples; hardness still likely blocks; still no decrypt without `prf_k` |
| New `secret.ct` / second CT | Multi-CT algebra; re-hash; document |
| Docs-only commit | Log only |
| Any 12-word phrase | `$RECON wallet check --mnemonic "..."` then claim if match |

### Claim path (only after verified match)

1. Offline confirm address == target  
2. Use Octra web client per recovered instructions  
3. Contact `dev@octra.org` for second 500k  
4. **Do not** post mnemonic in public issues/TG groups  

## Continuous jobs

| Timer | Interval | Script |
|-------|----------|--------|
| Watchdog | 2h | `scripts/watchdog.sh` |
| Integrity | 24h | `scripts/integrity-daily.sh` |
| Ops cycle | 6h | `scripts/ops-cycle.sh` |
| Archive | monthly | `scripts/archive-monthly.sh` |

## Candidate drop

Put one mnemonic per file:

```text
$W/candidates/inbox/note1.txt
```

Processed automatically by ops cycle → hits in `candidates/hits/`.

## Do NOT run for months

- BIP39 2^128 brute force  
- Full LPN ISD on 2 vCPU  
- Cache attacks without sk  
