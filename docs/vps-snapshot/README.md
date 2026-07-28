# VPS lab snapshot (published from live host)

Host: AWS `ubuntu@3.125.4.182`  
Lab root: `/home/ubuntu/octra_investigation`  
Toolkit: `repos/octra-recon` → https://github.com/nftboy07/octra

## Live ops (when this snapshot was exported)

| Item | Value |
|------|--------|
| Toolkit tip | matches `origin/main` |
| Challenge | `019380c` clarify lpn samples |
| PVAC pin | `071b0e9` public matrix sampling |
| Intel clones | 63 under `repos/intel/` |
| TG bot | `octra-tg-bot.service` continuous long-poll |
| Auto | `octra-auto.timer` + claim / lexicon / integrity / bodybind |

## Commands available on VPS

```bash
export W=/home/ubuntu/octra_investigation/workspace
export R=/home/ubuntu/octra_investigation/repos/octra-recon/.venv/bin/octra-recon

$R wire audit --workspace $W
$R mask diff --workspace $W
$R rng audit --workspace $W
$R exhaust run --workspace $W
$R lexicon run --workspace $W
$R days status --workspace $W
$R stack run --workspace $W --no-lexicon --no-race
$R claim run --workspace $W
```

Telegram: `/ping` `/wire` `/stack` `/mask` `/rng` `/exhaust` `/days` `/status` `/claim`

## Snapshot files

| File | Meaning |
|------|---------|
| `WIRE_AUDIT.md` | secret.ct dual-mask structure (22 CT / 301–315) |
| `CHALLENGE_DAYS.md` | Official Day 3 timing PASS log |
| `INTEL_REPOS.md` | Mirrored octra-labs + lambda0xE inventory |
| `intel_exhaust_summary.json` | All public-intel phrase candidates → **hits: 0** |

## Result

No private key / mnemonic recovered. Public package still blocks decrypt without
`sk` / `prf_k` / Rku / second CT / real algebraic break. See `../HFHE_V2_STATUS.md`.
