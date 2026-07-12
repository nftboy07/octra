# Fully automatic mode (no human help)

## What runs without you

| Timer | Interval | Action |
|-------|----------|--------|
| **octra-auto** | **15 min** | Pull toolkit + challenge + smoke-ui; sync artifacts; social; claim; on file change run unlock/LPN/integrity; deep audit if LPN changes; **GitHub-lexicon** standard hunt every 6h (or on intel change) |
| octra-watchdog | 30 min | Same auto-update wrapper |
| octra-claim | 1 h | Claim pipeline |
| octra-tg-poll | 2 min | Bot commands `/status` `/scan` `/claim` `/lexicon` |
| octra-bodybind | 24 h | Body commitment |
| octra-integrity | 24 h | Integrity |
| octra-lexicon | 24 h | Deep GitHub-lexicon hunt (BIP39∩local clones + brainwallet hashes) |
| octra-backup | 24 h | Log backup |
| octra-ops-cycle | 6 h | Also calls auto-update |
| cron | hourly | Fallback auto-update via watchdog |

## When new files appear (challenge / LPN)

1. Git fetch detects HEAD change **or** disk fingerprint changes  
2. Telegram: `AUTO: ...`  
3. Copy artifacts → workspace  
4. unlock scan + lpn summary/verify + integrity + claim  
5. If LPN samples changed: body-bind + **background deep audit**  
6. You only watch Telegram  

## Self-update of *this* toolkit

`auto-update.sh` always `git fetch` + `reset --hard origin/main` on `octra-recon`, reinstalls pip package and copies scripts. New code you push to GitHub is live within **≤15 minutes** with no SSH.

## Your only remaining tasks (optional)

- Keep AWS instance **running / billed**  
- Optionally add tokens in `~/.config/octra-recon/social.env` (once)  
- Optionally lock SSH to your IP in AWS console (once)  

No daily login required for updates.

## GitHub-lexicon key / passphrase hunt

`octra-recon lexicon run` mines text from local clones under `repos/` and
`repos/intel/`, intersects tokens with BIP39 English, and tests:

- brainwallet hashes (sha256 / dbl-sha256 / sha512 → 16-byte entropy → mnemonic)
- hex / base58 blobs found in public text
- checksum-valid 12-word windows if they appear in files
- bounded pairs/triples of high-frequency BIP39 tokens from the corpus

This is **not** a full BIP39 dictionary (2048^12 / 2^128). Honest CSPRNG seed
material will not be found this way. A hit would imply weak public-string
entropy (extraordinary). Cache file: `workspace/logs/github_lexicon_tested.json`.
TG: `/lexicon` for a quick pass; critical alert on any hit.
