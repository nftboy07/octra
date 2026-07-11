# Fully automatic mode (no human help)

## What runs without you

| Timer | Interval | Action |
|-------|----------|--------|
| **octra-auto** | **15 min** | Pull toolkit + challenge + smoke-ui; sync artifacts; social; claim; on file change run unlock/LPN/integrity; deep audit if LPN changes |
| octra-watchdog | 30 min | Same auto-update wrapper |
| octra-claim | 1 h | Claim pipeline |
| octra-tg-poll | 2 min | Bot commands `/status` `/scan` `/claim` |
| octra-bodybind | 24 h | Body commitment |
| octra-integrity | 24 h | Integrity |
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
