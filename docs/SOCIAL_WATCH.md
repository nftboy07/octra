# Social watch (GitHub + X/Twitter)

The VPS polls public intel and Telegram-alerts on **new** items (first run baselines silently).

## What is tracked

### GitHub
- Repos: `octra-labs/hfhe-challenge`, `pvac_hfhe_cpp`, `wallet-gen`, `lite_node`,
  `smoke-ui/octra-hfhe-v2-security-assessment`, `nftboy07/octra`, v1 recovery repo
- Per repo: new commits + new/updated issues & PRs
- Search: HFHE / LPN / bounty / target address style queries

### X / Twitter
- Accounts: `octra`, `lambda0xE`, `octralabs` (and search queries)
- Queries: HFHE challenge, bounty, lpn_samples, etc.

## Reliability

| Mode | How | Quality |
|------|-----|---------|
| **GitHub** | Public API | Good; better with `GITHUB_TOKEN` / `OCTRA_GITHUB_TOKEN` |
| **X API** | Bearer token | Best — set `OCTRA_X_BEARER_TOKEN` or `TWITTER_BEARER_TOKEN` |
| **X RSS** | Nitter-style instances | Best-effort fallback; instances die often |

## Configure tokens on VPS (optional but recommended)

```bash
sudo -u ubuntu mkdir -p /home/ubuntu/.config/octra-recon
sudo -u ubuntu tee -a /home/ubuntu/.config/octra-recon/social.env >/dev/null <<'EOF'
# GitHub classic/fine-grained PAT (public_repo read is enough)
OCTRA_GITHUB_TOKEN=ghp_xxx
# X API v2 Bearer (developer.twitter.com)
OCTRA_X_BEARER_TOKEN=AAAAAAAAAAAAAAAAAAAAxxx
EOF
sudo -u ubuntu chmod 600 /home/ubuntu/.config/octra-recon/social.env
```

Load into systemd by adding to service files EnvironmentFile=… or:

```bash
# quick test
set -a
source /home/ubuntu/.config/octra-recon/social.env
set +a
octra-recon ops social --workspace /home/ubuntu/octra_investigation/workspace
```

## Manual run

```bash
$R ops social --workspace $W
$R ops cycle --workspace $W
```

Alerts go to Telegram with prefixes `GH[…]`, `X[…]`, `SOCIAL CRITICAL`, etc.
