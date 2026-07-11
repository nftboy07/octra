# Tokens + AWS harden (outperform setup)

## 1. GitHub + X tokens (better intel)

```bash
mkdir -p ~/.config/octra-recon
chmod 700 ~/.config/octra-recon
nano ~/.config/octra-recon/social.env
```

```bash
# GitHub PAT: public_repo / read-only is enough
OCTRA_GITHUB_TOKEN=ghp_xxxxxxxx
# X API v2 Bearer from developer.twitter.com
OCTRA_X_BEARER_TOKEN=AAAAAAAAAAxxxxxxxx
```

```bash
chmod 600 ~/.config/octra-recon/social.env
# systemd already has EnvironmentFile=-.../social.env
sudo systemctl restart octra-watchdog.timer
```

## 2. AWS Security Group (SSH only from you)

In **AWS Console → EC2 → Security Groups** for the instance:

1. Inbound: remove `0.0.0.0/0` on port 22 if present  
2. Add: **SSH TCP 22 → My IP** only  
3. Keep egress open (GitHub/Telegram need outbound HTTPS)

Optional CLI (if `aws` configured):

```bash
# EXAMPLE — replace ids
# aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr 0.0.0.0/0
# aws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr YOUR.IP.V.4/32
```

## 3. Telegram bot commands

With `octra-tg-poll.timer` enabled, message your bot:

- `/status` — claim pipeline  
- `/scan` — unlock scan  
- `/claim` — next actions  
- `/help`

Only the configured `OCTRA_TELEGRAM_CHAT_ID` is answered.
