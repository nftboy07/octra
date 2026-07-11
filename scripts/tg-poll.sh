#!/usr/bin/env bash
# One long-poll cycle for Telegram commands (/status /scan /claim)
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
# load social/telegram env if present
set -a
[[ -f /home/ubuntu/.config/octra-recon/telegram.env ]] && . /home/ubuntu/.config/octra-recon/telegram.env
[[ -f /home/ubuntu/.config/octra-recon/social.env ]] && . /home/ubuntu/.config/octra-recon/social.env
set +a
"$RECON" telegram poll --workspace "$WS" || true
echo tg_poll_ok
