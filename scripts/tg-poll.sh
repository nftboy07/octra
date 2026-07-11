#!/usr/bin/env bash
# Continuous Telegram command poller (blocks in long-poll loops).
set -uo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
set -a
[[ -f /home/ubuntu/.config/octra-recon/telegram.env ]] && . /home/ubuntu/.config/octra-recon/telegram.env
[[ -f /home/ubuntu/.config/octra-recon/social.env ]] && . /home/ubuntu/.config/octra-recon/social.env
set +a

# oneshot mode for systemd Type=oneshot: do a few long-poll cycles (~2 min)
# continuous mode if TG_POLL_FOREVER=1
if [[ "${TG_POLL_FOREVER:-0}" == "1" ]]; then
  exec "$RECON" telegram poll-loop --workspace "$WS"
fi

# 4 x ~25s long-poll ≈ covers 2 min timer gap better than single 20s then idle
for i in 1 2 3 4; do
  "$RECON" telegram poll --workspace "$WS" || true
done
echo tg_poll_ok
