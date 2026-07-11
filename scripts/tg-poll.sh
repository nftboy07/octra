#!/usr/bin/env bash
# Telegram command poller — exclusive lock so only one getUpdates runs.
set -uo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
LOCK="${BASE}/logs/tg-poll.lock"

set -a
[[ -f /home/ubuntu/.config/octra-recon/telegram.env ]] && . /home/ubuntu/.config/octra-recon/telegram.env
[[ -f /home/ubuntu/.config/octra-recon/social.env ]] && . /home/ubuntu/.config/octra-recon/social.env
set +a

mkdir -p "${BASE}/logs"

# flock: skip if another poller is already running (avoids Telegram 409 Conflict)
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "tg_poll_skip_locked"
  exit 0
fi

# ~90s of long-poll coverage per timer fire
for i in 1 2 3; do
  "$RECON" telegram poll --workspace "$WS" || true
done
echo tg_poll_ok
