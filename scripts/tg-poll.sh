#!/usr/bin/env bash
# Continuous Telegram command poller (owns getUpdates exclusively).
# Prefer systemd Type=simple service; also safe as oneshot (runs ~2 min).
set -uo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
LOCK="${BASE}/logs/tg-poll.lock"
LOG="${BASE}/logs/tg-poll.log"

set -a
[[ -f /home/ubuntu/.config/octra-recon/telegram.env ]] && . /home/ubuntu/.config/octra-recon/telegram.env
[[ -f /home/ubuntu/.config/octra-recon/social.env ]] && . /home/ubuntu/.config/octra-recon/social.env
set +a

mkdir -p "${BASE}/logs" "$WS/logs"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

# flock: only one getUpdates owner
exec 9>"$LOCK"
if ! flock -n 9; then
  log "tg_poll_skip_locked"
  exit 0
fi

if [[ ! -x "$RECON" ]]; then
  log "recon missing"
  exit 0
fi

MODE="${1:-loop}"
if [[ "$MODE" == "once" ]]; then
  # ~75s coverage
  for i in 1 2 3; do
    "$RECON" telegram poll --workspace "$WS" >>"$LOG" 2>&1 || true
  done
  log "tg_poll_once_ok"
  exit 0
fi

# continuous long-poll (preferred)
log "tg_poll_loop_start"
# cycles=0 forever; systemd Restart=always will recover crashes
exec "$RECON" telegram poll-loop --workspace "$WS"
