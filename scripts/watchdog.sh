#!/usr/bin/env bash
# Poll upstream repos; on HEAD change re-verify LPN and Telegram-alert.
set -euo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
STATE_DIR="${BASE}/logs/watchdog"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
mkdir -p "$STATE_DIR"

notify() {
  local msg="$1"
  if [[ -x "$RECON" ]]; then
    "$RECON" telegram test --message "$msg" >/dev/null 2>&1 || true
  fi
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $msg" | tee -a "$STATE_DIR/events.log"
}

check_repo() {
  local name="$1"
  local path="$2"
  local branch_or_pin="$3"
  if [[ ! -d "$path/.git" ]]; then
    return 0
  fi
  git -C "$path" fetch origin --quiet 2>/dev/null || return 0
  local old new
  old="$(cat "$STATE_DIR/${name}.head" 2>/dev/null || true)"
  if [[ "$branch_or_pin" == "PIN:"* ]]; then
    new="${branch_or_pin#PIN:}"
    # still record remote default for awareness
    local tip
    tip="$(git -C "$path" rev-parse origin/HEAD 2>/dev/null || git -C "$path" rev-parse origin/main 2>/dev/null || echo unknown)"
    echo "$tip" > "$STATE_DIR/${name}.origin_tip"
  else
    new="$(git -C "$path" rev-parse "origin/${branch_or_pin}" 2>/dev/null \
      || git -C "$path" rev-parse origin/main 2>/dev/null \
      || git -C "$path" rev-parse HEAD)"
    if [[ -n "$old" && "$old" != "$new" ]]; then
      git -C "$path" checkout --detach --quiet "$new" || true
      notify "WATCHDOG: ${name} moved ${old:0:7} -> ${new:0:7}. Investigate unlock material."
      if [[ "$name" == "hfhe-challenge" && -x "$RECON" ]]; then
        # refresh artifacts junction targets
        cp -f "$path/secret.ct" "$path/pk.bin" "$path/params.json" \
              "$path/manifest.json" "$path/SHA256SUMS" "$path/pvac_commit.txt" \
              "$WS/artifacts/" 2>/dev/null || true
        "$RECON" lpn summary --workspace "$WS" >/dev/null 2>&1 || true
        notify "WATCHDOG: re-ran lpn summary after ${name} update."
      fi
    fi
    echo "$new" > "$STATE_DIR/${name}.head"
  fi
}

check_repo hfhe-challenge "$BASE/repos/hfhe-challenge" main
check_repo pvac_hfhe_cpp "$BASE/repos/pvac_hfhe_cpp" main
check_repo smoke-ui "$BASE/repos/smoke-ui" main
check_repo octra-recon "$BASE/repos/octra-recon" main

# daily heartbeat if file older than 20h
HEART="$STATE_DIR/last_heartbeat"
now=$(date +%s)
if [[ ! -f "$HEART" ]] || [[ $(( now - $(stat -c %Y "$HEART") )) -gt 72000 ]]; then
  h1=$(git -C "$BASE/repos/hfhe-challenge" log -1 --format=%h 2>/dev/null || echo '?')
  h2=$(git -C "$BASE/repos/octra-recon" log -1 --format=%h 2>/dev/null || echo '?')
  notify "WATCHDOG heartbeat: alive. challenge=${h1} toolkit=${h2}. No claim path without unlock."
  date -u +%Y-%m-%dT%H:%M:%SZ > "$HEART"
fi

echo "watchdog ok"
