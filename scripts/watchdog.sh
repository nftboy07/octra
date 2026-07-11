#!/usr/bin/env bash
# Poll upstream repos; on HEAD change unlock-scan + LPN + Telegram.
set -euo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
STATE_DIR="${BASE}/logs/watchdog"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
mkdir -p "$STATE_DIR" "$WS/candidates/inbox" "$WS/logs"

notify() {
  local msg="$1"
  if [[ -x "$RECON" ]]; then
    "$RECON" telegram test --message "$msg" >/dev/null 2>&1 || true
  fi
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $msg" | tee -a "$STATE_DIR/events.log"
}

react_challenge() {
  local path="$1"
  cp -f "$path/secret.ct" "$path/pk.bin" "$path/params.json" \
        "$path/manifest.json" "$path/SHA256SUMS" "$path/pvac_commit.txt" \
        "$WS/artifacts/" 2>/dev/null || true
  if [[ -x "$RECON" ]]; then
    "$RECON" unlock scan --workspace "$WS" || true
    "$RECON" lpn summary --workspace "$WS" >/dev/null 2>&1 || true
    "$RECON" ops integrity --workspace "$WS" >/dev/null 2>&1 || true
  fi
  # list top-level + suspicious names
  local listing
  listing=$(find "$path" -maxdepth 3 -type f \( \
      -iname '*rku*' -o -iname '*sk*' -o -iname '*prf*' -o -iname '*.bin' -o -iname '*recrypt*' \
    \) ! -path '*/.git/*' 2>/dev/null | head -40 | tr '\n' ' ')
  notify "WATCHDOG challenge react files: ${listing:0:350}"
}

check_repo() {
  local name="$1"
  local path="$2"
  local branch="$3"
  if [[ ! -d "$path/.git" ]]; then
    return 0
  fi
  git -C "$path" fetch origin --quiet 2>/dev/null || return 0
  local old new
  old="$(cat "$STATE_DIR/${name}.head" 2>/dev/null || true)"
  new="$(git -C "$path" rev-parse "origin/${branch}" 2>/dev/null \
    || git -C "$path" rev-parse origin/main 2>/dev/null \
    || git -C "$path" rev-parse HEAD)"
  if [[ -n "$old" && "$old" != "$new" ]]; then
    git -C "$path" checkout --detach --quiet "$new" || true
    local subject
    subject=$(git -C "$path" log -1 --format=%s "$new" 2>/dev/null || echo "")
    notify "WATCHDOG: ${name} ${old:0:7}->${new:0:7} | ${subject:0:120}"
    if [[ "$name" == "hfhe-challenge" ]]; then
      react_challenge "$path"
    fi
    if [[ "$name" == "pvac_hfhe_cpp" ]]; then
      notify "WATCHDOG: pvac moved — diff recrypt/lpn/serialize paths; FURY surface may change."
    fi
    if [[ "$name" == "octra-recon" && -x "$path/.venv/bin/pip" ]]; then
      "$path/.venv/bin/pip" install -q -e "$path" || true
    fi
  fi
  echo "$new" > "$STATE_DIR/${name}.head"
}

check_repo hfhe-challenge "$BASE/repos/hfhe-challenge" main
check_repo pvac_hfhe_cpp "$BASE/repos/pvac_hfhe_cpp" main
check_repo smoke-ui "$BASE/repos/smoke-ui" main
check_repo octra-recon "$BASE/repos/octra-recon" main

# lightweight github API poll (keyword alerts)
if [[ -x "$RECON" ]]; then
  "$RECON" ops github --workspace "$WS" >/dev/null 2>&1 || true
fi

# daily heartbeat if older than 20h
HEART="$STATE_DIR/last_heartbeat"
now=$(date +%s)
if [[ ! -f "$HEART" ]] || [[ $(( now - $(stat -c %Y "$HEART" 2>/dev/null || echo 0) )) -gt 72000 ]]; then
  if [[ -x "$RECON" ]]; then
    "$RECON" ops heartbeat --workspace "$WS" >/dev/null 2>&1 || true
  else
    notify "WATCHDOG heartbeat: recon binary missing"
  fi
  date -u +%Y-%m-%dT%H:%M:%SZ > "$HEART"
fi

echo "watchdog ok"
