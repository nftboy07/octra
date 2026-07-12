#!/usr/bin/env bash
# FULLY AUTOMATIC: pull everything, install self, sync artifacts, re-run checks, TG.
# No human intervention required. Safe to run every 15–30 minutes.
set -uo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
STATE="${BASE}/logs/auto"
WS="${BASE}/workspace"
RECON_REPO="${BASE}/repos/octra-recon"
export BASE

mkdir -p "$STATE" "$WS/artifacts" "$WS/logs" "$WS/reports" \
  "$WS/candidates/inbox" "$WS/candidates/s_inbox" "$WS/candidates/hits" "$WS/candidates/processed" \
  "$BASE/scripts" "$BASE/reports" "$BASE/logs"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$STATE/auto-update.log"; }

notify() {
  local msg="$1"
  local recon="${RECON_REPO}/.venv/bin/octra-recon"
  if [[ -x "$recon" ]]; then
    "$recon" telegram test --message "$msg" >/dev/null 2>&1 || true
  fi
  log "TG: $msg"
}

fingerprint_tree() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    echo "missing"
    return
  fi
  # stable fingerprint of tracked non-git files (names+sizes+mtimes+sha of small set)
  find "$dir" -type f ! -path '*/.git/*' -printf '%P %s %T@\n' 2>/dev/null | sort | sha256sum | awk '{print $1}'
}

changed_flag=0
note_change() {
  local name="$1"
  local old="$2"
  local new="$3"
  if [[ -n "$old" && "$old" != "$new" ]]; then
    log "CHANGE $name $old -> $new"
    changed_flag=1
    return 0
  fi
  return 1
}

# --- 1) Self-update toolkit FIRST so later steps use new code ---
if [[ -d "${RECON_REPO}/.git" ]]; then
  old=$(git -C "$RECON_REPO" rev-parse HEAD 2>/dev/null || echo "")
  git -C "$RECON_REPO" fetch origin --quiet 2>/dev/null || true
  git -C "$RECON_REPO" reset --hard origin/main --quiet 2>/dev/null || true
  new=$(git -C "$RECON_REPO" rev-parse HEAD 2>/dev/null || echo "")
  if note_change toolkit "$old" "$new"; then
    notify "AUTO: toolkit updated ${old:0:7}->${new:0:7}. Reinstalling..."
    if [[ ! -d "${RECON_REPO}/.venv" ]]; then
      python3 -m venv "${RECON_REPO}/.venv" || true
    fi
    "${RECON_REPO}/.venv/bin/pip" install -q -e "${RECON_REPO}" || true
    # refresh scripts + reinstall timers (idempotent)
    cp -f "${RECON_REPO}/scripts/"*.sh "${BASE}/scripts/" 2>/dev/null || true
    sed -i 's/\r$//' "${BASE}/scripts/"*.sh 2>/dev/null || true
    chmod +x "${BASE}/scripts/"*.sh 2>/dev/null || true
    for d in UNLOCK_RUNBOOK.md SOCIAL_WATCH.md TOKENS_AND_AWS.md OUTPERFORM_WRITEUP.md; do
      [[ -f "${RECON_REPO}/docs/${d}" ]] && cp -f "${RECON_REPO}/docs/${d}" "${BASE}/reports/${d}" || true
    done
    # only reinstall systemd if install-ops present (needs sudo nopasswd which ubuntu has)
    if [[ -x "${BASE}/scripts/install-ops.sh" ]]; then
      bash "${BASE}/scripts/install-ops.sh" >/dev/null 2>&1 || true
    fi
  fi
fi

RECON="${RECON_REPO}/.venv/bin/octra-recon"
if [[ ! -x "$RECON" ]]; then
  log "recon binary missing; attempting create venv"
  python3 -m venv "${RECON_REPO}/.venv" 2>/dev/null || true
  "${RECON_REPO}/.venv/bin/pip" install -q -e "${RECON_REPO}" 2>/dev/null || true
  RECON="${RECON_REPO}/.venv/bin/octra-recon"
fi

# --- 2) Update challenge / pvac / smoke-ui ---
update_repo() {
  local name="$1"
  local path="$2"
  local pin="${3:-}"  # empty = origin/main tip
  [[ -d "$path/.git" ]] || return 0
  local old new
  old=$(git -C "$path" rev-parse HEAD 2>/dev/null || echo "")
  git -C "$path" fetch origin --quiet 2>/dev/null || return 0
  if [[ -n "$pin" ]]; then
    # keep pin unless pin empty; still fetch so we know upstream tip
    git -C "$path" rev-parse "origin/main" >"$STATE/${name}.origin_tip" 2>/dev/null || true
    if [[ "$old" != "$pin" ]]; then
      git -C "$path" checkout --detach --quiet "$pin" 2>/dev/null || true
    fi
    new=$(git -C "$path" rev-parse HEAD 2>/dev/null || echo "")
  else
    new=$(git -C "$path" rev-parse origin/main 2>/dev/null || git -C "$path" rev-parse origin/HEAD 2>/dev/null || echo "$old")
    if [[ -n "$new" && "$new" != "$old" ]]; then
      git -C "$path" checkout --detach --quiet "$new" 2>/dev/null || true
    fi
    new=$(git -C "$path" rev-parse HEAD 2>/dev/null || echo "")
  fi
  if note_change "$name" "$old" "$new"; then
    local subj
    subj=$(git -C "$path" log -1 --format=%s 2>/dev/null || echo "")
    notify "AUTO: ${name} ${old:0:7}->${new:0:7} | ${subj:0:100}"
    echo "$name" >>"$STATE/changed_this_run.txt"
  fi
  echo "$new" >"$STATE/${name}.head"
}

: >"$STATE/changed_this_run.txt"
update_repo hfhe-challenge "${BASE}/repos/hfhe-challenge" ""
update_repo smoke-ui "${BASE}/repos/smoke-ui" ""
# pvac stays on challenge pin unless you change this
update_repo pvac_hfhe_cpp "${BASE}/repos/pvac_hfhe_cpp" "071b0e909c119de815e284b347c4bd979cb59ef3"

# --- 3) Intel forks (git only) ---
if [[ -x "${BASE}/scripts/intel-repos.sh" ]]; then
  bash "${BASE}/scripts/intel-repos.sh" >/dev/null 2>&1 || true
fi

# --- 4) Artifact sync + fingerprint (detect new files even inside same commit rare) ---
CH="${BASE}/repos/hfhe-challenge"
if [[ -d "$CH" ]]; then
  for f in secret.ct pk.bin params.json manifest.json SHA256SUMS pvac_commit.txt README.md; do
    [[ -f "$CH/$f" ]] && cp -f "$CH/$f" "$WS/artifacts/$f" || true
  done
  ln -sfn "$CH/lpn_samples" "$WS/artifacts/lpn_samples"
  ln -sfn "$CH" "$WS/repos/hfhe-challenge"
  ln -sfn "${BASE}/repos/pvac_hfhe_cpp" "$WS/repos/pvac_hfhe_cpp"
  ln -sfn "$RECON_REPO" "$WS/repos/octra-recon"
fi

fp_old=$(cat "$STATE/challenge_fp" 2>/dev/null || true)
fp_new=$(fingerprint_tree "$CH")
echo "$fp_new" >"$STATE/challenge_fp"
lpn_old=$(cat "$STATE/lpn_fp" 2>/dev/null || true)
lpn_new=$(fingerprint_tree "$CH/lpn_samples")
echo "$lpn_new" >"$STATE/lpn_fp"

challenge_changed=0
lpn_changed=0
if [[ -n "$fp_old" && "$fp_old" != "$fp_new" ]]; then
  challenge_changed=1
  changed_flag=1
  notify "AUTO: challenge tree fingerprint changed (new/updated files on disk)"
fi
if [[ -n "$lpn_old" && "$lpn_old" != "$lpn_new" ]]; then
  lpn_changed=1
  changed_flag=1
  notify "AUTO: lpn_samples fingerprint changed — re-verifying"
fi

# --- 5) Always-light pipeline; heavy only on change ---
if [[ -x "$RECON" ]]; then
  "$RECON" init --workspace "$WS" >/dev/null 2>&1 || true

  # always: social + claim + dashboard (cheap enough)
  "$RECON" ops social --workspace "$WS" >/dev/null 2>&1 || true
  # Auto-digest competitor/research repo advances (no human paste of TG alerts)
  "$RECON" intel digest --workspace "$WS" >/dev/null 2>&1 || true
  "$RECON" claim run --workspace "$WS" >/dev/null 2>&1 || true
  "$RECON" dashboard build --workspace "$WS" >/dev/null 2>&1 || true

  # GitHub-lexicon hunter: standard pass every ~6h; deep once/day
  # Mines BIP39∩local clones + brainwallet hashes (NOT 2^128 brute force)
  LEX_ST="$STATE/last_lexicon"
  LEX_DEEP="$STATE/last_lexicon_deep"
  STACK_ST="$STATE/last_stack"
  now_ts=$(date +%s)

  # Structural public-surface stack (wire/mask/rng) every 6h or on change
  run_stack=0
  if [[ ! -f "$STACK_ST" ]] || [[ $(( now_ts - $(stat -c %Y "$STACK_ST" 2>/dev/null || echo 0) )) -gt 21600 ]]; then
    run_stack=1
  fi
  if grep -qE 'smoke-ui|hfhe-challenge|pvac' "$STATE/changed_this_run.txt" 2>/dev/null; then
    run_stack=1
  fi
  if [[ "$run_stack" == "1" ]]; then
    log "full structural stack (no heavy lexicon/race)"
    out=$("$RECON" stack run --workspace "$WS" --no-lexicon --no-race 2>/dev/null || true)
    date -u +%Y-%m-%dT%H:%M:%SZ >"$STACK_ST"
    if echo "$out" | grep -qiE 'claim_ready.: true|"alert": true|UNLOCK|CRITICAL|WIRE ALERT|RNG ALERT'; then
      notify "AUTO STACK ALERT — check logs/full_stack.json and claim path"
    else
      log "stack structural ok"
    fi
  fi
  run_lex=0
  run_lex_deep=0
  if [[ ! -f "$LEX_ST" ]] || [[ $(( now_ts - $(stat -c %Y "$LEX_ST" 2>/dev/null || echo 0) )) -gt 21600 ]]; then
    run_lex=1
  fi
  if [[ ! -f "$LEX_DEEP" ]] || [[ $(( now_ts - $(stat -c %Y "$LEX_DEEP" 2>/dev/null || echo 0) )) -gt 86400 ]]; then
    run_lex_deep=1
  fi
  # also re-run standard lexicon when intel/repos moved
  if grep -qE 'smoke-ui|hfhe-challenge|intel|nftboy' "$STATE/changed_this_run.txt" 2>/dev/null; then
    run_lex=1
  fi
  if [[ "$run_lex_deep" == "1" && -x "$RECON" ]]; then
    log "lexicon deep hunt starting"
    # ~25k × ~100ms pure-Python Ed25519 ≈ 40min; cache skips prior work
    out=$("$RECON" lexicon run --workspace "$WS" --deep --max-candidates 25000 2>/dev/null || true)
    date -u +%Y-%m-%dT%H:%M:%SZ >"$LEX_DEEP"
    date -u +%Y-%m-%dT%H:%M:%SZ >"$LEX_ST"
    if echo "$out" | grep -qiE '"hits":\s*[1-9]'; then
      notify "CRITICAL: GitHub-lexicon HIT — check candidates/hits/ and claim path NOW"
    else
      tested=$(echo "$out" | python3 -c 'import sys,json
try:
 d=json.load(sys.stdin); print(d.get("tested",0), d.get("cache_size",0))
except Exception:
 print(0,0)' 2>/dev/null || echo "0 0")
      log "lexicon deep done tested_cache=${tested} hits=0"
    fi
  elif [[ "$run_lex" == "1" && -x "$RECON" ]]; then
    log "lexicon standard hunt starting"
    out=$("$RECON" lexicon run --workspace "$WS" --max-candidates 8000 2>/dev/null || true)
    date -u +%Y-%m-%dT%H:%M:%SZ >"$LEX_ST"
    if echo "$out" | grep -qiE '"hits":\s*[1-9]'; then
      notify "CRITICAL: GitHub-lexicon HIT — check candidates/hits/ and claim path NOW"
    else
      log "lexicon standard done hits=0"
    fi
  fi

  # process candidate drops
  for sf in "$WS/candidates/s_inbox"/*; do
    [[ -f "$sf" ]] || continue
    out=$("$RECON" race score-s --workspace "$WS" --s-file "$sf" 2>/dev/null || true)
    if echo "$out" | grep -q LIKELY_TRUE_SHARED_S; then
      notify "AUTO CRITICAL: TRUE S candidate $(basename "$sf")"
      mv "$sf" "$WS/candidates/hits/S_$(basename "$sf")" 2>/dev/null || true
    else
      mv "$sf" "$WS/candidates/processed/S_$(basename "$sf")" 2>/dev/null || true
    fi
  done

  if [[ "$challenge_changed" == "1" || "$lpn_changed" == "1" || -s "$STATE/changed_this_run.txt" ]]; then
    notify "AUTO: running full reaction pipeline..."
    "$RECON" unlock scan --workspace "$WS" >/dev/null 2>&1 || true
    "$RECON" lpn summary --workspace "$WS" >/dev/null 2>&1 || true
    "$RECON" lpn verify --workspace "$WS" >/dev/null 2>&1 || true
    "$RECON" ops integrity --workspace "$WS" >/dev/null 2>&1 || true
    "$RECON" intel digest --workspace "$WS" >/dev/null 2>&1 || true
    # body bind on LPN change
    if [[ "$lpn_changed" == "1" ]]; then
      bash "${BASE}/scripts/body-bind-daily.sh" >/dev/null 2>&1 || true
    fi
    # deep audit only when LPN fingerprint changes (slow ~10min) — background
    if [[ "$lpn_changed" == "1" ]]; then
      if [[ ! -f "$STATE/audit_running" ]]; then
        touch "$STATE/audit_running"
        (
          "$RECON" lpn audit --workspace "$WS" >"$BASE/logs/auto_lpn_audit.json" 2>&1 || true
          rm -f "$STATE/audit_running"
          notify "AUTO: deep LPN audit finished after sample change"
        ) &
        disown || true
        notify "AUTO: deep LPN audit started in background"
      fi
    fi
    # competitor research change (smoke-ui etc.): re-pull intel + race notes
    if grep -q smoke-ui "$STATE/changed_this_run.txt" 2>/dev/null; then
      notify "AUTO: smoke-ui research moved — digest written; bounty path check running"
      "$RECON" race run --workspace "$WS" >/dev/null 2>&1 || true
    fi
    "$RECON" claim run --workspace "$WS" >/dev/null 2>&1 || true
    notify "AUTO: reaction pipeline complete"
  fi
fi

# --- 6) Quiet heartbeat every 12h ---
HB="$STATE/last_heartbeat"
now=$(date +%s)
if [[ ! -f "$HB" ]] || [[ $(( now - $(stat -c %Y "$HB" 2>/dev/null || echo 0) )) -gt 43200 ]]; then
  h1=$(git -C "$CH" log -1 --format=%h 2>/dev/null || echo '?')
  h2=$(git -C "$RECON_REPO" log -1 --format=%h 2>/dev/null || echo '?')
  notify "AUTO heartbeat: alive challenge=${h1} toolkit=${h2} changes=${changed_flag}"
  date -u +%Y-%m-%dT%H:%M:%SZ >"$HB"
fi

log "auto-update done changed=${changed_flag}"
echo AUTO_UPDATE_OK
