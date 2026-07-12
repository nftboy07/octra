#!/usr/bin/env bash
# Daily deep GitHub-lexicon hunt (BIP39 ∩ local clones + brainwallet hashes).
# Not a 2^128 search. Safe to run via cron/systemd.
set -uo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
WS="${BASE}/workspace"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
LOG="${BASE}/logs/lexicon-daily.log"
mkdir -p "$(dirname "$LOG")" "$WS/logs" "$WS/candidates/hits"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

if [[ ! -x "$RECON" ]]; then
  log "recon missing"
  exit 0
fi

# refresh intel clones first if script present
if [[ -x "${BASE}/scripts/intel-repos.sh" ]]; then
  bash "${BASE}/scripts/intel-repos.sh" >>"$LOG" 2>&1 || true
fi

log "deep lexicon start"
out=$("$RECON" lexicon run --workspace "$WS" --deep --max-candidates 25000 2>&1) || true
echo "$out" >>"$LOG"
printf '%s\n' "$out" >"${BASE}/logs/lexicon_latest.json" 2>/dev/null || true

if echo "$out" | grep -qiE '"hits":\s*[1-9]'; then
  "$RECON" telegram test --message "CRITICAL LEXICON HIT — candidates/hits/ — claim NOW" >/dev/null 2>&1 || true
  log "HIT"
else
  tested=$(echo "$out" | python3 -c 'import sys,json,re
t=sys.stdin.read()
try:
 d=json.loads(t); print(d.get("tested",0), "cache", d.get("cache_size",0))
except Exception:
 m=re.search(r"\"tested\":\s*(\d+)", t); print(m.group(1) if m else 0)' 2>/dev/null || echo 0)
  log "done tested=${tested} hits=0"
fi
echo LEXICON_DAILY_OK
