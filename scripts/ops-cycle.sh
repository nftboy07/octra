#!/usr/bin/env bash
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
# Prefer full auto-update; fall back to ops cycle only
if [[ -x "${BASE}/scripts/auto-update.sh" ]]; then
  bash "${BASE}/scripts/auto-update.sh"
else
  RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
  WS="${BASE}/workspace"
  mkdir -p "$WS/candidates/inbox"
  "$RECON" ops cycle --workspace "$WS" || true
fi
echo ops_cycle_ok
