#!/usr/bin/env bash
# Thin wrapper: full automatic update is the source of truth.
set -uo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
if [[ -x "${BASE}/scripts/auto-update.sh" ]]; then
  bash "${BASE}/scripts/auto-update.sh"
elif [[ -x "${BASE}/repos/octra-recon/scripts/auto-update.sh" ]]; then
  bash "${BASE}/repos/octra-recon/scripts/auto-update.sh"
else
  echo "auto-update.sh missing" >&2
  exit 1
fi
