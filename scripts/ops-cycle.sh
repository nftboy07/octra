#!/usr/bin/env bash
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
mkdir -p "$WS/candidates/inbox"
"$RECON" ops cycle --workspace "$WS"
echo ops_cycle_ok
