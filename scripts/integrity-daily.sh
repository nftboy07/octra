#!/usr/bin/env bash
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
"$RECON" ops integrity --workspace "$WS"
"$RECON" unlock scan --workspace "$WS" || true
echo integrity_daily_ok
