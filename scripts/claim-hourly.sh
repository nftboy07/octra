#!/usr/bin/env bash
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
export BASE
"$RECON" claim run --workspace "$WS" || true
"$RECON" dashboard build --workspace "$WS" || true
echo claim_hourly_ok
