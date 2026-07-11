#!/usr/bin/env bash
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
"$RECON" ops archive --workspace "$WS"
# prune archives older than 180 days
find "${BASE}/archives" -type f -name 'octra-investigation-*.tar.gz' -mtime +180 -delete 2>/dev/null || true
echo archive_monthly_ok
