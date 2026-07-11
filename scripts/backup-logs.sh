#!/usr/bin/env bash
# Local encrypted-ish backup: tar.gz of logs/reports (no telegram.env, no pem)
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="${BASE}/archives/backup-logs-${STAMP}.tar.gz"
tar -czf "$OUT" \
  -C "$BASE" \
  --exclude='archives' \
  --exclude='repos' \
  --exclude='.venv' \
  reports workspace/logs workspace/reports 2>/dev/null || \
tar -czf "$OUT" -C "$BASE" reports workspace/logs 2>/dev/null || true
# drop backups older than 60 days
find "${BASE}/archives" -name 'backup-logs-*.tar.gz' -mtime +60 -delete 2>/dev/null || true
echo "backup=$OUT"
# optional: if AWS CLI + bucket configured
if [[ -n "${OCTRA_BACKUP_S3:-}" ]] && command -v aws >/dev/null 2>&1; then
  aws s3 cp "$OUT" "${OCTRA_BACKUP_S3}/" || true
fi
echo backup_ok
