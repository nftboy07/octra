#!/usr/bin/env bash
# Final hardening for multi-month unattended Octra lab VPS.
set -euo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"

echo "=== swap (2G) if missing ==="
if ! swapon --show | grep -q .; then
  if [[ ! -f /swapfile ]]; then
    sudo fallocate -l 2G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
  fi
  sudo swapon /swapfile || true
  if ! grep -q '/swapfile' /etc/fstab 2>/dev/null; then
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
  fi
fi
free -h

echo "=== logrotate ==="
sudo tee /etc/logrotate.d/octra-investigation >/dev/null <<'EOF'
/home/ubuntu/octra_investigation/logs/*.log
/home/ubuntu/octra_investigation/logs/watchdog/*.log
/home/ubuntu/octra_investigation/workspace/logs/*.json {
  weekly
  rotate 12
  compress
  missingok
  notifempty
  copytruncate
  maxsize 20M
}
EOF

echo "=== cron fallback (if systemd timer stalls) ==="
# hourly light check: if watchdog events older than 6h, force watchdog
CRON_LINE="17 * * * * OCTRA_BASE=${BASE} /bin/bash ${BASE}/scripts/watchdog.sh >> ${BASE}/logs/cron-watchdog.log 2>&1"
( crontab -l 2>/dev/null | grep -v 'scripts/watchdog.sh' || true; echo "$CRON_LINE" ) | crontab -
crontab -l

echo "=== ensure dirs ==="
mkdir -p "${BASE}/logs/watchdog" "${BASE}/archives" \
  "${WS}/candidates/inbox" "${WS}/candidates/processed" "${WS}/candidates/hits" \
  "${WS}/reports" "${BASE}/reports"

echo "=== disk pressure note ==="
df -h /

echo HARDEN_OK
