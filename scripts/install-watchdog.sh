#!/usr/bin/env bash
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
UNIT_DIR=/etc/systemd/system

sudo tee "$UNIT_DIR/octra-watchdog.service" >/dev/null <<EOF
[Unit]
Description=Octra HFHE challenge git watchdog
After=network-online.target

[Service]
Type=oneshot
User=ubuntu
WorkingDirectory=${BASE}
Environment=OCTRA_BASE=${BASE}
ExecStart=/bin/bash ${BASE}/scripts/watchdog.sh
Nice=10
EOF

sudo tee "$UNIT_DIR/octra-watchdog.timer" >/dev/null <<EOF
[Unit]
Description=Run Octra watchdog every 2 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=2h
Persistent=true
Unit=octra-watchdog.service

[Install]
WantedBy=timers.target
EOF

# install script copies
mkdir -p "${BASE}/scripts"
if [[ -f /home/ubuntu/octra_investigation/repos/octra-recon/scripts/watchdog.sh ]]; then
  cp /home/ubuntu/octra_investigation/repos/octra-recon/scripts/watchdog.sh "${BASE}/scripts/watchdog.sh"
fi
chmod +x "${BASE}/scripts/watchdog.sh" 2>/dev/null || true

sudo systemctl daemon-reload
sudo systemctl enable --now octra-watchdog.timer
sudo systemctl start octra-watchdog.service || true
systemctl list-timers octra-watchdog.timer --no-pager
echo WATCHDOG_INSTALLED
