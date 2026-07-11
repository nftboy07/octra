#!/usr/bin/env bash
# Install all 24x7 systemd timers for Octra investigation ops.
set -euo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
UNIT_DIR=/etc/systemd/system
RECON_SCRIPTS="${BASE}/repos/octra-recon/scripts"

mkdir -p "${BASE}/scripts" "${BASE}/logs" "${BASE}/archives" \
  "${BASE}/workspace/candidates/inbox" \
  "${BASE}/workspace/candidates/processed" \
  "${BASE}/workspace/candidates/hits" \
  "${BASE}/workspace/reports" \
  "${BASE}/reports"

# copy scripts from toolkit repo
for f in watchdog.sh integrity-daily.sh ops-cycle.sh archive-monthly.sh install-watchdog.sh install-ops.sh sync-to-vps.sh; do
  if [[ -f "${RECON_SCRIPTS}/${f}" ]]; then
    cp "${RECON_SCRIPTS}/${f}" "${BASE}/scripts/${f}"
  fi
done
# runbook
if [[ -f "${BASE}/repos/octra-recon/docs/UNLOCK_RUNBOOK.md" ]]; then
  cp "${BASE}/repos/octra-recon/docs/UNLOCK_RUNBOOK.md" "${BASE}/reports/UNLOCK_RUNBOOK.md"
  cp "${BASE}/repos/octra-recon/docs/UNLOCK_RUNBOOK.md" "${BASE}/workspace/reports/UNLOCK_RUNBOOK.md" 2>/dev/null || true
fi
chmod +x "${BASE}/scripts/"*.sh 2>/dev/null || true
sed -i 's/\r$//' "${BASE}/scripts/"*.sh 2>/dev/null || true

install_pair() {
  local name="$1"
  local desc="$2"
  local script="$3"
  local interval="$4"
  local boot="$5"

  sudo tee "$UNIT_DIR/${name}.service" >/dev/null <<EOF
[Unit]
Description=${desc}
After=network-online.target

[Service]
Type=oneshot
User=ubuntu
WorkingDirectory=${BASE}
Environment=OCTRA_BASE=${BASE}
ExecStart=/bin/bash ${BASE}/scripts/${script}
Nice=10
EOF

  sudo tee "$UNIT_DIR/${name}.timer" >/dev/null <<EOF
[Unit]
Description=${desc} timer

[Timer]
OnBootSec=${boot}
OnUnitActiveSec=${interval}
Persistent=true
Unit=${name}.service

[Install]
WantedBy=timers.target
EOF

  sudo systemctl enable --now "${name}.timer"
}

install_pair octra-watchdog "Octra git watchdog + github poll" watchdog.sh 2h 5min
install_pair octra-integrity "Octra daily integrity" integrity-daily.sh 24h 15min
install_pair octra-ops-cycle "Octra ops cycle" ops-cycle.sh 6h 10min
install_pair octra-archive "Octra monthly archive" archive-monthly.sh 730h 30min

sudo systemctl daemon-reload

# prime once
sudo systemctl start octra-watchdog.service || true
sudo systemctl start octra-integrity.service || true
sudo systemctl start octra-ops-cycle.service || true

systemctl list-timers 'octra-*' --no-pager || true
echo OPS_TIMERS_INSTALLED
