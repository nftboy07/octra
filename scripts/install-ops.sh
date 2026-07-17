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
for f in watchdog.sh auto-update.sh integrity-daily.sh ops-cycle.sh archive-monthly.sh install-watchdog.sh install-ops.sh sync-to-vps.sh \
  body-bind-daily.sh claim-hourly.sh tg-poll.sh backup-logs.sh vps-update.sh intel-repos.sh harden-vps.sh final-verification.sh \
  lexicon-daily.sh; do
  if [[ -f "${RECON_SCRIPTS}/${f}" ]]; then
    cp "${RECON_SCRIPTS}/${f}" "${BASE}/scripts/${f}"
  fi
done
mkdir -p "${BASE}/workspace/candidates/s_inbox"
# docs
for d in UNLOCK_RUNBOOK.md SOCIAL_WATCH.md TOKENS_AND_AWS.md OUTPERFORM_WRITEUP.md; do
  if [[ -f "${BASE}/repos/octra-recon/docs/${d}" ]]; then
    cp -f "${BASE}/repos/octra-recon/docs/${d}" "${BASE}/reports/${d}"
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
EnvironmentFile=-/home/ubuntu/.config/octra-recon/social.env
EnvironmentFile=-/home/ubuntu/.config/octra-recon/telegram.env
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

# Primary: full auto-update every 15 minutes (pulls code, artifacts, reacts)
install_pair octra-auto "Octra FULL auto-update (no human)" auto-update.sh 15min 2min
# Keep legacy names pointing at same auto path for compatibility
install_pair octra-watchdog "Octra watchdog wrapper -> auto-update" watchdog.sh 30min 5min
install_pair octra-integrity "Octra daily integrity" integrity-daily.sh 24h 15min
install_pair octra-ops-cycle "Octra ops cycle" ops-cycle.sh 6h 10min
install_pair octra-archive "Octra monthly archive" archive-monthly.sh 730h 30min
install_pair octra-claim "Octra claim-first pipeline" claim-hourly.sh 1h 3min
install_pair octra-bodybind "Octra LPN body-bind check" body-bind-daily.sh 24h 20min
install_pair octra-backup "Octra log backup" backup-logs.sh 24h 40min
install_pair octra-lexicon "Octra GitHub-lexicon deep hunt" lexicon-daily.sh 24h 50min
install_pair octra-tg-poll "Octra Telegram command poll (legacy oneshot)" tg-poll.sh 120s 1min

# Prefer continuous TG poller (always listening; no 120s gaps)
sudo tee /etc/systemd/system/octra-tg-bot.service >/dev/null <<EOF
[Unit]
Description=Octra Telegram bot continuous long-poll
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=${BASE}
Environment=OCTRA_BASE=${BASE}
EnvironmentFile=-/home/ubuntu/.config/octra-recon/social.env
EnvironmentFile=-/home/ubuntu/.config/octra-recon/telegram.env
ExecStart=/bin/bash ${BASE}/scripts/tg-poll.sh loop
Restart=always
RestartSec=5
Nice=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

# stop legacy oneshot poller to avoid getUpdates 409; use continuous bot
sudo systemctl disable --now octra-tg-poll.timer 2>/dev/null || true
sudo systemctl stop octra-tg-poll.service 2>/dev/null || true
sudo systemctl enable --now octra-tg-bot.service || true

# Prime once without blocking this installer on long-running oneshot jobs.
sudo systemctl start --no-block octra-auto.service || true
sudo systemctl start --no-block octra-watchdog.service || true
sudo systemctl start --no-block octra-integrity.service || true
sudo systemctl start --no-block octra-ops-cycle.service || true
sudo systemctl start --no-block octra-claim.service || true

systemctl list-timers 'octra-*' --no-pager || true
systemctl is-active octra-tg-bot.service || true
echo OPS_TIMERS_INSTALLED

# optional harden if present
if [[ -f ${BASE}/scripts/harden-vps.sh ]]; then bash ${BASE}/scripts/harden-vps.sh || true; fi

