#!/usr/bin/env bash
# Full VPS maintenance: pull code, reinstall timers, intel repos, health checks.
set -euo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON_REPO="${BASE}/repos/octra-recon"
RECON="${RECON_REPO}/.venv/bin/octra-recon"
WS="${BASE}/workspace"

echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) VPS UPDATE START ==="

mkdir -p "${BASE}/scripts" "${BASE}/logs" "${BASE}/reports" "${BASE}/archives" \
  "${WS}/candidates/inbox" "${WS}/candidates/processed" "${WS}/candidates/hits" \
  "${WS}/logs" "${WS}/reports" "${BASE}/repos/intel"

echo "=== pull toolkit ==="
cd "${RECON_REPO}"
git fetch origin
git reset --hard origin/main
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
.venv/bin/pip install -q -U pip
.venv/bin/pip install -q -e .

echo "=== install scripts ==="
cp -f scripts/* "${BASE}/scripts/" 2>/dev/null || true
sed -i 's/\r$//' "${BASE}/scripts/"*.sh 2>/dev/null || true
chmod +x "${BASE}/scripts/"*.sh 2>/dev/null || true

# docs
if [[ -f docs/UNLOCK_RUNBOOK.md ]]; then
  cp -f docs/UNLOCK_RUNBOOK.md "${BASE}/reports/UNLOCK_RUNBOOK.md"
  cp -f docs/UNLOCK_RUNBOOK.md "${WS}/reports/UNLOCK_RUNBOOK.md" 2>/dev/null || true
fi
if [[ -f docs/SOCIAL_WATCH.md ]]; then
  cp -f docs/SOCIAL_WATCH.md "${BASE}/reports/SOCIAL_WATCH.md"
fi

echo "=== sync main challenge/pvac/smoke-ui ==="
for pair in \
  "hfhe-challenge|https://github.com/octra-labs/hfhe-challenge.git" \
  "pvac_hfhe_cpp|https://github.com/octra-labs/pvac_hfhe_cpp.git" \
  "smoke-ui|https://github.com/smoke-ui/octra-hfhe-v2-security-assessment.git"
do
  name="${pair%%|*}"
  url="${pair##*|}"
  dir="${BASE}/repos/${name}"
  if [[ ! -d "${dir}/.git" ]]; then
    git clone --depth 1 "${url}" "${dir}" || true
  else
    git -C "${dir}" fetch origin --quiet || true
    if [[ "${name}" == "pvac_hfhe_cpp" ]]; then
      git -C "${dir}" checkout --detach --quiet 071b0e909c119de815e284b347c4bd979cb59ef3 || true
    else
      git -C "${dir}" checkout --detach --quiet origin/main 2>/dev/null \
        || git -C "${dir}" pull --ff-only || true
    fi
  fi
done

# refresh workspace artifacts from challenge
CH="${BASE}/repos/hfhe-challenge"
if [[ -d "${CH}" ]]; then
  cp -f "${CH}/secret.ct" "${CH}/pk.bin" "${CH}/params.json" \
        "${CH}/manifest.json" "${CH}/SHA256SUMS" "${CH}/pvac_commit.txt" \
        "${WS}/artifacts/" 2>/dev/null || true
  ln -sfn "${CH}/lpn_samples" "${WS}/artifacts/lpn_samples"
  ln -sfn "${CH}" "${WS}/repos/hfhe-challenge"
  ln -sfn "${BASE}/repos/pvac_hfhe_cpp" "${WS}/repos/pvac_hfhe_cpp"
  ln -sfn "${RECON_REPO}" "${WS}/repos/octra-recon"
fi

echo "=== reinstall ops timers ==="
bash "${BASE}/scripts/install-ops.sh" || true

echo "=== intel repos ==="
bash "${BASE}/scripts/intel-repos.sh" || true

echo "=== health checks ==="
"${RECON}" init --workspace "${WS}" >/dev/null || true
"${RECON}" telegram status || true
"${RECON}" lpn summary --workspace "${WS}" > "${BASE}/logs/post_update_lpn.json" 2>&1 || true
"${RECON}" unlock scan --workspace "${WS}" > "${BASE}/logs/post_update_unlock.json" 2>&1 || true
"${RECON}" ops integrity --workspace "${WS}" > "${BASE}/logs/post_update_integrity.json" 2>&1 || true
"${RECON}" ops social --workspace "${WS}" > "${BASE}/logs/post_update_social.json" 2>&1 || true

# compact status file
{
  echo "# VPS update status"
  echo
  echo "- time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- toolkit: $(git -C "${RECON_REPO}" log -1 --format='%h %s')"
  echo "- challenge: $(git -C "${BASE}/repos/hfhe-challenge" log -1 --format='%h %s' 2>/dev/null || echo missing)"
  echo "- pvac: $(git -C "${BASE}/repos/pvac_hfhe_cpp" log -1 --format='%h %s' 2>/dev/null || echo missing)"
  echo "- reboot_required: $(test -f /var/run/reboot-required && echo yes || echo no)"
  echo "- timers:"
  systemctl list-timers 'octra-*' --no-pager 2>/dev/null || true
  echo
  echo "- telegram: $(${RECON} telegram status 2>/dev/null | tr -d '\n' || true)"
} | tee "${BASE}/reports/VPS_UPDATE_STATUS.md"

"${RECON}" telegram test --message "VPS UPDATE complete. toolkit=$(git -C ${RECON_REPO} log -1 --format=%h). timers reinstalled. health checks ran. reboot_required=$(test -f /var/run/reboot-required && echo yes || echo no)." || true

echo "=== VPS UPDATE DONE ==="
