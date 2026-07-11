#!/usr/bin/env bash
# Sync all investigation code/repos on the VPS to latest known-good state.
set -euo pipefail

BASE=/home/ubuntu/octra_investigation
mkdir -p "$BASE"/{artifacts,logs,reports,repos,workspace}

echo "=== SYNC octra-recon (toolkit) ==="
cd "$BASE/repos/octra-recon"
git fetch origin
git reset --hard origin/main
git clean -fd -e .venv 2>/dev/null || true
rm -rf src/octra_recon.egg-info
git log -1 --oneline
git status -sb

echo "=== SYNC hfhe-challenge ==="
cd "$BASE/repos/hfhe-challenge"
git fetch origin
if ! git pull --ff-only; then
  git reset --hard origin/main
fi
git log -1 --oneline

echo "=== SYNC pvac_hfhe_cpp (pin 071b0e9) ==="
cd "$BASE/repos/pvac_hfhe_cpp"
git fetch origin
git checkout 071b0e909c119de815e284b347c4bd979cb59ef3
git log -1 --oneline

echo "=== SYNC smoke-ui ==="
cd "$BASE/repos/smoke-ui"
git fetch origin
if ! git pull --ff-only; then
  git reset --hard origin/main
fi
git log -1 --oneline

echo "=== REINSTALL toolkit ==="
cd "$BASE/repos/octra-recon"
python3 -m venv .venv
.venv/bin/pip install -q -U pip
.venv/bin/pip install -q -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/octra-recon --help | head -40

echo "=== REFRESH workspace ==="
WS="$BASE/workspace"
mkdir -p "$WS"/{artifacts,logs,reports,repos}
.venv/bin/octra-recon init --workspace "$WS"
cp -f "$BASE/repos/hfhe-challenge/secret.ct" \
      "$BASE/repos/hfhe-challenge/pk.bin" \
      "$BASE/repos/hfhe-challenge/params.json" \
      "$BASE/repos/hfhe-challenge/manifest.json" \
      "$BASE/repos/hfhe-challenge/SHA256SUMS" \
      "$BASE/repos/hfhe-challenge/pvac_commit.txt" \
      "$BASE/repos/hfhe-challenge/README.md" \
      "$WS/artifacts/" 2>/dev/null || true
# also keep a copy under BASE/artifacts
cp -f "$WS/artifacts/"* "$BASE/artifacts/" 2>/dev/null || true
ln -sfn "$BASE/repos/hfhe-challenge/lpn_samples" "$WS/artifacts/lpn_samples"
ln -sfn "$BASE/repos/hfhe-challenge/lpn_samples" "$BASE/artifacts/lpn_samples"
ln -sfn "$BASE/repos/hfhe-challenge" "$WS/repos/hfhe-challenge"
ln -sfn "$BASE/repos/pvac_hfhe_cpp" "$WS/repos/pvac_hfhe_cpp"
ln -sfn "$BASE/repos/octra-recon" "$WS/repos/octra-recon"
if [ -f "$BASE/reports/OPEN_SURFACE.md" ]; then
  cp -f "$BASE/reports/OPEN_SURFACE.md" "$WS/reports/OPEN_SURFACE.md"
fi

echo "=== QUICK LPN VERIFY ==="
.venv/bin/octra-recon lpn verify --workspace "$WS" | tail -30

echo "=== HEAD COMMITS ==="
for d in octra-recon hfhe-challenge pvac_hfhe_cpp smoke-ui; do
  echo -n "$d: "
  git -C "$BASE/repos/$d" log -1 --oneline
done

echo "=== REPOS TREE ==="
ls -la "$BASE/repos/"

# Notify Telegram if configured for this user (ubuntu)
RECON_BIN="$BASE/repos/octra-recon/.venv/bin/octra-recon"
if [[ -x "$RECON_BIN" ]]; then
  HOST_IP="$(curl -s --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo unknown)"
  MSG="Octra VPS sync complete on ${HOST_IP}. toolkit=$(git -C "$BASE/repos/octra-recon" log -1 --format=%h) challenge=$(git -C "$BASE/repos/hfhe-challenge" log -1 --format=%h)"
  "$RECON_BIN" telegram test --message "$MSG" || true
fi

echo SYNC_COMPLETE
