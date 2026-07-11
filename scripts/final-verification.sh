#!/usr/bin/env bash
# One-shot: everything we can verify before leaving the lab to chance.
set -euo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
CH="${BASE}/repos/hfhe-challenge"
REPORT="${BASE}/reports/FINAL_STATUS.md"
BIND=/tmp/verify_lpn_binding

mkdir -p "${BASE}/reports" "${BASE}/logs"

{
  echo "# FINAL STATUS — Octra HFHE Challenge v2 lab"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Host: $(hostname) / $(curl -s --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo no-meta)"
  echo
  echo "## Goal"
  echo
  echo "- Wallet: \`octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ\`"
  echo "- Reward: 1,000,000 OCT if private key / plaintext recovered"
  echo "- Strategy: 24x7 unlock sensor + instant wallet verify (not 2^128 brute force)"
  echo
  echo "## Pins"
  echo
  for r in octra-recon hfhe-challenge pvac_hfhe_cpp smoke-ui; do
    echo "- \`$r\`: \`$(git -C "$BASE/repos/$r" log -1 --format='%h %s' 2>/dev/null || echo missing)\`"
  done
  echo
  echo "## Automated jobs"
  echo
  systemctl list-timers 'octra-*' --no-pager 2>/dev/null || true
  echo
  echo "## Verification results"
  echo
} > "$REPORT"

run_json() {
  local title="$1"
  shift
  echo "### $title" >> "$REPORT"
  echo '```' >> "$REPORT"
  if "$@" >> "$REPORT" 2>&1; then
    echo "(exit 0)" >> "$REPORT"
  else
    echo "(exit $?)" >> "$REPORT"
  fi
  echo '```' >> "$REPORT"
  echo >> "$REPORT"
}

# Core CLI suite
run_json "Telegram status" "$RECON" telegram status
run_json "LPN summary" "$RECON" lpn summary --workspace "$WS"
run_json "Unlock scan" "$RECON" unlock scan --workspace "$WS"
run_json "Ops integrity" "$RECON" ops integrity --workspace "$WS"
run_json "Ops heartbeat" "$RECON" ops heartbeat --workspace "$WS"
run_json "Ops github poll" "$RECON" ops github --workspace "$WS"
run_json "Hypotheses (cheap)" "$RECON" hypotheses run --workspace "$WS"
run_json "Surface status" "$RECON" surface status --workspace "$WS"
run_json "Ops cycle" "$RECON" ops cycle --workspace "$WS"
run_json "Archive snapshot" "$RECON" ops archive --workspace "$WS"

# Binding tool if present / rebuild
if [[ ! -x "$BIND" ]]; then
  if command -v g++ >/dev/null 2>&1; then
    g++ -std=c++17 -O2 -maes -mpclmul -march=native \
      -I"$BASE/repos/pvac_hfhe_cpp/include" -I"$CH/source" \
      "$CH/source/tools/verify_lpn_sample_binding.cpp" -o "$BIND" 2>>"$REPORT" || true
  fi
fi

if [[ -x "$BIND" ]]; then
  ok=0
  for f in "$CH"/lpn_samples/*.jsonl; do
    if "$BIND" "$CH/pk.bin" "$CH/secret.ct" "$f" >/dev/null 2>&1; then
      ok=$((ok + 1))
    fi
  done
  {
    echo "### LPN official binding"
    echo
    echo "- Result: **${ok}/44** binding=1"
    echo
  } >> "$REPORT"
else
  echo "### LPN official binding" >> "$REPORT"
  echo "- Skipped (compiler/binary unavailable)" >> "$REPORT"
  echo >> "$REPORT"
fi

{
  echo "## Blocking truth (unchanged)"
  echo
  echo "1. No R_com oracle in v2"
  echo "2. Independent dual masks"
  echo "3. LPN samples = r1 only; need prf_k for decrypt"
  echo "4. BIP39 128-bit entropy — not brute-forceable here"
  echo "5. FURY needs public Rku (not in package at pin 071b0e9)"
  echo
  echo "## What is in God's hands"
  echo
  echo "- Octra publishing Rku / prf_k / second CT / real wire bug"
  echo "- Any external cryptanalytic breakthrough"
  echo
  echo "## What this lab will do without you"
  echo
  echo "- Watch GitHub every 2h (+ hourly cron fallback)"
  echo "- Integrity daily, ops cycle 6h, archive monthly"
  echo "- Telegram on unlock signals, commits, candidate hits"
  echo "- Verify any mnemonic dropped in candidates/inbox"
  echo
  echo "## Claim path (if hit)"
  echo
  echo "1. \`octra-recon wallet check --mnemonic \"...\"\`"
  echo "2. Octra web client + recovered instructions"
  echo "3. Contact dev@octra.org for second 500k"
  echo "4. Do not post mnemonic publicly"
  echo
  echo "---"
  echo "Lab complete. Rest is waiting for unlock material."
} >> "$REPORT"

cp -f "$REPORT" "$WS/reports/FINAL_STATUS.md" 2>/dev/null || true

if [[ -x "$RECON" ]]; then
  "$RECON" telegram test --message "FINAL VERIFICATION complete. Report: reports/FINAL_STATUS.md. 24x7 sensors armed. Unlock path only. Rest is patience." || true
fi

echo "Wrote $REPORT"
cat "$REPORT" | head -80
echo FINAL_VERIFICATION_OK
