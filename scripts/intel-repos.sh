#!/usr/bin/env bash
# Maintain extra intel clones (git protocol — no API rate limit) and report new HEADs.
set -euo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
INTEL="${BASE}/repos/intel"
STATE="${BASE}/logs/watchdog"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
mkdir -p "$INTEL" "$STATE"

notify() {
  local msg="$1"
  if [[ -x "$RECON" ]]; then
    "$RECON" telegram test --message "$msg" >/dev/null 2>&1 || true
  fi
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $msg" | tee -a "$STATE/events.log"
}

clone_or_update() {
  local name="$1"
  local url="$2"
  local dir="$INTEL/$name"
  if [[ ! -d "$dir/.git" ]]; then
    git clone --depth 20 "$url" "$dir" >/dev/null 2>&1 || return 0
  else
    git -C "$dir" fetch origin --quiet 2>/dev/null || return 0
    git -C "$dir" checkout --detach --quiet origin/HEAD 2>/dev/null \
      || git -C "$dir" checkout --detach --quiet origin/main 2>/dev/null \
      || true
  fi
  local new old subject
  new=$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo "")
  [[ -z "$new" ]] && return 0
  old=$(cat "$STATE/intel_${name}.head" 2>/dev/null || true)
  subject=$(git -C "$dir" log -1 --format=%s 2>/dev/null || echo "")
  if [[ -n "$old" && "$old" != "$new" ]]; then
    notify "INTEL git: ${name} ${old:0:7}->${new:0:7} | ${subject:0:140}"
  fi
  echo "$new" > "$STATE/intel_${name}.head"
}

# Official + public research forks/writeups
clone_or_update hfhe-challenge https://github.com/octra-labs/hfhe-challenge.git
clone_or_update pvac_hfhe_cpp https://github.com/octra-labs/pvac_hfhe_cpp.git
clone_or_update wallet-gen https://github.com/octra-labs/wallet-gen.git
clone_or_update smoke-ui https://github.com/smoke-ui/octra-hfhe-v2-security-assessment.git
clone_or_update v1-recovery https://github.com/Iamknownasfesal/octra-hfhe-challenge-recovery.git
clone_or_update nftboy07-octra https://github.com/nftboy07/octra.git

# Discover new public forks of the challenge (uses API only if token set — optional)
if [[ -n "${OCTRA_GITHUB_TOKEN:-}${GITHUB_TOKEN:-}" ]]; then
  token="${OCTRA_GITHUB_TOKEN:-$GITHUB_TOKEN}"
  # shellcheck disable=SC2016
  forks=$(curl -s -H "Authorization: Bearer $token" \
    "https://api.github.com/repos/octra-labs/hfhe-challenge/forks?per_page=10&sort=newest" \
    | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin)
  for f in d[:8]:
    print(f.get("full_name",""), f.get("clone_url",""))
except Exception:
  pass' 2>/dev/null || true)
  while read -r full url; do
    [[ -z "$full" || -z "$url" ]] && continue
    name="fork_${full//\//_}"
    clone_or_update "$name" "$url"
  done <<< "$forks"
fi

echo intel_repos_ok
