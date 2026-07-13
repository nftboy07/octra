#!/usr/bin/env bash
# Mirror ALL public repos from octra-labs + lambda0xE (+ known research forks).
# Git-only (no API required for static list); optional API discovery expands the set.
set -euo pipefail

BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
INTEL="${BASE}/repos/intel"
STATE="${BASE}/logs/watchdog"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
mkdir -p "$INTEL" "$STATE" "$BASE/repos" "$BASE/logs"

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
  local depth="${3:-30}"
  local dir="$INTEL/$name"
  if [[ ! -d "$dir/.git" ]]; then
    echo "clone $name ..."
    git clone --depth "$depth" "$url" "$dir" >/dev/null 2>&1 || {
      echo "clone_fail $name"
      return 0
    }
  else
    git -C "$dir" fetch origin --depth "$depth" --quiet 2>/dev/null || true
    git -C "$dir" checkout --detach --quiet origin/HEAD 2>/dev/null \
      || git -C "$dir" checkout --detach --quiet origin/main 2>/dev/null \
      || git -C "$dir" checkout --detach --quiet origin/master 2>/dev/null \
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
  echo "ok $name ${new:0:7}"
}

# Also keep primary challenge tree under BASE/repos (not only intel/)
sync_primary() {
  local name="$1"
  local url="$2"
  local pin="${3:-}"
  local dir="$BASE/repos/$name"
  if [[ ! -d "$dir/.git" ]]; then
    git clone --depth 50 "$url" "$dir" >/dev/null 2>&1 || return 0
  else
    git -C "$dir" fetch origin --quiet 2>/dev/null || true
    if [[ -n "$pin" ]]; then
      git -C "$dir" checkout --detach --quiet "$pin" 2>/dev/null || true
    else
      local tip
      tip=$(git -C "$dir" rev-parse origin/main 2>/dev/null \
        || git -C "$dir" rev-parse origin/HEAD 2>/dev/null || echo "")
      [[ -n "$tip" ]] && git -C "$dir" checkout --detach --quiet "$tip" 2>/dev/null || true
    fi
  fi
  echo "primary $name $(git -C "$dir" rev-parse --short HEAD 2>/dev/null || echo '?')"
}

echo "=== primary challenge trees ==="
sync_primary hfhe-challenge https://github.com/octra-labs/hfhe-challenge.git
sync_primary pvac_hfhe_cpp https://github.com/octra-labs/pvac_hfhe_cpp.git "071b0e909c119de815e284b347c4bd979cb59ef3"
sync_primary wallet-gen https://github.com/octra-labs/wallet-gen.git

echo "=== octra-labs (all public) ==="
# Every public org repo (as of 2026-07)
clone_or_update octra-labs_hfhe-challenge https://github.com/octra-labs/hfhe-challenge.git 50
clone_or_update octra-labs_pvac_hfhe_cpp https://github.com/octra-labs/pvac_hfhe_cpp.git 50
clone_or_update octra-labs_wallet-gen https://github.com/octra-labs/wallet-gen.git 30
clone_or_update octra-labs_webcli https://github.com/octra-labs/webcli.git 30
clone_or_update octra-labs_lite_node https://github.com/octra-labs/lite_node.git 30
clone_or_update octra-labs_ocs01-test https://github.com/octra-labs/ocs01-test.git 20
clone_or_update octra-labs_program-examples https://github.com/octra-labs/program-examples.git 20
clone_or_update octra-labs_circle_examples https://github.com/octra-labs/circle_examples.git 20

echo "=== lambda0xE (all public listed) ==="
# Original + forks — shallow to save disk; bounty-relevant first
clone_or_update lambda0xE_0x0FFH https://github.com/lambda0xE/0x0FFH.git 5
clone_or_update lambda0xE_lambda0xE https://github.com/lambda0xE/lambda0xE.git 5
clone_or_update lambda0xE_coq https://github.com/lambda0xE/coq.git 20
clone_or_update lambda0xE_gt https://github.com/lambda0xE/gt.git 10
clone_or_update lambda0xE_23gate https://github.com/lambda0xE/23gate.git 15
clone_or_update lambda0xE_blake2_simd https://github.com/lambda0xE/blake2_simd.git 10
clone_or_update lambda0xE_BLAKE3 https://github.com/lambda0xE/BLAKE3.git 10
clone_or_update lambda0xE_bqskit https://github.com/lambda0xE/bqskit.git 10
clone_or_update lambda0xE_chokidar https://github.com/lambda0xE/chokidar.git 5
clone_or_update lambda0xE_coq-lsp https://github.com/lambda0xE/coq-lsp.git 10
clone_or_update lambda0xE_eml https://github.com/lambda0xE/eml.git 10
clone_or_update lambda0xE_localsolana https://github.com/lambda0xE/localsolana.git 15

# Discover remaining lambda0xE + octra-labs via API when possible (unauth rate limit OK)
discover_user() {
  local user="$1"
  local prefix="$2"
  local page=1
  while [[ $page -le 3 ]]; do
    local hdr=()
    if [[ -n "${OCTRA_GITHUB_TOKEN:-}${GITHUB_TOKEN:-}" ]]; then
      hdr=(-H "Authorization: Bearer ${OCTRA_GITHUB_TOKEN:-$GITHUB_TOKEN}")
    fi
    local json
    json=$(curl -sS "${hdr[@]}" \
      "https://api.github.com/users/${user}/repos?per_page=100&page=${page}&type=all" 2>/dev/null || true)
    [[ -z "$json" || "$json" == "[]" ]] && break
    echo "$json" | python3 -c '
import sys, json
try:
  d = json.load(sys.stdin)
except Exception:
  sys.exit(0)
if not isinstance(d, list):
  sys.exit(0)
for r in d:
  name = r.get("name") or ""
  url = r.get("clone_url") or ""
  if name and url:
    print(name, url)
' 2>/dev/null | while read -r name url; do
      [[ -z "$name" || -z "$url" ]] && continue
      safe="${prefix}_${name//\//_}"
      clone_or_update "$safe" "$url" 15
    done
    # stop if fewer than 100
    count=$(echo "$json" | python3 -c 'import sys,json
try:
 print(len(json.load(sys.stdin)))
except Exception:
 print(0)' 2>/dev/null || echo 0)
    [[ "${count:-0}" -lt 100 ]] && break
    page=$((page + 1))
  done
}

discover_org() {
  local org="$1"
  local prefix="$2"
  local page=1
  while [[ $page -le 2 ]]; do
    local hdr=()
    if [[ -n "${OCTRA_GITHUB_TOKEN:-}${GITHUB_TOKEN:-}" ]]; then
      hdr=(-H "Authorization: Bearer ${OCTRA_GITHUB_TOKEN:-$GITHUB_TOKEN}")
    fi
    local json
    json=$(curl -sS "${hdr[@]}" \
      "https://api.github.com/orgs/${org}/repos?per_page=100&page=${page}&type=public" 2>/dev/null || true)
    [[ -z "$json" || "$json" == "[]" ]] && break
    echo "$json" | python3 -c '
import sys, json
try:
  d = json.load(sys.stdin)
except Exception:
  sys.exit(0)
if not isinstance(d, list):
  sys.exit(0)
for r in d:
  name = r.get("name") or ""
  url = r.get("clone_url") or ""
  if name and url:
    print(name, url)
' 2>/dev/null | while read -r name url; do
      [[ -z "$name" || -z "$url" ]] && continue
      safe="${prefix}_${name//\//_}"
      clone_or_update "$safe" "$url" 20
    done
    count=$(echo "$json" | python3 -c 'import sys,json
try:
 print(len(json.load(sys.stdin)))
except Exception:
 print(0)' 2>/dev/null || echo 0)
    [[ "${count:-0}" -lt 100 ]] && break
    page=$((page + 1))
  done
}

echo "=== API discover octra-labs + lambda0xE ==="
discover_org octra-labs octra-labs
discover_user lambda0xE lambda0xE

echo "=== research forks ==="
clone_or_update smoke-ui https://github.com/smoke-ui/octra-hfhe-v2-security-assessment.git 40
clone_or_update v1-recovery https://github.com/Iamknownasfesal/octra-hfhe-challenge-recovery.git 20
clone_or_update nftboy07-octra https://github.com/nftboy07/octra.git 30

# Challenge forks (if token)
if [[ -n "${OCTRA_GITHUB_TOKEN:-}${GITHUB_TOKEN:-}" ]]; then
  token="${OCTRA_GITHUB_TOKEN:-$GITHUB_TOKEN}"
  forks=$(curl -s -H "Authorization: Bearer $token" \
    "https://api.github.com/repos/octra-labs/hfhe-challenge/forks?per_page=20&sort=newest" \
    | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin)
  for f in d[:15]:
    print(f.get("full_name",""), f.get("clone_url",""))
except Exception:
  pass' 2>/dev/null || true)
  while read -r full url; do
    [[ -z "${full:-}" || -z "${url:-}" ]] && continue
    name="fork_${full//\//_}"
    clone_or_update "$name" "$url" 15
  done <<< "$forks"
fi

# Inventory snapshot
python3 - <<'PY' || true
import json, os, subprocess
from pathlib import Path
from datetime import datetime, timezone
base = Path(os.environ.get("OCTRA_BASE", "/home/ubuntu/octra_investigation"))
intel = base / "repos" / "intel"
rows = []
if intel.is_dir():
    for d in sorted(intel.iterdir()):
        if not (d / ".git").exists():
            continue
        try:
            head = subprocess.check_output(
                ["git", "-C", str(d), "rev-parse", "HEAD"], text=True
            ).strip()
            subj = subprocess.check_output(
                ["git", "-C", str(d), "log", "-1", "--format=%s"], text=True
            ).strip()
            remote = subprocess.check_output(
                ["git", "-C", str(d), "remote", "get-url", "origin"], text=True
            ).strip()
        except Exception:
            head, subj, remote = "?", "?", "?"
        rows.append({"name": d.name, "head": head[:12], "subject": subj[:160], "remote": remote})
out = {
    "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "count": len(rows),
    "repos": rows,
}
path = base / "workspace" / "logs" / "intel_repos_inventory.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(out, indent=2), encoding="utf-8")
md = base / "workspace" / "reports" / "INTEL_REPOS.md"
md.parent.mkdir(parents=True, exist_ok=True)
lines = ["# Intel repo mirror", "", f"Generated: {out['checked_at']}", f"Count: **{out['count']}**", ""]
for r in rows:
    lines.append(f"- `{r['name']}` `{r['head']}` — {r['subject']}")
md.write_text("\n".join(lines), encoding="utf-8")
print(f"inventory {len(rows)} repos -> {path}")
PY

# Refresh workspace artifacts from challenge tip
CH="$BASE/repos/hfhe-challenge"
WS="${BASE}/workspace"
if [[ -d "$CH" ]]; then
  mkdir -p "$WS/artifacts" "$WS/repos"
  for f in secret.ct pk.bin params.json manifest.json SHA256SUMS pvac_commit.txt README.md; do
    [[ -f "$CH/$f" ]] && cp -f "$CH/$f" "$WS/artifacts/$f" || true
  done
  ln -sfn "$CH/lpn_samples" "$WS/artifacts/lpn_samples" 2>/dev/null || true
  ln -sfn "$CH" "$WS/repos/hfhe-challenge" 2>/dev/null || true
  ln -sfn "$BASE/repos/pvac_hfhe_cpp" "$WS/repos/pvac_hfhe_cpp" 2>/dev/null || true
fi

echo intel_repos_ok count=$(ls -1 "$INTEL" 2>/dev/null | wc -l)
