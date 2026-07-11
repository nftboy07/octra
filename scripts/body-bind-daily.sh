#!/usr/bin/env bash
set -euo pipefail
BASE="${OCTRA_BASE:-/home/ubuntu/octra_investigation}"
RECON="${BASE}/repos/octra-recon/.venv/bin/octra-recon"
WS="${BASE}/workspace"
STATE="${BASE}/logs/body_bind_root.txt"
# race run includes body bind; extract root via python -c using installed package
ROOT=$("${RECON}" race run --workspace "${WS}" 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print((d.get("parts") or {}).get("body_bind",{}).get("root_body_commitment",""))' || true)
# faster: dedicated module call
ROOT=$(cd "${BASE}/repos/octra-recon" && .venv/bin/python - <<'PY'
from pathlib import Path
from octra_recon.race.body_bind import body_binding_audit
ws = Path("/home/ubuntu/octra_investigation/workspace")
print(body_binding_audit(ws).get("root_body_commitment",""))
PY
)
OLD=""
[[ -f "$STATE" ]] && OLD=$(cat "$STATE" | tr -d '\n')
echo "$ROOT" > "$STATE"
if [[ -n "$OLD" && -n "$ROOT" && "$OLD" != "$ROOT" ]]; then
  "${RECON}" telegram test --message "BODY BIND CHANGED: LPN equation bodies may have mutated. Investigate."
fi
echo "body_root=$ROOT"
echo body_bind_daily_ok
