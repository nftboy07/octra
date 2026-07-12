# Octra Recon Toolkit

This repository provides a small, reproducible Python CLI for the safe setup and
static collection portion of the supplied Octra investigation brief. It is
Windows-compatible and has no runtime dependencies outside Python 3.10+ and Git.

The CLI never executes cloned source files, wallet generators, downloaded
binaries, build steps, or network-node software. It also does not configure
firewalls, cron jobs, VPS services, or remote infrastructure.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -e .
octra-recon init --workspace .\investigation
octra-recon sources sync --workspace .\investigation
octra-recon sources status --workspace .\investigation
```

`sources sync` clones the four public repositories listed in
`src/octra_recon/sources.py`, fetches their declared revisions, and checks out a
detached commit. It does not initialise submodules or run source-controlled
commands.

## Artifact checks

Place approved, locally obtained challenge files in `investigation/artifacts/`.
The following commands only read those files and write results under
`investigation/logs/`.

```powershell
octra-recon artifacts verify --workspace .\investigation
octra-recon artifacts params --workspace .\investigation
octra-recon artifacts nonces --workspace .\investigation --block-size 16
octra-recon inventory --workspace .\investigation
```

`artifacts verify` validates a SHA-256 manifest when present. `artifacts params`
prints JSON metadata and, when `powg_B` is a list, writes an indexed dump.
`artifacts nonces` is a generic repeated fixed-size block detector, not a
protocol-aware nonce parser; its result must not be treated as a cryptographic
finding without source-format validation.

## Wallet checks and hypotheses

```powershell
octra-recon wallet check --mnemonic "word1 word2 ... word12"
octra-recon hypotheses run --workspace .\investigation
octra-recon lexicon run --workspace .\investigation
octra-recon lexicon run --workspace .\investigation --deep --max-candidates 25000
octra-recon surface status --workspace .\investigation
```

`wallet check` derives the Octra address (BIP39 → PBKDF2 → HMAC "Octra seed" →
Ed25519 → `oct`+base58(SHA256(pubkey))) and compares to the bounty target.
`hypotheses run` tests a few hundred low-entropy / public-string candidates only
(not a 2^128 search). `lexicon run` mines **local GitHub clones** (intel forks,
READMEs, text surfaces), intersects tokens with BIP39 English, builds
brainwallet-style sha256/sha512 → 128-bit entropy candidates, and checks the
target. It is **not** enumerating 2048^12. A tested-cache under
`logs/github_lexicon_tested.json` advances the frontier across runs; hits land
in `candidates/hits/` and fire Telegram. `surface status` records blocking
pillars, LPN notes, and FURY applicability (no Rku in the public package at pin
`071b0e9`).

## LPN sample checks (July 11 drop)

Place `lpn_samples/` under `artifacts/lpn_samples` or ensure
`repos/hfhe-challenge/lpn_samples` exists after source sync. These commands only
read sample metadata / hashes; they do not solve LPN or execute challenge C++.

```powershell
octra-recon lpn inventory --workspace .\investigation
octra-recon lpn verify --workspace .\investigation
octra-recon lpn summary --workspace .\investigation
```

`lpn inventory` checks file count (44), domain `pvac.prf.r.1`, parameters
`n=4096`, `t=16384`, `tau=1/8`, seed uniqueness, and writes hardness notes.
`lpn verify` checks `lpn_samples/*` digests listed in `SHA256SUMS`.
`lpn audit` runs a **smoke-ui–parity deep audit**: schema, filename coords,
GF(2) rank(A)/rank([A|y]), exact global A-row duplicates (SQLite), bit-balance
z-scores, aggregate match vs smoke-ui published ones-counts, and practical
negative-result notes (S alone ≠ decrypt). Full run scans ~721MB and may take
several minutes on a small VPS.

```powershell
octra-recon lpn audit --workspace .\investigation
```

Full metadata binding to `secret.ct` still requires compiling
`source/tools/verify_lpn_sample_binding.cpp` against pinned `pvac_hfhe_cpp`.

## Tests

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

## VPS deployment

The repository includes `scripts/bootstrap-vps.sh` for a Debian or Ubuntu VPS.
It installs the toolkit's Python and Git dependencies, creates a non-root `octra`
user, checks out a supplied commit, initializes `/home/octra/octra_investigation`,
and performs the same non-executing source sync and inventory as the local setup.

The script intentionally does not install build or profiling toolchains, configure
cron jobs, change firewall rules, or run cloned source code.

## Telegram notifications

Telegram support is optional and uses the standard Bot API without extra Python
dependencies. Configure it on the VPS from an interactive SSH session so the bot
token never enters Git, shell history, or this repository:

```bash
sudo -u octra -H bash /home/octra/octra_investigation/toolkit/scripts/configure-telegram.sh
sudo -u octra -H /home/octra/octra_investigation/toolkit/.venv/bin/octra-recon telegram status
sudo -u octra -H /home/octra/octra_investigation/toolkit/.venv/bin/octra-recon telegram test
```

The setup script stores the token and chat ID at
`/home/octra/.config/octra-recon/telegram.env` with owner-only permissions. Once
configured, supported CLI commands send a short completion or failure notification.
Run `telegram test` after starting a conversation with your bot or adding it to the
target group/channel.

## Race stack (outperform smoke-ui / claim speed)

```bash
octra-recon race run --workspace $W
octra-recon race score-s --workspace $W --s-file candidates/s_inbox/s.hex
# optional held-out:
octra-recon race score-s --workspace $W --s-file s.hex --holdout ct21_l1_s0_pvac_prf_r_1.jsonl
```

Includes: planted residual controls, noiseless small-n recovery, restricted-sample
BKW grid, equation-body commitments (stronger than official metadata-only binding),
composition map (S vs prf_k), and auto-scoring of `candidates/s_inbox/` on the VPS.

## 24×7 operations (VPS)

```bash
# after sync on VPS:
bash /home/ubuntu/octra_investigation/scripts/install-ops.sh

octra-recon unlock scan --workspace $W
octra-recon ops integrity --workspace $W
octra-recon ops cycle --workspace $W
octra-recon ops heartbeat --workspace $W
octra-recon ops github --workspace $W
octra-recon ops candidates --workspace $W
octra-recon ops archive --workspace $W
```

Timers (systemd): watchdog 2h, ops-cycle 6h, integrity 24h, archive ~monthly.  
Unlock runbook: `docs/UNLOCK_RUNBOOK.md`.  
Candidate drop: `workspace/candidates/inbox/` (one mnemonic per file).

## Scope and safeguards

See [docs/scope.md](docs/scope.md) for the workflow boundary and
[docs/source-manifest.md](docs/source-manifest.md) for the source pins. The
repository is intentionally limited to reproducible setup, integrity checking,
and static file inventory. Any build, fuzzing, network interaction, key recovery,
or security testing needs a separate authorized scope.
