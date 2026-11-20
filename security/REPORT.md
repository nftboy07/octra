# Security review: nftboy07/octra — honest kill

**Result:** I found no bug that an unprivileged attacker can exploit today. No PoC exploit exists. `security/verify_hardening.py` shows that the main defenses hold.

## Fork / upstream check
This repo is **not a fork of any Octra upstream**. It is a separate Python project, `octra-recon` (a "Octra Recon Toolkit": a CLI plus VPS/systemd scripts that watch the octra-labs HFHE bounty). Its tree does not overlap with any octra-labs repo (`pvac_hfhe_cpp`, `hfhe-challenge`, `wallet-gen`, `lite_node`). It only clones those repos as data. So there is no upstream commit to `diff` against. The whole repo (32 commits) is original code, and I reviewed all of it.

## What I examined and why it is safe
| Area | Attacker input | Why it is not exploitable |
|---|---|---|
| `sources.py` `_run_git`, `intel_digest.py`, `ops.py` | repo contents | Python calls `subprocess` only with list arguments: no `shell=True`, `eval`, `pickle` or `yaml`. Git runs with `protocol.file.allow=never` and no submodules. Cloned code is never executed. |
| `artifacts.py` `verify_checksums` / `extract_params` / `detect_repeated_blocks`, `workspace.py` `safe_relative_path` | `SHA256SUMS` names, artifacts | Absolute paths and paths with `..` are rejected, and symlinks are refused (shown by the PoC). |
| `ops.py` `process_candidates` | files dropped in `candidates/inbox` | Only checks BIP39 words. Output paths come from `path.name` alone, so they cannot point outside the folder. |
| `race/residual.py` `parse_s_bits` / `score_file` | candidate S, LPN jsonl | Only parses hex, bitstrings and ints. Python's int-digit limit caps the cost. |
| `tg_commands.py` `poll_once` / `handle_command` | Telegram messages | Messages from any `chat_id` other than the configured one are rejected. Commands are a fixed allowlist of read-only analyses with no arguments passed to a shell. |
| `telegram.py`, `configure-telegram.sh` | config | The config file is mode 600, and files readable by group or other are refused. |
| `scripts/intel-repos.sh` | GitHub API repo names/URLs | Names from GitHub cannot contain `/` or `..`, and clone URLs come from api.github.com. Cloning does not run hooks. |
| `scripts/auto-update.sh`, `install-ops.sh`, `harden-vps.sh` | the toolkit's own `origin/main` | They `reset --hard` to its own origin and then use sudo to install units. Exploiting this needs push access to this repo, so the attacker is not unprivileged. |
| `wallet.py` (Ed25519, BIP39, base58) | mnemonics | Output matches RFC 8032 TV1 and the BIP39 TREZOR vector, so there is no weakened key derivation. |

## Minor observations (not exploitable by an unprivileged attacker)
- `lpn.py` `verify_lpn_checksums` and `ops.py` `create_archive` (`tarfile.add`) follow symlinks. Abusing this needs write access to the workspace as the same user, and the result is only a hash or a backup of that user's own files.
- On error, Telegram replies include the end of a traceback, but only in the owner's configured chat.
- Auto-update plus passwordless sudo means a compromise of this GitHub repo gives root on the VPS. That is a supply-chain risk for the owner, not an attacker exploit.

## PoC / verification
```
$ PYTHONPATH=src python3 security/verify_hardening.py
PASS ed25519 matches RFC 8032 test vector 1
PASS BIP39 seed matches official test vector
PASS bad BIP39 checksum rejected
PASS safe_relative_path rejects '../etc/passwd'
PASS safe_relative_path rejects '/etc/passwd'
PASS safe_relative_path rejects 'a/../../b'
PASS verify_checksums refuses symlinked artifact
PASS verify_checksums refuses traversal in manifest
0 failures
```

## Submission venue
None. There is no finding to submit. The Octra bounty itself (recovering the HFHE challenge key) is out of scope for this tool repo.
