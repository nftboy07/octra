# Octra Recon Toolkit

This repository provides a small, reproducible Python CLI for the safe setup and
static collection portion of the supplied Octra investigation brief. It is
Windows-compatible and has no runtime dependencies outside Python 3.11+ and Git.

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

## Tests

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

## Scope and safeguards

See [docs/scope.md](docs/scope.md) for the workflow boundary and
[docs/source-manifest.md](docs/source-manifest.md) for the source pins. The
repository is intentionally limited to reproducible setup, integrity checking,
and static file inventory. Any build, fuzzing, network interaction, key recovery,
or security testing needs a separate authorized scope.
