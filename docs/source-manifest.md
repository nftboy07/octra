# Source manifest

The CLI stores the source declarations in `src/octra_recon/sources.py` and writes
the resolved commit IDs to `logs/sources.json` after each successful sync.

| Directory | Repository | Revision policy |
|---|---|---|
| `pvac_hfhe_cpp` | `octra-labs/pvac_hfhe_cpp` | Commit prefix `071b0e9` from the supplied brief |
| `hfhe-challenge` | `octra-labs/hfhe-challenge` | Tag `v2_fix` |
| `wallet-gen` | `octra-labs/wallet-gen` | Current default branch, recorded after sync |
| `lite_node` | `octra-labs/lite_node` | Current default branch, recorded after sync |

The supplied brief requested a `lite_node` commit before 2026-01-01 UTC. The
earliest commit currently available in its public history is dated 2026-06-25, so
the manifest intentionally records the current default branch instead. All other
declared revisions fail closed: if they cannot be resolved, the CLI does not choose
an alternative revision.
