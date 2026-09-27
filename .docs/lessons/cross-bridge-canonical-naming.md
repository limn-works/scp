# Cross-Bridge Canonical Naming and Matrix Hygiene

`scripts/bridge-aliases.json` maps each canonical operation to its name in each bridge.
PyO3 and UniFFI export bare verbs on a class (`governance_propose` on `Scp`/`SCP`); NAPI
exports flat free functions prefixed with the noun (`context_governance_propose`).

## Rules

- **Prefer a canonical name that already exists in all three bridges' source.** When no
  shared name exists, rename at the source for symmetry rather than growing the alias list.
- **Give sibling operations one stem.** `broadcast_block` / `broadcast_unblock`, never
  `broadcast_block` / `broadcast_unblock_subscriber`, which implies an asymmetry the protocol
  does not have.
- **Categorize an operation by its protocol concept, traced to its spec section, not by the
  source file it sits in.** `evaluate_invitation` lives in `context.rs` and is membership.
- **The JSON and the ratchet in `crates/scp-testing/tests/integration/ffi_conformance.rs` are
  one artifact split across two files.** `aliases_json_is_in_sync_with_parity_operations`
  checks the operation-count floor, unique canonical names, and alias hygiene per bridge. Run
  `cargo test -p scp-testing --test integration` after any matrix edit.

## The blind spot that is still open

`scripts/check-bridge-symmetry.sh` validates only operations registered in the matrix, so an
operation every bridge exports but nobody registered passes by being absent. One audit that
walked every `#[pymethods]`, `#[uniffi::export]`, and `#[napi]` entry point and diffed the
names against the JSON keys found 97 protocol operations missing from the matrix. No script
performs that inverse check today.
