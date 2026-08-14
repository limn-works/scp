---
name: issue-1933-event-log-verify-authoritative-tree
description: Crypto review of #1933 (event-log Merkle answers over the authoritative supervisor log). Branch fix/1933-f3 @4e52864b2 — verify/query/checkpoint seam is SOUND in all 3 bridges + runtime; residual = MCP context_events still publishes a bridge-local merkle_root, and the absence-proof primitive is still unverifiable (ADR-011 AC4 unsatisfiable).
metadata:
  type: project
---

Branch `fix/1933-f3-event-log-verify-authoritative-tree`. Reviewed twice:
`001c38544` (first pass) and `4e52864b2` (this one, based on `origin/main` `d1ebc5ab9`).

## Verdict at 4e52864b2 — the core seam is SOUND

One seam: `Supervisor::authoritative_event_log` (`supervisor.rs:11504`) →
`ContextEventLogProvider::rebuild_event_log_for_proof` (trait DEFAULT,
`builder.rs:594`). `entries()` is ONE mutex acquisition returning the live
append-order Vec; the replay re-runs `append_unsigned_event`, which enforces
sequence + prev_hash, and the test `snapshot_reconstructs_the_live_tree_exactly`
pins root+leaf-hash equality with the live tree.

Fixed since the first pass (all verified in code, not self-report):
- **Checkpoint** now signs the AUTHORITATIVE commitment on all 3 bridges via
  `Supervisor::unsigned_authoritative_checkpoint` (was the bridge-local tree).
- **`build_checkpoint`** (`queries_helpers.rs:791`) and
  **`classify_remote_checkpoint`** (`:912`) both take ONE
  `rebuild_event_log_for_proof` snapshot and FAIL CLOSED. The
  `unwrap_or([0u8;32])` / `.ok().flatten().map_or(0,…)` two-call fail-open pair
  is gone from both the signing and the judging side.
- **`event_log_query`** fail-open + `entries.is_empty() → bridge-local fallback`
  removed on all 3 bridges; empty-but-live ⇒ empty list, unknown ⇒ `SCP-CTX-2138`.
- **`verified: bool`** deleted from Py/Napi/UniFFI `Proof` + Swift/TS/Python SDK
  types, and Swift's `EventLog.verifyInclusion` deleted. Absence answers now ship
  BOTH neighbours' FULL inclusion proofs (`absence_neighbor_json`).
- New codes: `SCP-CTX-2138` (cannot reach authoritative log — fail closed) vs
  `SCP-CTX-2139` (honest proof failure over a readable log). Registered in
  `.docs/standards/sdk-common.md`.
- NAPI verify no longer calls `ensure_registered` (was mutating the UCAN registry
  before the ready gate) — verify is now read-only on all 3 bridges.
- `Supervisor::test_append_event` is `#[cfg(feature = "testing")]` and drives the
  REAL provider — a reach-seam, not a nullifier.

## Residuals still open at 4e52864b2

1. **BLOCKER — MCP `context_events` still publishes a bridge-local `merkle_root`.**
   PyO3 `crates/scp-ffi/src/mcp.rs:1179-1195`, UniFFI
   `crates/scp-ffi/uniffi/src/bridge.rs:5454-5474`. Reads `rt.event_log` /
   `ucan_state.event_log` (caller-shapeable through `provenance_attach`,
   `media_session_start`, outlet calls) and emits `{"event_count","merkle_root"}`
   under the SAME field names the authoritative checkpoint uses — over the shipped
   MCP resource surface. Also fail-OPEN: `.unwrap_or_else(|_| {"event_count": 0})`.
   NAPI diverges: `crates/scp-ffi/napi/src/mcp.rs:396` returns `[]`.
2. **Absence proofs are still unverifiable.** ADR-011 AC4
   (`.docs/adrs/phase-2.md:1123`) requires the verifier confirm the neighbours are
   "truly adjacent in sorted order" — impossible against an append-order RFC 6962
   root; `sorted_leaves: BTreeSet<([u8;32],u64)>` is local index state the root
   does not commit to. No `verify_absence` exists anywhere in the repo. The branch
   DOCUMENTS the residue in the bridge/SDK doc-comments instead of fixing it.
   Real fix = commit the sorted index (sorted-leaf root, or a sparse Merkle tree
   keyed by leaf hash) and add `verify_absence`; ADR-011 must move first.
3. **Checkpoint `epoch` is caller-supplied.** All 3 bridges pass `Some(epoch)`
   unconditionally, violating the contract their own new callee documents
   (`supervisor.rs:11534`, `checkpoint.rs:147`: `None` for Broadcast). The
   supervisor already derives both mls_epoch and broadcast-ness in
   `build_checkpoint` (`queries_helpers.rs:797-802`).
4. **Prune-then-prove-absence.** `truncate_log_keeping_tail`
   (`providers/event_log.rs:621-663`) RE-CHAINS the retained tail ⇒ pruned events
   become genuinely absent and every pre-prune inclusion proof / signed checkpoint
   stops verifying. Reachable in prod via governance checkpoint+pruning. The fix
   makes that answer *authoritative*-looking.
5. **Two proof seams.** `MerkleEventLogProvider` OVERRIDES
   `prove_event_inclusion`/`prove_event_consistency` to use `with_log` on the LIVE
   tree (`providers/event_log.rs:831+`) while `authoritative_event_log` uses the
   REPLAY default. Equal only by test. (`queries_helpers::prove_event_*` have zero
   callers.)
6. **Stale docs that now lie:** PyO3 public `event_log_query` docstring still
   promises the LogSummary fallback (`crates/scp-ffi/src/event_log.rs:702-705`);
   UniFFI `event_log_verify` doc says "keep `SCP-CTX-2025`" while the code emits
   `CTX_2139` (`uniffi/src/bridge.rs:15116`, mirrored into
   `bindings/swift/Sources/SCP/Internal/ScpBindings.swift`); Kotlin
   `InfraBindings.eventLogQuery` (`CoroutineBridge.kt:1131-1145`).
7. **Python SDK `_extract_root_hash` / `_extract_event_count`**
   (`bindings/python/scp_sdk/event_log.py:70-115`) still parse
   `payload["merkle_root"]` from query results and default to
   `_EMPTY_ROOT_HASH = "0"*64`. The bridge no longer emits that key, so they now
   always return an all-zeros root. Dead (tests only) but shipped in the package.

## Structural facts

- Event-log leaves are UNSIGNED (`ContextLog::append` sets `signature: vec![]`) —
  #1845. Leaf = `SHA-256(0x00 ‖ rmp_serde(Event))`.
- `context_import` IS signature-bound (`validate_export_for_import`, exporter_did
  == creator_did, root recomputed and `ct_eq`), so the authoritative log cannot be
  shaped by an unsigned import.
- Trait default `event_log_entries` (`builder.rs:420`) returns `Err`, not
  `Ok(None)` — a provider that forgets to implement it fails closed.
- Empty-tree root is `SHA-256("")`, NOT `[0u8;32]`.
- `prove_absence` on an empty-but-live log returns `EmptyLog` (⇒ CTX-2139), even
  though that is the one case where absence IS provable.

Run tests with `CARGO_TARGET_DIR=/Users/alec/.cargo/f3-review-isolated-target`
(the shared target dir is poisoned by a stale main checkout), and
`--features testing` for `-p scp-event-log`.
