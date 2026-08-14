---
name: outlet-out047-pass1-pyo3-streaming-saga
description: SCP-OUT-047 pass1 PyO3 cross-context streaming-saga FFI (open/poll/recover) review @3f5a906ec — substantially clean, 1 LOW auth asymmetry
metadata:
  type: project
---

# SCP-OUT-047 pass 1 — PyO3 streaming-saga FFI (branch feat/outlet-xctx-047-streaming-saga-ffi @3f5a906ec)

Files: crates/scp-ffi/src/outlet_stream.rs (open/poll/recover impls + PyScp methods),
crates/scp-ffi/common/src/streaming_saga.rs (StreamingSagaEntry, serialize_saga_chunk,
drive_recover_truncated_close), crates/scp-ffi/src/runtime.rs (per-instance registry).

**Verdict: substantially CLEAN.** Faithful mirror of same-context outlet_stream_open/poll_next.

CORRECT (verified): (1) block_on returns promptly at Commit — supervisor.rs:6739 tokio::spawns
seal task, returns StreamingSagaHandle at Commit (AC1/AC6); works on multi-thread AND
new_current_thread CI fallback (lib.rs:133). (2) GIL released across recv via py.allow_threads
(:551), identical to mirror :685. (3) Registry: Arc cloned out of DashMap shard guard before
await in poll (:543) + recover (:602); SagaId::new() unique; terminal/None/unknown all handled;
cleared on shutdown (runtime.rs:806). (4) No panicking unwraps on caller path; handle.receiver
is direct field move (no fallible take → no pump-stranding window unlike same-ctx open).
(5) Chokepoint context_id_to_bytes pinned in shared driver (streaming_saga.rs:181). (6)
serialize_saga_chunk terminal via ChunkPayload::is_terminal (End|Error{terminal}); Error{false}
stays resident. (7) Feature-gates compile on/off (only prod symbols referenced).

FINDINGS:
- **LOW (top): recover authenticates "hosted" but NOT pinned-invoker.** outlet_stream.rs:582-607
  only checks identity_registry_contains(caller_did); never compares caller_did vs
  entry.invoker_did. Same-ctx grant/cancel DO pin (caller_did != entry.invoker_did → SCP-PERM-3001,
  :779). Entry carries invoker_did → one-liner fix. Not exploitable single-tenant co-resident;
  becomes cross-principal force-settle/griefing if multi-tenant. Docstrings overclaim "§6.2.4
  caller auth" (open = 2-axis hosted+member; recover = 1 weak axis).
- **LOW: recover doesn't evict entry on success** (:616-626). Leftover until shutdown; self-cleans
  on next poll (returns None). Add registry.remove after the map_err?.
- **Observation (scope): no cancel/grant/terminate for xctx saga stream** — StreamingSagaEntry
  holds only receiver, no control handle. A can't cancel early to stop escrow; only stop polling
  (bounded-1 backpressure → settles at shutdown). Likely intentional pass-1 (3 canonical ops in
  bridge-aliases); confirm §5.4.5 doesn't require invoker-cancel before pass 2.

# REVISION pass @b09592356 — BOTH prior LOWs FIXED, CLEAN, no regression
Confirmed the F1/F2/F3 revision + both prior LOWs resolved:
- **Prior LOW #1 (invoker gate) FIXED**: recover now compares caller_did != invoker_did →
  caller_not_invoker_err (SCP-PERM-3001, "is not the invoker") AFTER hosted-auth, BEFORE
  signing-key resolve/driver. New e2e test xctx_streaming_saga_recover_hosted_non_invoker_rejected
  asserts reject + entry-survives via cfg-gated test seam.
- **Prior LOW #2 (evict) FIXED**: registry.remove(saga_id) after map_err? — success-only (drive
  error returns via ? before remove), executes exactly once, no double-remove/use-after-remove.
- **F1 reorder** (caller_did→pos3, ucan_token→pos9, spending_ucan dropped): impl uses NAMED params
  (internal use reorder-safe); pymethod #[pyo3(signature)] + forwarding + BOTH e2e call sites
  (only 2 callers: e2e 1845/1903) all updated to new positional order; 13 args match. Reorder
  ALIGNS streaming-saga open first-8-params EXACTLY with unary outlet_invoke_cross_context_saga
  (outlets.rs:2081) — correct agent-first canonical-shape move, not a divergence bug.
- **F2 rename** asserted_timestamp_ms/chain_depth→timestamp_ms/chain_depth: 0 dangling refs in
  outlet_stream.rs (grep hits are the UNARY saga in outlets.rs/napi/uniffi — separate fn, keeps
  asserted_* naming); values stay in same supervisor-call slots (chain_depth, nonce, timestamp).
- **F3 spending_ucan removal**: fully gone from saga path (only in comments 1183/1187); same-context
  outlet_stream_open retains+uses its own (392/400/1610/1621/1633). No dead ref.
- **Test seam** insert_test_streaming_saga_entry/test_streaming_saga_entry_present: plain `impl PyScp`
  (NOT #[pymethods]) gated cfg(any(test,testing,allow_in_memory_custody)); not Python-exported, not
  in prod build. NO #116-style orphan: e2e_bridge required-features=["allow_in_memory_custody"] so
  seam AND its only caller vanish together under no-feature; all imports (mpsc/Arc/Mutex/SagaId/
  StreamingSagaEntry) shared with prod paths → no unused-import under -D warnings. StreamingSagaEntry
  5-field construct matches struct exactly; SagaId(pub String) tuple ctor accessible.
- pipeline_wiring (scp-testing integration) substring gates still satisfied (enforce_caller_principal_
  binding / start_cross_context_...saga / drive_recover_truncated_close / identity_registry_contains
  all present). No DashMap ref held across await in recover (entry cloned out of scoped block).
