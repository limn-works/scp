# #1540 Reconnection Driver Tests (reconnect_sync.rs + pipeline b3_reconnect)

## Files
- `crates/scp-testing/tests/integration/reconnect_sync.rs` — 3 tokio tests (real relay + full-stack)
- `crates/scp-testing/tests/integration/pipeline_wiring.rs` — `b3_reconnect_drives_checkpoint_exchange` + strengthened b3_checkpoint/b3_merkle assertions

## Good patterns worth replicating
- `fn_body_contains(src, fn_name, callee)` (pipeline_wiring.rs:173) extracts a function's body via brace-matching (handles comments/strings) then checks callee is inside THAT body. Strictly stronger than whole-file string search — defeats `let _ = fn;` dead-reference gaming. All 5 new b3_reconnect assertions pin to REAL existing call sites (verified: finalize_send→create_and_broadcast_checkpoint_if_due→{create_checkpoint_if_due,send_checkpoint}; deliver_incoming→deliver_checkpoint_message→compare_remote_checkpoint; handle_build_local_checkpoint→send_checkpoint; driver event_log_sync/epoch_reconciliation).
- Determinism via injected `now: u64` param (reconnect_contexts_no_drain takes now) — classification has NO wall-clock dependency. Tier arithmetic checked against classify_offline_duration boundaries (≤tier_1=Short, ≤tier_2=Extended, else Long).
- Equivocation forge is correct per §9.9.3: equal event_count + flipped Merkle root (`forged_root[0] ^= 0xFF`) + VALID Bob signature over canonical hash → tests divergence detection, NOT signature failure. Real distinction.
- Synchronous emission: compare_remote_checkpoint emits EquivocationDetected into receive_buffer before its await returns, so subsequent drain_events is race-free.

## Flakiness assessment: LOW
- Native relay QUERY (client.rs:813) breaks on `query_complete` OR 30s deadline. Server emits query_complete unconditionally after blob loop (server.rs:1342) — empty store returns immediately. Worst case = slow (30s) not flaky.
- Part A tier assertion is classification-derived (independent of query results) → cannot flake on query content/timing.
- Each test does FullStackNetwork::new() fresh — no shared mutable state across tests.

## Coverage gap (the one real CHANGES-NEEDED item)
- Equivocation-on-RECEIVE (the security core) is tested via DIRECT `compare_remote_checkpoint` call, NOT through the two-peer relay deliver_incoming path. The pipeline assertion pins deliver_incoming→deliver_checkpoint_message→compare_remote_checkpoint structurally, but no integration test feeds a forged checkpoint as a wire ConsistencyCheckpoint message through deliver_commit_blob/deliver_incoming to prove the receive dispatch actually reaches comparison at runtime. Forgery test bypasses MessageType::ConsistencyCheckpoint dispatch (line 83-84 messaging_helpers). Root cause: ADR-049 Welcome-joined nodes (Bob) have no actor-backed send context, so a true two-peer relay equivocation exchange isn't yet possible — documented in test comments. Behavioral gap is real but architecturally constrained.
