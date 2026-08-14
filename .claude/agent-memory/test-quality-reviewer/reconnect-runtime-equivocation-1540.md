# #1540 runtime_equivocation_dispatch_and_targeted_drain review

reconnect_sync.rs `runtime_equivocation_dispatch_and_targeted_drain` (crates/scp-testing/tests/integration/reconnect_sync.rs).

## What it genuinely proves (verified against source)
- `compare_remote_checkpoint` / `drain_equivocation_alerts` route through the REAL actor mailbox (`MessagingCommand::CompareRemoteCheckpoint` / `DrainEquivocationAlerts` → dispatch_command), supervisor.rs:5544/5810. Not inline helpers.
- EquivocationDetected carries REAL roots: queries_helpers.rs:917-923 sets local_merkle_root/remote_merkle_root from actual values (membership.rs ContextEvent gained the two [u8;32] fields). Test asserts `*remote_merkle_root == forged_root`. Non-tautological.
- Targeted drain preserves DegradedMode in buffer: report_degraded_mode genuinely emits (queries_helpers.rs:296). drain_equivocation_alerts (membership.rs ReceiveBuffer) extracts only alerts, keeps rest in order. Real assertion.

## KEY GAP — replay idempotency mechanism NOT actually exercised
- The dedicated replay guard is `record_equivocation_if_fresh` (queries_helpers.rs:856), keyed `(event_count,timestamp)` strictly-newer per sender DID in `state.last_seen_remote_checkpoint`.
- BUT in this test, dispatch #1 APPENDS an EquivocationDetected event to the local log → local_count++. On dispatch #2 the forged checkpoint's event_count is now strictly LESS than local_count → comparison returns `Behind` (queries_helpers.rs:802), never reaching the `Equal` arm or record_equivocation_if_fresh.
- So "no second alert" here is a side effect of count-drift, NOT the idempotency guard. The `last_seen_remote_checkpoint` early-return branch has ZERO test coverage (grep: only state.rs:1390 asserts map starts empty). A true idempotency test needs two divergent checkpoints at the SAME stable local count.

## GAP — cross-epoch retry loop untested behaviorally
- epoch_reconciliation multi-pass `while !pending.is_empty() && total_merged < limit` loop (scp-ffi/common/src/reconnect.rs:308) only has a `fn_body_contains` structural pin (calls deliver_commit_blob). No test feeds >1-epoch blobs and asserts ordered drain across passes / steady-state termination / limit bound.

## Honest-limitation resolution (single-node MLS) — ACCEPTABLE
- fn_body_contains pins (real brace-matching call-site helper) confirm decrypt prefix deliver_incoming→deliver_checkpoint_message→compare_remote_checkpoint. Verified these production fns EXIST and chain is real: messaging_helpers.rs:1085 calls deliver_checkpoint_message, which calls compare_remote_checkpoint (line ~1176). Not phantom pins.
- Command-level test + structural decrypt-prefix pin is a sound resolution of "no runtime test of receive dispatch" given MLS can't decrypt own messages single-node. Two-node harness NOT strictly required for THIS gap.

## Flakiness: LOW. Deterministic keys (did_to_seed), in-memory fullstack, no time/order/network deps in the runtime test. (Part A live-relay test elsewhere blocks on 30s QUERY by design but is a different test.)
