---
name: heartbeat-loop-1533
description: Review of #1533 heartbeat send/receive loop tests (§9.9.2) — closed-loop suppression detection, AC2/3/8/9, pipeline assertion
metadata:
  type: project
---

# #1533 heartbeat loop (feat/1533-heartbeat-loop) test review

Verdict: APPROVE. Tests are genuine, not gamed. **Re-reviewed 2026-06: the three "minor gaps" below were FIXED and the fixes verified (mutation-tested) — see "Remediation verified" section.**

## Closed loop wiring (verified end-to-end, prod fns all exist)
- SEND: napi `context_subscribe_on` spawns `run_heartbeat_scheduler` (scp-ffi-common) → `Supervisor::send_heartbeat` → MessagingCommand::SendHeartbeat → `messaging_helpers::send_heartbeat` → `encrypt_and_send(... MessageType::Heartbeat, seq 0)`.
- RECEIVE: `deliver_incoming` classifies `MessageType::Heartbeat` → `DeliverOutcome::Heartbeat`; napi loop calls `transport_mgr.record_heartbeat_received()` → fans to all adapters → `NativeRelayAdapter` inherent method → `monitor.record_heartbeat_received(Instant::now())`.
- DeliverOutcome enum is NEW (was Option<(Vec,String)>); deliver_commit_blob collapses it back to Option for reconnect driver — correct.

## Pipeline assertion b3_heartbeat_send_receive_loop_wired
- REAL fn_body_contains call-site assertions (6 links). All pinned prod fns verified to EXIST (run_heartbeat_scheduler, context_subscribe_on, send_heartbeat, deliver_incoming). Ratchet 41→42. Not string-search gaming.

## AC answers
1. AC8 closed-loop GENUINE: `received_heartbeats_suppress_the_suspicion` proves record_heartbeat_received moves baseline so silence at t+121 is quiet, AND the same monitor fires at t+181 (negative control via aging baseline). `dropped_heartbeats_raise_suppression_after_threshold` = no record → fires past 120s threshold. Both real.
2. AC9 NOT rigged: EMA alpha=0.3, 5 failures 1.0→0.7→0.49→... honest stays 1.0 via successes. Crosses 0.5 threshold for suppressing only. is_flagged_for_replacement = rate<0.5.
3. AC2/AC3 GENUINE: `fullstack_heartbeat_send_does_not_advance_application_sequence` sends msg/heartbeat/msg, opens all 3 inner envelopes, asserts heartbeat is MessageType::Heartbeat seq 0 AND inner2.sequence==inner0.sequence+1 (consecutive — proves no app-seq consumed). Real crypto pipeline via FullStackNode.

## Flakiness
- suppression_suppression.rs tests: DETERMINISTIC. Use injected `now` param (tokio::time::Instant + Duration arithmetic). No wall clock, no sleeps. Low risk.
- HOWEVER: production receive-side `NativeRelayAdapter::record_heartbeat_received` uses `tokio::time::Instant::now()` (wall clock) — NOT covered by the deterministic suppression tests (those drive the monitor directly). The closed loop at the adapter level is only tested by `record_heartbeat_received_on_connected_adapter` (asserts no panic, not gap-clearing semantics).

## GAPS (minor, non-blocking)
- napi scheduler lifecycle (cancel-on-unsubscribe) NOT directly tested. `scheduler_select_exits_promptly_on_cancel` tests a REPLICA of the select shape (inlined copy), not the real run_heartbeat_scheduler — comment admits Supervisor can't be built without provider wiring. cancel wiring IS real (heartbeat_cancel = clone of handle.subscription_cancel, cancelled at lines 317/908/969). But no integration test proves subscribe→unsubscribe drains the scheduler JoinSet task.
- run_heartbeat_scheduler's "first immediate tick consumed" behavior untested.
- record_heartbeat_received at adapter level: connected test only asserts non-panic, doesn't assert the monitor baseline actually moved (would need to read back check_suppression).

## Remediation verified (re-review 2026-06, commit a2f1b2b1f)
All three gaps above were fixed. Mutation-tested as REAL negative controls:
- **Loop extracted to `scheduler_loop`** (generic over `on_tick`) so the REAL loop (not a select-replica) is unit-tested. Behavioral tests: first-immediate-tick-consumed, tick-on-interval, prompt-exit-on-{subscription,bridge}-cancel, no-sends-after-cancel. MUTATION: removing `timer.tick().await` first-tick-skip fails 2 tests (left:2 right:1). Good exemplar for "loop body needs an un-constructable dep (Supervisor)".
- **Adapter baseline-movement**: `record_heartbeat_received_on_connected_adapter` now drives real method against real monitor via `#[cfg(test)]` handle, asserts Some(past 240s)→record→None. MUTATION: no-op the inherent method → fails with exact "must move the baseline" assertion.
- **Teardown pin**: `b3_heartbeat_send_receive_loop_wired` TEARDOWN-link pins `cancel_token.cancel()` inside `context_subscribe_on` (single occurrence, common exit path covering unsubscribe/bridge/exhaustion/Terminated). Ratchet 41→42.
- Threshold change to uniform 240s: background-task test (5×61=305s) is CORRECT but loosely pins 240s; tight pin is `every_sending_profile_resolves_to_uniform_suppression_threshold` (exact from_mins(4)) + `debug_assert_eq!` in `for_profile`.
- DOC NIT (non-blocking): `scheduler_loop` docstring claims `select!` arm reorder is "observable by tests" — false; prompt-cancel tests pass by timer-not-ready, and `select!` is unbiased by default. Worth softening.
