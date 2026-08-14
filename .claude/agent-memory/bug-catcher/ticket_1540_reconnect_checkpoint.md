# #1540 Checkpoint Equivocation Sync + Reconnection Driver — Bug Findings (2026-06-14)

Branch: feat/1540-checkpoint-equivocation-sync. Reviewed against origin/main.

## HIGH — collect_equivocation_alerts steals + discards the receive buffer
- `crates/scp-ffi/common/src/reconnect.rs:165-195`. Phase 3 calls `supervisor.drain_events(context_id)` which drains the ENTIRE receive buffer (every ContextEvent), keeps only `EquivocationDetected`, and DROPS everything else (`_ => None`). The bridges' normal `receive()` path ALSO consumes events via `sup.drain_events` (PyO3 context.rs:1091/1129/4864). So app messages (MessageSent), MemberJoined/Left, etc. that the actor buffered during Phase 2 `deliver_commit_blob` are silently destroyed by reconnection — the application never sees them. Data loss. Fix: add a filtered drain (drain only EquivocationDetected, re-buffer the rest) or a dedicated equivocation-alert channel separate from the app receive buffer.

## MEDIUM — equivocation alert surfaced evidence-free
- `reconnect.rs:181-189`. The SDK-surfaced `EquivocationAlert` hardcodes local/remote merkle_root = [0u8;32] and evidence=None. The removed `compare_checkpoints` populated real roots + EquivocationEvidence. The actor's event-log append (queries_helpers.rs:822) records only the string "EquivocationDetected" + sender DID — NOT the divergent roots. So forensic roots are genuinely discarded (doc claim "available via the event log" is false). §9.9.4 wants evidence retained.

## MEDIUM — epoch_reconciliation feeds MLS Commits in blob_id (hash) order
- `reconnect.rs:230` sorts catch-up by blob_id; `epoch_reconciliation` (263-283) feeds them once, continue-on-error. OpenMLS process_message requires strict epoch order. Out-of-order Commits beyond the first matching gap fail and are never retried in the pass → epoch advances by 1 not N. Relies on exceeds_sequential_limit→fast-forward or repeated reconnect calls. Relay doesn't carry epoch in public header, so no clean ordering key. Design limitation.

## LOW — handle_issue_mls_update_actor returns err_mutated on failure
- handlers/lifecycle.rs. On advance_epoch failure, sends real Err to reply, then returns Outcome::err_mutated (mutated=true) with a DIFFERENT fabricated error. State did NOT mutate on failure → wasteful persist. Should be Outcome::err (mutated=false).

## LOW — signing key bytes [u8;32] not zeroized at FFI boundary
- PyO3 context.rs:4783 `signing_key.to_bytes()` → plain [u8;32] copied into reconnect_contexts; SigningKeyBytes is bare array. Doc claims caller zeroizes but the local copy isn't. Consistent with prior "to_vec at FFI boundary" findings.

## VERIFIED CORRECT
- Type reconciliation: scp-event-log ConsistencyCheckpoint field order matches old protocol version exactly; canonical hash (compute_checkpoint_canonical_hash) identical incl epoch flag byte; serde_bytes signature + deny_unknown_fields preserved. Re-export is sound.
- #1216 fix: runtime compare_remote_checkpoint keys equivocation strictly on Equal-count-different-root; no epoch==None⇒FullyCaughtUp short-circuit. Correct.
- deliver_checkpoint_message: dispatched after MLS auth + verify_and_unwrap, before sequence tracker, returns Ok(None), binds checkpoint.sender_did to MLS sender. Correct.
- mls_epoch saturating_add(1) after advance_epoch: correct (self-Update = exactly 1 epoch).
- Actor command/handler wiring: all 6 new variants (LocalMlsEpoch, NeedsReconnect, BuildLocalCheckpoint, CompareRemoteCheckpoint, ClearNeedsReconnect, IssueMlsUpdate) handled in dispatch + soft-default + not-impl-ack + context_id routing. No unhandled variant / mis-route. oneshot drop → TransportFailed mapped.

## Phase 6 queue drain (documented deviation)
- All 3 non-WASM bridges call reconnect_contexts_no_drain — none wire ReconnectionCoordinator::drain_context_queue. Currently benign ONLY because enqueue_message has no production caller (offline-send-enqueue path unwired). The doc rationalization is right-for-wrong-reason. Pre-existing gap, not a #1540 regression.
