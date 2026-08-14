# ADR-049 PR-3 TTL-close SEC fix re-review (branch feat/adr049-pr3-live-timers, HEAD 21a93a88e)

Re-review of 4 fix commits over 5752cd50a. SEC-1 + SEC-2 RESOLVED, no new blocking findings.

## SEC-1 (keys never destroyed + despawn on transient failure) -- RESOLVED
- `ttl_close_helpers::handle_ttl_expiry` (ttl_close_helpers.rs:115) is two-phase:
  Phase 1 = `ttl::apply_ttl_terminal_transition` (sync FSM Active->Expired + destroy_mls_group +
  destroy_sender_key) then `commit_class_s_keep` fail-closed persist of terminal Expired snapshot,
  OUTSIDE any timeout. Phase 2 = relay/event-log I/O bounded INSIDE timeout(30s).
- `commit_class_s_keep` (class_s.rs:2792): runs f, persist_state_fail_closed, returns persist err
  WITHOUT rollback = durable-before-ack, keep-on-failure. Snapshot reads handle.state()=Expired
  (shared ArcSwap), so terminal state is durable.
- Despawn gate (actor/mod.rs:812 on_ttl_tick): `terminal && result.is_complete() && persist_result.is_ok()`.
  is_complete() == all 4 steps incl STEP_MLS_DESTROYED + STEP_SENDER_KEY_DESTROYED. So NO despawn
  path leaves keys undestroyed. Transient failure -> keep alive + ttl_expiry_retry arm (5s backoff,
  Arm 2b), carries completed_steps bitmask so only failed step re-runs. Idempotent leaf via
  terminal_leaf_exists (ttl.rs:779).
- FFI ExecuteTtlClose (ttl_close.rs:231, B10) + FinalizeClose (:302) drive cell.handle.clone()
  (REAL shared ArcSwap), not detached throwaway. Inner error surfaced to caller (:246) + tracing::error.
  Ok reply => keys destroyed + durable. Single attempt, no auto-retry (caller-driven), acceptable.

## SEC-2 (non-terminal fire abandons timer) -- RESOLVED
- reconcile_timers (actor/mod.rs:672): is_active gate. !Active => ttl_timer=None + ttl_armed_deadline=None
  unconditionally. Active + deadline-change => re-arm sleep(deadline.saturating_sub(now)).
- on_ttl_tick non-terminal branch (:826) sets ttl_armed_deadline=None so reconcile re-evaluates.
  Belt-and-suspenders; reconcile's is_active gate already disarms non-Active.

## Defense-in-depth added (BUG-1): close/tombstone/promote now durably clear
  state.ttl.timer.deadline_unix_secs=None in fail-closed snapshot (lifecycle_helpers.rs:close_context_with_key,
  governance_helpers.rs:execute_close_context/tombstone_migrated_context). Plus respawn anti-resurrection
  (supervisor.rs:4388 snapshot.state != Active => skip) + B8 create precheck (:2701).

## B8 create-terminal precheck -- fail-CLOSED, doesn't block standing re-create
  supervisor.rs:2701 under bootstrap_spawn_lock. Ok(Some(terminal))=>refuse; Ok(_ None/non-terminal)=>create;
  Err=>refuse fail-closed. Standing re-create over non-terminal/absent id still allowed.

## Signature change: dispatch_start_ttl_timer bool anchor_deadline_to_creation -> Option<u64> deadline_override.
  Removes old local-clock arming path (strengthening). None=create(handler derives creation+ttl);
  Some=restore/import(persisted ttl_deadline_secs or creation+ttl fallback). Consistent across PyO3/NAPI/UniFFI.

## Non-findings verified
- No info leak: tracing logs context_id (public 64-hex) + ContextError Display; no key bytes/plaintext.
- No DoS spin: retry backoff 5s fixed, not attacker-triggerable. Non-terminal-Active spin unreachable
  (Active->Expired is unconditionally-valid FSM transition, actor is sole mutator).
- Minor residual (NOT a regression, pre-existing crash-durability class): process death during a
  pending retry (mailbox close via biased Arm1 None) can orphan key material in MLS storage if
  destruction failed transiently. Context stays terminal/dormant (restore skips non-Active, B8
  refuses re-create), so NO resurrection / NO access-control bypass -- keys orphaned but unreachable.
