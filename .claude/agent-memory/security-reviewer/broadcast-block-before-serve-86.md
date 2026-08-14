# Broadcast block-before-serve crash-durability (#86, §5.14.8) — HEAD 1ea5b32e4

branch fix/86-broadcast-block-before-serve-class-s. Folds broadcast security+roster
state into fail-closed Class-S `ContextSnapshot.broadcast: Option<BroadcastContextSnapshot>`.
DELETES legacy `persist_broadcast`/`load_broadcast` ContextPersistence trait methods.

## Verdict: SECURITY SOUND. Only 2 dead-code observations (clippy-clean, non-blocking).

### Verified properties
- §C fail-closed: block_broadcast_subscriber + execute_revoke(ban) + rotate_all_author_keys
  all route mutation through `commit_class_s_keep` (class_s.rs:2764 = run closure THEN
  persist_state_fail_closed; `.map` propagates Err). Err lands BEFORE emit_event/append_context_event/ack.
  KEEP = in-memory block retained on persist fail (safe direction). UNBLOCK stays best-effort (Ok on fail).
- Ban atomicity: execute_revoke read-arm does read_exclusion_list.insert(914) + governance_ban_subscriber(917)
  in SAME closure → persisted in one fail-closed row. Test 5 (supervisor.rs:16054) pins "Err before event-log
  append" with RecordingEventLog + non-vacuity control.
- §B mutation confinement: AuthorState.{broadcast_key,epoch,block_list} now PRIVATE. Best-effort view
  = BroadcastContextClassCMut (holds BroadcastContextClassCParts disjoint refs, forwards only benign
  publish/roster methods). Security mutators inherent &mut self on BroadcastContext, reachable only via
  rest_mut() in a fail-closed combinator. compile_fail doctest on field privacy (broadcast/mod.rs class_c_parts).
- §D serve-path: handle_broadcast_key_request (broadcast_helpers.rs:706) checks
  cell.access.read_exclusion_list.contains(requester) BEFORE delegating, uniform KEY_REQUEST_DENY_REASON
  (non-leakage). Test 7 = deny-even-if-still-subscriber.
- §E restore reconcile: load_persisted_context_state (lifecycle_helpers.rs:2354) builds broadcast from
  ctx_snapshot.broadcast then bc.apply_read_exclusions(read_exclusion_list). ALL production restore
  (respawn_from_snapshot, restore_all_contexts, RestoreContext cmd) converge on restore_context →
  load_persisted_context_state. No bypass.
- 5 snapshot builders ALL fold broadcast: canonical messaging_helpers::build_snapshot_from_state (3 dups
  now delegate to it) + manager_methods::snapshot_context (flush path). ContextSnapshot is struct-literal so
  compiler forces `broadcast:` at every site; only `None` sites = strip_snapshot_for_public (correct
  redaction) + test doubles.
- Trust boundary NOT widened: broadcast rides same ContextSnapshot as all Class-S state; full export signs
  JCS(snapshot) incl broadcast; public export redacts (broadcast:None).

### Observations (dead code, NOT security defects, clippy-clean b/c Mutex/DashMap Drop)
1. InMemoryPersistence.broadcasts (providers/persistence.rs:61) + NapiBridgePersistence.broadcasts
   (napi/runtime.rs:1852): write-only orphan fields (readers deleted).
2. ProtocolRepository store_broadcast_state/load_broadcast_state (store/context.rs:688,712): pub async,
   only self-tests call them. Latent divergent write-path (writes a row load_context never reads) if a
   future caller uses them. Recommend deleting both + make_broadcast_snapshot helper + 4 roundtrip tests.
