---
name: project-2c-pr5-broadcast-handshake
description: ADR-049 Phase 2C PR-5 — real Prepare/Commit/Abort dispatch for broadcast hosting-handshake saga (§5.14.13); RUNTIME-ONLY; mirror #1849 xctx pattern. Full file/structure map + design.
metadata:
  type: project
---

ADR-049 Phase 2C PR-5: wire the broadcast hosting-handshake saga (§5.14.13). Branch `feat/2c-pr5-broadcast-handshake` off origin/main tip `a81c15f6e` (#1883 leaf types). RUNTIME-ONLY (no FFI = PR-6).

**Why:** #1883 landed leaf types + replay-at-startup; the saga dispatch is still `NotImplemented`. Mirror the MERGED #1849 cross-context tool saga end-to-end.
**How to apply:** This is mechanical execution of ALL of §5.14.13 (partial=failure). Do NOT touch .docs/ (parallel coder), FFI, enforcement files.

## Leaf types (DONE in #1883, reuse — do NOT redefine)
`crates/scp-protocol/src/context/broadcast/hosting_handshake.rs`: BroadcastHostingRequest/Grant (+Fields+sign/verify, §9.5.1 preimages SCP-BCAST-HOST-REQ-V1:/GRANT-V1:), BroadcastHostConfig (clamp/validate/to_jcs; ranges rate[1,6000] subs[1,1e6]; expires>0), AcceptedHostSnapshotEntry, ForwardingPolicy(Verbatim/RoutingStripped), errors SCP-SAGA-13100-13102. KATs for BOTH preimages ALREADY EXIST (request_preimage_is_byte_exact_gated, grant_preimage_is_byte_exact) — confirm, add runtime KATs only if gap.

## Reference impl (#1849, MERGED) — mirror exactly
- `crates/scp-runtime/src/context/supervisor/supervisor.rs` (19.5K lines):
  - `SagaInput` enum @208; `BroadcastHostingHandshake` variant @262 has ONLY {host_context_id, broadcast_context_id, subscriber_did} — rich request material rides a NEW `BroadcastSagaCtx` (like xctx's CrossContextSagaCtx @456 carries signing keys/executor, NOT in SagaInput).
  - `start_cross_context_tool_invocation_saga` @5212: authorize-before-reserve gate1 (is_member caller) + gate2 (interface), build ctx, `saga_participant_context_set`+`try_reserve_context_set`@5455, `run_saga`@5341.
  - `run_saga`@5341 → `run_saga_fsm`@6373 (takes `xctx: Option<&mut CrossContextSagaCtx>`; ADD parallel `bctx: Option<&mut BroadcastSagaCtx>`). FSM: Initiated→PreparingA→PreparingB→Committing→Committed/Aborting/NeedsRepair. Journals evidence via `xctx_prepared_evidence_bytes`@7482 (ADD `bcast_prepared_evidence_bytes`).
  - `dispatch_prepare_phase`@6533 + `dispatch_commit_phase`@6725: BroadcastHostingHandshake arms currently NotImplemented (@6562, @6736) — REPLACE. `dispatch_xctx_prepare_a/_b`@6588/6626 send SagaPhaseMessage to co-resident actor via `self.lookup(hex).send(|reply| ...)`. ADD `dispatch_bcast_prepare_a/_b` + `dispatch_bcast_commit`.
  - `abort_saga`@7543 (xctx reverses economy; broadcast just sends Abort to prepared sides, drop staged). `saga_input_participants`@10664 + `saga_participant_context_set`@10740 + `saga_input_is_secret_bearing`@10793 ALREADY handle BroadcastHostingHandshake correctly (3-field read) — NO change.
  - Crash recovery: `recover_saga_entry`@5635, `reconstruct_xctx_prepared`@6024, `redrive_xctx_prepare_in_progress`@6156, `redrive_xctx_commit_in_progress`@6197. ADD broadcast analogues.
- `crates/scp-runtime/src/context/actor/commands.rs`: `SagaPhaseMessage` enum @2749 is `#[non_exhaustive]`, variants tool-specific (PrepareA/B/CommitBReserve/CommitBSettle/CommitA/CommitACheckWitness/Abort/EmitDivergenceMarker). ADD broadcast variants (BcastPrepareA/B/CommitB/CommitA/Abort). `InitiateBroadcastHostingHandshake` in BroadcastCommand @1749 (reply NotImplemented currently).
- `crates/scp-runtime/src/context/actor/mod.rs`@726-748: routes SagaPhase variants to handlers/saga.rs::dispatch.
- `crates/scp-runtime/src/context/actor/handlers/saga.rs` (5.8K): `dispatch`@178 → `dispatch_prepare_phase`/`dispatch_commit_phase`. ADD broadcast phase handlers here. NoopNonceTracker pattern @158.
- `crates/scp-runtime/src/context/actor/handlers/broadcast.rs`@~151: `reply_saga_deferred` + `InitiateBroadcastHostingHandshake` arm — REPLACE deferred.
- `crates/scp-runtime/src/context/supervisor/saga_journal.rs`: `mark_resolved(secret_bearing=false)`.
- `crates/scp-runtime/src/context/supervisor/saga_prepared_state.rs`: `BroadcastHostingHandshakePrepared`@389 is OPAQUE placeholder (host/broadcast ids, subscriber_did, broadcast_host_config_bytes). REPLACE with typed (add wrapping_pubkey, key_epoch_at_grant, granted_at_ms, grant_nonce, grant_timestamp_ms; config_bytes = CLAMPED granted_config JCS). ADD `BroadcastHostingHandshakePreparedWire` + to/from_evidence_bytes (currently MISSING, unlike the other two variants). Update `BroadcastHostingHandshakeSnapshot`@493 + from_prepared@534/into_prepared@571.

## Broadcast state (scp-protocol)
`crates/scp-protocol/src/context/broadcast/mod.rs`: BroadcastContext@553 {context_id, admission, subscribers: HashMap<String,SubscriberRecord>, authors: HashMap<String,AuthorState>}. AuthorState@226 has epoch + block_list (PER-AUTHOR). to_snapshot@1618/from_snapshot@1650 + BroadcastContextSnapshot@1695. is_blocked(author,sub)@985, handle_key_request@(helpers). NEEDS: add `accepted_hosts: HashMap<(host_id_hex,subscriber_did), AcceptedHostSnapshotEntry>` + aggregate-cap config + snapshot fields. current_key_epoch = author.epoch.
`crates/scp-runtime/src/context/broadcast_helpers.rs`: subscribe_broadcast@59 (MemberJoined append + idempotent register pattern to reuse at Commit-B), handle_broadcast_key_request@672 (the §5.14.2 pull), persist_broadcast_snapshot.

## PerContextState (state.rs)
`saga_pending: HashMap<SagaId,SagaPreparedState>`@755 + `xctx_nonce_dedup: NonceDedup`@793 (Class-S). ADD `bcast_request_nonce_dedup: NonceDedup` (broadcast author owns request-nonce dedup, §6.2.2 5min/10k). Test ctors `new_for_test_encrypted` / `new_for_test_broadcast`.

## Test harness (mirror, in supervisor.rs tests mod)
`xctx_saga_happy_path_commits_and_executes_once`@15758 + helpers @15412-15748: const XCTX_CALLER/TARGET/TOOL; RecordingEventLog@15424; xctx_supervisor_with_event_log@15468 (Supervisor::with_providers); xctx_caller_state@15617 / xctx_target_state@15670 (PerContextState::new_for_test_*, transition Active, add_member, ceiling, tool_interfaces); spawn_xctx_pair@15727 (build_actor_deps + spawn_actor_with_state). Concurrency gating tests in `crates/scp-runtime/tests/actor_saga_concurrent.rs` (generic start_saga). Real e2e tests live INSIDE supervisor.rs tests mod.

## Design decisions
- Commit-B (broadcast side, authoritative) does: validate request sig bound to subscriber_did; freshness (timestamp §9.14 skew + nonce dedup); block-list + rate-limit; gated→validate ucan messages:read re-bound to subscriber_did; clamp config→granted; capture current_key_epoch+granted_at_ms+grant nonce/ts at single Prepare-B instant into staged; aggregate-cap check (sum over live entries EXCLUDING this pair); sign grant; persist AcceptedHostSnapshotEntry + MemberJoined{subscriber} (idempotent re-register) on §5.15.3 sync path; NO key pushed. Commit-A: persist signed grant (durable relay proof) + host-registration. Idempotent by supervisor-minted SagaId.
- Abort: drop staged, no key/snapshot/append. RateLimited→Rejected{retry_after_ms}.
- NO honor_key_epoch_advance knob. forwarding_policy verbatim vs routing-stripped (preserve signed envelope). expires_at_ms>0 (clamp to granted_at_ms+max_grant_lifetime_ms default 7d). Aggregate cap default subs 100k/rate 6000.
- Class S (survives unwind, breaks atomicity/anti-replay/grant-auth): accepted_hosts snapshot, bcast_request_nonce_dedup, saga_pending. Class C: nothing new. Document in comments.

## Gates
fmt; clippy (uniffi/ffi/napi allow_in_memory_custody + scp-core/testing + scp-runtime/testing -Dwarnings; expect_used denied→map_err); test -p scp-runtime -p scp-protocol (+features scp-runtime/testing,saga-witness-test-mint if needed); check-error-codes.sh + check-saga-gating-granularity.sh (no weaken). DYLD_LIBRARY_PATH for tests. No issue numbers in source. Commit, do NOT push/PR/merge.

## STATUS: COMPLETE (committed 5338e6034 on feat/2c-pr5-broadcast-handshake, base a81c15f6e)
All ACs met. Gates ALL GREEN: fmt clean; full-workspace clippy with all CI features = 0 err/warn; scp-protocol 3037 pass + scp-runtime 1931 pass (incl 10 new broadcast saga tests) + integration targets pass; check-error-codes (2341 occ, codes 13110-13169 in-range) + check-saga-gating-granularity PASS; full workspace builds clean. 24 files, +3077/-83.

## Key design choices (resolved during impl)
- Parallel `bctx: Option<BroadcastSagaCtx>` threaded through run_saga/run_saga_fsm/dispatch_prepare/commit/abort (NOT a separate FSM) — reuses generic journal/reservation. Extracted `handle_commit_failure` + `saga_prepared_evidence_bytes` helpers to stay under clippy 100-line limit. Box::pin the 3 run_saga call sites + handle.rs start_saga (large_futures lint — bctx grew the future).
- accepted_hosts registry lives in `BroadcastContext` (Class-C field), persisted FAIL-CLOSED at Commit-B via deps.persistence.persist_broadcast (gets §5.15.3 sync). Aggregate cap also on BroadcastContext.
- NEW Class-S fields on ClassSState (+ ClassSStateSnapshot mirror + on-disk ContextSnapshot flat fields + ~10 construction sites): `bcast_request_nonce_dedup: NonceDedup` (B-owned, REQUEST_NONCE_SIZE=16) and `bcast_committed_grants: HashMap<SagaId,Vec<u8>>` (A-owned grant proof witness). Both drop-on-export.
- Grant the host receives = the byte-identical Prepare-B-signed grant carried in ctx.prepared_b → Commit-A; Commit-B returns a discarded snapshot echo. Replay-determinism via staged grant_nonce/grant_timestamp_ms/key_epoch_at_grant/granted_at_ms.
- Prepare-A persist uses commit_class_s_restore (auto-rollback); Prepare-B uses commit_class_s_keep_restore_split (record nonce KEEP + stage slot RESTORE); Commit-B/A use commit_class_s_keep with view.rest_mut() to reach Class-C broadcast/membership under the fail-closed combinator.
- Crash recovery: reconstruct_bcast_prepared (distinct rmp field-names = no xctx collision) + redrive_bcast_commit_in_progress (idempotent Commit-B re-ack + BroadcastCommitAReack witness). PR-7 owns the full replay-spawn; PR-5 keeps the evidence path live + actor idempotency.
- APIs: scp_protocol::jcs::to_vec (not crate::jcs_to_vec); parse_ucan (UcanToken has no new(str)); membership.contains; (key_resolver)(&did, SigningKeyId::Active); Capability::MessagesRead.

## Spec note surfaced (no blocker): §5.14.13 "subsequent HPKE pull authorized by the snapshot" — PR-5 makes the AcceptedHostSnapshotEntry exist + queryable (BroadcastContext::accepted_host); full §5.14.2 pull-side gating that CONSULTS the snapshot (block-list/gated-UCAN at serve time) is the §5.14.2 consumer's own wiring, not redone here.
