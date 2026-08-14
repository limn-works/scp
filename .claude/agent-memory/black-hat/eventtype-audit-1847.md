---
name: eventtype-audit-1847
description: Audit-trail completeness attack on fix/eventtype-audit-1847 (KeyEpochAdvance/MemberBlocked/TokenRevoked appends)
metadata:
  type: project
---

# fix/eventtype-audit-1847 audit-trail completeness attack

Branch adds KeyEpochAdvance-after-MemberBlocked (broadcast_helpers.rs:681), TokenRevoked
(recovery.rs revoke_ucans:993), GovernanceDeadlockRecovery, MediaSession leaves.

## Findings (audit integrity gaps)
- **BLACK-1847-01 HIGH — KeyEpochAdvance audit asymmetry.** KeyEpochAdvance leaf emitted ONLY in
  `block_broadcast_subscriber`. TWO other paths advance sender-key epochs with NO KeyEpochAdvance:
  (a) `execute_revoke` governance ban → `governance_ban_subscriber` rotates EVERY author's epoch
  (+`block_author` for one) but emits only ONE `AccessRevoked` leaf. Mass key rotation, zero epoch leaves.
  (b) `unsubscribe_broadcast(rotate_keys=true)` → `bc.unsubscribe` sets `author.epoch=new_epoch` for ALL
  authors (broadcast/mod.rs), emits only `MemberLeft`. Non-broadcast `rotate_sender_key` (revoke H7) too.
- **BLACK-1847-02 MED-HIGH — MemberBlocked never emitted for governance bans.** Governance ban of a
  subscriber emits AccessRevoked, not MemberBlocked. Auditor enumerating MemberBlocked to list blocked
  subjects MISSES every governance ban (incl. creator/author bans per BLACK-303 lineage).
- **BLACK-1847-03 HIGH — TokenRevoked fully decoupled from revocation success.** recovery.rs revoke_ucans:
  append gated on `if let Some(elp)=event_log_ref()` (None→silent skip), best-effort warn on failure, and
  fn returns Ok based on NOTIFICATION dispatch regardless. Revocation "succeeds" with no durable audit.
- **BLACK-1847-04 MED (architectural) — byzantine backend drops best-effort leaves undetectably.**
  event_log provider is `Box<dyn>`; Ok w/o persist undetectable. Cross-member §9.9.3 merkle convergence
  only catches leaves honest members ALWAYS append. Best-effort leaves (KeyEpochAdvance, TokenRevoked)
  may be legitimately absent → byzantine drop of exactly those is indistinguishable from benign failure.
- **BLACK-1847-05 MED — context_id_to_bytes case-sensitivity keying split.** state.rs:2254 uses 64-hex
  LOWERCASE branch else SHA-256(id). Non-canonical-case ctx id → SHA-256 slot ≠ digest slot digest-keyed
  readers use → audit leaves invisible. Same class as ADR-056 broadcast routing + FFI SHA-256 read stragglers.

Verdict: appends are correct where wired, but coverage is INCOMPLETE. KeyEpochAdvance is not a
soundness-complete witness of sender-key rotation; MemberBlocked not a complete witness of blocks;
TokenRevoked not bound to revocation success.

## SECOND PASS (7 commits @6553bb2b8, post first-pass fixes)
- **BLACK-1847-01 CONFIRMED HIGH, now SPEC-MUST-backed & IN SCOPE.** spec 05-contexts.md:2008 &
  :2015 say governance ban → "mandatory `KeyEpochAdvance` per author". execute_revoke
  (governance_helpers.rs:932) calls bc.governance_ban_subscriber → returns GovernanceBanResult with
  `rotated_authors: Vec<AuthorKeyRotation{author_did,new_epoch,new_key}>` (broadcast/mod.rs:402/1640)
  — EXACTLY the data for per-author KeyEpochAdvance leaves — but code keeps only `.len()` (l.934) and
  emits ONLY AccessRevoked (973-981). ZERO KeyEpochAdvance leaves on a spec-MANDATORY path. PR added
  KeyEpochAdvance to the NON-mandatory unilateral block path (best-effort, fine) but omitted the one
  the spec calls "mandatory". Also rotate_sender_key sites 1408/2539/lifecycle:402 emit none (spec
  explicit only for ban/block; those secondary). BLOCKER for double-zero.
- **BLACK-1847-06 NEW MED-HIGH — media appends DEAD on 3/4 SDKs.** ADR-024 AC8 only fires on NAPI/TS
  (media_activate_session_on modified in-place). PyO3 added SEPARATE `media_activate_session_with_log`
  pymethods on PyScp but Python SDK media.py:106 calls module free-fn `media_activate_session` (no log);
  _with_log NOT in _scp_core.pyi. UniFFI added per-instance `media_activate_session(&self)` that logs but
  generated Swift has 0 `fn_method.*media` (bindings NOT regenerated) and Swift/Kotlin SDK call the
  free-fn form anyway. Integration-checklist step-3 violation; appends uncalled = dead code.
- **LOW — recovery.rs:989 leftover `.clone()`.** TokenRevoked-add commit changed revoke(revocation_cid)
  →.clone(); removal commit left the clone. revocation_cid unused after. clippy redundant_clone did NOT
  fire (verified `cargo clippy -p scp-runtime` clean, nursery=warn) so NOT a CI break; revert to move.
- **CLOSED/RESISTANT this pass:** TokenRevoked removal JUSTIFIED — canonical wired producer is
  BridgeRevocationEventLogger (#499, resolvers.rs:844) JSON schema {token_cid,revoker_did,context_id};
  removed positional TokenRevokedPayload was a competing 2nd schema for same EventType (decode ambiguity).
  Recovery path revokes via blanket RevocationList+RecoveryEpochAdvanced, not per-token → correctly emits
  no TokenRevoked. No dangling TokenRevokedPayload/KeyEpochAdvancedPayload refs. positional MsgPack intact
  (encode_payload=rmp_serde::to_vec, payload.rs:51). PyO3 media append concurrency SOUND (with_context
  lock + append_unsigned_event re-verifies seq+prev_hash) — but dead per BLACK-1847-06.
- **LOW/architectural — GovernanceDeadlockRecovery coupling.** execute_reconfigure_governance now
  ALWAYS pairs GovernanceReconfigured+GovernanceDeadlockRecovery (fail-closed, correct today: sole caller
  is ReconfigureGovernance deadlock action @4353). If a future non-deadlock reconfigure reuses the fn it'd
  emit a false deadlock-recovery leaf. NOW guarded by INVARIANT comment @execute_reconfigure_governance.

## THIRD PASS (12 commits vs origin/main) — logic CLEAN, prior BLOCKERs CLOSED, 2 residual findings
BLACK-1847-01 CLOSED: governance-ban now loops `rotated_authors: Vec<AuthorKeyRotation>` → one KeyEpochAdvance
leaf/author (governance_helpers.rs execute_revoke, Read/Both branch only — Write-only calls block_author which
DESTROYS key, correctly no epoch leaf). BLACK-1847-06 CLOSED: media.py routes to `scp._native.media_*_with_log`
(#[pymethods] on PyScp), added to .pyi; breaking sig (required `scp: SCP`) is ADR-024-AC8-required, 0 callers broken.
unsubscribe path: `result.key_rotations: Vec<BlockResult>` looped (rotate_keys=false→empty→no-op, correct).
`old_epoch = new_epoch.saturating_sub(1)` EXACT everywhere (all rotations checked_add(1)/+=1 pre-validated →
new_epoch ≥ 1, never false 0==0). actor_did=author_did correct. Deadlock-recovery comment accurate. clone-removal safe.
- **FINDING (MEDIUM, test gap):** NO runtime test asserts EventType::KeyEpochAdvance leaf emission for
  block/unsubscribe/governance-ban (the PRIMARY #1847 deliverable). Only reconfigure got a test
  (governance_deadlock_recovery_appends_both_event_leaves). broadcast.rs `BroadcastKeyEpochAdvance` = WIRE type,
  NOT the EventType leaf. Best-effort warn-on-error emission regresses silently without a leaf-presence assertion.
- **FINDING (LOW/info):** checkpoint_events_since UNDER-COUNTS: multi-leaf ops bump counter ONCE while appending
  2..N leaves. Doc says "counts durable leaves". IMPACT NEGLIGIBLE — build_checkpoint (queries_helpers.rs:748)
  derives cp.event_count + merkle_root from ACTUAL event_log_entries not the counter → no cross-member mismatch;
  counter only gates checkpoint CADENCE (≥50 / >0&&600s). Merely delays a periodic checkpoint; all leaves still
  captured by next merkle_root.
