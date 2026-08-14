---
name: eventtype-audit-1847
description: Alignment review of EventType producer-audit branch fix/eventtype-audit-1847 (issue #1847) — TokenRevoked dual-schema, KeyEpochAdvance gaps, PyO3 media parity
metadata:
  type: project
---

# fix/eventtype-audit-1847 (issue #1847) EventType producer audit @ 737206f84 — NEEDS DISCUSSION

Branch adds missing EventType producers: GovernanceDeadlockRecovery (governance_helpers execute_reconfigure_governance), KeyEpochAdvance (broadcast_helpers block_broadcast_subscriber, after MemberBlocked), TokenRevoked (recovery.rs revoke_ucans), MediaSessionStarted/Ended (NAPI+UniFFI media bridges), + ProvenanceAttached/Received doc-fix.

**Why review flagged NEEDS DISCUSSION — findings:**

1. **HIGH — TokenRevoked has TWO incompatible payload schemas under one EventType.** New recovery.rs producer emits positional-MessagePack `TokenRevokedPayload{revocation_cid, scopes, revoked_at}`; pre-existing resolvers.rs (`crates/scp-ffi/common/src/resolvers.rs:871`) emits JSON `{context_id,revoker_did,token_cid}` via `token_revoked_payload` (revoke.rs:626), explicitly documented as the CONVERGENT §9.9.3 leaf preimage. Same `EventType::TokenRevoked` tag → decoder cannot pick a schema. Fix: recovery producer must reuse the JSON shared producer OR use a distinct EventType. Also unit mismatch: payload `revoked_at` doc=ms while leaf Event.timestamp=secs.

2. **MEDIUM — governance-ban KeyEpochAdvance producer still missing (check #4).** Spec 05-contexts §2008/§2015 mandates "All authors MUST rotate keys after a governance ban (mandatory KeyEpochAdvance per author)." `execute_revoke` Read/Both path (governance_helpers.rs ~926) calls `governance_ban_subscriber` (rotates all authors) but emits ReadAccessRevoked/AccessKeyRevoked/AccessRevoked, NO KeyEpochAdvance. Branch only wired the per-author unilateral block path.

3. **MEDIUM — KeyEpochAdvance payload diverges from spec schema.** Spec §2048 `KeyEpochAdvance{sender_did, epoch}`; impl `KeyEpochAdvancedPayload{old_epoch,new_epoch}`, old_epoch derived `new.saturating_sub(1)` (bakes +1 assumption). sender_did carried via Event.actor_did (ok).

4. **MEDIUM — PyO3 media producer parity gap.** ADR-024 AC8 (phase-5.md:304) leaves added to NAPI+UniFFI only. PyO3 `py_media_activate_session`/`py_media_end_session` (`crates/scp-ffi/src/media.rs:245,308`) do NOT append — yet PyO3 is the reference bridge (100% coverage). py_media_end_session doc says "returns metadata for event log recording" but never records.

5. **Uncommitted worktree change:** governance_helpers.rs converts GovernanceDeadlockRecovery append fail-closed(.await?)→best-effort(match+warn!). Not committed. Semantically defensible (companion audit leaf; primary GovernanceReconfigured already durable).

**ALIGNED / positives:**
- fail-closed vs best-effort (check #3) consistent: pattern = primary state leaf fail-closed, companion audit leaf best-effort. Spec §9.4.2 durability clause (§2029) puts guarantee on block STATE + read_exclusion_list, NOT audit leaves → best-effort audit leaves spec-consistent.
- ProvenanceAttached/Received doc-fix (737206f84) CORRECT — provenance producer uses `rmp_serde::to_vec` positional MP + SHA-256 (provenance.rs:290), doc now matches code (§24.3.3).
- GovernanceDeadlockRecovery placement correct: execute_reconfigure_governance requires deadlock justification (unavailable_dids/missed_windows) = genuine §10 recovery path. Emitting both GovernanceReconfigured + companion recovery leaf defensible.
- Media events single-initiator, non-convergent, appended via append_unsigned_event on FFI-side log — consistent with provenance/TokenRevoked-resolver precedent; AC8 mandates recording.

LESSON: an EventType-producer audit must (a) check for PRE-EXISTING producers of the same type before adding a new one — divergent payload schemas under one tag break decodability/§9.9.3; (b) sweep ALL spec-mandated producer sites for a type (per-author block AND governance ban both mandate KeyEpochAdvance), not just one; (c) verify bridge parity incl. PyO3 reference bridge.
