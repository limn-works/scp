---
name: issue1847-eventlog-payloads
description: Crypto review of issue #1847 event-log typed payloads (scp-event-log/src/payload.rs) on fix/eventtype-audit-1847
metadata:
  type: project
---

# Issue #1847 event-log typed payloads (branch fix/eventtype-audit-1847)

Reviewed scp-event-log/src/payload.rs + lib.rs EventType. Leaf preimage = SHA-256(0x00 ‖ rmp_serde(Event)); Event field-0 = event_type, so event_type IS bound into every leaf hash. Payloads encoded positional MsgPack (to_vec, NOT to_vec_named) = fixarray, field order = wire contract.

**Why:** ADR-011 typed-event unification; forensic audit trail hardening.

**How to apply — findings for future sessions:**
- Q1 (737206f84 doc fix) SOUND: ProvenanceAttached/Received payload = SHA-256 of positional-MsgPack DataProvenance (32B). Verified all 3 bridges (pyo3 provenance.rs:290, napi:136, uniffi bridge.rs:17428) use identical rmp_serde::to_vec(&prov)+Sha256, matches spec §24.3.3 ("JSON not used"). Prior "JSON" doc was wrong; fix correct.
- Wire-shape ambiguity (latent, NOT a bug): several payloads share identical positional shapes — KeyEpochAdvanced≡RecoveryEpochAdvanced ([u64,u64]); GovernanceActionExecuted≡RoleAssigned≡MembershipChange ([String,String]); AppUnbound≡AccessRevoked ([String]). Safe ONLY because (a) event_type bound in leaf hash, (b) project_payload dispatches on event_type. No in-payload domain tag. Any future decode without authoritative event_type silently misinterprets.
- KeyEpochAdvanced forensic: per-AUTHOR epoch; Event.actor_did=author_did enables per-author cross-leaf continuity (leaf[n+1].new==leaf[n].new+1). old_epoch = result.new_epoch.saturating_sub(1) — DERIVED not observed, but EXACT because block_subscriber (broadcast/mod.rs:1366) uses checked_add(1) unconditionally. So old_epoch is redundant/decorative (zero independent info), not wrong. Skip detection relies on new_epoch continuity only.
- **Q4 real finding (MEDIUM) — RESOLVED in 2nd pass:** GovernanceDeadlockRecoveryPayload.missed_windows was `.len()`; now `Vec<(String,u32)>` losslessly mirroring DeadlockJustification (governance/mod.rs:523: unavailable_dids Vec<DID>, missed_windows Vec<(DID,u32)>, detected_at u64) via `.map(|(d,n)|(d.0.clone(),*n))`. Per-DID evidence preserved. Empty-evidence guarded (rejects if both empty). Threshold/proposal_id still absent but that's a spec-scope note not a code bug.

## 2nd pass (fix/eventtype-audit-1847, full origin/main..HEAD diff)
- Positional MsgPack SOUND: 4 new structs (KeyEpochAdvancePayload[u64,u64], GovernanceDeadlockRecoveryPayload[Vec<String>,Vec<(String,u32)>,u64], MediaSessionStartedPayload[5], MediaSessionEndedPayload[6]) all use encode_payload (rmp_serde::to_vec positional). event_type bound in leaf (leaf_hash=SHA-256(0x00‖rmp_serde(full Event)); serialize_event_for_hashing tree.rs:277 = to_vec(event); EventType field-0 serialized by NAME) → KeyEpochAdvance≡RecoveryEpochAdvanced [u64,u64] collision safe.
- TokenRevokedPayload REMOVED cleanly (0 residual). Authoritative producer = scp-protocol/crypto/ucan/revoke.rs:626 token_revoked_payload → serde_json BTreeMap sorted keys (context_id,revoker_did,token_cid), cross-bridge convergent, fail-loud on serialize. No crypto gap.
- KeyEpochAdvance old_epoch=new_epoch.saturating_sub(1): EXACT (key_protocol.rs:470 new_epoch=current_epoch.checked_add(1); saturating==checked since new>=1). Redundant/decorative, not wrong. Best-effort append (warn).
- **NEW FINDING (MEDIUM): GovernanceDeadlockRecovery fail-closed is NOT atomic.** governance_helpers.rs:2926 execute_reconfigure_governance order: (1) commit_class_s_restore .await? (signer removal DURABLE) → (2) append GovernanceReconfigured .await? (DURABLE) → (3) encode+append GovernanceDeadlockRecovery .await? (the fail-closed leaf). On step-3 failure the takeover + primary leaf are ALREADY durable, so justification is still absent — exactly what the comment claims fail-closed prevents. Crash between (2)&(3) = same gap, no error. Direction (propagate>swallow) OK but comment overstates guarantee; true co-presence needs justification folded INTO GovernanceReconfigured leaf (single atomic leaf) or single atomic persist. Latent retry-duplication (retry appends 2nd GovernanceReconfigured).
- Media best-effort SOUND/LOW: missing leaf = under-counted participation (ADR-017 §7.3.2), no confidentiality/integrity impact (Merkle chain stays valid, append just didn't happen); matches Provenance*/OutletInvoked convention. actor_did="" for empty participants = degenerate but len-prefixed unambiguous leaf. All 3 bridges (napi/pyo3/uniffi) identical positional encode_payload.
- Cross-cutting: 2 new companion-leaf sites make OPPOSITE fail choices (gov fail-closed, key-epoch+media best-effort). Defensible on criticality but gov fail-closed doesn't deliver the atomicity it claims.
