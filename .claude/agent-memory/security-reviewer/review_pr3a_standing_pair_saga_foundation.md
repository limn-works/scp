# PR-3a standing-pair saga foundation types — security review (2026-06-16)

Worktree saga-3a, branch feat/actor-2c-3a-saga-foundation, HEAD 9cb8cc272.
Files: creation_receipt.rs (new, 476L), saga_prepared_state.rs (diff), scripts/check-error-codes.sh (additive SCP-SAGA band), mod.rs, sdk-common.md, 2 .docs.

VERDICT: SECURITY-CLEAN, zero required findings. Foundation types only; dispatch in later PR.

1. SECRET EXPOSURE: CreationReceipt fields = context_id(String,prefixed display), mode, template_id, creator_did, peer_did (all String), + 4 bools (mls_group_created/sender_key_created/event_log_created/published). NO MLS secret/sender-key/ratchet/private-key. group_id field REMOVED post-spec-revision (keys off derived_context_id via provider Entry::Vacant SHA-256("standing-"‖hex)). StandingPairCreatePreparedWire mirrors only public fields. Debug/Serialize derive on receipt is INTENTIONALLY safe (public plan-metadata, doc §"Not secret-bearing"). §9.4.3 non-derive barrier on actor-side StandingPairCreatePrepared (no Serialize) is preserved; explicit Wire mirror is the sanctioned serialize path. CLEAN.

2. rollback() destruction primitive: keys destroy ops on a SEPARATE `derived_context_id:&[u8;32]` ARGUMENT, NOT on receipt's own display context_id string (doc lines 192-194 explicit). provider destroy_mls_group/destroy_sender_key/destroy_event_log/delete_published key strictly on the [u8;32] via DashMap::remove/get_mut, NO fallback. So a confused/malformed receipt CANNOT redirect destruction — the caller (dispatch PR) supplies the id out-of-band. Steps gated on creation bools (never destroy a step that never ran). Best-effort: failing step logged+continue (tested). DESIGN SOUND. Forward obligation for dispatch PR: the id passed MUST be the saga's own derived_context_id (recompute/bind, not receipt-derived) — but that binding is the dispatch PR's job, out of scope here.

3. check-error-codes.sh: PURELY ADDITIVE. New SCP-SAGA arm copies GOV/ECON pattern exactly (`$num -ge 1000` guard + 13000-13999 range). Both regex match-lists extended (|SAGA). NO existing assertion weakened/removed. NEVER-WEAKEN respected. Band registered in sdk-common.md table (13000-13999, next after ECON 12000-12999).

4. from_bytes / from_evidence_bytes: serde_json::from_slice / rmp_serde::from_slice, both Result (no panic). Allocation bounded by struct shape — all scalar/String/Option/[u8;32] fixed fields; the only unbounded Vec<u8> fields (old group_id, creation_receipt_bytes) were REMOVED. jcs::to_vec returns Result (no panic). DID is plain pub String newtype, no validation on construct — consistent w/ codebase; spec §5.15.8 DID validation happens at Prepare-A/B (dispatch PR). CLEAN.

5. Error taxonomy: SCP-SAGA 13000-13999 band leaves room for SagaAborted/SagaBusy/SagaNeedsRepair typed errors; no code strings introduced in THIS PR (honest unregistered until dispatch). No info-leak surface added.

OBSERVATION (non-security, alignment): spec §5.15.8 field table (05-contexts.md:1817) still lists `creation_receipt_bytes: Vec<u8>` while code carries typed `creation_receipt: Option<CreationReceipt>` on the actor struct + Wire mirror. Different serialization boundary (table = journal evidence shape; code field = in-memory typed). Receipt still JCS-round-trips via to_bytes/from_bytes per spec. Flag for dispatch-PR alignment, NOT a security defect.
