---
name: xctx-tool-invoke-saga-624
description: Crypto review of §6.2.4 cross-context tool-invocation saga (feat/actor-2c-6.2.4-xctx-saga) — receipt/divergence preimages SOUND, UCAN re-bind SOUND, but receipt.verify never called on production path (HIGH)
metadata:
  type: project
---

# §6.2.4 Cross-Context Tool Invocation Saga — crypto review (branch feat/actor-2c-6.2.4-xctx-saga)

Files: scp-protocol/src/context/tools/cross_context_saga.rs; scp-runtime/src/context/actor/handlers/saga.rs; scp-runtime/src/context/supervisor/supervisor.rs.

**SOUND items:**
- `CrossContextToolReceipt` preimage (`SCP-XCTX-RECEIPT-V1:`, cross_context_saga.rs:179) byte-exact to spec §6.2.4 normative order: Fixed32(caller_ctx),Fixed32(target_ctx),VarBytes(caller_did),RawBytes16(nonce),VarBytes(tool_reg_id),Fixed32(output_hash),VarBytes(tool_invoked_event_id),U8(chain_depth),U64(timestamp_ms). canonical_hash §9.5.1 (4B-BE len-prefix VarBytes). Splice-safe (only adjacent var fields are self-delimiting VarBytes; RawBytes16 nonce at fixed offset between delimited neighbors). output_hash=SHA-256(output_jcs) recomputed from carried bytes; signer JCS-canonicalizes (RFC8785 serde_json_canonicalizer) at sign time (saga.rs:1047). verify_strict (no malleability).
- `CrossContextDivergenceMarker` preimage (`SCP-XCTX-DIVERGENCE-V1:`): VarBytes(saga_id),RawBytes16(nonce),U8(committed_side.tag Caller=0/Target=1),VarBytes(committed_event_id). Tag bound+covered.
- UCAN confused-deputy re-bind (Prepare-B, saga.rs:589 validate_ucan_rebind): resolves proof from B's OWN store, required_cap=CapabilityUri(target_hex,"tool_invoke",tool_reg_id) binds tool+executing-ctx, presenting_agent_did=caller_did → validate_ucan step5 AudienceMismatch rejects proof delegated to diff principal; check_capability_match rejects diff tool; +attenuation+ceiling. Fresh per-validation nonce tracker correct (stored long-lived proof). Ungated path None no-ops but gated by validate_inbound_policy require_spending_ucan.
- B-recorded provenance signed not caller-asserted + replay-deterministic: recorded_timestamp_ms=B clock, recorded_nonce=B staged copy of wire nonce, recorded_chain_depth=asserted+1; staged into saga_pending; receipt signed from STAGED values at Commit (saga.rs:1065/1069/1070), never re-read from wire. Freshness/dedup on B; nonce stays recorded on persist fail (fail-closed). serde_nonce_16 length-strict.

**HIGH (open):** Receipt NEVER verified on any production path. saga.rs:1139 commit_a uses only req.receipt.len() (receipt_len :1189), never deserializes/verify. supervisor.rs:5852 commit_a_settle forwards raw bytes. receipt flows to SagaOutput.receipt→FFI unverified. Only receipt.verify() calls are #[cfg(test)]. Contradicts §6.2.4 *Signer authorization* normative ("consumer MUST confirm signing key is Active Signing Key for target_context_id"). HIGH-not-CRITICAL today: co-resident topology mints receipt itself w/ ctx.target_signing_key (supervisor.rs:5825, correct-by-construction); escrow amount from held Prepare-A reservation not receipt. But becomes confused-deputy/forged-provenance vector when target is remote (transport-independence direction), and A records output_hash into provenance edge from req.output_bytes w/o checking it matches signed receipt. Fix: in commit_a, deserialize+resolve target Active Signing Key via key_resolver+receipt.verify + assert output_hash/nonce/caller_did/ctx-ids match, BEFORE settling escrow + writing edge (process-before-verify ordering defect).

**MED:** A's logged output_hash (saga.rs:1188 hex_output_hash(req.output_bytes)) unbound to receipt's SHA-256(jcs) — diverges for outputs whose serde≠JCS, breaking dual-log join. Fix: derive from receipt's carried output_jcs after verify.
**LOW:** trait name sign_prehashed_preimage misleads (plain Ed25519 over §9.5.1 digest, NOT RFC8032 Ed25519ph) — cosmetic rename.
