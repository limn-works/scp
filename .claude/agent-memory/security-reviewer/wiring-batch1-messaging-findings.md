---
name: wiring-batch1-messaging-findings
description: Security review findings for wiring/batch-1-messaging branch -- envelope pipeline, access keys, reorder buffer, anti-replay, FFI signing keys
type: project
---

## Wiring Batch 1 Messaging -- Full Security Review (2026-03-24, updated)

### Files Reviewed (15 total)
- messaging.rs, provider.rs, governance.rs, lifecycle.rs, trust_recovery.rs, mod.rs (scp-runtime)
- sign.rs (envelope/inner)
- builder.rs, validation.rs, inner/mod.rs (scp-protocol)
- interface.rs (tools)
- context.rs (PyO3, NAPI), bridge.rs (UniFFI), bridge_connector.rs

### HIGH Findings
1. **NAPI/UniFFI signing key resolution silently falls back to None**: `.ok()` swallows errors, `#[cfg(not(feature))]` branch unconditionally sets None for production NAPI builds. Pre-existing #810 but wiring makes it actively break encrypted send.
2. **Recovery MessageType bypass**: Any member can set `message_type = Recovery` to skip access key unwrapping. No authorization gate or payload validation.
3. **TOCTOU on access key**: Read in Phase 1 under lock, used in Phase 2/3 without re-check. Concurrent governance revocation not caught.
4. **Reorder buffer messages skip re-verification**: BufferedMessage stores pre-decrypted plaintext. Membership re-checked at delivery but signature/access key NOT re-verified. 30s max window.

### MEDIUM Findings
1. **Sender key AAD hardcoded zeros**: seal/open use epoch=0, sequence=0 (continued #1422)
2. **Access key wrapping AAD hardcoded zeros**: wrap_content/unwrap_content use epoch=0, sequence=0. Real sequence available but not passed.
3. **Bridge trust level discarded**: evaluate_trust_level result only logged, never gates or propagates
4. **SequenceTracker/ReorderBuffer not persisted**: Anti-replay resets on restart. Plan specifies "mark for reconnection" but not implemented.
5. **SequenceTracker validate() TOCTOU**: Read-only validate() and advance() in separate lock acquisitions. Concurrent deliver_incoming for same sender/sequence can both pass.
6. **Access keys in ContextSnapshot**: Serialized rmp_serde bytes not wrapped in Zeroizing (AccessKey type itself has Zeroize/ZeroizeOnDrop).
7. **No capability check on FFI access key ops**: generate/revoke/restore in all 3 bridges lack authorization. Any caller with context_id + member_did can manage access keys, bypassing governance.

### GOOD Patterns
- Signature verification before anti-replay (tracker poisoning prevention)
- Cross-context injection defense (inner.context_id == context_id check)
- MLS credential vs inner envelope sender DID match check
- Constant-time content integrity check (subtle::ConstantTimeEq)
- Domain-separated routing IDs (send + subscribe paths match)
- Fail-closed trait defaults for seal/open (return Err, not Ok(None))
- Correct TimestampValidator (both future + past bounds with saturating arithmetic)
- Sequence 0 rejection (first message must be sequence 1)
- ReorderBuffer bounded (100 per sender per context, overflow force-closes oldest gap)
- Correct create_inner_envelope_raw order: hash -> sign -> pad
- Sequence rollback on encrypted send failure
