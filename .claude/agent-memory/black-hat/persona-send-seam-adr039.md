---
name: persona-send-seam-adr039
description: Adversarial audit of ADR-039 message-send persona seam (branch persona-dynamic-send-seam @6cd0a0caf) — verdict UNBREAKABLE at seam; residuals only
metadata:
  type: project
---

# ADR-039 message-send persona seam audit (2026-08-03)

Branch `persona-dynamic-send-seam` @ `6cd0a0caf`. Files:
- `crates/scp-ffi/common/src/persona.rs` — PersonaSource callable + ResolvedMessageSigner(key,persona) atomic
- `crates/scp-ffi/common/src/bridge_instance.rs:527,2159,2177` — RwLock<PersonaSource>, accessor, test-only setter
- PyO3 `crates/scp-ffi/src/context.rs:3420` resolve_message_signer
- NAPI `crates/scp-ffi/napi/src/context.rs:1838` resolve_napi_message_signer (mailbox decompose)
- UniFFI `crates/scp-ffi/uniffi/src/bridge.rs:11164` resolve_uniffi_message_signer
- Core stamp+sign: `messaging_helpers.rs:118 build_encrypted_envelope`, `:906 send_message` reconstruct

**Verdict: stamp/key divergence UNREPRESENTABLE, prod cannot reach #agent.**
- Persona read ONCE per send → local `persona`; resolver selects key by matching that
  persona, builds ResolvedMessageSigner::new(key,persona); message_signer() derives variant
  from stored persona. Both signing_key_bytes + signing_key_id derive from ONE MessageSigner
  (NAPI site + supervisor.send_message:9958). Handler re-pairs co-located fields. No independent
  re-derivation. Receiver resolves stamped VM cryptographically → mismatch = REJECTED not accepted.
- Only non-Active injection = `set_persona_source_for_test` gated `#[cfg(any(test,feature="testing"))]`.
  `testing` NOT in any default/server list across all 4 ffi Cargo.toml. Default = pure const closure
  `|| SigningKeyId::Active`, no state inspect. RwLock poison → into_inner still returns installed
  (default Active). No prod setter.
- Fail-closed: #agent w/ no agent key → SCP-IDENT-1023, never falls back to #active.

**Residuals (not breaks):**
1. NAPI/UniFFI agent-path custody asymmetry: exports registry-identity's agent handle via the
   HANDLE's custody (not the identity's own custody). KeyHandle = per-custody-instance AtomicU64
   from 1. If handle custody ≠ sender identity custody (cross-identity handle confusion), export
   could return wrong id's key → but receiver rejects (fail-closed), never accepted mismatch. Dormant
   (agent unreachable in prod). PyO3 is symmetric (uses entry.custody+entry handle) — cleaner.
2. Default #active for autonomous agent sends = agent→human attribution. DELIBERATE ADR-039 fail-safe
   (human accountability). Repudiation-of-provenance is by-design, gated by active-key custody.
3. Could not locate a named "G1" gate script asserting scp-ffi-common/testing absence from shipped;
   isolation rests on feature-list discipline (sound today, no mechanical belt-and-suspenders found).
