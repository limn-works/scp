---
name: adr049-pr7-atomic-crypto-move
description: ADR-049 PR-7 atomic crypto move (feat/adr049-pr7-atomic-crypto-move) artifact-accuracy convergence re-review — ZERO findings at de5e9b1a5
metadata:
  type: project
---

# ADR-049 PR-7 Atomic Crypto Move — Convergence Re-Review (2026-07-15) — ZERO FINDINGS

Branch `feat/adr049-pr7-atomic-crypto-move`, HEAD `de5e9b1a5`, range `2a916e9c2..de5e9b1a5` (14 files +704/-148). Double-zero pass #1.

**Why:** PR-7 relocated 11 steady-state MLS crypto methods off `MlsCryptoProvider` onto the actor's `PerContextState` (now actor-owned, Class-C coalesced). Prior round left ONE LOW wording nit + requested an ADR §9 confidentiality clause; both landed in `de5e9b1a5`.

**How to apply:** All 4 confirm points PASS —
1. "retired from the production call path" present in BOTH `governance_helpers.rs` (~1220) and `lifecycle_helpers.rs` (~823). Provider `validate_key_package` now cfg-gated test-only; §15 KP validation routes through stateless `deps.mls.validate_key_package` + `scp_mls::group::key_package_in_did` (validates sig/lifetime AND extracts+binds DID — the "validated twice by design" comment is accurate).
2. ADR §9 confidentiality clause (~line 202) is ACCURATE, not overclaiming. Verified the two-layer construction: prod seal path `actor/state.rs:1703` does serialize → `encrypt_sender_layer` (AES-256-GCM, random 12-byte per-msg nonce, `scp-protocol/.../sender_keys/encrypt.rs:59`) → `scp_mls::encrypt::encrypt` wraps that. So MLS plaintext = sender-layer ciphertext + non-secret epoch/seq header; an MLS-AEAD (key,nonce) reuse (≈2⁻³² after reuse_guard) leaks only XOR of pseudorandom sender-layer ciphertexts, no message plaintext. Clause correctly scopes residual as "MLS-layer AUTHENTICITY only, no confidentiality break end-to-end."
3. No artifact/provenance regression. Provider sender-key copies (`distribute_sender_key`, `store_member_sender_key`, `set_sender_key_unchecked`, `handle_sender_key_request`) correctly `#[cfg(any(test, feature="testing"))]`-gated with honest "test/fixture-only, production zero-grep clean" rustdoc; oracle-vs-actor byte-sync obligation correctly DROPPED. #1608 refs pre-existing/untouched.
4. Issue refs all real+OPEN, titles match disclosed residuals EXACTLY: #1608 (SenderKeyStore epoch monotonicity — pre-existing), #2146 (sender-key answer block-list unwired, blocked_dids empty — new residual in `handlers/messaging.rs:357` + `messaging_helpers.rs:3173`, §9.16.6 membership gate is live defense), #2149 (crash-surviving MLS send-generation floor — ADR §9 + reset_member arm). NO enforcement file touched (14 changed files, none on the CLAUDE.md enforcement list).

VERDICT: ALIGNED, zero findings — clean convergence pass.
