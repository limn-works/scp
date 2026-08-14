---
name: standing-pair-5-15-8
description: Cryptographic soundness of §5.15.8 standing-pair creation (single-context async), collision-resolution credential-confirmation, injectivity invariant, derived_context_id
metadata:
  type: project
---

§5.15.8 standing-pair creation (spec/standing-pair-not-a-saga-v2). Classification SETTLED = single-context async MLS creation, not a saga.

**Code verification (branch chore/fuzz-pin-nightly main worktree):**
- `derive_standing_context_digest` (crates/scp-runtime/src/context/standing_helpers.rs:56): `SHA-256(b"standing:" ‖ a ‖ b":" ‖ b)`, a/b = lexicographic min/max of DID `as_ref()`. MATCHES spec line 1820 exactly.
- `generate_standing_context_id`: `"standing-" ‖ hex(digest)`. MATCHES.
- `context_id_bytes` (crates/scp-protocol/src/context/mod.rs:74): `SHA-256(context_id_string)`. So MLS group `[u8;32]` key = `SHA-256("standing-" ‖ hex(derived_context_id))`. CONFIRMS spec's precise Entry::Vacant guard claim (line 1824).
- `create_mls_group` Entry::Vacant guard at provider.rs:743 — keys on the passed `[u8;32]` = the canonical digest. MATCHES.

**Key finding — DID↔leaf-key binding gap (PRE-EXISTING, not this spec's fault):**
- `ScpCredential.resolve_signing_key(did_doc)` (crypto/mls/credential.rs:154) is ONLY called in tests — NEVER in production. open_envelope (encrypt.rs:331) extracts `sender_did` from the leaf `ScpCredential` as a SELF-ASSERTED string; nothing cross-checks leaf MLS signature key == DID-document-resolved VM key.
- Spec DOES mandate the binding: §9 line 587 (KeyPackage sig MUST verify vs DID doc VM) + §9 line 706 (InnerEnvelope: verifier resolves declared signing_key_id from DID doc). So §5.15.8's "creator credential resolves to did_lo" is sound *contingent on that binding being enforced* — which is spec-mandated but not yet wired. This is the same self-asserted-credential class as finding_hpke_not_rfc9180.
- Collision-resolution destroy path itself is NOT yet implemented (no creator-credential-gated destroy in code) — consistent with Phase 2E "Known limitation". This was a spec-design soundness review.

**Welcome authenticity mechanism:** create_group uses `use_ratchet_tree_extension(true)` (group.rs:310) → Welcome carries full tree. join_group_from_bytes (group.rs:670) StagedWelcome::new_from_welcome validates tree+leaf sigs. So did_hi CAN read creator-leaf ScpCredential post-join, MLS-authenticated at leaf-key level. Creator leaf = leaf present at creation (the committer/non-self leaf in 2-leaf case).

**Verdict: SOUND** (all 5 claims). Injectivity prose accurate; §9.5.1 len-prefix cross-ref correct; recommended hardening internally consistent. Residual: spec should make the leaf-key↔DID binding a named precondition of the creator-confirmation step.
