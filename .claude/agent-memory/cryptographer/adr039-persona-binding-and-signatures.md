---
name: adr039-persona-binding-and-signatures
description: ADR-039 shared-DID persona binding (#active/#agent) signature soundness plus the general signature-verification / DID-format notes (two incompatible attestation canonical forms)
metadata:
  type: project
---

# ADR-039 shared-DID persona binding (#active / #agent)

- `signing_key_id` (`SigningKeyId` enum, #active/#agent) IS in the SIGNED canonical preimage of `InnerEnvelope` — envelope/inner/mod.rs `compute_canonical_hash` ~L557, final `VarBytes` (length-prefixed) field. `verify` recomputes with `inner.signing_key_id` (~L370). Persona cannot be flipped post-sign without breaking the signature. **SOUND.**
- `KeyResolver` widened DID-only → `Fn(&DID, SigningKeyId) -> Option<VerifyingKey>`. `verify_and_unwrap` (messaging_helpers.rs:309) resolves by `inner.signing_key_id`. Verify-before-unwrap correct; `payload_hash` compared via `ct_eq`.
- `SigningKeyId::from_fragment` strict: only `"#active"` / `"#agent"`; rejects `"#0"`, `"active"`, `""`. `economy_logic::resolve_public_key_by_kid` fails CLOSED on an unknown kid. The no-kid `resolve_public_key` defaults to #active (only on the no-kid UCAN path).
- Governance votes all pass `SigningKeyId::Active`; `SignedVote` has NO kid field, so votes are always #active by construction — no wrong-key-accept. Per-VM votes deferred (documented).
- **GAP (not a regression)**: the only prod `KeyResolver` wiring (scp-node/self_host.rs:453) returns `None` for ALL `(DID, kid)`; FFI bridges hardcode `signing_key_id=Active` + `not_configured_key_resolver → None`. #agent end-to-end is still non-functional outside in-crate tests despite the "wired into live pipeline" claim. The receive path IS correct GIVEN a real document-derived resolver (only present in agent_binding_pipeline_tests.rs).

# Signature verification (general)

- `claim_shadow()` verifies the attestation signature then the claim signature before the state transition
- Ed25519 via ed25519_dalek, signatures over SHA-256 canonical hashes (claiming.rs)
- Ed25519 via ed25519_dalek, signatures over raw canonical bytes (trust/attestation.rs)
- **TWO different canonical forms exist for attestations — must consolidate** (see [[event-log-merkle-and-canonical-hash]])
- DID formats: `did:dht:z<z-base-32>` (prod), `did:key:<hex>` (test, non-standard)
- The `did:key` format in claiming.rs does NOT conform to the W3C did:key spec (missing multicodec/multibase)
