---
name: adr039-persona-and-signing
description: ADR-039 #active/#agent persona binding through the signed preimage and key resolvers, plus signature-verification, determinism, and randomness facts
metadata:
  type: project
---

# ADR-039 shared-DID persona binding (#active/#agent)

ADR-039, shared-DID human-agent identity model, lives at `.docs/adrs/phase-1.md`
line 1231.

- `signing_key_id` (`SigningKeyId` enum) IS inside the SIGNED canonical preimage
  of `InnerEnvelope` — envelope/inner/mod.rs `compute_canonical_hash` ~L557, as a
  final length-prefixed VarBytes field. Verify recomputes with
  `inner.signing_key_id` (~L370), so a persona cannot be flipped post-sign
  without breaking the signature. SOUND.
- `KeyResolver` widened from DID-only to `Fn(&DID, SigningKeyId) -> Option<VerifyingKey>`.
  `verify_and_unwrap` (messaging_helpers.rs:309) resolves by
  `inner.signing_key_id`. Verify-before-unwrap ordering is correct; `payload_hash`
  compared via `ct_eq`.
- `SigningKeyId::from_fragment` is strict: only `"#active"` / `"#agent"`; it
  rejects `"#0"`, `"active"`, `""`. `economy_logic::resolve_public_key_by_kid`
  fails CLOSED on an unknown kid. `resolve_public_key` defaults to `#active` only
  on a no-kid UCAN path.
- Governance votes all pass `SigningKeyId::Active`, and `SignedVote` carries no
  kid field, so votes are `#active` by construction — no wrong-key accept.
- GAP (not a regression): the only production `KeyResolver` wiring
  (scp-node/self_host.rs:453) returns `None` for every `(DID, kid)`, and FFI
  bridges hardcode `signing_key_id = Active` with
  `not_configured_key_resolver` → `None`. So `#agent` end to end stays
  non-functional outside in-crate tests, despite a "wired into live pipeline"
  claim. Receive path is correct GIVEN a real document-derived resolver, which
  exists only in agent_binding_pipeline_tests.rs.

# Signature verification

- `claim_shadow()` verifies an attestation signature, then a claim signature,
  before any state transition.
- Ed25519 via ed25519_dalek. claiming.rs signs SHA-256 canonical hashes;
  trust/attestation.rs signs raw canonical bytes. TWO different canonical forms
  exist for attestations and must be consolidated.
- DID formats: `did:dht:z<z-base-32>` in production, `did:key:<hex>` in tests
  (non-standard). claiming.rs's `did:key` form does NOT conform to the W3C
  `did:key` spec — it omits multicodec and multibase.

# Deterministic serialization

- nesting.rs uses a `BTreeSet` for `requires_approval_for`, which keeps
  serde_json output sorted.
- `content_hash()` returns `Result` so errors propagate.

# Randomness

- Production: `OsRng` (CSPRNG) through the `KeyCustody` trait.
- Tests: `thread_rng()`, acceptable for test-only code.
