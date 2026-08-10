---
name: ffi-bridges-ucan-and-persona
description: scp-ffi bridge crypto audit (UCAN revocation CID mismatch, IDs, nonces), PR #127 envelope/AES-GCM/UCAN findings, and ADR-039 #active/#agent persona binding
metadata:
  type: project
---

# ADR-039 shared-DID persona binding (`#active` / `#agent`)

- `signing_key_id` (`SigningKeyId`) IS in the SIGNED canonical preimage of
  `InnerEnvelope` — `envelope/inner/mod.rs` `compute_canonical_hash` ~L557, final
  `VarBytes` (length-prefixed) field. Verify recomputes with `inner.signing_key_id`
  (~L370). Persona cannot be flipped post-sign without breaking the signature. SOUND.
- `KeyResolver` widened DID-only → `Fn(&DID, SigningKeyId) -> Option<VerifyingKey>`.
  `verify_and_unwrap` (`messaging_helpers.rs:309`) resolves by `inner.signing_key_id`;
  verify-before-unwrap correct; `payload_hash` compared via `ct_eq`.
- `SigningKeyId::from_fragment` is strict: only `"#active"` / `"#agent"`; rejects
  `"#0"`, `"active"`, `""`. `economy_logic` `resolve_public_key_by_kid` fails CLOSED
  on unknown kid. No-kid `resolve_public_key` defaults `#active` (only on the no-kid
  UCAN path).
- Governance votes all pass `SigningKeyId::Active`; `SignedVote` has NO kid field, so
  votes are `#active` by construction — no wrong-key-accept. Per-VM votes deferred.
- GAP (not a regression): the only prod `KeyResolver` wiring
  (`scp-node/self_host.rs:453`) returns `None` for ALL `(DID, kid)`; FFI bridges
  hardcode `signing_key_id = Active` + `not_configured_key_resolver → None`. `#agent`
  end-to-end is still non-functional outside in-crate tests despite the "wired into
  live pipeline" claim. Receive path is correct GIVEN a real document-derived
  resolver (only in `agent_binding_pipeline_tests.rs`).

# scp-ffi bridge layer (reviewed 2026-02-28)

- `compute_simple_cid`: SHA-256 + `"bafyrei"` prefix is NOT a valid CID v1 — purely
  an opaque internal ID.
- `UcanHeader::validate()` skips the `typ` field check (only `alg` + `ucv`).
- Context ID: `as_nanos()` only, no randomness — collision/predictability risk.
- Nonce format `{millis}-{16 random hex bytes}` matches the `UcanPayload.nnc` spec.
- Base64 `URL_SAFE_NO_PAD` correct for JWT. MCP handles: 128-bit CSPRNG, sufficient.
- `encode_hex` infallible for `String`, no truncation bugs.
- `extract_implementation_hash`: correct 64-char hex validation, byte-by-byte decode.

# PR #127 crypto audit (2026-03-01)

- **CRITICAL**: UniFFI `ucan_revoke` (`bridge.rs:2220`) revokes by `token_id`, NOT the
  content-hash CID. The validation pipeline (`validate.rs:467`) checks
  `compute_revocation_cid(&payload) = SHA-256(JSON)`. UniFFI inserts the raw
  `token_id` string ⇒ revocations are no-ops for mobile/desktop. PyO3, WASM, and NAPI
  all correctly compute the CID before revoking.
- **HIGH**: WASM `WasmUcanPayload` (`wasm/ucan.rs:139-151`) duplicates `UcanPayload`
  (`mod.rs:289`). Field order must match for CID consistency; no compile-time or test
  enforcement.
- Inner envelope: domain separator `SCP-INNER-ENVELOPE-V1`, length-prefixed variable
  fields — SOUND.
- AES-256-GCM: `OsRng` nonces throughout, `Zeroize` + `ZeroizeOnDrop` on all key types — SOUND.
- Broadcast key rotation: fresh random keys (not HKDF), epoch overflow checked — SOUND.
- Outer envelope pipeline: MLS → SenderKey → deserialize → verify sender → content
  integrity → sig — SOUND.
- UCAN mint: 24h max expiry, clock error propagation, Ed25519 signing via
  `KeyCustody` — SOUND.
- Nonce tracker: format validation, freshness ±5min, capacity 100K, pruning,
  serialization — SOUND.
- Attestation renewal: mandatory re-verification before `renewed_at` update — SOUND.
- `MessageType::as_discriminator_byte()` exists but is NOT used in
  `compute_canonical_hash` — the docstring is misleading.
