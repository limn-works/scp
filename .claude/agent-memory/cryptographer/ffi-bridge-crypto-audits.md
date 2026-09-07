---
name: ffi-bridge-crypto-audits
description: scp-ffi bridge-layer crypto review (2026-02-28) and the PR #127 cross-bridge audit, including the UniFFI revocation-CID defect
metadata:
  type: project
---

# scp-ffi bridge layer (reviewed 2026-02-28)

- `compute_simple_cid`: SHA-256 plus a `"bafyrei"` prefix is NOT a valid CIDv1 —
  it is a purely opaque internal id.
- `UcanHeader::validate()` skips its `typ` field check and validates only `alg`
  and `ucv`.
- Context id derives from `as_nanos()` with no randomness — collision and
  predictability risk.
- rand 0.8 `thread_rng()` is a CSPRNG (ChaCha12 reseeded from OsRng).
- Nonce format `{millis}-{16 random hex bytes}` matches the `UcanPayload.nnc`
  spec. Base64 `URL_SAFE_NO_PAD` is correct for JWT.
- MCP handles carry 128-bit CSPRNG randomness, which is sufficient.
- `encode_hex` is infallible for `String` with no truncation bugs.
- `extract_implementation_hash` validates 64 hex characters and decodes
  byte by byte.

# PR #127 crypto audit (2026-03-01)

- CRITICAL: UniFFI `ucan_revoke` (bridge.rs:2220) revokes by `token_id` rather
  than by content-hash CID, while the validation pipeline (validate.rs:467)
  checks `compute_revocation_cid(&payload) = SHA-256(JSON)`. UniFFI inserts a raw
  `token_id` string, so revocations are no-ops for mobile and desktop. PyO3,
  WASM, and NAPI bridges all compute a CID before revoking.
- HIGH: WASM `WasmUcanPayload` (wasm/ucan.rs:139–151) duplicates `UcanPayload`
  (mod.rs:289). Field order must match for CID consistency, and neither a
  compile-time check nor a test enforces that.
- Inner envelope: domain separator `SCP-INNER-ENVELOPE-V1`, length-prefixed
  variable fields — SOUND.
- AES-256-GCM: OsRng nonces throughout, `Zeroize` + `ZeroizeOnDrop` on all key
  types — SOUND.
- Broadcast key rotation: fresh random keys (not HKDF), epoch overflow checked —
  SOUND.
- Outer envelope pipeline: MLS → sender key → deserialize → verify sender →
  content integrity → signature — SOUND.
- UCAN mint: 24h max expiry, clock error propagation, Ed25519 signing via
  `KeyCustody` — SOUND.
- Nonce tracker: format validation, ±5min freshness, 100K capacity, pruning,
  serialization — SOUND.
- Attestation renewal performs mandatory re-verification before updating
  `renewed_at` — SOUND.
- `MessageType::as_discriminator_byte()` exists but is NOT used in
  `compute_canonical_hash`, so its docstring misleads.
