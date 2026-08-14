---
name: ucan-and-ffi-bridge-audit
description: scp-ffi bridge-layer crypto audit (2026-02-28) and the PR #127 audit — UniFFI revocation-CID bug, WASM payload duplication, envelope/AES-GCM/UCAN-mint soundness
metadata:
  type: project
---

# scp-ffi bridge layer (reviewed 2026-02-28)

- `compute_simple_cid`: SHA-256 + `"bafyrei"` prefix is NOT a valid CID v1 — purely an opaque internal ID
- `UcanHeader::validate()` skips the `typ` field check (checks `alg` + `ucv` only)
- Context ID: `as_nanos()` only, no randomness — collision/predictability risk
- rand 0.8 `thread_rng()` is a CSPRNG (ChaCha12 reseeded from OsRng)
- Nonce format `{millis}-{16 random hex bytes}` matches the `UcanPayload.nnc` spec
- Base64 `URL_SAFE_NO_PAD` correct for JWT
- MCP handles: 128-bit CSPRNG randomness, sufficient
- `encode_hex`: infallible for String, no truncation bugs
- `extract_implementation_hash`: correct 64-char hex validation, byte-by-byte decode

# PR #127 crypto audit (2026-03-01)

- **CRITICAL**: UniFFI `ucan_revoke` (bridge.rs:2220) revokes by `token_id`, NOT the content-hash CID. The validation pipeline (validate.rs:467) checks `compute_revocation_cid(&payload) = SHA-256(JSON)`. UniFFI inserts the raw `token_id` string ⇒ revocations are **no-ops for mobile/desktop**. PyO3, WASM and NAPI all correctly compute the CID before revoking.
- **HIGH**: WASM `WasmUcanPayload` (wasm/ucan.rs:139-151) duplicates `UcanPayload` (mod.rs:289). Field order must match for CID consistency; no compile-time or test enforcement.
- Inner envelope: domain separator `SCP-INNER-ENVELOPE-V1`, length-prefixed variable fields — SOUND
- AES-256-GCM: OsRng nonces throughout, `Zeroize` + `ZeroizeOnDrop` on all key types — SOUND
- Broadcast key rotation: fresh random keys (not HKDF), epoch overflow checked — SOUND
- Outer envelope pipeline: MLS → SenderKey → deserialize → verify sender → content integrity → sig — SOUND
- UCAN mint: 24h max expiry, clock error propagation, Ed25519 signing via `KeyCustody` — SOUND
- Nonce tracker: format validation, freshness ±5min, capacity 100K, pruning, serialization — SOUND
- Attestation renewal: mandatory re-verification before `renewed_at` update — SOUND
- `MessageType::as_discriminator_byte()` exists but is NOT used in `compute_canonical_hash` — docstring misleading
