---
name: project-adr057-transport-jssocket
description: ADR-057 #1980-independent relay transport slice — JsSocket + pseudonym fan-out; Step-2 MLS-key seed-extraction finding
metadata:
  type: project
---

ADR-057 in-browser client transport slice (branch feat/adr057-transport-jssocket, base #2174). Injected `Socket` outbound port + sync inbound pump + per-context pseudonym fan-out + announce/ingest over an already-shared MLS group. DEFER: invitation join path, HPKE-open custody, #1980 key-to-WebCrypto move.

**Why:** browser has no identity key in wasm; only wasm-held Ed25519 is the per-context MLS `SignatureKeyPair`. Ruling (Alec 2026-07-16, ADR-057 planning-session-10, Option A): derive the browser pseudonym over the MLS key via shared `scp_crypto::pseudonym`. MLS-keyed → does NOT byte-match native identity-keyed pseudonym for same human; acceptable under device-local-pseudonym model; documented §9.10.4.A deviation pending #1980.

**Step-2 seed-extraction finding (HIGHEST RISK, RESOLVED):** `openmls_basic_credential::SignatureKeyPair` ED25519 stores `private = ed25519_dalek::SigningKey::to_bytes()` = the **32-byte RFC-8032 seed** (registry lib.rs:92, `new()` ED25519 arm), exactly what `SigningKey::from_bytes` consumes — NOT 64-byte expanded. Its `private()` accessor is `#[cfg(feature="test-utils")]`-gated (unavailable in shipped build). The type derives `serde::Serialize/Deserialize` (available without test-utils). So prod `scp-mls::ScpMlsGroup::derive_pseudonym` recovers the seed via the crate's own serde form (`rmp_serde::to_vec_named(signer)` → deserialize into `struct { private: Vec<u8> }`; `private` is plain Vec<u8> → round-trips as positional u8 seq, NOT serde_bytes). Cross-checked in a scp-mls unit test against the test-utils `.private()` accessor (scp-mls dev-deps enable test-utils), so an upstream serde-shape change fails loudly. Fail-closed if seed != 32 bytes. New `MlsError::PseudonymDerivationFailed`.

**How to apply:** when touching MLS-key→pseudonym derivation or any "extract Ed25519 seed from openmls signer in wasm-safe prod code," reuse the serde reach-through — do NOT reach for test-utils `private()` in prod. See [[project-eventlog-committer-assigned-timestamp]].

**send_message API break (refinement #2):** `send_message` return `Vec<u8>`→`()` + required `socket` param + `PseudonymRegistryEmpty` guard. ONLY non-test consumer of the old ciphertext-return is the wasm wrapper (scp-client-wasm lib.rs:462, updated by Step 10). All other ciphertext-return consumers are in-crate integration tests (two_party_exchange, multi_party_convergence, sender_key_distribution, snapshot_restore, driver_adversarial) — rewired to a loopback Socket + pseudonym setup. No external/SDK/harness consumer needs the old mode, so the "report rather than break" gate is clear.

Shared TTL: `scp_protocol::envelope::outer::DEFAULT_APP_DATA_BLOB_TTL_SECS = 300`; native `messaging_helpers::DEFAULT_BLOB_TTL_SECS` repointed to consume it (behavior-preserving).
