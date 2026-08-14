---
name: adr057-t1-crate-topology
description: ADR-057 T1 dissolved scp-primitives; new wasm-safe homes for verify_ed25519, DID model, Clock (commit d12691ef6)
metadata:
  type: project
---

ADR-057 Amendment (2026-06-30), commit d12691ef6 on refactor/dissolve-primitives-split-identity: dissolved scp-primitives into three wasm-safe leaf/capability crates.

**Why:** Enable in-browser SCP client (wasm32) without pulling tokio; kill the primitives junk-drawer.

**New crypto homes (single source of truth, no duplicates — verified):**
- `scp-crypto/src/lib.rs` — `verify_ed25519_signature` (verify_strict, ed25519-dalek). Moved from scp-primitives/crypto.rs, byte-identical.
- `scp-did/src/lib.rs` — `DID`, `SigningKeyId`, `extract_public_key_from_did` (did:dht=zbase32, did:key=hex gated behind `testing`).
- `scp-did/src/document.rs` — `DidDocument`, `VerificationMethod`, `Service`, `DidRotationEvent`, `MigrationProof`, `PreRotationProof`, `decode_multibase_key` (base58btc / multibase 'z'), `serde_hex_array` (array32/array64). Enum `DidDocumentError` RENAMED `DidError` — NOT serialized (only thiserror::Error derive), so rename touches no wire artifact.
- `scp-did/src/attestation.rs` — key-custody/identity-link attestation types (was did_attestation.rs).
- `scp-clock/src/lib.rs` — `Clock`, `SystemClock`, `TestClock`, `ClockError` (was scp-primitives/time.rs, byte-identical).

**Encoding distinction preserved:** did:dht uses z-base-32 (`zbase32::decode`); publicKeyMultibase uses base58btc (`bs58`). Two distinct paths, both unchanged. No base58/zbase32 confusion introduced.

scp-mls credential.rs + epoch_grace.rs now import same moved types from scp_did/scp_clock (no From-conversion inserted — identical types). scp-event-log re-exports DID from scp_did, verify from scp_crypto.

**LOW nit:** stale `scp-primitives` mentions remain in doc-comments (scp-mls/src/lib.rs:12, credential.rs:12, scp-event-log/src/lib.rs:13/53, crypto.rs:6/8, scp-identity/src/cache.rs:80) despite commit claiming "zero references" — comments only, no code/dep refs.
