---
name: key-files
description: Where each cryptographic construction lives after the scp-core split into scp-protocol, scp-runtime, and the wasm-safe leaf crates
metadata:
  type: reference
---

Verified against the tree in September 2026; confirm with `git ls-files` if a path fails.

- **Canonical hashing framework:** `crates/scp-protocol/src/crypto/canonical.rs`
- **Event log / Merkle:** `crates/scp-event-log/src/{tree,proof,checkpoint}.rs`
- **Inner envelope (preimage, sign, verify):** `crates/scp-protocol/src/envelope/inner/mod.rs`, `crates/scp-runtime/src/envelope/inner/{mod,sign}.rs`
- **Outer envelope seal/open:** `crates/scp-protocol/src/envelope/outer/mod.rs`, `crates/scp-runtime/src/envelope/outer/{mod,ops}.rs`
- **Sender keys:** `crates/scp-protocol/src/crypto/sender_keys/{mod,encrypt,broadcast,key_protocol_verify}.rs`, `crates/scp-runtime/src/crypto/sender_keys/{mod,key_protocol}.rs`
- **Access keys / CEK wrapping (AES-256-KW, RFC 3394):** `crates/scp-protocol/src/crypto/access_keys/{mod,wrapping}.rs`, `crates/scp-runtime/src/crypto/access_keys/{mod,wire,lifecycle}.rs`
- **HPKE core:** `crates/scp-protocol/src/crypto/hpke.rs`; runtime shim `crates/scp-runtime/src/crypto/hpke_backend.rs`
- **Pseudonyms:** `crates/scp-crypto/src/pseudonym.rs`, `crates/scp-protocol/src/context/pseudonym.rs`, `crates/scp-runtime/src/envelope/pseudonym.rs`
- **UCAN:** mint and `compute_cid` in `crates/scp-runtime/src/crypto/ucan/mint.rs`; `nonce.rs`, `revoke.rs` (`compute_revocation_cid`), `validate.rs` (11-step pipeline) in `crates/scp-protocol/src/crypto/ucan/`
- **Custody violations / attestation renewal:** `crates/scp-protocol/src/trust/{custody_violation,renewal}.rs`
- **Browser MLS (seed extraction):** `crates/scp-mls/src/group.rs`
- **Platform custody:** `crates/scp-platform/src/{sqlite,android}/key_custody.rs`
