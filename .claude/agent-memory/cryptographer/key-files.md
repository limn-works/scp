---
name: key-files
description: Where each cryptographic construction lives in this repository — Merkle log, envelopes, sender keys, UCAN, custody, bridges, identity
metadata:
  type: reference
---

# Key files by construction

Paths recorded before the scp-core → scp-protocol/scp-runtime split; verify a
path with `git ls-files` before acting on it.

## Event log and proofs
- `crates/scp-core/src/event_log/tree.rs` — Merkle tree, leaf/interior hashing
- `crates/scp-core/src/event_log/proof.rs` — inclusion and absence proofs
- `crates/scp-core/src/event_log/checkpoint.rs` — consistency checkpoints

## Envelopes and sender keys
- `crates/scp-core/src/envelope/inner.rs` — inner envelope, canonical hash, domain separator
- `crates/scp-core/src/envelope/outer.rs` — seal/open pipeline, SCP-177 sender key resolution
- `crates/scp-core/src/envelope/pseudonym.rs` — pseudonym derivation spec, delegates to KeyCustody
- `crates/scp-core/src/crypto/sender_keys/` — sender key protocol, HKDF, X25519

## UCAN
- `crates/scp-core/src/crypto/ucan/mint.rs` — minting, CID computation
- `crates/scp-core/src/crypto/ucan/nonce.rs` — nonce generation, NonceTracker
- `crates/scp-core/src/crypto/ucan/revoke.rs` — revocation CID, RevocationList
- `crates/scp-core/src/crypto/ucan/validate.rs` — 11-step validation pipeline

## Trust, claiming, governance
- `crates/scp-core/src/bridge/claiming.rs` — shadow claiming, dual signature verification
- `crates/scp-core/src/context/nesting.rs` — governance config hashing, BTreeSet
- `crates/scp-core/src/trust/renewal.rs` — attestation renewal with re-verification
- `crates/scp-protocol/src/trust/custody_violation.rs` — ADR-039 layer-4 custody violation records and their verifiers

## Economy
- `crates/scp-core/src/economy/credentials.rs` — adapter credential management
- `crates/scp-core/src/store/mod.rs` — ProtocolRepository definition
- `crates/scp-core/src/store/economy.rs` — adapter credential storage impl

## FFI bridges
- `crates/scp-ffi/src/ucan.rs` — PyO3 UCAN bridge (correct CID handling)
- `crates/scp-ffi/napi/src/ucan.rs` — NAPI UCAN bridge (correct CID handling)
- `crates/scp-ffi/napi/src/identity.rs` — Node/Bun identity bridge
- `crates/scp-ffi/uniffi/src/bridge.rs` — UniFFI bridge (revocation CID mismatch)
- `crates/scp-ffi/wasm/src/ucan.rs` — WASM UCAN bridge (partial validation)
- `crates/scp-ffi/wasm/src/custody.rs` — WASM key custody FFI boundary

## Platform and identity
- `bindings/swift/Sources/SCP/Platform/` — Apple platform adapters
- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/` — Android adapters
- `crates/scp-platform/src/testing/key_custody.rs` — InMemoryKeyCustody reference impl plus golden vectors
- `crates/scp-transport/src/relay/bridge.rs` — bridge auth, SCP-BRIDGE-REGISTER-V1 separator
- `crates/scp-identity/src/resolver.rs` — DualLayerResolver, healing publisher, anti-rollback
- `crates/scp-identity/src/resolution.rs` — `did_routing_id()`, relay-based resolution
- `crates/scp-identity/src/dht.rs` — DidDht, BEP44, `did_from_ed25519_public_key`, migration proofs
