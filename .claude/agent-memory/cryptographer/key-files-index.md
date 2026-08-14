---
name: key-files-index
description: Where the crypto lives — file paths for Merkle/event-log, envelopes, sender keys, UCAN, DID/identity, FFI bridges, and platform adapters
metadata:
  type: reference
---

Paths drift; verify a path exists before recommending action on it.

## Event log / Merkle
- `crates/scp-core/src/event_log/tree.rs` — Merkle tree, leaf/interior hashing
- `crates/scp-core/src/event_log/proof.rs` — inclusion/absence proofs
- `crates/scp-core/src/event_log/checkpoint.rs` — consistency checkpoints

## Envelopes / sender keys
- `crates/scp-core/src/envelope/inner.rs` — inner envelope, canonical hash, domain separator
- `crates/scp-core/src/envelope/outer.rs` — seal/open pipeline, SCP-177 sender-key resolution
- `crates/scp-core/src/envelope/pseudonym.rs` — pseudonym derivation spec (delegates to KeyCustody)
- `crates/scp-core/src/crypto/sender_keys/` — sender-key protocol, HKDF, X25519

## UCAN
- `crates/scp-core/src/crypto/ucan/mint.rs` — minting, CID computation
- `crates/scp-core/src/crypto/ucan/nonce.rs` — nonce generation, NonceTracker
- `crates/scp-core/src/crypto/ucan/revoke.rs` — revocation CID, RevocationList
- `crates/scp-core/src/crypto/ucan/validate.rs` — 11-step validation pipeline

## DID / identity / relay
- `crates/scp-identity/src/dht.rs` — DidDht, BEP44, `did_from_ed25519_public_key`, migration proofs
- `crates/scp-identity/src/resolution.rs` — the `did_routing_id` family, relay-based resolution
- `crates/scp-identity/src/resolver.rs` — DualLayerResolver, healing publisher, anti-rollback
- `crates/scp-identity/src/republish.rs` — RepublishEntry/RelayPublisher/republish loops
- `crates/scp-dht/src/lib.rs` — `bep44_signable`, `verify_bep44_signature`
- `crates/scp-protocol/src/envelope/did_record.rs` — `DidRecordV1` relay frame (§9.10.12)
- `crates/scp-transport/src/relay/bridge.rs` — bridge auth, `SCP-BRIDGE-REGISTER-V1`
- `crates/scp-transport/src/relay/did_record_validation.rs` — relay admission classify
- `crates/scp-transport/src/native/did_slot.rs` — DID slot registry, single-slot rule

## Trust / bridge / economy
- `crates/scp-core/src/bridge/claiming.rs` — shadow claiming, dual-sig verification
- `crates/scp-core/src/context/nesting.rs` — governance config hashing, BTreeSet
- `crates/scp-core/src/trust/renewal.rs` — attestation renewal with re-verification
- `crates/scp-core/src/economy/credentials.rs` — adapter credential management
- `crates/scp-core/src/store/mod.rs` / `store/economy.rs` — ProtocolRepository + credential storage

## FFI bridges
- `crates/scp-ffi/src/ucan.rs` — PyO3 (correct CID handling)
- `crates/scp-ffi/napi/src/ucan.rs` — NAPI (correct CID handling)
- `crates/scp-ffi/uniffi/src/bridge.rs` — UniFFI (revocation CID mismatch bug)
- `crates/scp-ffi/wasm/src/ucan.rs` — WASM (partial validation)
- `crates/scp-ffi/wasm/src/custody.rs` — WASM key custody FFI boundary
- `crates/scp-ffi/napi/src/identity.rs` — Node/Bun identity bridge

## Platform
- `crates/scp-platform/src/testing/key_custody.rs` — InMemoryKeyCustody reference impl + golden vectors
- `bindings/swift/Sources/SCP/Platform/` — Apple adapters
- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/` — Android adapters
