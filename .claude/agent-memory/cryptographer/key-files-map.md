---
name: key-files-map
description: Map of the crypto-relevant source files across crates and bindings — where each construction lives
metadata:
  type: project
---

# Crypto-relevant file map

> Paths drift; verify with a grep before recommending. Crate layout moved from
> `scp-core` to `scp-protocol` / `scp-runtime` for several of these — treat the
> `scp-core/src/...` entries as "the facade path at review time."

## Event log / Merkle

- `crates/scp-core/src/event_log/tree.rs` — Merkle tree, leaf/interior hashing
- `crates/scp-core/src/event_log/proof.rs` — inclusion/absence proofs
- `crates/scp-core/src/event_log/checkpoint.rs` — consistency checkpoints

## Envelopes / sender keys

- `crates/scp-core/src/envelope/inner.rs` — inner envelope, canonical hash, domain separator
- `crates/scp-core/src/envelope/outer.rs` — seal/open pipeline, SCP-177 sender key resolution
- `crates/scp-core/src/envelope/pseudonym.rs` — pseudonym derivation spec (delegates to `KeyCustody`)
- `crates/scp-core/src/crypto/sender_keys/` — sender key protocol, HKDF, X25519
- `crates/scp-protocol/src/crypto/hpke.rs` — RFC 9180 HPKE core
- `crates/scp-protocol/src/envelope/did_record.rs` — `DidRecordV1` relay frame (§9.10.12)

## UCAN

- `crates/scp-core/src/crypto/ucan/mint.rs` — minting, CID computation
- `crates/scp-core/src/crypto/ucan/nonce.rs` — nonce generation, `NonceTracker`
- `crates/scp-core/src/crypto/ucan/revoke.rs` — revocation CID, `RevocationList`
- `crates/scp-core/src/crypto/ucan/validate.rs` — 11-step validation pipeline

## Trust / bridge

- `crates/scp-core/src/bridge/claiming.rs` — shadow claiming, dual sig verification
- `crates/scp-core/src/trust/renewal.rs` — attestation renewal with re-verification
- `crates/scp-core/src/context/nesting.rs` — governance config hashing, `BTreeSet`

## Identity / DID / relay

- `crates/scp-identity/src/resolver.rs` — `DualLayerResolver`, healing publisher, anti-rollback
- `crates/scp-identity/src/resolution.rs` — `did_routing_id()`, relay-based resolution
- `crates/scp-identity/src/republish.rs` — `RepublishManager`, `RelayPublisher`, `did_record_routing_id`
- `crates/scp-identity/src/dht.rs` — `DidDht`, BEP44 signing, `did_from_ed25519_public_key`, migration proofs
- `crates/scp-dht/src/lib.rs` — `bep44_signable`, `verify_bep44_signature`
- `crates/scp-transport/src/native/relay_publisher.rs` — production DID-record WRITE path
- `crates/scp-transport/src/native/relay_querier.rs` — production DID-record READ path
- `crates/scp-transport/src/native/did_slot.rs` — relay DID slot registry / single-slot rule
- `crates/scp-transport/src/relay/did_record_validation.rs` — relay frame admission check
- `crates/scp-transport/src/relay/bridge.rs` — bridge auth, `SCP-BRIDGE-REGISTER-V1`

## FFI bridges

- `crates/scp-ffi/src/ucan.rs` — PyO3 (correct CID handling)
- `crates/scp-ffi/napi/src/ucan.rs` — NAPI (correct CID handling)
- `crates/scp-ffi/napi/src/identity.rs` — Node/Bun identity bridge
- `crates/scp-ffi/uniffi/src/bridge.rs` — UniFFI (revocation CID mismatch bug)
- `crates/scp-ffi/wasm/src/ucan.rs` — WASM (partial validation)
- `crates/scp-ffi/wasm/src/custody.rs` — WASM key custody FFI boundary

## Platform / storage

- `crates/scp-platform/src/testing/key_custody.rs` — `InMemoryKeyCustody` reference impl + golden vectors
- `crates/scp-core/src/economy/credentials.rs` — adapter credential management
- `crates/scp-core/src/store/mod.rs` / `store/economy.rs` — `ProtocolRepository`
- `bindings/swift/Sources/SCP/Platform/` — Apple platform adapters
- `bindings/kotlin/scp-kt-android/src/main/kotlin/works/limn/scp/android/platform/` — Android adapters
