---
name: split-primitives-canonicality
description: BLACK-DID-01 feature-coupling regression in refactor/dissolve-primitives-split-identity (HEAD cc23e51f6) — did:key gate moved to scp-did/testing, now reachable via allow_in_memory_custody
metadata:
  type: project
---

# refactor/dissolve-primitives-split-identity — z-base-32 canonicality audit (HEAD cc23e51f6)

Reviewed range 86519aa6f..cc23e51f6. Topology refactor (dissolve scp-primitives, extract wasm-safe scp-did) + uniform z-base-32 canonicality. One authority parser `scp_did::extract_public_key_from_did`; 3 sites delegate.

## BLACK-DID-01 (MEDIUM) — did:key gate coupling regression, UCAN path
- `crates/scp-ffi/common/src/resolvers.rs` BridgeDidResolver now delegates to `scp_did::extract_public_key_from_did`. did:key:{hex} branch is gated by **scp-did/testing** (was scp-ffi-common's own `testing`).
- scp-ffi-common `testing = ["resolvers", "scp-did/testing"]` (Cargo.toml:20).
- REGRESSION: `allow_in_memory_custody` pulls `dep:scp-testing` → scp-core/testing → scp-protocol/testing → **scp-did/testing** (confirmed via `cargo tree -p scp-ffi --features allow_in_memory_custody -e normal` shows `scp-did default,testing`). OLD did:key gate (scp-ffi-common/testing) was NOT enabled by allow_in_memory_custody. So an allow_in_memory_custody build (docs say "testing, CLI, desktop") NOW accepts did:key issuers in the production UCAN validation path where it rejected them before.
- SHIPPED ARTIFACTS SAFE: build-matrix.yml python-wheel/napi/uniffi all use default features (no allow_in_memory_custody). Nightly unit-graph of `cargo build -p scp-ffi --release` shows scp-did=('default',) only → did:key rejected. Mitigation: keep did:key gate on a dedicated/narrow flag, not scp-did/testing.

## CLEAN probes
- (b) DidDht::verify: NEW `extract_public_key(...).is_ok_and(|k| pk==k)` is strict SUBSET of OLD `decoded==pk` (adds 32-byte + canonical). No old-false→new-true weakening; legit self-cert DIDs always canonical (built by zbase32::encode). CLEAN.
- (c) app_sandbox extract_ed25519_pubkey_from_did: old stripped "did:dht:" not the 'z' → 33 bytes → deny-all bug for did:dht. Fix accepts valid did:dht, but feeds AppDeclaration::verify() Ed25519 sig check (validate_declaration Step2 before Step3 cap-grant). Extract≠authorization. CLEAN.
- (d) enforcement: check-no-shim-reexports.sh NEW (positive closed check over 4 crates, well-scoped defense-in-depth, registered ci.yml:187 + CLAUDE.md). check-protocol-deps.sh / check-no-mutable-globals.sh = comment renames only, banned lists unchanged. scp-client-wasm publish=false dropped from release. No weakening, no new laundering paths. CLEAN.
