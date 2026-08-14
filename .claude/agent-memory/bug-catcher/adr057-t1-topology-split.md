# ADR-057 T1 — dissolve scp-primitives / extract scp-did (refactor/dissolve-primitives-split-identity)

Reviewed range 86519aa6f..8d6819674. Verdict: CLEAN (one LOW doc nit).

## Topology
- scp-primitives DISSOLVED → scp-clock (time.rs), scp-crypto (crypto.rs, Ed25519 verify).
- New wasm-safe scp-did owns DID data model: DID, SigningKeyId, extract_public_key_from_did (from primitives/identity.rs) + DidDocument/VerificationMethod/attestation (moved OUT of scp-protocol/identity/{document,did_attestation}.rs). `DidDocumentError` renamed → `DidError`.
- Shims deleted: scp-event-log/src/{crypto,time}.rs, scp-protocol/src/{time.rs, crypto/ed25519.rs}, scp-runtime/src/crypto/mls/mod.rs's `pub use scp_mls::*` (sync MLS re-exports). scp-runtime mls/mod.rs KEPT — hosts node-only async bridge (provider/storage/backend/production_backend/storage_adapter). scp-core/lib.rs `pub mod mls` recomposes: sync types from scp_mls, async bridge from scp_runtime.

## Verification methods that mattered (reusable)
- **Wrong-crate-import ("compiles but wrong symbol") risk is LOW here** because scp-clock/scp-crypto/scp-did export DISJOINT symbols — a mis-mapped import fails to compile. Only genuine ambiguity: two `Clock` traits (scp_clock::Clock vs scp_testing::Clock, `Send+Sync+'static`) — pre-existing, mapping unchanged.
- **release.yml topo-sort check**: parse ONLY `[dependencies]` (section-aware awk; NOT dev/build/target sections) for `scp-* = { path`. scp-media is a DEV-dep of scp-runtime (line 89), so runtime→media is NOT a publish-order cycle. Publish order (clock,crypto,did,platform,event-log,protocol,identity,mls,client,client-wasm,runtime,core,transport,mcp,media,node,relay) is a valid topological sort — every normal-dep edge points earlier.
- **did:key `testing` feature** correctly repointed scp-primitives/testing → scp-did/testing in event-log, protocol, mls, client, client-wasm. Gate `#[cfg(any(test, feature="testing"))]` preserved verbatim.
- **hex** made non-optional in scp-did (was `testing=["dep:hex"]` in primitives) — CORRECT: document.rs uses hex::encode/decode unconditionally (VM key serde), not just the gated did:key block.

## The one LOW note
- scp-clock Cargo.toml `testing = []` is INERT (gates nothing). TestClock is unconditionally `pub` (no cfg), same as old primitives. Comment "Exposes TestClock ... for downstream test builds" is misleading — TestClock ships in release builds regardless. scp-client/client-wasm enable `scp-clock/testing` = no-op. No behavior change vs before; pure doc inaccuracy.
