---
name: adr057-amendment-dissolve-primitives-t1-d2a783a55
description: ADR-057 Amendment (dissolve scp-primitives, extract scp-did) + T1 execution review at d2a783a55 — ALIGNED, 0 findings
metadata:
  type: project
---

# ADR-057 Amendment "Dissolve scp-primitives; extract scp-did" — T1 review @ d2a783a55 (2026-07-02) — ALIGNED, 0 findings

Branch `refactor/dissolve-primitives-split-identity`, range `86519aa6f..d2a783a55` (6 commits, 4 review rounds baked in: pass-1 d12691ef6 → pass-4 d2a783a55). 367 files ±.

**Why:** ADR-057 interim Prereq-3 (Slice 1/1a) parked DID types in scp-protocol + left DID/SigningKeyId in scp-primitives junk drawer + used re-export shims — reproduced the smell it was meant to fix. Amendment supersedes Prereq-3: dissolve scp-primitives → scp-clock/scp-crypto/scp-did; scp-did is the ONE DID-data-model home (wasm-safe leaf); scp-identity keeps native DHT/method/resolution subsystem, imports model from scp-did.

**How to apply / verified facts (all confirmed clean at this HEAD):**
- scp-clock = zero-dep leaf; scp-crypto = ed25519-dalek only; scp-did leaf deps = ed25519-dalek + serialization crates, NO scp-crypto edge (validates key bytes via `VerifyingKey::from_bytes` ZIP-215, never `verify_ed25519_signature`) — matches ADR table exactly. `cargo tree -p scp-did` shows zero scp-* deps (pure leaf). Fence: `cargo tree -p scp-client` reaches no scp-runtime/scp-identity/scp-platform/tokio.
- scp-primitives fully gone (dir deleted, README deleted, 0 live refs; 18 remaining mentions all intentional docs/gate describing the dissolution). DidDocumentError→DidError (0 old refs). DidDocument defined only in scp-did. document.rs/did_attestation.rs moved out of scp-protocol (scp-protocol/identity keeps attestation.rs=IdentityLinkAttestation wire type [ADR flags this as defensible protocol-residue], block_list, scpid, private_state).
- Gate `scripts/check-no-shim-reexports.sh`: closed set {scp_clock,scp_crypto,scp_did,scp_mls}, honestly scoped (canonical pub-use spellings only, exotic laundering audit-policed, load-bearing invariants = rustc acyclicity + wasm fence + check-protocol-deps.sh), registered in CLAUDE.md enforcement list line 112, PASSES. Also deletes scp-runtime/src/crypto/mls/mod.rs `pub use scp_mls` shim (gone).
- **T1c inventory (future slice) is EXACTLY accurate**: all 6 bep44_signable cross-crate sites present (scp-ffi/src+napi/src identity.rs prod; uniffi/bridge.rs, common/resolvers.rs, napi/tools.rs, scp-node/self_host.rs test); scp-identity lib.rs:49 re-exports verify_bep44_signature (to be removed at T1c); extract_public_key duplication (scp_identity::dht:2728 vs scp_did::extract_public_key_from_did) confirmed = flagged consolidation candidate.
- Artifacts retargeted: ci.yml/docs.yml (path filters), release.yml (leaf-first publish order scp-clock/crypto/did → platform → event-log → protocol → identity → mls → client…; summary line), fuzz/Cargo.toml (→clock/did/mls, scp-crypto correctly dropped as dead pass-4, all deps used), templates/personal-relay, clippy.toml, white-paper ("six"→"eleven additional crates", 11 enumerated ✓), specs 16/20/21, architecture.md, scp-runtime/README, TS bridge.ts doc (scp_did::DidRotationEvent), check-protocol-deps.sh + check-no-mutable-globals.sh doc refs. ADR anchor link resolves.
- ADR-055 consistency: no stale crate-topology refs in ADR-055; ADR-057 "Amends: ADR-055" relationship untouched by amendment.

**Only observation (NOT a finding):** ADR ASCII dep graph draws only scp-did's consumer edges, showing scp-clock/scp-crypto as bare leaves with no drawn consumers — illustrative simplification; prose is accurate (both are consumed widely).

Verdict: ALIGNED. Zero findings across code↔ADR fidelity, internal consistency (4 rounds), ADR-055, and artifact fidelity.
