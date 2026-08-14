---
name: adr057-dissolve-primitives-split-did-81ef76c56
description: ADR-057 Amendment execution (dissolve scp-primitives → scp-clock/scp-crypto; extract wasm-safe scp-did) review at 81ef76c56 — NEEDS-DISCUSSION (1 release-pipeline break)
metadata:
  type: project
---

# ADR-057 Amendment T1 (dissolve scp-primitives; extract scp-did) @ 81ef76c56

Branch `refactor/dissolve-primitives-split-identity`, range `86519aa6f..81ef76c56` (8 commits, 371 files). Verdict **NEEDS DISCUSSION** — code↔ADR fidelity is essentially perfect; ONE mechanical release-pipeline contradiction.

**FINDING (MODERATE-HIGH, release path):** `crates/scp-client-wasm/Cargo.toml:9` has `publish = false` (set by base commit #1983), but this change set added `.github/workflows/release.yml:436-439` step `cargo publish -p scp-client-wasm --allow-dirty` (no continue-on-error) → hard-fails ("cannot be published, publish=false"), aborting all subsequent publishes (scp-runtime/core/...). Corollaries same root: git TAGS entry release.yml:177 + dry-run crates.io summary release.yml:872 both list scp-client-wasm. Fix = drop scp-client-wasm from the crates.io publish sequence (it's a wasm-bindgen cdylib, deliberately unpublished), not flip the manifest.

**INFORMATIONAL:** ADR table (line 107) lists `ClockError` among scp-clock's "Owns", but it's `pub(crate)` (scp-clock/src/lib.rs:31), not public. Defensible ("Owns"=housed types) — nit.

**Everything else VERIFIED CLEAN:**
- Crate table Owns/From/Coupling all accurate. git renames match "From" col exactly: primitives/time.rs→scp-clock, primitives/crypto.rs→scp-crypto, primitives/identity.rs→scp-did/lib.rs, protocol/identity/document.rs→scp-did/document.rs, protocol/identity/did_attestation.rs→scp-did/attestation.rs (R097).
- scp-did = pure leaf (ed25519-dalek + serialization only, NO scp-crypto edge); validates keys via `ed25519_dalek::VerifyingKey::from_bytes` (document.rs:1297), never verify_ed25519_signature — matches ADR line 109. scp-clock zero-dep. scp-crypto = ed25519-dalek only.
- DidDocumentError→DidError done (scp-did/document.rs:55). mls/mod.rs `pub use scp_mls::*` shim DELETED.
- Gate `scripts/check-no-shim-reexports.sh` = positive closed set {scp_clock,scp_crypto,scp_did,scp_mls}, scans all crates/**/src, passes; registered in CLAUDE.md enforcement list + ci.yml. wasm-fence job extended to clock/crypto/did/protocol/mls/client-wasm. check-protocol-deps.sh comment de-staled.
- Fence holds: scp-mls/scp-client Cargo.toml have no tokio/scp-runtime/scp-identity. WasmClock correctly in scp-client-wasm/src/time.rs (not the leaf).
- T1c inventory accurate as forward-looking: dht_client/ still in scp-identity; verify_bep44_signature still re-exported at identity/lib.rs:49 (T1c will remove); parser-canonicality directive grounded — scp_did::extract_public_key_from_did (lib.rs:120) genuinely LACKS the z-base-32 round-trip check that scp_identity::dht::extract_public_key has (test `..rejects_non_canonical_zbase32_padding` dht.rs:3289). Rejected-alt 5 (no scp-dht at DID-method layer) consistent.
- Artifacts: architecture.md graph, specs 16/20/21, white-paper ("eleven additional crates" count verified=11), CLAUDE.md project map, .clippy.toml, bridge.ts DidRotationEvent→scp_did all consistent. NO stale scp-primitives refs anywhere except agent-memory + historical README/ADR prose. ADR-055 has no scp-primitives refs.
- Compiles: leaf crates native ✓, wasm fence (exact CI cmd) exit 0 ✓, scp-identity/runtime/core native ✓.
- Release order topologically valid: clock,crypto,did,platform,event-log,protocol,identity,mls,client,client-wasm,runtime,core (scp-identity moved after protocol — harmless, it only deps clock/did/platform).
