---
name: adr062-slice6-nullifier-severance
description: ADR-062 Slice 6 SCP-CAPINJECT-006 nullifier severance @554994606 — SHIP verdict, could not reach any nullifier in shipped build
metadata:
  type: project
---

# ADR-062 Slice 6 / SCP-CAPINJECT-006 nullifier severance @554994606 (branch feat/adr062-slice6-nullifier-severance)

VERDICT: SHIP. Could not reach any of the 4 in-memory nullifiers (key custody / device attestation / DHT / pre-rotation) in a shipped SDK build. Fail-closed holds on every create path + all 3 bridges.

**Why:** Two-layer defense, the first is compile-time-airtight:
- L1 (type existence, PRIMARY): nullifier TYPES live in `scp-platform/src/testing/` gated `#[cfg(feature="testing")] pub mod testing` (lib.rs:67); `scp_dht::InMemoryDhtClient` is `#[cfg(feature="testing")] pub use` (dht/lib.rs:28). Removed `scp-platform/testing` from unconditional prod dep lines (scp-identity now `["software_platform","in-memory-storage"]`). KEY LEVER: the ONLY concrete `impl PreRotationCustody` is `InMemoryPreRotationCustody` (platform/testing/pre_rotation_custody.rs:67). Every create entry (DidMethod::create, config.rs create_inner, dht.rs create/create_with_agent_key) requires `&impl PreRotationCustody`. In a shipped (no-testing) build NO value satisfies that bound → identity creation is COMPILE-TIME-forced to fail closed. Even a malicious in-tree dev can't construct one without enabling scp-platform/testing (G1 catches).
- L2 (G1 gate, defense-in-depth): scripts/check-shipped-feature-graph.sh — closed positive ⊆-whitelist of durability-only features; `cargo tree -e features,no-dev`. PASSES on real tree. no-dev EMPIRICALLY load-bearing (scp-ffi graph: testing 2× with-dev, 0× no-dev).

**Fail-closed verified:** config.rs create_inner (IDENT via NoPreRotationBackend), scp-node resolve_identity + resolve_identity_persistent Generate arms (`#[cfg(feature="testing")]` mint / `#[cfg(not)]` → NodeError::Identity(NoPreRotationBackend)), all 3 bridges identity_create (pyo3 identity.rs, napi identity.rs, uniffi bridge.rs all `#[cfg(not(feature="testing"))]` → IDENT_1059/IDENT_1008). server.rs self-host DHT gated `any(test,feature=testing)` w/ prod arm `ClientDhtConfig::default().into_client()?`. IDENT_1059 defined error_codes.rs:263, mapped all bridges.

**Real shipped build invocations MATCH gate's modeled `--no-default-features --features server`:** wheel=maturin default(server)+extension-module(pyo3-only); napi=`cargo build -p scp-ffi-napi --release` (default=server); uniffi=`cargo build -p scp-ffi-uniffi --release` + build-xcframework.sh release `EXTRA_FEATURES=""` (testing ONLY in DEV_MODE). All default==["server"].

**Migration clean:** zero `allow_in_memory_custody` refs remain anywhere; feature deleted; no re-export alias. Only ungated `pub use InMemory*` = `InMemoryPersistence` (runtime providers/mod.rs:24) = durability-only storage, NOT a nullifier.

## Findings (all LOW / non-blocking)
- **F1 (LOW, accuracy):** Plan A5 + G1 script comment claim "nullifier arms `#[cfg(feature="testing")]` ONLY, never any(test,...)" but config.rs create_inner (identity/src/config.rs:8189-region), the 4 FFI `new_in_memory_for_test` ctors (scp-ffi/src/scp.rs:364, uniffi/scp.rs:166, napi/scp.rs:4450, PyBridgeInstance), and server.rs DHT arm all use `#[cfg(any(test, feature="testing"))]`. BENIGN — cfg(test) is structurally unreachable in a dependency/shipped artifact (only set for the crate under `cargo test -p X`), so `any(test,feature)` collapses to feature-only in shipped. But the STATED invariant is literally false + unenforced. Fix: align code to feature-only OR correct comment (soundness actually rests on L1 type-gating + test-cfg-unreachable, not on arms being feature-only).
- **F2 (LOW, latent):** G1 hardcodes `--no-default-features --features server` not derived from each artifact's real `default`(+maturin/napi extras). Coincides today (default==["server"], extension-module pyo3-only). If future `default` gains a testing-pulling feature, real wheel ships it, G1 blind. Fix: derive invocation from build config or assert default==["server"].
- **F3 (info):** allowlist hygiene self-test `assert_allowlist_has_no_nullifier` is finite denylist (NULLIFIER_CONTROL_FEATURES) inside the whitelist; a future nullifier under a NEW name added to allowlist passes hygiene + ⊆. Requires editing protected enforcement file (human review) + feature resolving in. Acceptable, primary ⊆ closed.
- Attestation exemption (pure-helpers-allowlist.txt +3: identity_attest_device ×2 + identity_verify_device_attestation) CANNOT hide a nullifier — narrowly scoped named `&self` methods, ADR-048 §1 method-vs-free-fn structural rule, orthogonal to nullifier gating. Fail-closed IDENT_1015/1016. Transient, tied to #2171.
