---
name: adr062-slice6-nullifier-severance
description: ADR-062 Slice 6 / SCP-CAPINJECT-006 keystone nullifier-severance security audit (554994606) — SECURE, 0 blockers
metadata:
  type: project
---

# ADR-062 Slice 6 (SCP-CAPINJECT-006) — nullifier severance — 2026-07-16 — SECURE, 0 BLOCKERS

Branch `feat/adr062-slice6-nullifier-severance` @554994606, base 2adb7dd36. Moves ALL FOUR
in-memory security nullifiers (+ 5th did:key) to `#[cfg(feature="testing")]`-only, DELETES
`allow_in_memory_custody` feature, makes prod identity create FAIL CLOSED, adds G1 gate.

**Core structural move (SOUND):** removed `testing` from the 4 unconditional prod
`scp-platform` dep lines (scp-ffi, scp-ffi-napi, scp-identity, scp-node) → replaced with
durability-only `software_platform`+`in-memory-storage`. Folded `scp-platform/testing`+
`dep:scp-testing` into each crate's own `testing` feature. `allow_in_memory_custody` was
never the real gate (code-level gate over a type that shipped anyway); now the type is
out-of-scope in shipped builds by construction.

**Nullifier type gating (VERIFIED feature-only, A5-compliant):** scp-platform/src/lib.rs:67
`#[cfg(feature="testing")] pub mod testing;` (InMemoryKeyCustody/DeviceAttestation/
PreRotationCustody). scp-dht InMemoryDhtClient `#[cfg(feature="testing")]`. scp-platform
`in_memory` module (durability InMemoryStorage) gated SEPARATELY by in-memory-storage/push —
independent of testing. scp-protocol did:key edge: scp-did/scp-event-log `features=["testing"]`
are under `[dev-dependencies]` (line 54+), NOT shipped; normal-dep did:key behind
scp-protocol's own `testing` feature (line 47), absent from shipped graph.

**Feature-graph escape check (CLEAN):** grep confirms `scp-platform/testing` & `scp-dht/testing`
appear ONLY inside `testing=[...]` lists across all Cargo.toml. `allow_in_memory_custody` = 0
residual refs anywhere. scp-platform `testing=["software_platform","in-memory-storage",
"in-memory-push"]` — no prod feature pulls it.

**Fail-closed (VERIFIED typed errors, never fake-Ok/nullifier substitute):**
- scp-identity/src/config.rs create_inner: `#[cfg(not(any(test,feature="testing")))]` →
  `Err(IdentityError::NoPreRotationBackend)`. New error variant in lib.rs:162+.
- scp-node/src/lib.rs resolve_identity + resolve_identity_persistent Generate arms →
  `NodeError::Identity(NoPreRotationBackend)` under `#[cfg(not(feature="testing"))]`. Two real
  `#[cfg(not(feature="testing"))]` tokio tests assert fail-closed (inputs via dev-dep custody,
  but the arm is FEATURE-selected so assertion is real).
- server.rs (F1): retyped Explicit phantoms InMemoryKeyCustody→FileKeyCustody; auto-generate
  None arm → `ServerError::AutoGenerateUnavailable` under `#[cfg(not(any(test,testing)))]`.
  Explicit(id) arm reuses CALLER identity (created upstream where it fails closed) — no
  pre-rotation bypass. start_for_testing is a normal (non-nullifier) fn.
- attestation: pyo3 identity_attest_device has BOTH arms (testing + not-testing→typed IDENT_1015).
  uniffi verify has both arms (3916 testing / 3952 not-testing). IDENT_1059/1015/1016 codes.

**G1 gate (scripts/check-shipped-feature-graph.sh) — SOUND, RAN CLEAN:** positive ⊆-allowlist
(durability-only, ZERO nullifier features), closed-by-construction, dev-deps excluded
(`-e features,no-dev`), checks all 3 bridges with `--no-default-features --features server`.
Fixture harness proves (a) novel feature rejected (b) allowlist load-bearing (c) clean accepted
(soundness) leaked testing feature rejected + assert_allowlist_has_no_nullifier. RAN: all 3
shipped artifacts PASS; fixtures pass. Wired into ci.yml job `shipped-feature-graph` +
`fail-closed-pre-rotation`, both in required-jobs aggregation. Added to CLAUDE.md enforcement list.

**Observations (non-blocking):**
1. pyo3 identity_verify_device_attestation (src/identity.rs:920) is `#[cfg(feature="testing")]`
   on the WHOLE pyfunction → inner `#[cfg(not(feature="testing"))]` block (939-951) is DEAD.
   In prod the symbol is absent; SDK scp.py:953 hasattr-guards → raises IDENT-1016. Fails closed
   but asymmetric vs attest_device/uniffi (which keep both arms). Minor cleanliness.
2. Mint sites use `any(test,feature="testing")` (config.rs/node/server) vs A5 "feature-only".
   SAFE: shipped cdylib never has test cfg, so collapses to feature-only; TYPES are strictly
   feature-only. G1 equivalence holds because shipped artifacts are never `--test` builds.
3. Residual trust: G1 equivalence assumes allowlisted durability features (in-memory-storage/
   push) never gate a nullifier — convention, not mechanically enforced. A future nullifier
   hidden behind an allowlisted feature would pass G1. Low risk (type-gating is primary; allowlist
   is a human-approval enforcement file). Acceptable defense-in-depth.
