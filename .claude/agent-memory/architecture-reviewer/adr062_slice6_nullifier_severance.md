---
name: adr062-slice6-nullifier-severance
description: ADR-062 Slice6 / SCP-CAPINJECT-006 review — sever 4 in-memory nullifiers to testing-only + fail-closed pre-rotation + G1 gate @ 554994606
metadata:
  type: project
---

ADR-062 Slice 6 (SCP-CAPINJECT-006) @ scp-identity branch feat/adr062-slice6-nullifier-severance, HEAD 554994606 (base 2adb7dd36). **APPROVE-WITH-CHANGES.**

**Structural move:** removed `testing` from 4 unconditional prod dep lines (scp-identity, scp-node, scp-ffi, scp-ffi-napi Cargo.toml). Compiler then forces every `scp_platform::testing::*` prod ref to re-gate or fail closed. `allow_in_memory_custody` deleted. `InMemoryPreRotationCustody` now `#[cfg(feature="testing")]` in scp-platform (module gated, satisfies A5 for the TYPE). Shipped identity creation FAILS CLOSED: `IdentityError::NoPreRotationBackend` (scp-identity/lib.rs) → IDENT_1059 (scp-ffi-common/error_codes.rs) → each bridge maps via own `no_pre_rotation_backend()` helper. Verified: shipped `cargo check -p scp-identity` compiles clean; G1 real gate + fixture harness both PASS.

**Sound & compliant:** §Decision 6 (zero nullifier allowlist), §Decision 4 (typed fail-closed, no nullifier fallback), G1 closed ⊆-whitelist (positive, not denylist; fixtures prove closed + load-bearing + soundness). Layering clean — NO core→bridge dep (IdentityError in scp-identity; IDENT_1059 in ffi-common; NodeError wraps IdentityError, normal direction). DOA-safe: create still returns Result so Err→Ok transition needs no signature change.

**Type-system backstop (key strength):** ~25-site fail-closed duplication across 3 bridges + config.rs + 2 node sites is ACCEPTABLE, not a smell — InMemoryPreRotationCustody absent on shipped builds means "forgetting to fail closed" = COMPILE ERROR, not silent nullifier. Shared piece (IDENT_1059) IS centralized. Distinct bridge error types make shared helper impossible.

**NEW findings:**
1. MED — config.rs mint arm + import gated `#[cfg(any(test, feature="testing"))]`, diverging from scp-node's `#[cfg(feature="testing")]`-ONLY. Consequence: config.rs fail-closed arm is STRUCTURALLY UNTESTABLE via `cargo test -p scp-identity` (test cfg always selects mint) — ROOT CAUSE of known AC5 scp-identity coverage gap. scp-node's pattern (mint behind feature, fail-closed behind not(feature), success tests behind feature) tests BOTH arms; adopt it. Not an A5 soundness break (call site, type properly feature-gated, G1 unaffected), just inconsistency + testability gap.
2. LOW — scp-identity normal dep carries `scp-platform/in-memory-storage` but InMemoryStorage used ONLY in config.rs:451 `#[cfg(test)]` (already covered by dev-dep testing⟹in-memory-storage). Dead weight in shipped graph; Cargo.toml comment ("durability-only dev storage affordance") misleading — scp-identity never constructs it on shipped path (callers inject Storage). Drop to `["software_platform"]`.
3. LOW/OBS — G1 ARTIFACTS = 3 FFI crates only; scp-node/scp-relay BINARIES not directly gated though ADR §Consequences ~line129 anticipates node-graph gating. Node covered transitively via scp-ffi→scp-node(server) + node default-features empty; residual narrow gap = explicit `cargo build -p scp-node --features testing` release. Add binaries to ARTIFACTS or document transitive coverage.
4. OBS/inquisitor — config.rs doc "returns handle so future durable backend threaded without API change" is questionable: #1729 real backend must be INJECTED (no-singletons tenet) = threading param through create_inner + ~25 sites = API change. "No API change" only holds if internally constructed (violates DI).

Already-known (not re-reported): AC3/AC5 missing tests, dead pyo3 block, G1 comment/`--features server` items.
