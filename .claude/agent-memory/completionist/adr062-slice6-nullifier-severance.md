---
name: adr062-slice6-nullifier-severance
description: SCP-CAPINJECT-006 (ADR-062 Slice 6) 11-AC review @554994606 — 9 MET, AC3+AC5 test-clauses unmet
metadata:
  type: project
---

# SCP-CAPINJECT-006 / ADR-062 Slice 6 (nullifier severance) — completeness review

Branch feat/adr062-slice6-nullifier-severance, HEAD 554994606, base 2adb7dd36 (worktree agent-a6c1a49a577aec4e6). Severs all 4 in-memory nullifiers (custody/attestation/DHT/pre-rotation) to test-harness-only; deletes allow_in_memory_custody; adds G1 shipped-feature-graph ⊆-allowlist gate.

**Verdict: INCOMPLETE — functionally complete + structurally proven, but AC3 and AC5 explicit TEST clauses unmet.**

Structural proofs run and PASSED: bare `cargo build --workspace` (no testing) exit 0 — the definitive proof all 4 nullifier types are cfg-gated out of prod (they're testing-only types; if any weld site weren't gated, compile fails). clippy (testing string) exit 0, fmt exit 0, G1 gate + fixtures exit 0, validate-prd exit 0 (437 stories).

**Key mechanism (plan's insight):** the real gate was never `allow_in_memory_custody` (code-gate over a type that shipped anyway). It was `scp-platform/testing` enabled UNCONDITIONALLY in prod dep lines of scp-ffi/napi/uniffi/identity/node. Removing it from those lines + folding into each crate's own `testing` feature forces the compiler to re-gate or fail-close every `scp_platform::testing::*` prod ref.

## Per-AC: AC1✓ AC2✓ AC3✗(test) AC4✓ AC5✗(test) AC6✓ AC7✓ AC8✓ AC9✓ AC10✓ AC11✓
- AC1 MET: allow_in_memory_custody grep=0 across crates/.github/CLAUDE/TESTING/CONTRIBUTING/matrix AND bindings/ (the missed-then-fixed dir). Sole residual = .docs/lessons/test-whitelist-masks-ci-red.md (stale, outside AC grep).
- AC2 MET+honest reword: FfiKeyCustody::InMemory testing-gated; custody "in_memory" ACCEPT arm testing-gated + `#[cfg(not(testing))] "in_memory" => Err` REJECT arm in all 3 parsers (src/identity.rs parse_custody_inner, napi/scp.rs, uniffi parse_custody_method); durability STORAGE "in_memory" (StorageConfig::InMemory) preserved — the reword scopes to custody region, does NOT collide. Test identity_create_in_memory_rejected_without_feature exists.
- AC4 MET structurally: no scp-platform/in-memory-pre-rotation feature; all InMemoryPreRotationCustody refs cfg-gated (bare build proves). scp-identity prod dep = software_platform+in-memory-storage only (no testing).
- AC6 MET: server.rs prod uses FileKeyCustody (import :21, IdentitySource::<FileKeyCustody> :355/:468); InMemoryKeyCustody/scp_platform::testing only in #[cfg(test)] mod (:955); common/Cargo.toml scp-platform/testing=0.
- AC7/8/9 MET: G1 = positive ⊆-whitelist (scripts/check-shipped-feature-graph.sh), ZERO nullifiers on allowlist, fixtures (a novel-reject / b omit-load-bearing-reject / c clean-accept) + soundness leaked-nullifier-reject + assert_allowlist_has_no_nullifier all pass; runs 3 artifacts incl --features server; 4 nullifier names absent from resolved graph; added to CLAUDE.md enforcement list.
- AC10 MET: fmt/clippy(testing string)/bare-build all exit 0. (Did NOT run full workspace nextest myself.)
- AC11 MET: validate-prd exit 0.

## THE TWO GAPS (why INCOMPLETE)
- **AC3 test clause UNMET:** "a test asserts the shipped attestation op returns a typed Err." NO such test exists anywhere. Exhaustive enumeration of ALL `#[cfg(not(feature="testing"))]` tests in tree = {dht(2, Slice-1), uniffi custody-reject(1), scp-node pre_rotation(2)} — zero attestation. Python test_real_ffi attest tests run under a TESTING maturin build (expect success), so never exercise the shipped decline. Bridge gating itself IS correct (uniffi+napi ship fail-closed attest+verify methods returning IDENT_1010/1015/1016; pyo3 attest_device ships fail-closed method; pyo3 VERIFY is testing-only in the bridge but the Python SDK wrapper scp.py:953 synthesizes the SCP-IDENT-1016 decline via a `hasattr` guard — so matrix note is HONEST at SDK level, not phantom). Pure-helpers exemption (#2171, 3 entries, additive, transient, real &self methods) is LEGITIMATE not gamed; check-pure-helpers.sh unchanged.
- **AC5 test clause PARTIALLY UNMET:** "async tests assert ALL production identity creation on a shipped build returns the typed error — not only the callback-custody bridge but also the File and Sqlite custody create paths and the scp-node self-host create path." Only the scp-node self-host path is tested (2 tests, gated `#[cfg(not(feature="testing"))]`, select fail-closed via FEATURE while test-cfg supplies in-memory inputs — genuine). The 3 FFI-bridge (callback/File/Sqlite) create paths have fail-closed arms (bare-build-proven, return no_pre_rotation_backend()/IDENT_1059) but NO executing test. AC5's stated rationale "every create path funnels through config.rs:334 lowering" is INACCURATE for the FFI bridges — they have independent `#[cfg(not(testing))]` arms (e.g. pyo3 identity.rs:1111) that bypass config.rs create_inner entirely. (config.rs create_inner's prod arm is `#[cfg(not(any(test,testing)))]` — untestable under test-cfg by construction.)

## Out-of-AC edits (all accounted for)
- handle-affinity "restore": napi identity_migrate — check_handle moved to FIRST stmt before the `#[cfg(not(testing))]` fail-closed early-return, so mismatched-instance handles still get SCP-PERM-3030 not IDENT_1059. JUSTIFIED (handle-affinity enforcement requires check_handle before early return).
- attestation wording (error_codes.rs, sdk-capability-matrix.json): AC1(g)/AC3 in-scope.
- build-xcframework.sh feature string (allow_in_memory_custody,testing→testing): in-scope AC10.
- swift Outlets+Streaming.swift + OutletStreamingTests reformat (multi-line if-case): cosmetic SwiftLint scope-creep, unrelated to Slice 6, harmless. LOW flag.

## LOW code-hygiene
- src/identity.rs:939-951: dead `#[cfg(not(feature="testing"))]` block INSIDE the `#[cfg(feature="testing")]`-gated module fn identity_verify_device_attestation (registration also testing-gated at :2767). Never compiles in any config — looks like a fail-closed path but is unreachable (the real pyo3 verify decline lives in the Python SDK hasattr guard). Should be deleted.

LESSON: for "sever testing-only type from prod" stories, the bare `cargo build --workspace` (no testing) is the single load-bearing structural proof — a testing-only type left un-gated on a prod path fails compile. But the AC's explicit "a test asserts shipped op fails closed" clauses are a SEPARATE checkbox: a `#[cfg(not(feature="testing"))]` test only runs under `cargo test -p <crate>` without testing, which is clean for leaf crates (scp-node) but impractical for FFI bridges that need testing for most tests — so bridge fail-closed paths tend to get structural-only coverage. Enumerate ALL `#[cfg(not(feature="testing"))]` tests to find what's actually asserted vs merely compiled.
