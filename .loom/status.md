# Loom Status — Iteration 9

## Failing Tests
None. All 2,322+ tests pass across the workspace.

## Uncommitted Changes
None. All work committed.

## Fixed This Iteration
None (no prior failures).

## Tests Added / Updated
No new test files added this iteration (ADR stories are docs-only; SCP-077 UniFFI scaffolding has 6 existing tests that continue to pass).

## Tool-Gated Stories
None skipped.

## Subagent Outcomes

| Story | Result | Summary |
|-------|--------|---------|
| SCP-060 | PASS | ADR-022 completed in .docs/adrs/phase-4.md with all required sections: Decision (dual-target wasm-bindgen + napi-rs), Rationale, Implementation, Dependencies, Acceptance Criteria, Scope. Committed at fe7927b. |
| SCP-082 | PASS | ADR-025 completed in .docs/adrs/phase-5.md with all required sections: Secure Enclave (P-256), Keychain (Ed25519/X25519), App Attest, APNs with opaque payloads, NSFileProtectionCompleteUntilFirstUserAuthentication. Committed at 0e1afcc. |
| SCP-077 | PASS | UniFFI bridge crate created at crates/scp-ffi/uniffi/ with scp.udl (namespace anchor), bridge.rs (~1700 lines, ScpError enum, all record/enum/object types, 19 async functions, error conversions), lib.rs (tokio runtime, scaffolding). Uses proc-macro approach. UniFFI 0.29. Committed at 080e770. |

## Review Outcomes

| Story | Result | Issues | Fixes Applied |
|-------|--------|--------|---------------|
| SCP-060 | PASS | Minor: shared.md package name inconsistency, minor ADR sketch issues (non-blocking) | No fixes needed |
| SCP-082 | FAIL→FIXED | MAJOR: StrongBox paragraph was wrong (Android feature, not Apple); MAJOR: force-try `try!` in make() factory contradicted acceptance criteria; MINOR: DeviceAttestationProvider missing from ADR-021 UDL | Fixed in 3a9f0c2: removed StrongBox paragraph, fixed make() to use `throws`, added DeviceAttestationProvider to ADR-021 |
| SCP-077 | FAIL→FIXED | CRITICAL: scp-platform testing feature in [dependencies] (not dev-deps), putting InMemoryKeyCustody in production cdylib; MAJOR: timestamp-based IDs (predictable); MAJOR: eprintln! in FFI lib; MAJOR: poisoned mutex silently defaults to Closed | Fixed in 6fa9a1f: moved testing feature to dev-deps, replaced timestamp IDs with UUID v4, replaced eprintln! with tracing::error!, fixed poisoned mutex to return ScpError |

## Next Iteration

Actionable stories now unblocked by SCP-060, SCP-077, SCP-082 completion:
- **SCP-078** (UniFFI async bridging + Rust scaffolding) — blocked by SCP-077 (now done) ✓
- **SCP-079** (WASM bridge via wasm-bindgen) — blocked by SCP-060 (now done) ✓
- **SCP-083** (ADR-026: Swift SDK) — blocked by SCP-082 (now done) ✓
- **SCP-105** (ADR-027: Android Platform Adapter) — blocked by SCP-082 (now done) ✓

These four stories can run in parallel in the next iteration (no file conflicts).
