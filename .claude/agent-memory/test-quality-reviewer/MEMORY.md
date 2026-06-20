# Test Quality Reviewer Memory

## SCP Project Conventions

### Swift Testing
- All Swift tests use Swift Testing framework (@Test, #expect, @Suite) -- never XCTest
- Standard at `.docs/standards/swift.md` lines 112-136
- `@unchecked Sendable` prohibited in production (line 23) but used in test mocks -- consider documenting exception
- Test files at `bindings/swift/Tests/SCPTests/`

### Swift SDK Architecture (affects test design)
- All bridge functions are stubs returning errors until SCP-103 (XCFramework) ships
- Bridge injection via typed closures (ContextBridge.SendFn etc.) enables behavioral testing
- Context is an actor; DTOs are nonisolated structs
- CheckedContinuation bridges async Rust FFI to Swift concurrency
- See `swift-sdk-patterns.md` for details

### Common Anti-Patterns Found
- Tautological assertions: `#expect(value >= 0)` on unsigned/empty-default values provides zero signal
- Duplicated mock types across test files instead of shared test helpers
- Polling loops with Task.sleep for synchronization instead of deterministic mechanisms
- Local `var` captured by `@Sendable` closures = data race under Swift 6 strict concurrency
- Relative file paths in test fixture loading (use #filePath for repo root)
- Tests claiming to verify access control but using @testable import (which exposes internals)

### Good Patterns Worth Replicating
- ContextTests mock injection: typed closure injection for every bridge function
- Locked<Value> wrapper with NSLock for test-side mutable state in concurrent tests
- Doc comments on test suites explaining scope and known limitations
- "Stub-era" marking so update scope is visible when real bridges ship

### Rust ContextManager Test Patterns
- Tests live in `crates/scp-runtime/src/context/manager/tests/{governance,lifecycle,messaging,mod}.rs`
- MockCrypto in mod.rs: call_order, fail_* flags, epochs_advanced_shared for observing crypto calls
- OrderTrackingCrypto wrapper: good pattern for verifying cross-method call ordering
- `governance_params()` helper creates standard test params; extend via `params.consequence_rules`, `params.economic_policy`
- `drain_events()` + pattern matching on ContextEvent variants is the standard event assertion pattern
- Best test pattern: `test_full_lifecycle_economy` -- multi-step with intermediate assertions and boundary failure

### Common Anti-Patterns Found (Rust)
- Multi-pass agent generation creates systematic test duplication (~50% waste in batch-2 governance)
- Tests bypassing ContextManager API to call internal functions directly (evaluate_cost, record_spend) -- not wiring tests
- RoleDemotion tests asserting event emission instead of actual role state change
- Sybil resistance tests on no-op functions asserting Ok -- tautological
- See `feedback_test_duplication.md` for details

### Python validator tests (bindings/python/tests/test_validation.py, test_types.py)
- All `validate_*` in scp_sdk/context.py are `-> None`, raise-on-invalid (ValidationError or ValueError)
- `assert validate_x(...) is None` is a small improvement over bare call: guards against accidental refactor to return-bool/return-error-string (some sibling validators DO return `str|None`: validate_against_template, validate_context_params). NOT vacuous, but weak.
- STRONGER assertion available for test_nfc_normalization: validator NFC-normalizes internally but discards result (returns None), so normalization is unobservable via this fn. To observe, would need to assert AssetEntry/ContentPath round-trip or expose normalized form. Current test only proves "decomposed form does not raise" — does not prove it normalizes vs. just accepts non-ASCII.
- Negative coverage is strong: pytest.raises with `match=` on message substrings + error code (SCP-VALID-7010/11/12). Good.
- Coverage GAPS: validate_admission has NO negative/case-insensitivity-specific gap test for whitespace (" open"); validate_broadcast_key_hex positive only tests 64-char — boundary 63/65 rejection lives in test, verify. _validate_csp / _validate_hostname / SiteConfig.__post_init__ validators — check separate coverage.

### Kotlin SmokeTest CustodyType
- CustodyType.rawValue IS real behavior, NOT tautology: consumed at FFI boundary `identityCreate(custody.rawValue)` (CoroutineBridge.kt:1465, Identity.kt:241). Asserting "platform" pins the wire contract Rust depends on.
- fromRawValue round-trip + unknown->null is genuine, non-brittle, pure (no native dep). Good smoke test choice given native lib not yet linked.
- Minor: only 1 of 3 enum values' rawValue asserted (PLATFORM); IN_MEMORY tested via fromRawValue, SOFTWARE untested. Parameterize for completeness.

## Review Checklist Additions (SCP-specific)
- Conformance dispatcher must cover ALL operations from `.docs/scaffold/shared.md` categories
- Every SDK source module needs a corresponding test file (Trust.swift was missing tests)
- Cross-reference acceptance criteria operations against actual SDK API surface (e.g., "append" vs "query")
- For wiring tests: verify the test goes through ContextManager public API, not internal state manipulation
- [TS SDK bridge error shape](ts_sdk_bridge_error_shape.md) — trust.ts classifies plain-Error bridge errors by [SCP-PERM] message regex; mapBridgeError is bypassed
- [TS SDK trust/parity tests](ts-sdk-trust-tests.md) — strict mock-bridge harness (M-1) is gold standard; TS classifier ~46 cases vs Python ~111 (per-prefix gap); tier mapping only in skipped real-NAPI group
- [Gate self-tests over-determined](gate-selftest-over-determined.md) — validator "fails on bad input → exit 1" tests pass for the wrong reason if input trips multiple error branches; isolate the branch + assert the specific signal, not just exit code
