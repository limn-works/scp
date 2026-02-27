# Swift SDK Test Patterns (SCP)

## Bridge Stub Era (pre-SCP-103)

All UniFFI bridge functions are placeholder stubs that return errors. Tests can only verify:
1. Type shapes (stored property readback) -- Low ROI but establishes API contract
2. Error propagation through CheckedContinuation -- Medium ROI, validates async bridging
3. State machine behavior via mock injection -- High ROI, genuine behavioral coverage

When SCP-103 (XCFramework) ships, ALL bridge error tests will need updating.

## Mock Injection Pattern (ContextBridge)

The Context actor accepts injected bridge functions as typed closures:
- `ContextBridge.CreateFn`, `SendFn`, `SubscribeFn`, `LeaveFn`, `CloseFn`
- Tests provide mock implementations, enabling state machine and stream lifecycle testing
- This is the highest-value test pattern in the Swift SDK

Other modules (Identity, UCAN, Transport, EventLog, MCP) use free-function stubs
instead of injected closures. They cannot be mocked at the Swift layer -- only the
bridge error path is testable. Consider adding injection points for these modules.

## Concurrency in Tests

- Use `Locked<Value>` (NSLock-based wrapper) for mutable state shared with @Sendable closures
- Never use bare `var` captured by @Sendable closures -- data race under Swift 6
- Actor-isolated properties require `await` in tests (e.g., `#expect(await context.state == .active)`)
- AsyncStream testing: push via MessageListenerProtocol, consume via `for await`

## Conformance Test Runner

- Located at `bindings/swift/Tests/SCPTests/Conformance/ConformanceTests.swift`
- `dispatch(operation:input:)` maps operation strings to SDK calls
- Must stay in sync with categories in `.docs/scaffold/shared.md`
- Fixture directory: `tests/conformance/` (shared across all SDKs, may not exist yet)
- Use `#filePath` for reliable repo root resolution, not relative paths

## Files Reviewed
- SCP-102 (2026-02-27): All 8 test files. Verdict: Revise. Missing TrustTests, incomplete conformance dispatcher, tautological assertion.
