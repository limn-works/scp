# PR-6c Swift saga wrapper tests (#1939) — ToolSagaTests.swift

Reviewed @1bf944be1. `Context.invokeToolCrossContextSaga` (§6.2.4 UniFFI wrapper), 9 XCTest tests against the REAL engine (xcframework links Rust). All 9 green.

## Verdict: SHIP (one non-blocking strengthening recommended)

## Mutation-confirmed load-bearing guards
- Dropped source-active guard → testSagaRejectsInactiveSourceContext FAILS (bridge returns SCP-VALID-7001 nonce error, not SCP-CTX-2001). Guard is load-bearing; test exercises the real wrapper guard, not a coincidental bridge code.
- Replaced UTF-8 guard with lossy decode → testSagaRejectsNonUtf8Input FAILS (reaches bridge → SCP-VALID-7001). Guard load-bearing.
- Inactive-source test setup is sound: ceiling at makeParams() includes `context:close`, so `source.close()` actually succeeds (precondition real).

## Finding: forwarding test nonce is MALFORMED (non-blocking, strengthen)
- Helper `nonceHex = String(repeating: "ab", count: 32)` = 64 hex = 32 bytes. Bridge REQUIRES 16 bytes / 32 hex chars (`crates/scp-ffi/uniffi/src/bridge.rs:5463`, napi tools.rs:761). Comment at line ~64 "64 hex chars = 32 bytes — well-formed" is FACTUALLY WRONG.
- Consequence: testSagaForwardsArgumentsToBridge halts at the bridge's EARLY nonce-format validation (SCP-VALID-7001), not at the saga prepare/consent logic. Forwarding claim still holds (a bridge error ≠ a guard code proves bytes crossed FFI), but the smoke test is shallower than its docstring implies.
- FIX: set helper to `String(repeating: "ab", count: 16)` and correct the comment. Valid nonce pushes the forwarding test past nonce validation into the real saga (likely SagaAborted on no-consent) — strictly stronger linkage proof.

## Classification of the typed-error / SagaResult tests (4 + 2)
- Construct ScpError.Saga* / SagaResult directly + assert fields. Partly re-tests UniFFI-generated code BUT pins the SDK's public error/result contract (cases exist; retryAfterMs/sagaId/contendedContext present with right labels+types; nil never synthesized). Because Swift surfaces generated types directly as its contract (no re-map layer), this is a meaningful compile-time tripwire. Medium ROI, non-blocking.
- retryAfterMs nil (never 0) is explicitly pinned — good (0 would read "retry now").

## Contract-impossible gap (correctly declined)
- No end-to-end triggering of SagaAborted/Busy/NeedsRepair terminals — requires committed-saga bidirectional-consent setup, a Rust/integration concern. Docstring discloses this honestly. Not a wrapper-layer gap.

## Isolation/flakiness: LOW
- setUp/tearDown per test, .inMemory storage, no shared mutable state, no order deps. nowMs() wall-clock unused by guard tests and pre-empted by nonce validation in forwarding test → no time-flakiness.
