# Finding 014: NAPI tool invocation is echo-only stub — no handler dispatch or schema validation

## Severity: major

## Summary

The NAPI bridge's tool invocation returns echo mode without real handler dispatch. No JSON schema validation, no handler lookup, no cross-context invocation, no tool session management.

## Evidence

**File:** `crates/scp-ffi/napi/src/tools.rs`

NAPI tool_invoke flow:
1. [STUB] Validate UCAN present
2. [MISSING] Schema validation
3. [MISSING] Handler dispatch
4. [STUB] Echo input as output

**Comparison:** PyO3 (`crates/scp-ffi/src/tools.rs:py_tool_invoke`) performs:
1. Full UCAN validation for `tool:invoke` capability
2. Tool lookup in context registry
3. Input validation against JSON schema
4. Handler dispatch to registered handler
5. Output validation against JSON schema
6. Return typed result

Also missing from NAPI:
- `tool_invoke_cross_context` — cross-context tool invocation
- `tool_session_create` / `tool_session_invoke` / `tool_session_close` — session management

## Impact

Tools cannot be meaningfully invoked through the TypeScript SDK — invocations return the input as output without executing tool logic.

## Suggested Fix

Port tool invocation logic from PyO3 bridge, implementing full handler dispatch, schema validation, and cross-context invocation support.
