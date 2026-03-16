# Finding 005: WASM bridge tool invocation missing role-based capability check

## Severity: major

## Summary

The WASM bridge's tool invocation path does not perform role-based capability checks (`has_tool_invoke_capability`). Any WASM client can invoke any tool in any context regardless of their role assignment.

## Evidence

**WASM bridge:** `crates/scp-ffi/wasm/src/manager.rs`
- `invoke_tool` method at line ~1870 dispatches directly to handler or echo mode
- No call to `has_tool_invoke_capability` anywhere in the WASM bridge (confirmed via grep)
- The WASM CLAUDE.md documents this: "Tool Invocation — Capability Check: `tool_invoke` currently ignores the `identity_did` parameter"

**PyO3 bridge has the check:** `crates/scp-ffi/src/mcp.rs` performs `has_tool_invoke_capability` before dispatch
**UniFFI bridge has the check:** `crates/scp-ffi/uniffi/src/bridge.rs` validates UCAN capabilities
**NAPI bridge has the check:** Via UCAN validation in tool invocation path

## Expected Behavior

Before executing a tool, verify the invoking identity has the `tool_invoke:{tool_id}` capability for the target context via role state checking.

## Root Cause

`WasmContextRuntime` has no `RoleState` field. Role assignments and capability checking were not wired into the WASM manager. The WASM CLAUDE.md explicitly documents this gap.

## Suggested Fix

1. Add `RoleState` field to `WasmContextRuntime` (or `PerContextState`)
2. Populate role state during context creation and membership changes
3. Add `has_tool_invoke_capability` check before tool dispatch
4. Port the check logic from scp-core's `context::roles` module
