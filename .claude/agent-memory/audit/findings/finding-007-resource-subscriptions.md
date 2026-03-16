# Finding 007: MCP resource subscriptions are no-ops across all bridges

## Severity: moderate

## Summary

The MCP `subscribe_resource` method accepts subscriptions silently but never delivers updates. No bridge implements actual resource subscription delivery.

## Evidence

**PyO3 bridge:** `crates/scp-ffi/src/mcp.rs`, lines 1029-1033
```rust
fn subscribe_resource(&self, _uri: &str) -> Result<(), String> {
    // Resource subscriptions are not yet wired to the transport layer.
    // Accept the subscription silently.
    Ok(())
}
```

**UniFFI bridge:** `crates/scp-ffi/uniffi/src/bridge.rs`, lines 4825-4829
```rust
fn subscribe_resource(&self, _uri: &str) -> Result<(), String> {
    // Resource subscriptions are not yet wired to the transport layer.
    // Accept the subscription silently (matching PyO3 behavior).
    Ok(())
}
```

**NAPI bridge:** `crates/scp-ffi/napi/src/mcp.rs`, lines 390-392
```rust
fn subscribe_resource(&self, _uri: &str) -> Result<(), String> {
    Err("resource subscriptions require full relay integration".to_owned())
}
```

## Expected Behavior

MCP resource subscriptions should deliver updates when the subscribed resource changes (e.g., new context events, membership changes).

## Root Cause

Resource subscription delivery requires transport-layer integration to push updates to MCP clients. The transport-to-MCP bridge path hasn't been built.

## Suggested Fix

1. Wire relay message delivery to MCP resource subscription notifications
2. Track active subscriptions per MCP client
3. Push notifications when subscribed resources change
