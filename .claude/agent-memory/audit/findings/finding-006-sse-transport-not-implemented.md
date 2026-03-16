# Finding 006: SSE MCP transport not implemented in NAPI and UniFFI bridges

## Severity: moderate

## Summary

The MCP SSE (Server-Sent Events) client transport returns "not yet implemented" errors in both the NAPI and UniFFI bridges. Only stdio transport works for MCP client connections on these platforms.

## Evidence

**NAPI bridge:** `crates/scp-ffi/napi/src/mcp.rs`, lines 312-319
```rust
impl McpTransport for SseMcpTransport {
    fn send_request(&self, _request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
        Err("SSE client transport not yet implemented for NAPI — use stdio transport".to_owned())
    }
    fn send_notification(&self, _notification: &JsonRpcNotification) -> Result<(), String> {
        Err("SSE client transport not yet implemented for NAPI — use stdio transport".to_owned())
    }
}
```

**UniFFI bridge:** `crates/scp-ffi/uniffi/src/bridge.rs`, lines 4398-4424
```rust
/// SSE transport is a placeholder — stdio is the primary transport for
fn send_request(&self, _request: &JsonRpcRequest) -> Result<JsonRpcResponse, String> {
    Err("SSE client transport not yet implemented for UniFFI — use stdio transport".to_owned())
}
```

**PyO3 bridge has real SSE:** `crates/scp-ffi/src/mcp.rs` contains `SseClientTransport` with real HTTP/SSE parsing.

## Expected Behavior

SSE transport should work on all non-WASM platforms for MCP client connections.

## Root Cause

SSE was implemented in the PyO3 bridge (using raw TcpStream) but not ported to NAPI or UniFFI.

## Suggested Fix

Port the SSE client transport implementation from `crates/scp-ffi/src/mcp.rs` (`SseClientTransport`) to NAPI and UniFFI bridges, or extract to `crates/scp-ffi/common/` for sharing.
