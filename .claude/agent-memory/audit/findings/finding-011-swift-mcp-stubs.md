# Finding 011: Swift SDK MCP functions throw "not yet wired" errors

## Severity: moderate

## Summary

The Swift SDK's `Mcp.swift` has 4 public functions that throw errors with "not yet wired to UniFFI" messages. These are user-facing API methods that will fail at runtime.

## Evidence

**File:** `bindings/swift/Sources/SCP/Mcp.swift`, lines 140-168

| Method | Error Code | Message |
|--------|-----------|---------|
| `McpBridge.defaultServe` | SCP-MCP-10001 | "not yet wired to UniFFI — awaiting mcp_serve export" |
| `McpBridge.defaultClientCreate` | SCP-MCP-10002 | "not yet wired" |
| `McpBridge.defaultClientListTools` | SCP-MCP-10003 | "not yet wired" |
| `McpBridge.defaultClientInvoke` | SCP-MCP-10004 | "not yet wired" |

These affect public methods: `serveMcp()`, `McpClient.connect()`, `listTools()`, `invoke()`.

## Impact

Swift SDK users cannot use MCP server or client functionality. All MCP operations fail at runtime with errors.

## Suggested Fix

Wire these to UniFFI bridge MCP exports (`mcp_server_create`, `mcp_client_connect_stdio`, etc.) which do exist in the UniFFI bridge.
