# Finding 001: NAPI MCP ContextProvider is entirely stubbed

## Severity: major

## Summary

The NAPI bridge's MCP ContextProvider (`McpNapiBridgeProvider`) returns stub/error responses for all methods. The MCP server running on Node.js/Bun cannot serve tools, validate capabilities, list members, or provide events — all operations return errors or empty results.

## Evidence

**File:** `crates/scp-ffi/napi/src/mcp.rs`

- `agent_role()` returns `None` (line 338-348)
- `context_tools()` returns empty `Vec` (line 354-356)
- `validate_capability()` returns error "not implemented" (line 358-368)
- `invoke_tool()` returns error "requires ContextManager integration" (line 370-380)
- `context_members()` returns empty `Vec` (line 382-384)
- `context_events()` returns empty array (line 386-388)
- `subscribe_resource()` returns error (line 390-392)
- SSE transport: `send_request()` and `send_notification()` return "not yet implemented" (lines 313-319)

## Expected Behavior

The PyO3 bridge (`crates/scp-ffi/src/mcp.rs`) has full implementations:
- `agent_role()` reads from role state (line 615-630)
- `context_tools()` reads from tool registry (line 633-649)
- `validate_capability()` performs full UCAN validation (line 651+)
- `invoke_tool()` dispatches to handler or echo mode (line 739+)

The UniFFI bridge (`crates/scp-ffi/uniffi/src/bridge.rs`) also has full implementations:
- `agent_role()` reads from ContextManager (line 4462)
- `context_tools()` reads from handle registry (line 4478)
- `validate_capability()` performs UCAN validation (line 4498)
- `invoke_tool()` has real dispatch (line 4608)

## Root Cause

The NAPI MCP bridge was implemented as a minimal skeleton and never wired to the ContextManager or tool registry.

## Additional: Missing MCP utility functions in NAPI

Beyond the ContextProvider stubs, the NAPI bridge is also missing these MCP functions that exist in PyO3:
- `mcp_server_wait` — blocking wait for server completion
- `mcp_server_info` — query server status/info
- `mcp_client_info` — query client connection info
- `mcp_server_register_tool` / `mcp_server_deregister_tool` — dynamic tool registration on MCP server

PyO3 has 21 MCP functions; NAPI has 15 (6 missing).

## Suggested Fix

Port the MCP ContextProvider implementation from the UniFFI bridge to the NAPI bridge, adapting the runtime access patterns (NAPI uses `crate::runtime::context_manager()` and `crate::runtime::with_context()`). Also implement the missing 6 MCP utility functions.
