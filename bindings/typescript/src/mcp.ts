/**
 * MCP (Model Context Protocol) handle types for the SCP TypeScript SDK.
 *
 * After Phase 4 PR 4 (#1549, ADR-048) Agent B1, {@link McpServer} and
 * {@link McpClient} collapse to pure handle types that wrap the raw
 * NAPI object. All MCP operations live on the {@link SCP} class
 * (`scp.mcpServerCreate`, `scp.mcpServerStop`,
 * `scp.mcpClientConnectStdio`, `scp.mcpClientConnectSse`,
 * `scp.mcpClientDisconnect`, `scp.mcpClientListTools`,
 * `scp.mcpClientInvoke`). The free-function shims (`serveMcp`,
 * `connectMcp`, `connectMcpStdio`) that predated ADR-048 were deleted
 * in the same commit.
 *
 * See ADR-015 in `.docs/adrs/phase-3.md` and `crates/scp-mcp/`.
 */

// ---------------------------------------------------------------------------
// Opaque native handles (raw napi-rs class instances)
// ---------------------------------------------------------------------------

/** Opaque NAPI handle returned by `scp.mcpServerCreate`. */
export type NativeMcpServerHandle = unknown;

/** Opaque NAPI handle returned by `scp.mcpClientConnectStdio` / `mcpClientConnectSse`. */
export type NativeMcpClientHandle = unknown;

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

/**
 * Pure handle to a running MCP server — thin wrapper around the raw
 * NAPI handle returned by {@link SCP.mcpServerCreate}. Stop the server
 * via `scp.mcpServerStop(server._rawHandle)`.
 */
export interface McpServer {
  /** @internal Raw napi-rs MCP server handle. */
  readonly _rawHandle: NativeMcpServerHandle;
}

// ---------------------------------------------------------------------------
// MCP Client
// ---------------------------------------------------------------------------

/**
 * Pure handle to an MCP client connection — thin wrapper around the raw
 * NAPI handle returned by {@link SCP.mcpClientConnectStdio} or
 * {@link SCP.mcpClientConnectSse}. Disconnect via
 * `scp.mcpClientDisconnect(client._rawHandle)`, list/invoke tools via
 * `scp.mcpClientListTools(client._rawHandle)` and
 * `scp.mcpClientInvoke(client._rawHandle, ...)`.
 */
export interface McpClient {
  /** @internal Raw napi-rs MCP client handle. */
  readonly _rawHandle: NativeMcpClientHandle;
}
