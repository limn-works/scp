/**
 * MCP (Model Context Protocol) types for the SCP TypeScript SDK.
 *
 * Defines handle interfaces for servers and clients. The functional
 * entry points (`serveMcp`, `connectMcp`, `connectMcpStdio`) moved
 * onto the {@link SCP} class in Phase 4 PR 4 (#1549, ADR-048) as
 * `scp.mcpServerCreate(...)`, `scp.mcpClientConnectSse(...)`,
 * `scp.mcpClientConnectStdio(...)` etc. The `McpServer` / `McpClient`
 * interfaces below survive for Agent B to collapse; the free-function
 * shims that predated ADR-048 were deleted in the same commit.
 *
 * See ADR-015 in `.docs/adrs/phase-3.md` and `crates/scp-mcp/`.
 */

import type { ToolDefinition } from "./types";

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

/** Handle to a running MCP server. */
export interface McpServer extends AsyncDisposable {
  /** The URL the server is listening on. */
  readonly url: string;
  /** The tools exposed by this server. */
  readonly tools: readonly ToolDefinition[];
  /** Stops the MCP server. */
  stop(): Promise<void>;
}

// ---------------------------------------------------------------------------
// MCP Client
// ---------------------------------------------------------------------------

/** Handle to an MCP client connection. */
export interface McpClient extends AsyncDisposable {
  /** The server URL this client is connected to. */
  readonly serverUrl: string;
  /** Lists available tools on the MCP server. */
  listTools(): Promise<readonly ToolDefinition[]>;
  /** Invokes a tool on the MCP server. */
  invokeTool(
    toolName: string,
    input: Readonly<Record<string, unknown>>,
    contextId?: string,
    invokerDid?: string,
  ): Promise<unknown>;
  /** Disconnects from the MCP server. */
  disconnect(): Promise<void>;
}
