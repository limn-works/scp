/**
 * MCP (Model Context Protocol) module for the SCP TypeScript SDK.
 *
 * Provides functions for exposing SCP tools via MCP and connecting to MCP
 * servers. MCP integration enables SCP contexts to serve as tool providers
 * for AI agents that speak the MCP protocol.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and `crates/scp-mcp/`.
 */

import type { Context } from "./context.js";
import { mapBridgeError, TransportError } from "./errors.js";
import type { McpClientConfig, McpServerConfig, ToolDefinition } from "./types.js";

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

/**
 * Starts an MCP server that exposes context tools via JSON-RPC.
 *
 * The server listens for MCP-protocol tool invocation requests and routes
 * them to the corresponding SCP context tool.
 *
 * @param ctx - The SCP context whose tools to expose.
 * @param config - MCP server configuration.
 * @returns A handle to the running server.
 * @throws {TransportError} If the server cannot be started.
 */
export async function serveMcp(ctx: Context, config: McpServerConfig): Promise<McpServer> {
  try {
    const _ = ctx;
    const host = config.host ?? "127.0.0.1";
    const port = config.port ?? 0;

    // MCP server implementation will be wired to the MCP crate in an
    // integration story. For now, return a server handle with the configured
    // tools.
    const url = `http://${host}:${port}`;

    let stopped = false;

    const server: McpServer = {
      url,
      tools: config.tools,
      async stop(): Promise<void> {
        if (stopped) {
          return;
        }
        stopped = true;
      },
      async [Symbol.asyncDispose](): Promise<void> {
        await server.stop();
      },
    };

    return server;
  } catch (error) {
    throw mapBridgeError(error);
  }
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
  invokeTool(toolName: string, input: Readonly<Record<string, unknown>>): Promise<unknown>;
  /** Disconnects from the MCP server. */
  disconnect(): Promise<void>;
}

/**
 * Connects to an MCP server.
 *
 * Establishes a JSON-RPC connection to the specified MCP server URL and
 * returns a client handle for tool listing and invocation.
 *
 * @param config - MCP client configuration.
 * @returns An MCP client handle.
 * @throws {TransportError} If the connection fails.
 */
export async function connectMcp(config: McpClientConfig): Promise<McpClient> {
  try {
    // MCP client implementation will be wired to the MCP crate in an
    // integration story.
    let disconnected = false;

    const client: McpClient = {
      serverUrl: config.serverUrl,
      async listTools(): Promise<readonly ToolDefinition[]> {
        if (disconnected) {
          throw new TransportError(
            "MCP client is disconnected -- call connectMcp() to reconnect",
            "SCP-TRANS-5010",
          );
        }
        return [];
      },
      async invokeTool(
        toolName: string,
        input: Readonly<Record<string, unknown>>,
      ): Promise<unknown> {
        if (disconnected) {
          throw new TransportError(
            "MCP client is disconnected -- call connectMcp() to reconnect",
            "SCP-TRANS-5010",
          );
        }
        const _ = { toolName, input };
        return {};
      },
      async disconnect(): Promise<void> {
        if (disconnected) {
          return;
        }
        disconnected = true;
      },
      async [Symbol.asyncDispose](): Promise<void> {
        await client.disconnect();
      },
    };

    return client;
  } catch (error) {
    throw mapBridgeError(error);
  }
}
