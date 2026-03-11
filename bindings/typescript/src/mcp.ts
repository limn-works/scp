/**
 * MCP (Model Context Protocol) module for the SCP TypeScript SDK.
 *
 * Provides functions for exposing SCP tools via MCP and connecting to MCP
 * servers. MCP integration enables SCP contexts to serve as tool providers
 * for AI agents that speak the MCP protocol.
 *
 * On native targets (Bun/Node.js), all operations delegate to the napi-rs
 * bridge (`mcp_server_create`, `mcp_client_connect_stdio`, etc.). On WASM
 * targets (browser), a graceful degradation is provided since subprocess
 * spawning is unavailable.
 *
 * See ADR-015 in `.docs/adrs/phase-3.md` and `crates/scp-mcp/`.
 */

import type { Context } from "./context";
import { mapBridgeError, TransportError } from "./errors";
import { BRIDGE_TARGET } from "./internal/bridge";
import { safeJsonParse } from "./internal/json-utils";
import type { McpClientConfig, McpServerConfig, ToolDefinition } from "./types";

// ---------------------------------------------------------------------------
// Native addon MCP handle types (from napi-rs)
// ---------------------------------------------------------------------------

/** Opaque server handle from the napi-rs bridge. */
interface NativeServerHandle {
  readonly handleId: string;
}

/** Opaque client handle from the napi-rs bridge. */
interface NativeClientHandle {
  readonly handleId: string;
}

/** Tool info returned by `mcp_client_list_tools`. */
interface NativeToolInfo {
  readonly name: string;
  readonly description: string;
  readonly inputSchemaJson: string;
}

/** Invoke result returned by `mcp_client_invoke`. */
interface NativeInvokeResult {
  readonly contentJson: string;
  readonly isError: boolean;
  readonly source: string;
  readonly invokedBy: string;
  readonly contextId: string;
  readonly timestamp: number;
}

// ---------------------------------------------------------------------------
// Native addon loading (lazy, MCP-specific functions)
// ---------------------------------------------------------------------------

/** Shape of the native addon's MCP-related exports. */
interface McpNativeAddon {
  mcpServerCreate(config: {
    identityDid: string;
    contextIds: string[];
    transport: string;
  }): Promise<NativeServerHandle>;
  mcpServerStop(handle: NativeServerHandle): Promise<void>;
  mcpClientConnectStdio(command: string[]): Promise<NativeClientHandle>;
  mcpClientConnectSse(url: string): Promise<NativeClientHandle>;
  mcpClientDisconnect(handle: NativeClientHandle): Promise<void>;
  mcpClientListTools(handle: NativeClientHandle): Promise<NativeToolInfo[]>;
  mcpClientInvoke(
    handle: NativeClientHandle,
    toolName: string,
    inputJson: string,
    contextId: string,
    invokerDid: string,
  ): Promise<NativeInvokeResult>;
}

let _mcpAddon: McpNativeAddon | null = null;

async function getMcpAddon(): Promise<McpNativeAddon> {
  if (_mcpAddon !== null) {
    return _mcpAddon;
  }

  if (BRIDGE_TARGET !== "native") {
    throw new TransportError(
      "MCP native bridge is only available in Bun/Node.js environments",
      "SCP-TRANS-5001",
    );
  }

  // Load the native addon using the same pattern as internal/native.ts
  const { createRequire } = await import("node:module");
  const req = createRequire(import.meta.url);

  const platform = process.platform;
  const arch = process.arch;
  const platformMap: Record<string, string> = {
    "linux-x64": "@limn-works/scp-ts-napi-linux-x64-gnu",
    "linux-arm64": "@limn-works/scp-ts-napi-linux-arm64-gnu",
    "darwin-x64": "@limn-works/scp-ts-napi-darwin-x64",
    "darwin-arm64": "@limn-works/scp-ts-napi-darwin-arm64",
    "win32-x64": "@limn-works/scp-ts-napi-win32-x64-msvc",
  };

  const key = `${platform}-${arch}`;
  const pkg = platformMap[key];
  if (pkg === undefined) {
    throw new TransportError(`No native addon for platform ${key}`, "SCP-TRANS-5001");
  }

  try {
    _mcpAddon = req(pkg) as unknown as McpNativeAddon;
  } catch {
    throw new TransportError(`Failed to load native addon ${pkg} for MCP bridge`, "SCP-TRANS-5001");
  }

  return _mcpAddon;
}

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
 * On native targets, delegates to the napi-rs `mcp_server_create` bridge
 * function which starts a real MCP server on the tokio runtime.
 *
 * @param ctx - The SCP context whose tools to expose.
 * @param config - MCP server configuration.
 * @returns A handle to the running server.
 * @throws {TransportError} If the server cannot be started.
 */
export async function serveMcp(ctx: Context, config: McpServerConfig): Promise<McpServer> {
  try {
    const host = config.host ?? "127.0.0.1";
    const port = config.port ?? 0;
    const url = `http://${host}:${port}`;

    if (BRIDGE_TARGET === "native") {
      const addon = await getMcpAddon();

      // Determine transport from port: if port is specified, use SSE;
      // otherwise default to stdio.
      const transport = port > 0 ? "sse" : "stdio";

      const nativeHandle = await addon.mcpServerCreate({
        identityDid: ctx._handle.creatorDid,
        contextIds: [ctx._handle.contextId],
        transport,
      });

      let stopped = false;

      const server: McpServer = {
        url,
        tools: config.tools,
        async stop(): Promise<void> {
          if (stopped) {
            return;
          }
          stopped = true;
          await addon.mcpServerStop(nativeHandle);
        },
        async [Symbol.asyncDispose](): Promise<void> {
          await server.stop();
        },
      };

      return server;
    }

    // WASM fallback: MCP server is not available in browser environments
    // because it requires subprocess spawning (stdio) or socket binding (SSE).
    throw new TransportError(
      "MCP server is not available in browser environments -- use a Bun/Node.js runtime",
      "SCP-TRANS-5002",
    );
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
  invokeTool(
    toolName: string,
    input: Readonly<Record<string, unknown>>,
    contextId?: string,
    invokerDid?: string,
  ): Promise<unknown>;
  /** Disconnects from the MCP server. */
  disconnect(): Promise<void>;
}

/**
 * Connects to an MCP server.
 *
 * Establishes a JSON-RPC connection to the specified MCP server URL and
 * returns a client handle for tool listing and invocation.
 *
 * On native targets, delegates to the napi-rs `mcp_client_connect_sse`
 * bridge function for URL-based connections.
 *
 * @param config - MCP client configuration.
 * @returns An MCP client handle.
 * @throws {TransportError} If the connection fails.
 */
export async function connectMcp(config: McpClientConfig): Promise<McpClient> {
  try {
    if (BRIDGE_TARGET === "native") {
      const addon = await getMcpAddon();

      const nativeHandle = await addon.mcpClientConnectSse(config.serverUrl);
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
          const tools = await addon.mcpClientListTools(nativeHandle);
          return tools.map((t: NativeToolInfo) => ({
            name: t.name,
            description: t.description || "",
            inputSchema: safeJsonParse(t.inputSchemaJson || "{}", "mcpClientListTools") as Readonly<
              Record<string, unknown>
            >,
            outputSchema: {} as Readonly<Record<string, unknown>>,
            operator: "",
          }));
        },
        async invokeTool(
          toolName: string,
          input: Readonly<Record<string, unknown>>,
          contextId?: string,
          invokerDid?: string,
        ): Promise<unknown> {
          if (disconnected) {
            throw new TransportError(
              "MCP client is disconnected -- call connectMcp() to reconnect",
              "SCP-TRANS-5010",
            );
          }
          const result = await addon.mcpClientInvoke(
            nativeHandle,
            toolName,
            JSON.stringify(input),
            contextId ?? "",
            invokerDid ?? "",
          );
          return {
            content: safeJsonParse(result.contentJson, "mcpClientInvoke"),
            isError: result.isError,
            source: result.source,
            invokedBy: result.invokedBy,
            contextId: result.contextId,
            timestamp: result.timestamp,
          };
        },
        async disconnect(): Promise<void> {
          if (disconnected) {
            return;
          }
          disconnected = true;
          await addon.mcpClientDisconnect(nativeHandle);
        },
        async [Symbol.asyncDispose](): Promise<void> {
          await client.disconnect();
        },
      };

      return client;
    }

    // WASM fallback: MCP client is not available in browser environments
    // because it requires subprocess spawning or HTTP connections to local
    // MCP servers.
    throw new TransportError(
      "MCP client is not available in browser environments -- use a Bun/Node.js runtime",
      "SCP-TRANS-5003",
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Connects to an MCP server via stdio transport.
 *
 * Spawns the given command as a subprocess and communicates via
 * line-delimited JSON-RPC over stdin/stdout.
 *
 * Only available on native targets (Bun/Node.js).
 *
 * @param command - The command to execute (e.g., `"uvx"`).
 * @param args - Arguments to pass to the command.
 * @returns An MCP client handle.
 * @throws {TransportError} If the subprocess fails to start or handshake fails.
 */
export async function connectMcpStdio(
  command: string,
  args: readonly string[] = [],
): Promise<McpClient> {
  try {
    if (BRIDGE_TARGET !== "native") {
      throw new TransportError(
        "MCP stdio client is not available in browser environments",
        "SCP-TRANS-5004",
      );
    }

    const addon = await getMcpAddon();
    const nativeHandle = await addon.mcpClientConnectStdio([command, ...args]);
    let disconnected = false;

    const client: McpClient = {
      serverUrl: `stdio://${command}`,
      async listTools(): Promise<readonly ToolDefinition[]> {
        if (disconnected) {
          throw new TransportError(
            "MCP client is disconnected -- call connectMcpStdio() to reconnect",
            "SCP-TRANS-5010",
          );
        }
        const tools = await addon.mcpClientListTools(nativeHandle);
        return tools.map((t: NativeToolInfo) => ({
          name: t.name,
          description: t.description || "",
          inputSchema: safeJsonParse(t.inputSchemaJson || "{}", "mcpClientListTools") as Readonly<
            Record<string, unknown>
          >,
          outputSchema: {} as Readonly<Record<string, unknown>>,
          operator: "",
        }));
      },
      async invokeTool(
        toolName: string,
        input: Readonly<Record<string, unknown>>,
        contextId?: string,
        invokerDid?: string,
      ): Promise<unknown> {
        if (disconnected) {
          throw new TransportError(
            "MCP client is disconnected -- call connectMcpStdio() to reconnect",
            "SCP-TRANS-5010",
          );
        }
        const result = await addon.mcpClientInvoke(
          nativeHandle,
          toolName,
          JSON.stringify(input),
          contextId ?? "",
          invokerDid ?? "",
        );
        return {
          content: safeJsonParse(result.contentJson, "mcpClientInvoke"),
          isError: result.isError,
          source: result.source,
          invokedBy: result.invokedBy,
          contextId: result.contextId,
          timestamp: result.timestamp,
        };
      },
      async disconnect(): Promise<void> {
        if (disconnected) {
          return;
        }
        disconnected = true;
        await addon.mcpClientDisconnect(nativeHandle);
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
