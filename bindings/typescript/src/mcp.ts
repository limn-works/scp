/**
 * MCP (Model Context Protocol) handle types for the SCP TypeScript SDK.
 *
 * After Phase 4 PR 4 (#1549, ADR-048) Agent B1, {@link McpServer} and
 * {@link McpClient} are pure handle types that wrap the raw NAPI object.
 * All MCP operations live on the {@link SCP} class
 * (`scp.mcpServerCreate`, `scp.mcpServerStop`,
 * `scp.mcpClientConnectStdio`, `scp.mcpClientConnectSse`,
 * `scp.mcpClientDisconnect`, `scp.mcpClientListTools`,
 * `scp.mcpClientInvoke`): the create and connect methods return these
 * objects, and every other method takes them back.
 *
 * See ADR-015 in `.docs/adrs/phase-3.md` and `crates/scp-mcp/`.
 */

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

/**
 * Pure handle to a running MCP server, returned by
 * {@link SCP.mcpServerCreate}. Stop the server with
 * `scp.mcpServerStop(server)`.
 */
export class McpServer {
  /** The raw napi-rs MCP server handle; private, so it also brands real instances. */
  readonly #rawHandle: unknown;

  private constructor(rawHandle: unknown) {
    this.#rawHandle = rawHandle;
  }

  /** @internal Raw napi-rs MCP server handle — not part of the public API. */
  get _rawHandle(): unknown {
    return this.#rawHandle;
  }

  /** @internal Wraps the raw handle `scp.mcpServerCreate` receives from the bridge. */
  static _fromHandle(raw: unknown): McpServer {
    return new McpServer(raw);
  }

  /**
   * Reports whether `value` is an `McpServer` this SDK constructed.
   *
   * @internal Used by the `SCP` methods to reject a wrong argument with
   *   `SCP-VALID-7005` before any bridge call.
   */
  static _isMcpServer(value: unknown): value is McpServer {
    return typeof value === "object" && value !== null && #rawHandle in value;
  }
}

// ---------------------------------------------------------------------------
// MCP Client
// ---------------------------------------------------------------------------

/**
 * Pure handle to an MCP client connection, returned by
 * {@link SCP.mcpClientConnectStdio} or {@link SCP.mcpClientConnectSse}.
 * Disconnect with `scp.mcpClientDisconnect(client)`; list and invoke tools
 * with `scp.mcpClientListTools(client)` and `scp.mcpClientInvoke(client, ...)`.
 */
export class McpClient {
  /** The raw napi-rs MCP client handle; private, so it also brands real instances. */
  readonly #rawHandle: unknown;

  private constructor(rawHandle: unknown) {
    this.#rawHandle = rawHandle;
  }

  /** @internal Raw napi-rs MCP client handle — not part of the public API. */
  get _rawHandle(): unknown {
    return this.#rawHandle;
  }

  /** @internal Wraps the raw handle an `scp.mcpClientConnect*` call receives from the bridge. */
  static _fromHandle(raw: unknown): McpClient {
    return new McpClient(raw);
  }

  /**
   * Reports whether `value` is an `McpClient` this SDK constructed.
   *
   * @internal Used by the `SCP` methods to reject a wrong argument with
   *   `SCP-VALID-7005` before any bridge call.
   */
  static _isMcpClient(value: unknown): value is McpClient {
    return typeof value === "object" && value !== null && #rawHandle in value;
  }
}
