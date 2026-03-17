[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / connectMcp

# Function: connectMcp()

> **connectMcp**(`config`): `Promise`\<[`McpClient`](../interfaces/McpClient.md)\>

Defined in: [src/mcp.ts:233](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L233)

Connects to an MCP server.

Establishes a JSON-RPC connection to the specified MCP server URL and
returns a client handle for tool listing and invocation.

On native targets, delegates to the napi-rs `mcp_client_connect_sse`
bridge function for URL-based connections.

## Parameters

### config

[`McpClientConfig`](../interfaces/McpClientConfig.md)

MCP client configuration.

## Returns

`Promise`\<[`McpClient`](../interfaces/McpClient.md)\>

An MCP client handle.

## Throws

If the connection fails.
