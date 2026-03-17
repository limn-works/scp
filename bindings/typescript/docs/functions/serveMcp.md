[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / serveMcp

# Function: serveMcp()

> **serveMcp**(`ctx`, `config`): `Promise`\<[`McpServer`](../interfaces/McpServer.md)\>

Defined in: [src/mcp.ts:149](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L149)

Starts an MCP server that exposes context tools via JSON-RPC.

The server listens for MCP-protocol tool invocation requests and routes
them to the corresponding SCP context tool.

On native targets, delegates to the napi-rs `mcp_server_create` bridge
function which starts a real MCP server on the tokio runtime.

## Parameters

### ctx

[`Context`](../classes/Context.md)

The SCP context whose tools to expose.

### config

[`McpServerConfig`](../interfaces/McpServerConfig.md)

MCP server configuration.

## Returns

`Promise`\<[`McpServer`](../interfaces/McpServer.md)\>

A handle to the running server.

## Throws

If the server cannot be started.
