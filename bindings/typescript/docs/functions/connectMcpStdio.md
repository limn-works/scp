[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / connectMcpStdio

# Function: connectMcpStdio()

> **connectMcpStdio**(`command`, `args?`): `Promise`\<[`McpClient`](../interfaces/McpClient.md)\>

Defined in: [src/mcp.ts:329](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L329)

Connects to an MCP server via stdio transport.

Spawns the given command as a subprocess and communicates via
line-delimited JSON-RPC over stdin/stdout.

Only available on native targets (Bun/Node.js).

## Parameters

### command

`string`

The command to execute (e.g., `"uvx"`).

### args?

readonly `string`[] = `[]`

Arguments to pass to the command.

## Returns

`Promise`\<[`McpClient`](../interfaces/McpClient.md)\>

An MCP client handle.

## Throws

If the subprocess fails to start or handshake fails.
