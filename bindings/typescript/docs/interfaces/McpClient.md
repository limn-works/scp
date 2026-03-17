[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / McpClient

# Interface: McpClient

Defined in: [src/mcp.ts:204](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L204)

Handle to an MCP client connection.

## Extends

- `AsyncDisposable`

## Properties

### serverUrl

> `readonly` **serverUrl**: `string`

Defined in: [src/mcp.ts:206](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L206)

The server URL this client is connected to.

## Methods

### \[asyncDispose\]()

> **\[asyncDispose\]**(): `PromiseLike`\<`void`\>

Defined in: node\_modules/typescript/lib/lib.esnext.disposable.d.ts:40

#### Returns

`PromiseLike`\<`void`\>

#### Inherited from

`AsyncDisposable.[asyncDispose]`

***

### disconnect()

> **disconnect**(): `Promise`\<`void`\>

Defined in: [src/mcp.ts:217](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L217)

Disconnects from the MCP server.

#### Returns

`Promise`\<`void`\>

***

### invokeTool()

> **invokeTool**(`toolName`, `input`, `contextId?`, `invokerDid?`): `Promise`\<`unknown`\>

Defined in: [src/mcp.ts:210](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L210)

Invokes a tool on the MCP server.

#### Parameters

##### toolName

`string`

##### input

`Readonly`\<`Record`\<`string`, `unknown`\>\>

##### contextId?

`string`

##### invokerDid?

`string`

#### Returns

`Promise`\<`unknown`\>

***

### listTools()

> **listTools**(): `Promise`\<readonly [`ToolDefinition`](ToolDefinition.md)[]\>

Defined in: [src/mcp.ts:208](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L208)

Lists available tools on the MCP server.

#### Returns

`Promise`\<readonly [`ToolDefinition`](ToolDefinition.md)[]\>
