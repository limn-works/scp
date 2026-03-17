[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / McpServer

# Interface: McpServer

Defined in: [src/mcp.ts:126](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L126)

Handle to a running MCP server.

## Extends

- `AsyncDisposable`

## Properties

### tools

> `readonly` **tools**: readonly [`ToolDefinition`](ToolDefinition.md)[]

Defined in: [src/mcp.ts:130](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L130)

The tools exposed by this server.

***

### url

> `readonly` **url**: `string`

Defined in: [src/mcp.ts:128](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L128)

The URL the server is listening on.

## Methods

### \[asyncDispose\]()

> **\[asyncDispose\]**(): `PromiseLike`\<`void`\>

Defined in: node\_modules/typescript/lib/lib.esnext.disposable.d.ts:40

#### Returns

`PromiseLike`\<`void`\>

#### Inherited from

`AsyncDisposable.[asyncDispose]`

***

### stop()

> **stop**(): `Promise`\<`void`\>

Defined in: [src/mcp.ts:132](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/mcp.ts#L132)

Stops the MCP server.

#### Returns

`Promise`\<`void`\>
