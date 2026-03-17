[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / McpServerConfig

# Interface: McpServerConfig

Defined in: [src/types.ts:663](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L663)

Configuration for an MCP server.

## Properties

### host?

> `readonly` `optional` **host**: `string`

Defined in: [src/types.ts:669](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L669)

Host to bind to.

***

### port?

> `readonly` `optional` **port**: `number`

Defined in: [src/types.ts:667](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L667)

Port to listen on.

***

### tools

> `readonly` **tools**: readonly [`ToolDefinition`](ToolDefinition.md)[]

Defined in: [src/types.ts:665](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L665)

Tools to expose via MCP.
