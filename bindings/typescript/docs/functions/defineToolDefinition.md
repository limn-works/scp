[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / defineToolDefinition

# Function: defineToolDefinition()

> **defineToolDefinition**(`params`): [`ToolDefinition`](../interfaces/ToolDefinition.md)

Defined in: [src/tools.ts:43](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/tools.ts#L43)

Creates a validated `ToolDefinition` object.

Validates required fields and returns an immutable tool definition suitable
for registration via `Context.registerTool()`.

## Parameters

### params

Tool definition parameters.

#### cost?

[`ToolCost`](../interfaces/ToolCost.md)

#### description

`string`

#### implementationHash?

`Uint8Array`\<`ArrayBufferLike`\>

#### inputSchema

`Readonly`\<`Record`\<`string`, `unknown`\>\>

#### name

`string`

#### operator

`string`

#### outputSchema

`Readonly`\<`Record`\<`string`, `unknown`\>\>

#### testVectors?

readonly [`TestVector`](../interfaces/TestVector.md)[]

## Returns

[`ToolDefinition`](../interfaces/ToolDefinition.md)

A validated `ToolDefinition`.

## Throws

If required fields are missing or invalid.
