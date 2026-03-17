[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ToolDefinition

# Interface: ToolDefinition

Defined in: [src/types.ts:235](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L235)

Definition of a tool that can be registered in a context.

## Properties

### cost?

> `readonly` `optional` **cost**: [`ToolCost`](ToolCost.md)

Defined in: [src/types.ts:251](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L251)

Optional per-invocation cost metadata (spec section 5.4.1).

***

### description

> `readonly` **description**: `string`

Defined in: [src/types.ts:239](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L239)

Tool description.

***

### implementationHash?

> `readonly` `optional` **implementationHash**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [src/types.ts:249](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L249)

SHA-256 hash of the implementation binary.

***

### inputSchema

> `readonly` **inputSchema**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/types.ts:241](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L241)

JSON Schema for tool input.

***

### name

> `readonly` **name**: `string`

Defined in: [src/types.ts:237](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L237)

Human-readable tool name.

***

### operator

> `readonly` **operator**: `string`

Defined in: [src/types.ts:245](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L245)

DID of the tool operator (responsible party) or Identity reference.

***

### outputSchema

> `readonly` **outputSchema**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/types.ts:243](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L243)

JSON Schema for tool output.

***

### testVectors?

> `readonly` `optional` **testVectors**: readonly [`TestVector`](TestVector.md)[]

Defined in: [src/types.ts:247](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L247)

Test vectors for integrity verification.
