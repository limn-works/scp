[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ToolSessionInvokeResult

# Interface: ToolSessionInvokeResult

Defined in: [src/types.ts:297](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L297)

Result of invoking a tool within a stateful session, with provenance metadata (spec section 6.2.1).

## Properties

### contextId

> `readonly` **contextId**: `string`

Defined in: [src/types.ts:303](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L303)

The context ID in which the tool was invoked.

***

### invokerDid

> `readonly` **invokerDid**: `string`

Defined in: [src/types.ts:305](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L305)

The DID of the invoker.

***

### output

> `readonly` **output**: `string`

Defined in: [src/types.ts:299](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L299)

The serialized output from the tool invocation (JSON string).

***

### sessionId

> `readonly` **sessionId**: `string`

Defined in: [src/types.ts:301](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L301)

The session ID this invocation was executed within.

***

### timestamp

> `readonly` **timestamp**: `number`

Defined in: [src/types.ts:307](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L307)

Unix timestamp (milliseconds since epoch) of the invocation.
