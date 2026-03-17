[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / CrossContextInvocationResult

# Interface: CrossContextInvocationResult

Defined in: [src/types.ts:311](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L311)

Result of a cross-context tool invocation (spec section 6.2).

## Properties

### chainDepth

> `readonly` **chainDepth**: `number`

Defined in: [src/types.ts:321](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L321)

Chain depth of the cross-context invocation.

***

### invokerDid

> `readonly` **invokerDid**: `string`

Defined in: [src/types.ts:319](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L319)

The DID of the invoker.

***

### output

> `readonly` **output**: `string`

Defined in: [src/types.ts:313](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L313)

The serialized output from the tool invocation (JSON string).

***

### sourceContextId

> `readonly` **sourceContextId**: `string`

Defined in: [src/types.ts:315](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L315)

The source context ID.

***

### targetContextId

> `readonly` **targetContextId**: `string`

Defined in: [src/types.ts:317](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L317)

The target context ID.

***

### timestamp

> `readonly` **timestamp**: `number`

Defined in: [src/types.ts:323](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L323)

Unix timestamp (milliseconds since epoch) of the invocation.
