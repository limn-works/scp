[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Message

# Interface: Message

Defined in: [src/types.ts:151](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L151)

A message received from an SCP context.

## Properties

### content

> `readonly` **content**: `string` \| `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [src/types.ts:155](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L155)

Message content (decoded from the transport payload).

***

### contextId

> `readonly` **contextId**: `string`

Defined in: [src/types.ts:161](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L161)

Context ID this message belongs to.

***

### provenance?

> `readonly` `optional` **provenance**: [`Provenance`](Provenance.md)

Defined in: [src/types.ts:163](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L163)

Optional provenance metadata.

***

### senderDid

> `readonly` **senderDid**: `string`

Defined in: [src/types.ts:153](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L153)

DID of the message sender.

***

### sequence

> `readonly` **sequence**: `number`

Defined in: [src/types.ts:159](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L159)

Monotonic sequence number within the context event log.

***

### timestamp

> `readonly` **timestamp**: `number`

Defined in: [src/types.ts:157](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L157)

Unix timestamp (seconds since epoch) when the message was created.
