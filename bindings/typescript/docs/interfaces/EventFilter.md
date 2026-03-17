[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / EventFilter

# Interface: EventFilter

Defined in: [src/types.ts:405](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L405)

Filter parameters for event log queries.

## Properties

### actorDid?

> `readonly` `optional` **actorDid**: `string`

Defined in: [src/types.ts:409](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L409)

Filter by actor DID.

***

### afterSequence?

> `readonly` `optional` **afterSequence**: `number`

Defined in: [src/types.ts:411](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L411)

Return events with sequence greater than this value.

***

### beforeSequence?

> `readonly` `optional` **beforeSequence**: `number`

Defined in: [src/types.ts:413](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L413)

Return events with sequence less than this value.

***

### eventType?

> `readonly` `optional` **eventType**: `string`

Defined in: [src/types.ts:407](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L407)

Filter by event type.

***

### limit?

> `readonly` `optional` **limit**: `number`

Defined in: [src/types.ts:415](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L415)

Maximum number of events to return.
