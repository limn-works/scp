[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / EventClaim

# Interface: EventClaim

Defined in: [src/types.ts:419](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L419)

A claim to verify against the event log.

## Properties

### eventHash?

> `readonly` `optional` **eventHash**: `string`

Defined in: [src/types.ts:425](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L425)

Event hash (hex) for absence proofs.

***

### leafIndex?

> `readonly` `optional` **leafIndex**: `number`

Defined in: [src/types.ts:423](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L423)

Leaf index for inclusion proofs.

***

### type

> `readonly` **type**: `"inclusion"` \| `"absence"`

Defined in: [src/types.ts:421](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L421)

Claim type: `"inclusion"` or `"absence"`.
