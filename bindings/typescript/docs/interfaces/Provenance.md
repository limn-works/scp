[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Provenance

# Interface: Provenance

Defined in: [src/types.ts:171](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L171)

Provenance metadata for a message or data artifact.

## Properties

### chainDepth

> `readonly` **chainDepth**: `number`

Defined in: [src/types.ts:179](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L179)

Chain depth — how many cross-context hops this data has traversed.

***

### signature

> `readonly` **signature**: `Uint8Array`

Defined in: [src/types.ts:177](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L177)

Cryptographic signature over the provenance chain.

***

### sourceContextId

> `readonly` **sourceContextId**: `string`

Defined in: [src/types.ts:175](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L175)

Context ID where the data originated.

***

### sourceDid

> `readonly` **sourceDid**: `string`

Defined in: [src/types.ts:173](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L173)

DID of the original data source.
