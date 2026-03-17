[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / UcanToken

# Interface: UcanToken

Defined in: [src/types.ts:331](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L331)

A UCAN token with metadata.

## Properties

### audience

> `readonly` **audience**: `string`

Defined in: [src/types.ts:339](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L339)

Audience DID.

***

### capabilities

> `readonly` **capabilities**: readonly `string`[]

Defined in: [src/types.ts:341](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L341)

Capability URIs granted by this token.

***

### encoded

> `readonly` **encoded**: `string`

Defined in: [src/types.ts:335](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L335)

The encoded JWT string.

***

### expiresAt?

> `readonly` `optional` **expiresAt**: `number`

Defined in: [src/types.ts:343](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L343)

Expiry timestamp (seconds since epoch). `undefined` means no expiry.

***

### id

> `readonly` **id**: `string`

Defined in: [src/types.ts:333](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L333)

Unique token identifier.

***

### issuer

> `readonly` **issuer**: `string`

Defined in: [src/types.ts:337](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L337)

Issuer DID.
