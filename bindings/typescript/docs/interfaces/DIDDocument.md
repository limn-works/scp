[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / DIDDocument

# Interface: DIDDocument

Defined in: [src/types.ts:187](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L187)

A DID Document returned by identity resolution.

## Properties

### agentPublicKey?

> `readonly` `optional` **agentPublicKey**: `string`

Defined in: [src/types.ts:203](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L203)

The agent key's public key as a multibase-encoded string, or `undefined` if no agent key exists (ADR-039).

***

### alsoKnownAs

> `readonly` **alsoKnownAs**: readonly `string`[]

Defined in: [src/types.ts:197](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L197)

Alternative DID identifiers for this subject.

***

### assertionMethods

> `readonly` **assertionMethods**: readonly `string`[]

Defined in: [src/types.ts:195](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L195)

Assertion method references.

***

### authentication

> `readonly` **authentication**: readonly `string`[]

Defined in: [src/types.ts:193](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L193)

Authentication method references.

***

### hasAgentKey

> `readonly` **hasAgentKey**: `boolean`

Defined in: [src/types.ts:201](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L201)

Whether this document contains an `#agent` verification method (ADR-039).

***

### id

> `readonly` **id**: `string`

Defined in: [src/types.ts:189](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L189)

The DID string this document describes.

***

### serviceEndpoints

> `readonly` **serviceEndpoints**: readonly `string`[]

Defined in: [src/types.ts:199](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L199)

Service endpoint entries.

***

### verificationMethods

> `readonly` **verificationMethods**: readonly [`VerificationMethod`](VerificationMethod.md)[]

Defined in: [src/types.ts:191](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L191)

Verification methods in the document.
