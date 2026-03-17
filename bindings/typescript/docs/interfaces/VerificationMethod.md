[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / VerificationMethod

# Interface: VerificationMethod

Defined in: [src/types.ts:207](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L207)

A verification method from a DID Document.

## Properties

### controller

> `readonly` **controller**: `string`

Defined in: [src/types.ts:213](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L213)

Controller DID.

***

### id

> `readonly` **id**: `string`

Defined in: [src/types.ts:209](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L209)

Verification method ID.

***

### publicKeyMultibase

> `readonly` **publicKeyMultibase**: `string`

Defined in: [src/types.ts:215](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L215)

Public key in multibase encoding.

***

### type

> `readonly` **type**: `string`

Defined in: [src/types.ts:211](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L211)

Verification method type (e.g., `"Ed25519VerificationKey2020"`).
