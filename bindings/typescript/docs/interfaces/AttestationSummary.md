[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / AttestationSummary

# Interface: AttestationSummary

Defined in: [src/types.ts:459](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L459)

Summary of an attestation.

## Properties

### issuer

> `readonly` **issuer**: `string`

Defined in: [src/types.ts:463](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L463)

Issuer DID.

***

### revoked

> `readonly` **revoked**: `boolean`

Defined in: [src/types.ts:467](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L467)

Whether the attestation has been revoked.

***

### type

> `readonly` **type**: `string`

Defined in: [src/types.ts:461](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L461)

Attestation type.

***

### valid

> `readonly` **valid**: `boolean`

Defined in: [src/types.ts:465](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L465)

Whether the attestation is currently valid.
