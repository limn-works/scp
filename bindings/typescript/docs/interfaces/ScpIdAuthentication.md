[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ScpIdAuthentication

# Interface: ScpIdAuthentication

Defined in: [src/auth.ts:53](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L53)

Result of a successful SCPID verification (section 3.11.4 step 11).

## Properties

### did

> `readonly` **did**: `string`

Defined in: [src/auth.ts:55](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L55)

The authenticated DID.

***

### signed\_at

> `readonly` **signed\_at**: `number`

Defined in: [src/auth.ts:59](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L59)

Unix timestamp (milliseconds) when the client signed.

***

### signing\_key\_id

> `readonly` **signing\_key\_id**: `string`

Defined in: [src/auth.ts:57](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L57)

Which verification method produced the signature.
