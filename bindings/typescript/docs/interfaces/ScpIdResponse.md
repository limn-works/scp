[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ScpIdResponse

# Interface: ScpIdResponse

Defined in: [src/auth.ts:35](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L35)

SCPID response signed by the client (section 3.11.3).

## Properties

### audience

> `readonly` **audience**: `string`

Defined in: [src/auth.ts:45](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L45)

Echo of the challenge audience URI.

***

### did

> `readonly` **did**: `string`

Defined in: [src/auth.ts:39](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L39)

The signer's DID (e.g. `"did:dht:z6Mk..."`).

***

### nonce

> `readonly` **nonce**: `string`

Defined in: [src/auth.ts:43](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L43)

Echo of the challenge nonce (hex-encoded string).

***

### protocol

> `readonly` **protocol**: `string`

Defined in: [src/auth.ts:37](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L37)

Protocol identifier and version: `"scpid/1.0"`.

***

### signature

> `readonly` **signature**: `string`

Defined in: [src/auth.ts:49](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L49)

Ed25519 signature (hex-encoded string).

***

### signed\_at

> `readonly` **signed\_at**: `number`

Defined in: [src/auth.ts:47](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L47)

Unix timestamp (milliseconds) when the client signed.

***

### signing\_key\_id

> `readonly` **signing\_key\_id**: `string`

Defined in: [src/auth.ts:41](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L41)

Which verification method signed: `"#active"` or `"#agent"`.
