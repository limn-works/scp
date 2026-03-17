[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ScpIdChallenge

# Interface: ScpIdChallenge

Defined in: [src/auth.ts:21](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L21)

SCPID challenge issued by a relying party (section 3.11.2).

## Properties

### audience

> `readonly` **audience**: `string`

Defined in: [src/auth.ts:27](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L27)

URI identifying the relying party.

***

### expires\_at

> `readonly` **expires\_at**: `number`

Defined in: [src/auth.ts:31](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L31)

Unix timestamp (milliseconds) when the challenge expires.

***

### issued\_at

> `readonly` **issued\_at**: `number`

Defined in: [src/auth.ts:29](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L29)

Unix timestamp (milliseconds) when the challenge was created.

***

### nonce

> `readonly` **nonce**: `string`

Defined in: [src/auth.ts:25](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L25)

32-byte CSPRNG nonce (hex-encoded string).

***

### protocol

> `readonly` **protocol**: `string`

Defined in: [src/auth.ts:23](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L23)

Protocol identifier and version: `"scpid/1.0"`.
