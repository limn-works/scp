[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / revokeUcan

# Function: revokeUcan()

> **revokeUcan**(`ctx`, `token`, `revokerDid`): `Promise`\<`void`\>

Defined in: [src/ucan.ts:79](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/ucan.ts#L79)

Revokes a UCAN token using the full revocation pipeline.

Performs authorization (revoker must be the token's issuer or the context
creator), adds the token to the context's revocation list, and appends a
TokenRevoked event to the context's Merkle event log.

## Parameters

### ctx

[`Context`](../classes/Context.md)

The context the token belongs to.

### token

`string`

The full encoded JWT string of the token to revoke.

### revokerDid

`string`

The DID of the entity requesting the revocation.
  Must be the token's issuer or the context creator.

## Returns

`Promise`\<`void`\>

## Throws

If revocation fails (unauthorized, malformed, etc.).
