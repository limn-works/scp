[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mintUcan

# Function: mintUcan()

> **mintUcan**(`ctx`, `memberDid`, `capabilities`): `Promise`\<[`UcanToken`](../interfaces/UcanToken.md)\>

Defined in: [src/ucan.ts:53](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/ucan.ts#L53)

Mints a new UCAN token for a context member.

Creates a UCAN token granting the specified capabilities to the member.
The token is signed by the context admin's key and scoped to this context.

## Parameters

### ctx

[`Context`](../classes/Context.md)

The context to mint the token for.

### memberDid

`string`

The DID of the member receiving the token.

### capabilities

readonly `string`[]

Capability URIs to grant.

## Returns

`Promise`\<[`UcanToken`](../interfaces/UcanToken.md)\>

The minted UCAN token with metadata.

## Throws

If minting fails.
