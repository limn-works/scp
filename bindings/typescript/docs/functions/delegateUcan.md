[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / delegateUcan

# Function: delegateUcan()

> **delegateUcan**(`ctx`, `originalToken`, `delegatorDid`, `targetDid`, `capabilities`): `Promise`\<[`UcanToken`](../interfaces/UcanToken.md)\>

Defined in: [src/ucan.ts:108](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/ucan.ts#L108)

Delegates a UCAN token to another member.

Creates a new UCAN token that delegates a subset of the original token's
capabilities to another member. The delegator must be the audience of the
original token (iss/aud chain linkage). Attenuation rules ensure the
delegated token cannot exceed the original's scope.

Delegates to the real `bridge.ucanDelegate()` which performs Ed25519
signing via the delegator's retained `KeyCustody` and enforces
attenuation, iss/aud chain validation, and ceiling compliance.

## Parameters

### ctx

[`Context`](../classes/Context.md)

The context to delegate within.

### originalToken

[`UcanToken`](../interfaces/UcanToken.md)

The original token to delegate from (must include `encoded` JWT).

### delegatorDid

`string`

The DID of the entity delegating (must match originalToken.audience).

### targetDid

`string`

The DID of the delegation target.

### capabilities

readonly `string`[]

Capability URIs to delegate (must be a subset of the original).

## Returns

`Promise`\<[`UcanToken`](../interfaces/UcanToken.md)\>

The delegated UCAN token.

## Throws

If delegation fails or capabilities exceed the original.
