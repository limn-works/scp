[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / scpidSign

# Function: scpidSign()

> **scpidSign**(`identity`, `signingKeyId`, `challenge`): `Promise`\<[`ScpIdResponse`](../interfaces/ScpIdResponse.md)\>

Defined in: [src/auth.ts:101](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L101)

Sign an SCPID challenge with a registered identity's key (section 3.11.3).

Looks up the identity by DID in the global registry, selects the
appropriate signing key, and produces a signed SCPID response.

## Parameters

### identity

[`Identity`](../classes/Identity.md)

An `Identity` instance whose DID is registered.

### signingKeyId

`string`

`"#active"` or `"#agent"`.

### challenge

[`ScpIdChallenge`](../interfaces/ScpIdChallenge.md)

The challenge to sign.

## Returns

`Promise`\<[`ScpIdResponse`](../interfaces/ScpIdResponse.md)\>

A new `ScpIdResponse`.

## Throws

If the DID is not registered or signing fails.

## Throws

If `signingKeyId` is invalid or the challenge
  is malformed.
