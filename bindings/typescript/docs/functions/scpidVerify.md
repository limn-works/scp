[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / scpidVerify

# Function: scpidVerify()

> **scpidVerify**(`response`, `challenge`): `Promise`\<[`ScpIdAuthentication`](../interfaces/ScpIdAuthentication.md)\>

Defined in: [src/auth.ts:134](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/auth.ts#L134)

Verify a signed SCPID response against the original challenge (section 3.11.4).

Resolves the signer's DID document via the global DID resolver
(initialized during identity creation), then runs the 11-step
verification pipeline.

**Not available in the WASM bridge.** SCPID verification requires DID
document resolution which depends on network access and a full DID
resolver. Use the native (napi-rs) bridge instead.

## Parameters

### response

[`ScpIdResponse`](../interfaces/ScpIdResponse.md)

The signed response from the client.

### challenge

[`ScpIdChallenge`](../interfaces/ScpIdChallenge.md)

The original challenge issued by the relying party.

## Returns

`Promise`\<[`ScpIdAuthentication`](../interfaces/ScpIdAuthentication.md)\>

An `ScpIdAuthentication` on success.

## Throws

If the DID resolver is not initialized, DID
  resolution fails, the signature is invalid, the challenge has expired,
  or any other verification step fails. Also thrown in WASM mode.

## Throws

If either JSON structure is malformed.
