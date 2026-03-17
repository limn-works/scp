[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / validateUcan

# Function: validateUcan()

> **validateUcan**(`ctx`, `token`, `capability`): `Promise`\<`void`\>

Defined in: [src/ucan.ts:32](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/ucan.ts#L32)

Validates a UCAN token for a required capability within a context.

Performs full validation: signature verification, time bounds checking,
delegation chain traversal, attenuation enforcement, nonce replay
detection, and capability matching.

## Parameters

### ctx

[`Context`](../classes/Context.md)

The context the token is presented in.

### token

`string`

The encoded UCAN token string (JWT format).

### capability

`string`

The required capability URI.

## Returns

`Promise`\<`void`\>

## Throws

If validation fails.
