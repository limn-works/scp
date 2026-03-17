[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / resolveAddress

# Function: resolveAddress()

> **resolveAddress**(`query`): `Promise`\<[`AddressResolution`](../type-aliases/AddressResolution.md)[]\>

Defined in: [src/discovery.ts:237](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L237)

Resolves an SCP address (DID or `scp://` URI) to typed `AddressResolution` results.

Wraps `discoverContexts()` and returns `AddressResolution[]` with the
discriminated union structure matching §22.2.1.

Currently resolves context addresses only. Identity resolution (petnames,
attestation handles, domain handles) requires handle tool infrastructure
defined in §22.3-22.6 and will be wired when those subsystems are
available.

## Parameters

### query

`string`

A DID string or `scp://` URI.

## Returns

`Promise`\<[`AddressResolution`](../type-aliases/AddressResolution.md)[]\>

Typed address resolution results.

## Throws

If discovery fails.

## Throws

If the query is neither a DID nor an `scp://` URI.
