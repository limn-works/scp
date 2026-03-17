[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / discoverContexts

# Function: discoverContexts()

> **discoverContexts**(`query`): `Promise`\<[`DiscoveryResult`](../interfaces/DiscoveryResult.md)[]\>

Defined in: [src/discovery.ts:210](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L210)

Discovers contexts from a DID string or `scp://` URI.

## Parameters

### query

`string`

A DID string or `scp://` URI.

## Returns

`Promise`\<[`DiscoveryResult`](../interfaces/DiscoveryResult.md)[]\>

Parsed discovery results including trust level and resolution path.

## Throws

If discovery fails.

## Throws

If the query is neither a DID nor an `scp://` URI.
