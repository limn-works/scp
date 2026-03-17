[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / provenanceCheckChainDepth

# Function: provenanceCheckChainDepth()

> **provenanceCheckChainDepth**(`chainDepth`, `maxDepth?`): `Promise`\<`boolean`\>

Defined in: [src/provenance.ts:157](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L157)

Checks whether a provenance chain depth is within the allowed limit.

## Parameters

### chainDepth

`number`

The chain depth to check.

### maxDepth?

`number`

Optional custom max depth (default: 3).

## Returns

`Promise`\<`boolean`\>

`true` if within limit, `false` otherwise.
