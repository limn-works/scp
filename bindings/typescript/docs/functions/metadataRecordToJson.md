[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / metadataRecordToJson

# Function: metadataRecordToJson()

> **metadataRecordToJson**(`contextId`, `sequence`, `signerDid`, `timestamp`, `structural`, `operational`, `signatureHex`): `string`

Defined in: [src/context.ts:1504](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1504)

Serializes a MetadataRecord to a JSON string (spec §5.7.2).

## Parameters

### contextId

`string`

The context this metadata describes.

### sequence

`number`

Monotonically increasing sequence number (starts at 1).

### signerDid

`string`

DID of the admin who signed this record.

### timestamp

`number`

Unix timestamp in milliseconds.

### structural

[`StructuralMetadata`](../interfaces/StructuralMetadata.md)

Structural metadata object.

### operational

[`OperationalMetadata`](../interfaces/OperationalMetadata.md)

Operational metadata object.

### signatureHex

`string`

Ed25519 signature as hex string (128 hex chars).

## Returns

`string`

JSON string of the MetadataRecord.
