[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Checkpoint

# Interface: Checkpoint

Defined in: [src/types.ts:395](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L395)

A consistency checkpoint from the event log.

## Properties

### eventCount

> `readonly` **eventCount**: `number`

Defined in: [src/types.ts:399](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L399)

The number of events in the log at checkpoint time.

***

### root

> `readonly` **root**: `string`

Defined in: [src/types.ts:397](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L397)

The Merkle root hash as a hex string.

***

### timestamp

> `readonly` **timestamp**: `number`

Defined in: [src/types.ts:401](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L401)

Timestamp of the checkpoint (seconds since epoch).
