[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / TransportStatus

# Interface: TransportStatus

Defined in: [src/types.ts:351](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L351)

Transport connection status.

## Properties

### connected

> `readonly` **connected**: `boolean`

Defined in: [src/types.ts:353](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L353)

`true` if the transport is currently connected to a relay.

***

### latencyMs

> `readonly` **latencyMs**: `number` \| `null`

Defined in: [src/types.ts:357](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L357)

Round-trip latency in milliseconds. `null` if not measured.

***

### relayUrl

> `readonly` **relayUrl**: `string` \| `null`

Defined in: [src/types.ts:355](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L355)

The relay URL if connected. `null` if disconnected.
