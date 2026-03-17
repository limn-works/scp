[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaSendSignaling

# Function: mediaSendSignaling()

> **mediaSendSignaling**(`signalingJson`): `Promise`\<[`SendSignalingResult`](../interfaces/SendSignalingResult.md)\>

Defined in: [src/media.ts:333](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L333)

Serializes a signaling message for transport.

## Parameters

### signalingJson

`string`

JSON string representing a signaling message.

## Returns

`Promise`\<[`SendSignalingResult`](../interfaces/SendSignalingResult.md)\>

A SendSignalingResult with payload (base64) and messageType.

## Throws

If the JSON is not a valid signaling message.
