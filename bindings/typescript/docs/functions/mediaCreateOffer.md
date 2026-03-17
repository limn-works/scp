[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaCreateOffer

# Function: mediaCreateOffer()

> **mediaCreateOffer**(`sessionId`, `sdp`, `senderDid`): `Promise`\<[`SignalingResult`](../interfaces/SignalingResult.md)\>

Defined in: [src/media.ts:221](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L221)

Creates an SDP offer signaling message.

## Parameters

### sessionId

`string`

The media session ID.

### sdp

`string`

Raw SDP payload string.

### senderDid

`string`

DID of the participant creating the offer.

## Returns

`Promise`\<[`SignalingResult`](../interfaces/SignalingResult.md)\>

A SignalingResult with session_id and message.
