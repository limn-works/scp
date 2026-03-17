[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaCreateIceCandidate

# Function: mediaCreateIceCandidate()

> **mediaCreateIceCandidate**(`sessionId`, `candidate`, `senderDid`, `options?`): `Promise`\<[`SignalingResult`](../interfaces/SignalingResult.md)\>

Defined in: [src/media.ts:274](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L274)

Creates an ICE candidate signaling message.

## Parameters

### sessionId

`string`

The media session ID.

### candidate

`string`

ICE candidate attribute string.

### senderDid

`string`

DID of the participant who gathered the candidate.

### options?

Optional SDP association fields.

#### sdpMid?

`string`

#### sdpMlineIndex?

`number`

## Returns

`Promise`\<[`SignalingResult`](../interfaces/SignalingResult.md)\>

A SignalingResult with session_id and message.
