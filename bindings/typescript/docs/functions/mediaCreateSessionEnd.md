[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaCreateSessionEnd

# Function: mediaCreateSessionEnd()

> **mediaCreateSessionEnd**(`sessionId`, `senderDid`): `Promise`\<[`SignalingResult`](../interfaces/SignalingResult.md)\>

Defined in: [src/media.ts:309](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L309)

Creates a session-end signaling message.

## Parameters

### sessionId

`string`

The media session ID.

### senderDid

`string`

DID of the participant ending the session.

## Returns

`Promise`\<[`SignalingResult`](../interfaces/SignalingResult.md)\>

A SignalingResult with session_id and message.
