[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaJoinSession

# Function: mediaJoinSession()

> **mediaJoinSession**(`sessionJson`, `participantDid`): `Promise`\<[`MediaSession`](../interfaces/MediaSession.md)\>

Defined in: [src/media.ts:170](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L170)

Adds a participant to a media session.

## Parameters

### sessionJson

`string`

JSON string representing the session.

### participantDid

`string`

DID of the participant to add.

## Returns

`Promise`\<[`MediaSession`](../interfaces/MediaSession.md)\>

Updated MediaSession.

## Throws

If the session has ended.
