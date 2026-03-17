[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaActivateSession

# Function: mediaActivateSession()

> **mediaActivateSession**(`sessionJson`): `Promise`\<[`MediaSession`](../interfaces/MediaSession.md)\>

Defined in: [src/media.ts:151](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L151)

Activates a media session (transitions from Initiating to Active).

## Parameters

### sessionJson

`string`

JSON string representing the session.

## Returns

`Promise`\<[`MediaSession`](../interfaces/MediaSession.md)\>

Updated MediaSession.

## Throws

If the session is not in the Initiating state.
