[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaEndSession

# Function: mediaEndSession()

> **mediaEndSession**(`sessionJson`, `timestamp`): `Promise`\<[`EndSessionResult`](../interfaces/EndSessionResult.md)\>

Defined in: [src/media.ts:192](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L192)

Ends a media session and returns metadata for event log recording.

## Parameters

### sessionJson

`string`

JSON string representing the session.

### timestamp

`number`

Unix timestamp (seconds) when the session ended.

## Returns

`Promise`\<[`EndSessionResult`](../interfaces/EndSessionResult.md)\>

An object with `session` and `metadata` fields.

## Throws

If the session has already ended or timestamp is invalid.
