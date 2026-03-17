[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaInitiateSession

# Function: mediaInitiateSession()

> **mediaInitiateSession**(`contextId`, `ceiling`, `capabilities`, `participants`, `timestamp`): `Promise`\<[`MediaSession`](../interfaces/MediaSession.md)\>

Defined in: [src/media.ts:121](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L121)

Initiates a media session after validating capabilities against the ceiling.

## Parameters

### contextId

`string`

The context hosting this media session.

### ceiling

`string`[]

The context's capability ceiling as capability name strings.

### capabilities

`string`[]

Media capabilities to activate (e.g., `["voice", "video"]`).

### participants

`string`[]

Initial participant DIDs.

### timestamp

`number`

Unix timestamp (seconds) for session creation.

## Returns

`Promise`\<[`MediaSession`](../interfaces/MediaSession.md)\>

A MediaSession object.

## Throws

If any capability string is invalid.

## Throws

If capabilities/participants are empty or capability missing from ceiling.
