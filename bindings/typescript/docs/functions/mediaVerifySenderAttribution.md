[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaVerifySenderAttribution

# Function: mediaVerifySenderAttribution()

> **mediaVerifySenderAttribution**(`signalingJson`, `envelopeSenderDid`): `Promise`\<`boolean`\>

Defined in: [src/media.ts:356](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L356)

Verifies that the sender DID in a signaling message matches the envelope sender.

## Parameters

### signalingJson

`string`

JSON string representing a signaling message.

### envelopeSenderDid

`string`

The DID from the authenticated SCP envelope.

## Returns

`Promise`\<`boolean`\>

`true` if the sender attribution is valid.

## Throws

If the JSON is invalid.

## Throws

If the sender DID does not match.
