[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mediaCheckCapability

# Function: mediaCheckCapability()

> **mediaCheckCapability**(`ceiling`, `capability`): `Promise`\<`boolean`\>

Defined in: [src/media.ts:97](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L97)

Checks that a media capability is present in the context ceiling.

## Parameters

### ceiling

`string`[]

List of capability name strings from the context ceiling.

### capability

`string`

Media capability: `"voice"`, `"video"`, or `"screen_share"`.

## Returns

`Promise`\<`boolean`\>

`true` if the capability is present.

## Throws

If the capability string is invalid.

## Throws

If the capability is not in the ceiling.
