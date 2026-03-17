[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / SendSignalingResult

# Interface: SendSignalingResult

Defined in: [src/media.ts:51](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L51)

Result of preparing a signaling message for transport.

## Properties

### messageType

> `readonly` **messageType**: `string`

Defined in: [src/media.ts:55](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L55)

Message type discriminator (always `"Signaling"`).

***

### payload

> `readonly` **payload**: `string`

Defined in: [src/media.ts:53](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/media.ts#L53)

Base64-encoded payload bytes.
