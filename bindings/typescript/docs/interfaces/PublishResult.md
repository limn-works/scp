[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / PublishResult

# Interface: PublishResult

Defined in: [src/types.ts:86](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L86)

Result of publishing an asset to a broadcast context (SCP-290).

Returned by `broadcastPublishAsset` and `broadcastPublishAssets`.

## Properties

### blobId

> `readonly` **blobId**: `string`

Defined in: [src/types.ts:88](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L88)

Hex-encoded SHA-256 of the serialized broadcast envelope.

***

### deployId

> `readonly` **deployId**: `string`

Defined in: [src/types.ts:92](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L92)

The deploy ID for this asset (auto-generated or caller-provided).

***

### etag

> `readonly` **etag**: `string`

Defined in: [src/types.ts:90](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L90)

Hex-encoded SHA-256 of the asset body.
