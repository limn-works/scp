[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / BatchPublishResult

# Interface: BatchPublishResult

Defined in: [src/types.ts:100](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L100)

Result of publishing multiple assets to a broadcast context (SCP-292).

Returned by `broadcastPublishAssets`.

## Properties

### deployId

> `readonly` **deployId**: `string`

Defined in: [src/types.ts:104](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L104)

The shared deploy ID for this batch.

***

### results

> `readonly` **results**: [`PublishResult`](PublishResult.md)[]

Defined in: [src/types.ts:102](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L102)

Per-asset publish results.
