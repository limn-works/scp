[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / templateGetParams

# Function: templateGetParams()

> **templateGetParams**(`templateId`): [`ContextParams`](../interfaces/ContextParams.md)

Defined in: [src/context.ts:1550](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1550)

Gets the canonical ContextParams for a well-known template (spec §5.12.1).

## Parameters

### templateId

`string`

One of: `BilateralEphemeral`, `BilateralPersistent`,
  `Coordination`, `GroupDiscussion`, `PublicBroadcast`, `GatedBroadcast`,
  `scp:template/tool-interface`, `PaidService`, `PaidBroadcast`,
  `DiscoveryContext`.

## Returns

[`ContextParams`](../interfaces/ContextParams.md)

ContextParams object.
