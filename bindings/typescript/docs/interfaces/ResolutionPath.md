[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ResolutionPath

# Interface: ResolutionPath

Defined in: [src/types.ts:612](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L612)

Structured metadata recording which layer resolved an address.

This is provenance for the resolution itself: which layer, what source,
and when.

See §22.7 Resolution Path.

## Properties

### layer

> `readonly` **layer**: [`ResolutionLayer`](../type-aliases/ResolutionLayer.md)

Defined in: [src/types.ts:614](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L614)

The resolution layer that produced this result.

***

### resolvedAt

> `readonly` **resolvedAt**: `number`

Defined in: [src/types.ts:620](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L620)

Unix timestamp (seconds) when resolution occurred.

***

### source

> `readonly` **source**: `string`

Defined in: [src/types.ts:616](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L616)

Human-readable source identifier (discovery context name, domain, platform).

***

### sourceId

> `readonly` **sourceId**: `string` \| `null`

Defined in: [src/types.ts:618](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L618)

Discovery context ID (hex), present only for the `DiscoveryContext` layer.
