[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / AssetEntry

# Interface: AssetEntry

Defined in: [src/types.ts:72](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L72)

An asset to publish to a broadcast context (SCP-290, spec section 18.11.8).

Typed interface to prevent positional transposition of path/contentType/body.

## Properties

### body

> `readonly` **body**: `Uint8Array`

Defined in: [src/types.ts:78](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L78)

Raw content bytes.

***

### contentType

> `readonly` **contentType**: `string`

Defined in: [src/types.ts:76](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L76)

Validated MIME type (e.g., `text/html`, `text/css`).

***

### path

> `readonly` **path**: `string`

Defined in: [src/types.ts:74](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L74)

Validated URL path (e.g., `/index.html`, `/styles.css`).
