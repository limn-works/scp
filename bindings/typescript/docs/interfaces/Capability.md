[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Capability

# Interface: Capability

Defined in: [src/types.ts:223](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L223)

A UCAN capability definition.

## Properties

### action

> `readonly` **action**: `string`

Defined in: [src/types.ts:227](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L227)

The action allowed on the resource (e.g., `"read"`, `"write"`).

***

### resource

> `readonly` **resource**: `string`

Defined in: [src/types.ts:225](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L225)

The resource URI the capability grants access to.
