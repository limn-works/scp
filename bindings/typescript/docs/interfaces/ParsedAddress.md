[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ParsedAddress

# Interface: ParsedAddress

Defined in: [src/discovery.ts:21](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L21)

A parsed SCP address.

## Indexable

\[`key`: `string`\]: `unknown`

Additional fields depend on the address type.

## Properties

### type

> `readonly` **type**: `string`

Defined in: [src/discovery.ts:23](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L23)

Address type: `"DiscoveryHandle"`, `"DomainHandle"`, `"AttestationHandle"`, or `"Unscoped"` (PascalCase per §22.11.3).
