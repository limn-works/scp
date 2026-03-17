[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / addressResolve

# Function: addressResolve()

> **addressResolve**(`ownerDid`, `address`, `knownContextsJson?`): `Promise`\<[`AddressResolution`](../type-aliases/AddressResolution.md)[]\>

Defined in: [src/discovery.ts:516](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L516)

Resolves a human-readable address via multi-path resolution pipeline.

Uses the petname layer first, then handle registries, then attestation
and domain layers per §22.8.

## Parameters

### ownerDid

`string`

DID of the identity whose petname map to consult.

### address

`string`

The address string to resolve (e.g., `"alice@cooking-community"`).

### knownContextsJson?

`string`

Optional JSON object mapping context IDs to names.
  If omitted, uses all registered discovery contexts.

## Returns

`Promise`\<[`AddressResolution`](../type-aliases/AddressResolution.md)[]\>

Typed address resolution results.

## Throws

If `ownerDid` is empty or address parsing fails.
