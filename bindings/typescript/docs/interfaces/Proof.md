[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Proof

# Interface: Proof

Defined in: [src/types.ts:385](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L385)

A Merkle proof from the event log.

## Properties

### details

> `readonly` **details**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/types.ts:391](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L391)

Proof details (Merkle path or sorted neighbors).

***

### proofType

> `readonly` **proofType**: `"inclusion"` \| `"absence"`

Defined in: [src/types.ts:389](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L389)

Proof type: `"inclusion"` or `"absence"`.

***

### verified

> `readonly` **verified**: `boolean`

Defined in: [src/types.ts:387](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L387)

`true` if the claim was verified successfully.
