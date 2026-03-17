[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ToolCost

# Interface: ToolCost

Defined in: [src/types.ts:255](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L255)

Per-invocation cost metadata for a tool (spec section 5.4.1).

## Properties

### amount

> `readonly` **amount**: `number`

Defined in: [src/types.ts:257](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L257)

Cost per invocation in the smallest currency unit.

***

### costFormula?

> `readonly` `optional` **costFormula**: `string`

Defined in: [src/types.ts:263](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L263)

Optional pricing formula identifier for dynamic pricing (spec section 19.4).

***

### currency

> `readonly` **currency**: `string`

Defined in: [src/types.ts:259](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L259)

ISO 4217 or protocol-defined currency code.

***

### payee

> `readonly` **payee**: `string`

Defined in: [src/types.ts:261](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L261)

DID of the payment recipient. May differ from the tool operator.
