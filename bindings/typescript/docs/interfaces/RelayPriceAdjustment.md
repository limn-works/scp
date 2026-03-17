[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / RelayPriceAdjustment

# Interface: RelayPriceAdjustment

Defined in: [src/economy.ts:19](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L19)

Result of an EIP-1559-style relay price adjustment.

## Properties

### direction

> `readonly` **direction**: `"Increased"` \| `"Decreased"` \| `"Unchanged"`

Defined in: [src/economy.ts:25](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L25)

Direction: "Increased", "Decreased", or "Unchanged".

***

### newBasePrice

> `readonly` **newBasePrice**: `number`

Defined in: [src/economy.ts:21](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L21)

New base price (smallest currency unit).

***

### previousBasePrice

> `readonly` **previousBasePrice**: `number`

Defined in: [src/economy.ts:23](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L23)

Previous base price before adjustment.
