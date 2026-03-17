[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / adjustRelayPrice

# Function: adjustRelayPrice()

> **adjustRelayPrice**(`configJson`, `utilizationPct`): `Promise`\<[`RelayPriceAdjustment`](../interfaces/RelayPriceAdjustment.md)\>

Defined in: [src/economy.ts:188](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L188)

Computes an EIP-1559-style relay price adjustment.

## Parameters

### configJson

`string`

Relay pricing config JSON string.

### utilizationPct

`number`

Current utilization percentage (0-100).

## Returns

`Promise`\<[`RelayPriceAdjustment`](../interfaces/RelayPriceAdjustment.md)\>

Price adjustment result.
