[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / evaluateFormula

# Function: evaluateFormula()

> **evaluateFormula**(`formulaJson`, `metrics?`): `Promise`\<`number`\>

Defined in: [src/economy.ts:157](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L157)

Evaluates a pricing formula against observable metrics.

## Parameters

### formulaJson

`string`

Pricing formula JSON string.

### metrics?

[`ObservableMetrics`](../interfaces/ObservableMetrics.md)

Observable metrics.

## Returns

`Promise`\<`number`\>

Computed cost, or -1 on overflow.
