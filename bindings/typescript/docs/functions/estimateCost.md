[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / estimateCost

# Function: estimateCost()

> **estimateCost**(`policyJson`, `actionType`, `metrics?`): `Promise`\<`number`\>

Defined in: [src/economy.ts:64](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L64)

Estimates the cost for an action in a context.

## Parameters

### policyJson

`string`

Economic policy JSON string (empty/"null" for free contexts).

### actionType

[`PaidActionType`](../type-aliases/PaidActionType.md)

The type of action to estimate.

### metrics?

[`ObservableMetrics`](../interfaces/ObservableMetrics.md)

Observable metrics (all optional, default to 0).

## Returns

`Promise`\<`number`\>

Estimated cost (smallest currency unit), or -1 on overflow.
