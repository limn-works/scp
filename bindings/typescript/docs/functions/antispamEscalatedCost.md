[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / antispamEscalatedCost

# Function: antispamEscalatedCost()

> **antispamEscalatedCost**(`contextId`, `senderDid`, `now`, `baseCost`, `thresholds`, `floor?`, `cap?`): `Promise`\<`number`\>

Defined in: [src/economy.ts:319](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L319)

Computes the escalated cost for a sender based on antispam velocity.

## Parameters

### contextId

`string`

The context ID.

### senderDid

`string`

The sender's DID.

### now

`number`

Current Unix timestamp in seconds.

### baseCost

`number`

Base cost (smallest currency unit).

### thresholds

readonly readonly \[`number`, `number`\][]

Array of [velocityThreshold, additionalCost] pairs.

### floor?

`number`

Optional minimum cost.

### cap?

`number`

Optional maximum cost.

## Returns

`Promise`\<`number`\>

Escalated cost (smallest currency unit).
