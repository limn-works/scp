[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / classifyOfflineCustom

# Function: classifyOfflineCustom()

> **classifyOfflineCustom**(`lastRelayContact`, `now`, `tier1ThresholdSecs`, `tier2ThresholdSecs`): `Promise`\<`string`\>

Defined in: [src/sync.ts:58](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/sync.ts#L58)

Classifies an offline duration using custom policy thresholds.

## Parameters

### lastRelayContact

`number`

Unix timestamp (seconds) of last relay contact.

### now

`number`

Current Unix timestamp (seconds).

### tier1ThresholdSecs

`number`

Custom upper bound for short offline tier (seconds).

### tier2ThresholdSecs

`number`

Custom upper bound for extended offline tier (seconds).

## Returns

`Promise`\<`string`\>

`"short"`, `"extended"`, or `"long"`.
