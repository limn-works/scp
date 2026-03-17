[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / classifyOffline

# Function: classifyOffline()

> **classifyOffline**(`lastRelayContact`, `now`): `Promise`\<`string`\>

Defined in: [src/sync.ts:40](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/sync.ts#L40)

Classifies an offline duration into the appropriate recovery tier.

## Parameters

### lastRelayContact

`number`

Unix timestamp (seconds) of last relay contact.

### now

`number`

Current Unix timestamp (seconds).

## Returns

`Promise`\<`string`\>

`"short"`, `"extended"`, or `"long"`.
