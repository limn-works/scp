[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / antispamVelocity

# Function: antispamVelocity()

> **antispamVelocity**(`contextId`, `senderDid`, `now`): `Promise`\<`number`\>

Defined in: [src/economy.ts:294](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L294)

Queries the sender's message velocity within the sliding window.

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

## Returns

`Promise`\<`number`\>

Number of messages within the window.
