[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / antispamRecord

# Function: antispamRecord()

> **antispamRecord**(`contextId`, `senderDid`, `timestamp`): `Promise`\<`void`\>

Defined in: [src/economy.ts:273](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L273)

Records a message for antispam velocity tracking.

## Parameters

### contextId

`string`

The context ID.

### senderDid

`string`

The sender's DID.

### timestamp

`number`

Unix timestamp in seconds.

## Returns

`Promise`\<`void`\>
