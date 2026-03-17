[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / budgetRecordSpend

# Function: budgetRecordSpend()

> **budgetRecordSpend**(`contextId`, `did`, `amount`): `Promise`\<`void`\>

Defined in: [src/economy.ts:249](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L249)

Records a spend against a member's budget.

## Parameters

### contextId

`string`

The context ID.

### did

`string`

The member's DID.

### amount

`number`

Amount spent (smallest currency unit).

## Returns

`Promise`\<`void`\>

## Throws

If no budget exists or spend exceeds remaining.
