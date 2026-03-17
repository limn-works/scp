[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / budgetRemaining

# Function: budgetRemaining()

> **budgetRemaining**(`contextId`, `did`): `Promise`\<`number`\>

Defined in: [src/economy.ts:216](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L216)

Queries the remaining budget for a member in a context.

## Parameters

### contextId

`string`

The context ID.

### did

`string`

The member's DID.

## Returns

`Promise`\<`number`\>

Remaining budget (smallest currency unit).
