[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / validatePolicyChange

# Function: validatePolicyChange()

> **validatePolicyChange**(`currentJson`, `proposedJson`): `Promise`\<`boolean`\>

Defined in: [src/economy.ts:138](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L138)

Validates a proposed economic policy change.

## Parameters

### currentJson

`string`

Current economic policy JSON string.

### proposedJson

`string`

Proposed new policy JSON string.

## Returns

`Promise`\<`boolean`\>

`true` if the change is valid.

## Throws

If the policy is locked or invalid.
