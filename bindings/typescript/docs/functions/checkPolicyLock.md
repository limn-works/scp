[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / checkPolicyLock

# Function: checkPolicyLock()

> **checkPolicyLock**(`policyJson`): `Promise`\<`boolean`\>

Defined in: [src/economy.ts:121](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L121)

Checks whether an economic policy is locked (immutable).

## Parameters

### policyJson

`string`

Economic policy JSON string.

## Returns

`Promise`\<`boolean`\>

`true` if the policy is locked.
