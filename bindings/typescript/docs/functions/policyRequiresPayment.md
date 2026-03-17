[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / policyRequiresPayment

# Function: policyRequiresPayment()

> **policyRequiresPayment**(`policyJson`): `Promise`\<`boolean`\>

Defined in: [src/economy.ts:91](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L91)

Checks whether an economic policy requires payment for any action.

## Parameters

### policyJson

`string`

Economic policy JSON string.

## Returns

`Promise`\<`boolean`\>

`true` if payment is required.
