[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / restoreContext

# Function: restoreContext()

> **restoreContext**(`contextId`): `Promise`\<`void`\>

Defined in: [src/context.ts:1284](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1284)

Restores a single persisted context from storage.

## Parameters

### contextId

`string`

The context ID to restore.

## Returns

`Promise`\<`void`\>

## Throws

If restoration fails (SCP-CTX-2064).
