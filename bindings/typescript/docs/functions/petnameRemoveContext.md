[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / petnameRemoveContext

# Function: petnameRemoveContext()

> **petnameRemoveContext**(`ownerDid`, `contextId`): `Promise`\<`void`\>

Defined in: [src/discovery.ts:316](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L316)

Removes a petname from a context.

## Parameters

### ownerDid

`string`

DID of the identity that owns this petname map.

### contextId

`string`

Context ID to remove the petname from.

## Returns

`Promise`\<`void`\>

## Throws

If `ownerDid` is empty.
