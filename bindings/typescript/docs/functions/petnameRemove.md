[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / petnameRemove

# Function: petnameRemove()

> **petnameRemove**(`ownerDid`, `targetDid`): `Promise`\<`void`\>

Defined in: [src/discovery.ts:279](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L279)

Removes a petname from a DID.

## Parameters

### ownerDid

`string`

DID of the identity that owns this petname map.

### targetDid

`string`

DID to remove the petname from.

## Returns

`Promise`\<`void`\>

## Throws

If `ownerDid` is empty.
