[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / petnameSet

# Function: petnameSet()

> **petnameSet**(`ownerDid`, `targetDid`, `name`): `Promise`\<`void`\>

Defined in: [src/discovery.ts:263](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L263)

Assigns a petname to a DID within the owner's local namespace.

## Parameters

### ownerDid

`string`

DID of the identity that owns this petname map.

### targetDid

`string`

DID to assign the petname to.

### name

`string`

The petname string.

## Returns

`Promise`\<`void`\>

## Throws

If `ownerDid` is empty.
