[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / petnameGetForDid

# Function: petnameGetForDid()

> **petnameGetForDid**(`ownerDid`, `targetDid`): `Promise`\<`string` \| `null`\>

Defined in: [src/discovery.ts:369](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L369)

Gets the petname assigned to a DID, if any.

## Parameters

### ownerDid

`string`

DID of the identity that owns this petname map.

### targetDid

`string`

DID to look up.

## Returns

`Promise`\<`string` \| `null`\>

The petname string, or `null` if no petname is assigned.

## Throws

If `ownerDid` is empty.
