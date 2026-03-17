[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / petnameGetForContext

# Function: petnameGetForContext()

> **petnameGetForContext**(`ownerDid`, `contextId`): `Promise`\<`string` \| `null`\>

Defined in: [src/discovery.ts:389](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L389)

Gets the petname assigned to a context, if any.

## Parameters

### ownerDid

`string`

DID of the identity that owns this petname map.

### contextId

`string`

Context ID to look up.

## Returns

`Promise`\<`string` \| `null`\>

The petname string, or `null` if no petname is assigned.

## Throws

If `ownerDid` is empty.
