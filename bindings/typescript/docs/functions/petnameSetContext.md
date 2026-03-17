[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / petnameSetContext

# Function: petnameSetContext()

> **petnameSetContext**(`ownerDid`, `contextId`, `name`): `Promise`\<`void`\>

Defined in: [src/discovery.ts:296](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L296)

Assigns a petname to a context within the owner's local namespace.

## Parameters

### ownerDid

`string`

DID of the identity that owns this petname map.

### contextId

`string`

Context ID to assign the petname to.

### name

`string`

The petname string.

## Returns

`Promise`\<`void`\>

## Throws

If `ownerDid` is empty.
