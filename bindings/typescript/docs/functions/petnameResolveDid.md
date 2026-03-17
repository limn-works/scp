[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / petnameResolveDid

# Function: petnameResolveDid()

> **petnameResolveDid**(`ownerDid`, `name`): `Promise`\<`string`[]\>

Defined in: [src/discovery.ts:333](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L333)

Resolves a petname to a list of DIDs.

## Parameters

### ownerDid

`string`

DID of the identity that owns this petname map.

### name

`string`

The petname to resolve.

## Returns

`Promise`\<`string`[]\>

Array of DID strings matching the petname.

## Throws

If `ownerDid` is empty.
