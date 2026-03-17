[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / petnameResolveContext

# Function: petnameResolveContext()

> **petnameResolveContext**(`ownerDid`, `name`): `Promise`\<`string`[]\>

Defined in: [src/discovery.ts:351](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L351)

Resolves a petname to a list of context IDs.

## Parameters

### ownerDid

`string`

DID of the identity that owns this petname map.

### name

`string`

The petname to resolve.

## Returns

`Promise`\<`string`[]\>

Array of context ID strings matching the petname.

## Throws

If `ownerDid` is empty.
