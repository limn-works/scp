[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / handleDeregister

# Function: handleDeregister()

> **handleDeregister**(`discoveryContextId`, `handle`, `did`): `Promise`\<[`HandleDeregisterResult`](../interfaces/HandleDeregisterResult.md)\>

Defined in: [src/discovery.ts:485](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L485)

Deregisters a handle from a discovery context.

## Parameters

### discoveryContextId

`string`

ID of the discovery context.

### handle

`string`

The handle string to deregister.

### did

`string`

DID of the registrant requesting deregistration.

## Returns

`Promise`\<[`HandleDeregisterResult`](../interfaces/HandleDeregisterResult.md)\>

Deregistration result with a `removed` boolean.
