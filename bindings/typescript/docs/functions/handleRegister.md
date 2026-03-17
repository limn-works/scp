[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / handleRegister

# Function: handleRegister()

> **handleRegister**(`discoveryContextId`, `handle`, `targetJson`, `registrantDid`, `options?`): `Promise`\<[`HandleRegisterResult`](../interfaces/HandleRegisterResult.md)\>

Defined in: [src/discovery.ts:432](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L432)

Registers a handle in a discovery context.

## Parameters

### discoveryContextId

`string`

ID of the discovery context.

### handle

`string`

The handle string to register.

### targetJson

`string`

JSON describing the target (`{ "type": "identity", "did": "..." }` or `{ "type": "context", "context_id": "...", "relay_urls": [...] }`).

### registrantDid

`string`

DID of the registrant.

### options?

Optional description and tags.

#### description?

`string`

#### tags?

`string`[]

## Returns

`Promise`\<[`HandleRegisterResult`](../interfaces/HandleRegisterResult.md)\>

Registration result.

## Throws

If `targetJson` is malformed.
