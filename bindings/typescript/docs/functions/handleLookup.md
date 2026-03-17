[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / handleLookup

# Function: handleLookup()

> **handleLookup**(`discoveryContextId`, `handle`, `typeFilter?`): `Promise`\<[`HandleLookupResult`](../interfaces/HandleLookupResult.md)\>

Defined in: [src/discovery.ts:463](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L463)

Looks up a handle in a discovery context.

## Parameters

### discoveryContextId

`string`

ID of the discovery context.

### handle

`string`

The handle string to look up.

### typeFilter?

`string`

Optional filter: `"identity"` or `"context"`.

## Returns

`Promise`\<[`HandleLookupResult`](../interfaces/HandleLookupResult.md)\>

Lookup result with a `results` array of matching entries.
