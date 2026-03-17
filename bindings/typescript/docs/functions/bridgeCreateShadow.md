[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / bridgeCreateShadow

# Function: bridgeCreateShadow()

> **bridgeCreateShadow**(`bridgeId`, `platformHandle`, `bridgeMode`, `contextId?`): `Promise`\<[`ShadowIdentity`](../interfaces/ShadowIdentity.md)\>

Defined in: [src/bridge.ts:114](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/bridge.ts#L114)

Creates a shadow identity for an external platform participant.

## Parameters

### bridgeId

`string`

The bridge connector ID.

### platformHandle

`string`

External platform handle.

### bridgeMode

[`BridgeMode`](../type-aliases/BridgeMode.md)

Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.

### contextId?

`string`

Context the shadow is being created in.

## Returns

`Promise`\<[`ShadowIdentity`](../interfaces/ShadowIdentity.md)\>

The shadow identity result.
