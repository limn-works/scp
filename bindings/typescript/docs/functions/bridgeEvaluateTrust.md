[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / bridgeEvaluateTrust

# Function: bridgeEvaluateTrust()

> **bridgeEvaluateTrust**(`isBridged?`, `isNativeTransport?`, `shadowStatus?`): `Promise`\<`number`\>

Defined in: [src/bridge.ts:92](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/bridge.ts#L92)

Evaluates the trust level for an action based on bridge provenance.

## Parameters

### isBridged?

`boolean` = `false`

Whether the action has bridge provenance.

### isNativeTransport?

`boolean` = `true`

Whether the transport is native SCP.

### shadowStatus?

[`ShadowStatus`](../type-aliases/ShadowStatus.md) = `"shadow"`

`"shadow"` or `"claimed"`.

## Returns

`Promise`\<`number`\>

Trust tier as an integer (0-3).
