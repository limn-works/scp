[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / toolSessionInvoke

# Function: toolSessionInvoke()

> **toolSessionInvoke**(`handle`, `sessionId`, `inputJson`, `invokerDid`, `ucanToken`, `proofTokens?`): `Promise`\<[`ToolSessionInvokeResult`](../interfaces/ToolSessionInvokeResult.md)\>

Defined in: [src/tools.ts:218](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/tools.ts#L218)

Invokes a tool within an active session.

Each call is individually governed: the invoker must hold `ToolInvoke`
capability and present a valid UCAN token. Session state is carried forward
across invocations. The session's call count is incremented on each
successful invocation.

## Parameters

### handle

`BridgeContextHandle`

Bridge handle for the context containing the tool session.

### sessionId

`string`

The session to invoke within.

### inputJson

`string`

Input data as a JSON string matching the tool's input schema.

### invokerDid

`string`

The DID of the invoker (capability checked per call).

### ucanToken

`string`

JWT-encoded UCAN token authorizing the invocation.

### proofTokens?

readonly `string`[]

Optional list of encoded parent UCAN token strings.

## Returns

`Promise`\<[`ToolSessionInvokeResult`](../interfaces/ToolSessionInvokeResult.md)\>

A [ToolSessionInvokeResult](../interfaces/ToolSessionInvokeResult.md) with the tool output and provenance.

## Throws

If the session is not found or has expired.
