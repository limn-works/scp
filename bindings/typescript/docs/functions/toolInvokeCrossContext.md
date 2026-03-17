[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / toolInvokeCrossContext

# Function: toolInvokeCrossContext()

> **toolInvokeCrossContext**(`sourceHandle`, `targetHandle`, `toolId`, `inputJson`, `invokerDid`, `ucanToken`, `chainDepth?`, `proofTokens?`): `Promise`\<[`CrossContextInvocationResult`](../interfaces/CrossContextInvocationResult.md)\>

Defined in: [src/tools.ts:113](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/tools.ts#L113)

Invokes a tool across context boundaries.

The source context initiates the call and the target context contains the
tool. Both contexts must have approved the interface before calls are
permitted. Rate limits and chain depth are enforced per spec section 6.2.

## Parameters

### sourceHandle

`BridgeContextHandle`

Bridge handle for the calling context.

### targetHandle

`BridgeContextHandle`

Bridge handle for the context containing the tool.

### toolId

`string`

The ID of the tool to invoke.

### inputJson

`string`

Input data as a JSON string matching the tool's input schema.

### invokerDid

`string`

The DID of the participant invoking the tool.

### ucanToken

`string`

JWT-encoded UCAN token authorizing the invocation.

### chainDepth?

`number` = `0`

Current cross-context chain depth (0 for first hop). Must be 0-5
  (protocol hard maximum per spec §24.4). Individual contexts may configure a lower
  limit via `max_chain_depth` (recommended default: 3).

### proofTokens?

readonly `string`[]

Optional list of encoded parent UCAN token strings.

## Returns

`Promise`\<[`CrossContextInvocationResult`](../interfaces/CrossContextInvocationResult.md)\>

A [CrossContextInvocationResult](../interfaces/CrossContextInvocationResult.md) with the tool output and provenance.

## Throws

If chainDepth is out of range (0-5).

## Throws

If the bridge call fails (inactive context, rate limit, etc.).
