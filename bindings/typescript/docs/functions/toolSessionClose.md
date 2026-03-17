[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / toolSessionClose

# Function: toolSessionClose()

> **toolSessionClose**(`handle`, `sessionId`): `Promise`\<`void`\>

Defined in: [src/tools.ts:258](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/tools.ts#L258)

Closes a stateful tool session.

Removes the session from the store, releasing the caller's session slot.
After closing, any further invocations with this session ID will fail.

## Parameters

### handle

`BridgeContextHandle`

Bridge handle for the context containing the tool session.

### sessionId

`string`

The session to close.

## Returns

`Promise`\<`void`\>

## Throws

If the session is not found.
