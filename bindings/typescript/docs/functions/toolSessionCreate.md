[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / toolSessionCreate

# Function: toolSessionCreate()

> **toolSessionCreate**(`handle`, `toolId`, `sourceContextId`, `ttlSeconds?`): `Promise`\<[`ToolSessionResult`](../interfaces/ToolSessionResult.md)\>

Defined in: [src/tools.ts:177](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/tools.ts#L177)

Creates a stateful tool session.

Sessions enable multi-turn workflows with state preservation across
invocations. Each session is subject to per-caller caps (default: 5
concurrent sessions per caller, per spec section 6.2.1).

## Parameters

### handle

`BridgeContextHandle`

Bridge handle for the context containing the tool.

### toolId

`string`

The tool to create a session for.

### sourceContextId

`string`

The calling context (session cap tracked per caller).

### ttlSeconds?

`number`

Optional time-to-live in seconds. Omit for context-lifetime session.

## Returns

`Promise`\<[`ToolSessionResult`](../interfaces/ToolSessionResult.md)\>

A [ToolSessionResult](../interfaces/ToolSessionResult.md) containing the session ID.

## Throws

If ttlSeconds is negative or not an integer.

## Throws

If the bridge call fails (inactive context, session cap, etc.).
