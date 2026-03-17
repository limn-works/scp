[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Event

# Interface: Event

Defined in: [src/types.ts:371](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L371)

A protocol event from the context event log.

## Properties

### actorDid

> `readonly` **actorDid**: `string`

Defined in: [src/types.ts:375](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L375)

DID of the actor who produced this event.

***

### eventType

> `readonly` **eventType**: `string`

Defined in: [src/types.ts:373](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L373)

Event type (e.g., `"ContextCreated"`, `"MessageSent"`, `"ToolInvoked"`).

***

### payload

> `readonly` **payload**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/types.ts:379](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L379)

Event-specific data.

***

### sequence

> `readonly` **sequence**: `number`

Defined in: [src/types.ts:381](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L381)

Monotonic sequence number within the log.

***

### timestamp

> `readonly` **timestamp**: `number`

Defined in: [src/types.ts:377](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L377)

Unix timestamp (seconds since epoch).
