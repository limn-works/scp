[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / EventLog

# Class: EventLog

Defined in: [src/event-log.ts:33](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/event-log.ts#L33)

Event log accessor for an SCP context.

Event logs are append-only, Merkle-tree-backed logs of all protocol events
within a context. They provide verifiable audit trails and enable trust
evaluation based on observed behavior.

```typescript
const log = new EventLog(ctx);
const events = await log.query({ eventType: "MessageSent" });
const proof = await log.verify({ type: "inclusion", leafIndex: 0 });
const checkpoint = await log.checkpoint();
```

## Constructors

### Constructor

> **new EventLog**(`ctx`): `EventLog`

Defined in: [src/event-log.ts:42](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/event-log.ts#L42)

Creates an EventLog accessor for a context.

#### Parameters

##### ctx

[`Context`](Context.md)

The context whose event log to access.

#### Returns

`EventLog`

## Methods

### checkpoint()

> **checkpoint**(): `Promise`\<[`Checkpoint`](../interfaces/Checkpoint.md)\>

Defined in: [src/event-log.ts:88](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/event-log.ts#L88)

Creates a consistency checkpoint of the event log.

Returns the current Merkle root hash, event count, and timestamp.

#### Returns

`Promise`\<[`Checkpoint`](../interfaces/Checkpoint.md)\>

A checkpoint with the current log state.

#### Throws

If checkpoint creation fails.

***

### query()

> **query**(`filter?`): `Promise`\<readonly [`Event`](../interfaces/Event.md)[]\>

Defined in: [src/event-log.ts:53](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/event-log.ts#L53)

Queries the event log with optional filter criteria.

#### Parameters

##### filter?

[`EventFilter`](../interfaces/EventFilter.md)

Optional filter parameters. Pass `undefined` for all events.

#### Returns

`Promise`\<readonly [`Event`](../interfaces/Event.md)[]\>

An array of matching events.

#### Throws

If the query fails or the context is not active.

***

### verify()

> **verify**(`claim`): `Promise`\<[`Proof`](../interfaces/Proof.md)\>

Defined in: [src/event-log.ts:71](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/event-log.ts#L71)

Verifies a claim against the event log (Merkle proof).

Generates and verifies an inclusion or absence proof for the given claim.

#### Parameters

##### claim

[`EventClaim`](../interfaces/EventClaim.md)

The claim to verify.

#### Returns

`Promise`\<[`Proof`](../interfaces/Proof.md)\>

A proof with the verification result.

#### Throws

If verification fails.
