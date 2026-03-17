[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Relay

# Class: Relay

Defined in: [src/server.ts:121](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L121)

Opaque handle to a running SCP relay server.

Use the static factory methods [Relay.startInMemory](#startinmemory) or
[Relay.startLocal](#startlocal) to create an instance. Call [Relay.shutdown](#shutdown)
to stop the relay, or use `await using` for automatic cleanup.

## Implements

- `AsyncDisposable`

## Accessors

### isShutdown

#### Get Signature

> **get** **isShutdown**(): `boolean`

Defined in: [src/server.ts:139](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L139)

`true` if [shutdown](#shutdown) has already been called.

##### Returns

`boolean`

***

### relayPort

#### Get Signature

> **get** **relayPort**(): `number`

Defined in: [src/server.ts:134](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L134)

The port the relay is listening on.

##### Returns

`number`

***

### relayUrl

#### Get Signature

> **get** **relayUrl**(): `string`

Defined in: [src/server.ts:129](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L129)

The WebSocket URL clients should connect to (e.g. `ws://127.0.0.1:PORT/scp/v1`).

##### Returns

`string`

## Methods

### \[asyncDispose\]()

> **\[asyncDispose\]**(): `Promise`\<`void`\>

Defined in: [src/server.ts:178](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L178)

`AsyncDisposable` support for `await using`.

#### Returns

`Promise`\<`void`\>

#### Implementation of

`AsyncDisposable.[asyncDispose]`

***

### shutdown()

> **shutdown**(): `Promise`\<`void`\>

Defined in: [src/server.ts:173](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L173)

Signal the relay to stop accepting new connections.

In-flight connection handlers drain naturally. Idempotent.

#### Returns

`Promise`\<`void`\>

***

### startInMemory()

> `static` **startInMemory**(): `Promise`\<`Relay`\>

Defined in: [src/server.ts:149](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L149)

Start a relay with in-memory blob storage on an OS-assigned port.

#### Returns

`Promise`\<`Relay`\>

A `Relay` whose [relayUrl](#relayurl) property contains the
WebSocket URL for clients.

***

### startLocal()

> `static` **startLocal**(`dataDir`): `Promise`\<`Relay`\>

Defined in: [src/server.ts:162](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L162)

Start a relay with redb-backed blob storage on an OS-assigned port.

Opens (or creates) a redb database at `<dataDir>/blobs.redb`.

#### Parameters

##### dataDir

`string`

Directory for persistent blob storage.

#### Returns

`Promise`\<`Relay`\>
