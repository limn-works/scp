[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Node

# Class: Node

Defined in: [src/server.ts:195](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L195)

Opaque handle to a running SCP application node.

An application node includes a running relay server, a generated DID
identity, and (optionally) persistent storage. Use the static factory
methods [Node.startInMemory](#startinmemory) or [Node.startLocal](#startlocal) to create
an instance.

## Implements

- `AsyncDisposable`

## Accessors

### did

#### Get Signature

> **get** **did**(): `string`

Defined in: [src/server.ts:213](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L213)

The node's DID string (e.g. `did:dht:z6Mk...`).

##### Returns

`string`

***

### isShutdown

#### Get Signature

> **get** **isShutdown**(): `boolean`

Defined in: [src/server.ts:218](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L218)

`true` if [shutdown](#shutdown) has already been called.

##### Returns

`boolean`

***

### relayPort

#### Get Signature

> **get** **relayPort**(): `number`

Defined in: [src/server.ts:208](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L208)

The port the node's relay is listening on.

##### Returns

`number`

***

### relayUrl

#### Get Signature

> **get** **relayUrl**(): `string`

Defined in: [src/server.ts:203](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L203)

The WebSocket URL for this node's relay (e.g. `ws://127.0.0.1:PORT/scp/v1`).

##### Returns

`string`

## Methods

### \[asyncDispose\]()

> **\[asyncDispose\]**(): `Promise`\<`void`\>

Defined in: [src/server.ts:258](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L258)

`AsyncDisposable` support for `await using`.

#### Returns

`Promise`\<`void`\>

#### Implementation of

`AsyncDisposable.[asyncDispose]`

***

### shutdown()

> **shutdown**(): `Promise`\<`void`\>

Defined in: [src/server.ts:253](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L253)

Signal the node to stop (relay + background tasks).

In-flight connection handlers drain naturally. Idempotent.

#### Returns

`Promise`\<`void`\>

***

### startInMemory()

> `static` **startInMemory**(): `Promise`\<`Node`\>

Defined in: [src/server.ts:228](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L228)

Start a full application node with in-memory storage.

Auto-wires in-memory key custody, in-memory storage, in-memory DHT
client, self-signed TLS, and a relay on an OS-assigned port.

#### Returns

`Promise`\<`Node`\>

***

### startLocal()

> `static` **startLocal**(`dataDir`): `Promise`\<`Node`\>

Defined in: [src/server.ts:242](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L242)

Start a full application node with file-backed storage.

Opens (or creates) persistent storage at `<dataDir>/storage/` and a
redb blob database at `<dataDir>/blobs.redb`.

#### Parameters

##### dataDir

`string`

Directory for persistent storage.

#### Returns

`Promise`\<`Node`\>
