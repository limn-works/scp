[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / InMemorySqliteStorage

# Class: InMemorySqliteStorage

Defined in: [src/storage/wasm-sqlite.ts:352](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L352)

In-memory storage adapter for testing.

Uses wa-sqlite's `:memory:` database without encryption. Provides the same
StorageInterface so conformance tests can run without OPFS or IndexedDB.

This class is exported for testing only. Production code should use
[WasmSqliteStorage](WasmSqliteStorage.md).

## Implements

- [`StorageInterface`](../interfaces/StorageInterface.md)

## Methods

### delete()

> **delete**(`key`): `Promise`\<`void`\>

Defined in: [src/storage/wasm-sqlite.ts:414](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L414)

Delete the value stored under the given key. No-op if absent.

#### Parameters

##### key

`string`

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`StorageInterface`](../interfaces/StorageInterface.md).[`delete`](../interfaces/StorageInterface.md#delete)

***

### deletePrefix()

> **deletePrefix**(`prefix`): `Promise`\<`number`\>

Defined in: [src/storage/wasm-sqlite.ts:444](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L444)

Delete all keys matching the given prefix. Returns the count deleted.

#### Parameters

##### prefix

`string`

#### Returns

`Promise`\<`number`\>

#### Implementation of

[`StorageInterface`](../interfaces/StorageInterface.md).[`deletePrefix`](../interfaces/StorageInterface.md#deleteprefix)

***

### exists()

> **exists**(`key`): `Promise`\<`boolean`\>

Defined in: [src/storage/wasm-sqlite.ts:474](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L474)

Check whether a key exists without reading its value.

#### Parameters

##### key

`string`

#### Returns

`Promise`\<`boolean`\>

#### Implementation of

[`StorageInterface`](../interfaces/StorageInterface.md).[`exists`](../interfaces/StorageInterface.md#exists)

***

### listKeys()

> **listKeys**(`prefix`): `Promise`\<`string`[]\>

Defined in: [src/storage/wasm-sqlite.ts:418](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L418)

List all keys matching the given prefix in lexicographic order.

#### Parameters

##### prefix

`string`

#### Returns

`Promise`\<`string`[]\>

#### Implementation of

[`StorageInterface`](../interfaces/StorageInterface.md).[`listKeys`](../interfaces/StorageInterface.md#listkeys)

***

### retrieve()

> **retrieve**(`key`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

Defined in: [src/storage/wasm-sqlite.ts:396](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L396)

Retrieve the byte array stored under the given key, or null if absent.

#### Parameters

##### key

`string`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

#### Implementation of

[`StorageInterface`](../interfaces/StorageInterface.md).[`retrieve`](../interfaces/StorageInterface.md#retrieve)

***

### store()

> **store**(`key`, `data`): `Promise`\<`void`\>

Defined in: [src/storage/wasm-sqlite.ts:377](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L377)

Store a byte array under the given key, replacing any existing value.

#### Parameters

##### key

`string`

##### data

`Uint8Array`

#### Returns

`Promise`\<`void`\>

#### Implementation of

[`StorageInterface`](../interfaces/StorageInterface.md).[`store`](../interfaces/StorageInterface.md#store)

***

### open()

> `static` **open**(): `Promise`\<`InMemorySqliteStorage`\>

Defined in: [src/storage/wasm-sqlite.ts:367](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L367)

Opens a new in-memory storage instance.

#### Returns

`Promise`\<`InMemorySqliteStorage`\>

A fully initialized InMemorySqliteStorage instance.
