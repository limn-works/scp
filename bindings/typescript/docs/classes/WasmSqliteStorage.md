[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / WasmSqliteStorage

# Class: WasmSqliteStorage

Defined in: [src/storage/wasm-sqlite.ts:183](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L183)

Browser storage adapter using wa-sqlite with OPFS or IndexedDB VFS.

Per spec section 17.5 ("Browser: The One Exception"), SQLCipher is unavailable
in WASM. Each value is encrypted with AES-GCM using a CryptoKey derived from
the identity's WebCrypto key before writing.

Use the static [WasmSqliteStorage.open](#open) factory to create instances.
The constructor is private -- callers must go through open() to ensure the
database is initialized.

Schema: `CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID`

See SCP-PERSIST-062.

## Implements

- [`StorageInterface`](../interfaces/StorageInterface.md)

## Accessors

### vfs

#### Get Signature

> **get** **vfs**(): [`VfsType`](../type-aliases/VfsType.md)

Defined in: [src/storage/wasm-sqlite.ts:239](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L239)

Returns the VFS backend type in use.

##### Returns

[`VfsType`](../type-aliases/VfsType.md)

## Methods

### delete()

> **delete**(`key`): `Promise`\<`void`\>

Defined in: [src/storage/wasm-sqlite.ts:271](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L271)

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

Defined in: [src/storage/wasm-sqlite.ts:301](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L301)

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

Defined in: [src/storage/wasm-sqlite.ts:331](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L331)

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

Defined in: [src/storage/wasm-sqlite.ts:275](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L275)

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

Defined in: [src/storage/wasm-sqlite.ts:253](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L253)

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

Defined in: [src/storage/wasm-sqlite.ts:243](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L243)

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

> `static` **open**(`dbName`, `encryptionKey`): `Promise`\<`WasmSqliteStorage`\>

Defined in: [src/storage/wasm-sqlite.ts:207](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L207)

Opens a new WasmSqliteStorage backed by wa-sqlite.

Detects the best available VFS (OPFS primary, IndexedDB fallback) and
initializes the KV schema.

#### Parameters

##### dbName

`string`

The database file name (e.g., "scp-storage").

##### encryptionKey

`CryptoKey`

AES-GCM CryptoKey for value encryption.

#### Returns

`Promise`\<`WasmSqliteStorage`\>

A fully initialized WasmSqliteStorage instance.
