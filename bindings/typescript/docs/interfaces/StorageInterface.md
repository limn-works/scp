[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / StorageInterface

# Interface: StorageInterface

Defined in: [src/storage/wasm-sqlite.ts:26](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L26)

Key-value byte storage interface matching the scp-platform Storage trait.

All methods are async. Keys are UTF-8 strings; values are opaque byte arrays.
See ADR-006 and spec section 17.

## Methods

### delete()

> **delete**(`key`): `Promise`\<`void`\>

Defined in: [src/storage/wasm-sqlite.ts:32](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L32)

Delete the value stored under the given key. No-op if absent.

#### Parameters

##### key

`string`

#### Returns

`Promise`\<`void`\>

***

### deletePrefix()

> **deletePrefix**(`prefix`): `Promise`\<`number`\>

Defined in: [src/storage/wasm-sqlite.ts:36](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L36)

Delete all keys matching the given prefix. Returns the count deleted.

#### Parameters

##### prefix

`string`

#### Returns

`Promise`\<`number`\>

***

### exists()

> **exists**(`key`): `Promise`\<`boolean`\>

Defined in: [src/storage/wasm-sqlite.ts:38](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L38)

Check whether a key exists without reading its value.

#### Parameters

##### key

`string`

#### Returns

`Promise`\<`boolean`\>

***

### listKeys()

> **listKeys**(`prefix`): `Promise`\<`string`[]\>

Defined in: [src/storage/wasm-sqlite.ts:34](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L34)

List all keys matching the given prefix in lexicographic order.

#### Parameters

##### prefix

`string`

#### Returns

`Promise`\<`string`[]\>

***

### retrieve()

> **retrieve**(`key`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

Defined in: [src/storage/wasm-sqlite.ts:30](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L30)

Retrieve the byte array stored under the given key, or null if absent.

#### Parameters

##### key

`string`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\> \| `null`\>

***

### store()

> **store**(`key`, `data`): `Promise`\<`void`\>

Defined in: [src/storage/wasm-sqlite.ts:28](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/storage/wasm-sqlite.ts#L28)

Store a byte array under the given key, replacing any existing value.

#### Parameters

##### key

`string`

##### data

`Uint8Array`

#### Returns

`Promise`\<`void`\>
