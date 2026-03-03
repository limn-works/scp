/**
 * Storage adapters for the SCP TypeScript SDK.
 *
 * Provides browser-compatible key-value storage backed by wa-sqlite with
 * OPFS (primary) or IndexedDB (fallback) VFS. Values are encrypted with
 * AES-GCM per spec section 17.5.
 *
 * See SCP-PERSIST-062.
 */

export {
  InMemorySqliteStorage,
  WasmSqliteStorage,
  prefixSuccessor,
  type StorageInterface,
  type VfsType,
} from "./wasm-sqlite.js";
