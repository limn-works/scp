/**
 * WasmSqliteStorage -- Browser storage adapter using wa-sqlite with OPFS.
 *
 * Uses OPFSCoopSyncVFS as primary VFS (best performance, requires SharedArrayBuffer).
 * Falls back to IDBBatchAtomicVFS for Safari incognito and environments without OPFS.
 *
 * Per spec section 17.5, values are encrypted with AES-GCM using a CryptoKey derived
 * from the identity's WebCrypto key before writing to wa-sqlite.
 *
 * See SCP-PERSIST-062.
 */

import * as SQLite from "wa-sqlite";
import SQLiteESMFactory from "wa-sqlite/dist/wa-sqlite-async.mjs";

// ---------------------------------------------------------------------------
// StorageInterface
// ---------------------------------------------------------------------------

/**
 * Key-value byte storage interface matching the scp-platform Storage trait.
 *
 * All methods are async. Keys are UTF-8 strings; values are opaque byte arrays.
 * See ADR-006 and spec section 17.
 */
export interface StorageInterface {
  /** Store a byte array under the given key, replacing any existing value. */
  store(key: string, data: Uint8Array): Promise<void>;
  /** Retrieve the byte array stored under the given key, or null if absent. */
  retrieve(key: string): Promise<Uint8Array | null>;
  /** Delete the value stored under the given key. No-op if absent. */
  delete(key: string): Promise<void>;
  /** List all keys matching the given prefix in lexicographic order. */
  listKeys(prefix: string): Promise<string[]>;
  /** Delete all keys matching the given prefix. Returns the count deleted. */
  deletePrefix(prefix: string): Promise<number>;
  /** Check whether a key exists without reading its value. */
  exists(key: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Async mutex for serializing wa-sqlite access
// ---------------------------------------------------------------------------

/**
 * Simple async mutex that serializes access to a single wa-sqlite connection.
 *
 * wa-sqlite (async mode) cannot handle concurrent prepare/step/finalize
 * calls on the same database handle. This mutex ensures only one SQL
 * operation executes at a time, queuing any concurrent callers.
 */
class AsyncMutex {
  #queue: Promise<void> = Promise.resolve();

  /** Executes `fn` exclusively -- concurrent callers wait in FIFO order. */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const waiting = this.#queue;
    this.#queue = gate;
    await waiting;
    try {
      return await fn();
    } finally {
      release?.();
    }
  }
}

// ---------------------------------------------------------------------------
// AES-GCM encryption helpers
// ---------------------------------------------------------------------------

/** AES-GCM IV length in bytes. */
const IV_LENGTH = 12;

/**
 * Encrypts data with AES-GCM. Returns IV prepended to ciphertext.
 *
 * A fresh random IV is generated for every call. The caller provides
 * a CryptoKey suitable for AES-GCM (256-bit).
 */
async function encrypt(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext.buffer as ArrayBuffer,
  );
  const result = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), IV_LENGTH);
  return result;
}

/**
 * Decrypts data encrypted by {@link encrypt}. Expects IV prepended to ciphertext.
 */
async function decrypt(key: CryptoKey, ivAndCiphertext: Uint8Array): Promise<Uint8Array> {
  const iv = ivAndCiphertext.slice(0, IV_LENGTH);
  const ciphertext = ivAndCiphertext.slice(IV_LENGTH);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(plaintext);
}

// ---------------------------------------------------------------------------
// Prefix successor utility
// ---------------------------------------------------------------------------

/**
 * Computes the exclusive upper bound for a prefix range scan.
 *
 * Given a prefix string, returns the lexicographically next string that is
 * not a prefix match. This enables efficient B-tree range queries:
 * `WHERE key >= prefix AND key < prefixSuccessor(prefix)`.
 *
 * Returns null if the prefix consists entirely of 0xFF bytes (no successor
 * exists), which means the range scan should use an unbounded upper limit.
 *
 * This mirrors the Rust SqliteStorage prefix_successor pattern.
 */
export function prefixSuccessor(prefix: string): string | null {
  const bytes = new TextEncoder().encode(prefix);
  // Work backwards from the end, incrementing the last byte that is not 0xFF.
  for (let i = bytes.length - 1; i >= 0; i--) {
    const b = bytes[i];
    if (b !== undefined && b < 0xff) {
      const result = new Uint8Array(i + 1);
      result.set(bytes.slice(0, i));
      result[i] = b + 1;
      return new TextDecoder().decode(result);
    }
  }
  // All bytes are 0xFF -- no successor exists.
  return null;
}

// ---------------------------------------------------------------------------
// VFS detection
// ---------------------------------------------------------------------------

/** Detected VFS backend type. */
export type VfsType = "opfs" | "idb";

/**
 * Detects which VFS backend is available in the current environment.
 *
 * Prefers OPFSCoopSyncVFS (requires SharedArrayBuffer and OPFS).
 * Falls back to IDBBatchAtomicVFS (IndexedDB-based, wider compatibility).
 */
function detectVfs(): VfsType {
  // OPFSCoopSyncVFS requires SharedArrayBuffer and the OPFS API.
  if (typeof SharedArrayBuffer !== "undefined" && typeof navigator !== "undefined") {
    const storageManager = navigator.storage;
    if (storageManager && typeof storageManager.getDirectory === "function") {
      return "opfs";
    }
  }
  return "idb";
}

// ---------------------------------------------------------------------------
// WasmSqliteStorage
// ---------------------------------------------------------------------------

/**
 * Browser storage adapter using wa-sqlite with OPFS or IndexedDB VFS.
 *
 * Per spec section 17.5 ("Browser: The One Exception"), SQLCipher is unavailable
 * in WASM. Each value is encrypted with AES-GCM using a CryptoKey derived from
 * the identity's WebCrypto key before writing.
 *
 * Use the static {@link WasmSqliteStorage.open} factory to create instances.
 * The constructor is private -- callers must go through open() to ensure the
 * database is initialized.
 *
 * Schema: `CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID`
 *
 * See SCP-PERSIST-062.
 */
export class WasmSqliteStorage implements StorageInterface {
  readonly #db: number;
  readonly #sqlite: SQLiteAPI;
  readonly #encryptionKey: CryptoKey;
  readonly #vfsType: VfsType;
  readonly #mutex = new AsyncMutex();

  private constructor(db: number, sqlite: SQLiteAPI, encryptionKey: CryptoKey, vfsType: VfsType) {
    this.#db = db;
    this.#sqlite = sqlite;
    this.#encryptionKey = encryptionKey;
    this.#vfsType = vfsType;
  }

  /**
   * Opens a new WasmSqliteStorage backed by wa-sqlite.
   *
   * Detects the best available VFS (OPFS primary, IndexedDB fallback) and
   * initializes the KV schema.
   *
   * @param dbName - The database file name (e.g., "scp-storage").
   * @param encryptionKey - AES-GCM CryptoKey for value encryption.
   * @returns A fully initialized WasmSqliteStorage instance.
   */
  static async open(dbName: string, encryptionKey: CryptoKey): Promise<WasmSqliteStorage> {
    const vfsType = detectVfs();
    const module = await SQLiteESMFactory();
    const sqlite = SQLite.Factory(module);

    // Register the appropriate VFS.
    // VFS classes are untyped -- cast through unknown to satisfy vfs_register.
    if (vfsType === "opfs") {
      const { OriginPrivateFileSystemVFS } = await import(
        "wa-sqlite/src/examples/OriginPrivateFileSystemVFS.js"
      );
      const vfs = new OriginPrivateFileSystemVFS();
      await vfs.isReady;
      sqlite.vfs_register(vfs as unknown as SQLiteVFS, true);
    } else {
      const { IDBBatchAtomicVFS } = await import("wa-sqlite/src/examples/IDBBatchAtomicVFS.js");
      const vfs = new IDBBatchAtomicVFS();
      await vfs.isReady;
      sqlite.vfs_register(vfs as unknown as SQLiteVFS, true);
    }

    const db = await sqlite.open_v2(dbName);

    // Create the KV table.
    const createSql =
      "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID";
    await run(sqlite, db, createSql);

    return new WasmSqliteStorage(db, sqlite, encryptionKey, vfsType);
  }

  /** Returns the VFS backend type in use. */
  get vfs(): VfsType {
    return this.#vfsType;
  }

  async store(key: string, data: Uint8Array): Promise<void> {
    const encrypted = await encrypt(this.#encryptionKey, data);
    await this.#mutex.run(() =>
      run(this.#sqlite, this.#db, "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", [
        key,
        encrypted,
      ]),
    );
  }

  async retrieve(key: string): Promise<Uint8Array | null> {
    return this.#mutex.run(async () => {
      const rows = await query(this.#sqlite, this.#db, "SELECT value FROM kv WHERE key = ?", [key]);
      if (rows.length === 0) {
        return null;
      }
      const row = rows[0];
      if (!row) {
        return null;
      }
      const encrypted = row[0];
      if (!(encrypted instanceof Uint8Array)) {
        return null;
      }
      return decrypt(this.#encryptionKey, encrypted);
    });
  }

  async delete(key: string): Promise<void> {
    await this.#mutex.run(() => run(this.#sqlite, this.#db, "DELETE FROM kv WHERE key = ?", [key]));
  }

  async listKeys(prefix: string): Promise<string[]> {
    return this.#mutex.run(async () => {
      const successor = prefixSuccessor(prefix);
      let rows: SQLiteRow[];
      if (successor === null) {
        rows = await query(
          this.#sqlite,
          this.#db,
          "SELECT key FROM kv WHERE key >= ? ORDER BY key",
          [prefix],
        );
      } else {
        rows = await query(
          this.#sqlite,
          this.#db,
          "SELECT key FROM kv WHERE key >= ? AND key < ? ORDER BY key",
          [prefix, successor],
        );
      }
      return rows.map((row) => {
        const val = row[0];
        return typeof val === "string" ? val : String(val);
      });
    });
  }

  async deletePrefix(prefix: string): Promise<number> {
    return this.#mutex.run(async () => {
      const successor = prefixSuccessor(prefix);
      let countRows: SQLiteRow[];
      if (successor === null) {
        countRows = await query(this.#sqlite, this.#db, "SELECT COUNT(*) FROM kv WHERE key >= ?", [
          prefix,
        ]);
        await run(this.#sqlite, this.#db, "DELETE FROM kv WHERE key >= ?", [prefix]);
      } else {
        countRows = await query(
          this.#sqlite,
          this.#db,
          "SELECT COUNT(*) FROM kv WHERE key >= ? AND key < ?",
          [prefix, successor],
        );
        await run(this.#sqlite, this.#db, "DELETE FROM kv WHERE key >= ? AND key < ?", [
          prefix,
          successor,
        ]);
      }
      const row = countRows[0];
      if (!row) {
        return 0;
      }
      const count = row[0];
      return typeof count === "number" ? count : 0;
    });
  }

  async exists(key: string): Promise<boolean> {
    return this.#mutex.run(async () => {
      const rows = await query(this.#sqlite, this.#db, "SELECT 1 FROM kv WHERE key = ?", [key]);
      return rows.length > 0;
    });
  }
}

// ---------------------------------------------------------------------------
// InMemorySqliteStorage -- testing adapter (no encryption, in-memory DB)
// ---------------------------------------------------------------------------

/**
 * In-memory storage adapter for testing.
 *
 * Uses wa-sqlite's `:memory:` database without encryption. Provides the same
 * StorageInterface so conformance tests can run without OPFS or IndexedDB.
 *
 * This class is exported for testing only. Production code should use
 * {@link WasmSqliteStorage}.
 */
export class InMemorySqliteStorage implements StorageInterface {
  readonly #db: number;
  readonly #sqlite: SQLiteAPI;
  readonly #mutex = new AsyncMutex();

  private constructor(db: number, sqlite: SQLiteAPI) {
    this.#db = db;
    this.#sqlite = sqlite;
  }

  /**
   * Opens a new in-memory storage instance.
   *
   * @returns A fully initialized InMemorySqliteStorage instance.
   */
  static async open(): Promise<InMemorySqliteStorage> {
    const module = await SQLiteESMFactory();
    const sqlite = SQLite.Factory(module);
    const db = await sqlite.open_v2(":memory:");
    const createSql =
      "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID";
    await run(sqlite, db, createSql);
    return new InMemorySqliteStorage(db, sqlite);
  }

  async store(key: string, data: Uint8Array): Promise<void> {
    await this.#mutex.run(() => {
      // wa-sqlite's bind_blob passes a null pointer for zero-length arrays,
      // violating NOT NULL constraints. Use zeroblob(0) SQL literal instead.
      if (data.length === 0) {
        return run(
          this.#sqlite,
          this.#db,
          "INSERT OR REPLACE INTO kv (key, value) VALUES (?, zeroblob(0))",
          [key],
        );
      }
      return run(this.#sqlite, this.#db, "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", [
        key,
        data,
      ]);
    });
  }

  async retrieve(key: string): Promise<Uint8Array | null> {
    return this.#mutex.run(async () => {
      const rows = await query(this.#sqlite, this.#db, "SELECT value FROM kv WHERE key = ?", [key]);
      if (rows.length === 0) {
        return null;
      }
      const row = rows[0];
      if (!row) {
        return null;
      }
      const value = row[0];
      if (value instanceof Uint8Array) {
        return value;
      }
      return null;
    });
  }

  async delete(key: string): Promise<void> {
    await this.#mutex.run(() => run(this.#sqlite, this.#db, "DELETE FROM kv WHERE key = ?", [key]));
  }

  async listKeys(prefix: string): Promise<string[]> {
    return this.#mutex.run(async () => {
      const successor = prefixSuccessor(prefix);
      let rows: SQLiteRow[];
      if (successor === null) {
        rows = await query(
          this.#sqlite,
          this.#db,
          "SELECT key FROM kv WHERE key >= ? ORDER BY key",
          [prefix],
        );
      } else {
        rows = await query(
          this.#sqlite,
          this.#db,
          "SELECT key FROM kv WHERE key >= ? AND key < ? ORDER BY key",
          [prefix, successor],
        );
      }
      return rows.map((row) => {
        const val = row[0];
        return typeof val === "string" ? val : String(val);
      });
    });
  }

  async deletePrefix(prefix: string): Promise<number> {
    return this.#mutex.run(async () => {
      const successor = prefixSuccessor(prefix);
      let countRows: SQLiteRow[];
      if (successor === null) {
        countRows = await query(this.#sqlite, this.#db, "SELECT COUNT(*) FROM kv WHERE key >= ?", [
          prefix,
        ]);
        await run(this.#sqlite, this.#db, "DELETE FROM kv WHERE key >= ?", [prefix]);
      } else {
        countRows = await query(
          this.#sqlite,
          this.#db,
          "SELECT COUNT(*) FROM kv WHERE key >= ? AND key < ?",
          [prefix, successor],
        );
        await run(this.#sqlite, this.#db, "DELETE FROM kv WHERE key >= ? AND key < ?", [
          prefix,
          successor,
        ]);
      }
      const row = countRows[0];
      if (!row) {
        return 0;
      }
      const count = row[0];
      return typeof count === "number" ? count : 0;
    });
  }

  async exists(key: string): Promise<boolean> {
    return this.#mutex.run(async () => {
      const rows = await query(this.#sqlite, this.#db, "SELECT 1 FROM kv WHERE key = ?", [key]);
      return rows.length > 0;
    });
  }
}

// ---------------------------------------------------------------------------
// wa-sqlite helper types and functions
// ---------------------------------------------------------------------------

/** SQLite C API surface exposed by wa-sqlite. */
type SQLiteAPI = ReturnType<typeof SQLite.Factory>;

/** A row returned by a query -- array of column values. */
type SQLiteRow = Array<string | number | Uint8Array | null>;

/** Bind parameter types accepted by wa-sqlite. */
type BindValue = string | number | Uint8Array | null;

/**
 * Executes a SQL statement that does not return rows (INSERT, DELETE, CREATE).
 */
async function run(
  sqlite: SQLiteAPI,
  db: number,
  sql: string,
  params?: BindValue[],
): Promise<void> {
  const str = sqlite.str_new(db, sql);
  const prepared = await sqlite.prepare_v2(db, sqlite.str_value(str));
  if (prepared === null) {
    sqlite.str_finish(str);
    throw new Error(`Failed to prepare SQL: ${sql}`);
  }
  try {
    if (params) {
      for (let i = 0; i < params.length; i++) {
        const param = params[i];
        if (param === null || param === undefined) {
          sqlite.bind(prepared.stmt, i + 1, null);
        } else if (typeof param === "string") {
          sqlite.bind_text(prepared.stmt, i + 1, param);
        } else if (typeof param === "number") {
          sqlite.bind(prepared.stmt, i + 1, param);
        } else {
          // Uint8Array
          sqlite.bind_blob(prepared.stmt, i + 1, param);
        }
      }
    }
    await sqlite.step(prepared.stmt);
  } finally {
    sqlite.finalize(prepared.stmt);
    sqlite.str_finish(str);
  }
}

/**
 * Executes a SQL query and returns all result rows.
 */
async function query(
  sqlite: SQLiteAPI,
  db: number,
  sql: string,
  params?: BindValue[],
): Promise<SQLiteRow[]> {
  const str = sqlite.str_new(db, sql);
  const prepared = await sqlite.prepare_v2(db, sqlite.str_value(str));
  if (prepared === null) {
    sqlite.str_finish(str);
    throw new Error(`Failed to prepare SQL: ${sql}`);
  }
  const rows: SQLiteRow[] = [];
  try {
    if (params) {
      for (let i = 0; i < params.length; i++) {
        const param = params[i];
        if (param === null || param === undefined) {
          sqlite.bind(prepared.stmt, i + 1, null);
        } else if (typeof param === "string") {
          sqlite.bind_text(prepared.stmt, i + 1, param);
        } else if (typeof param === "number") {
          sqlite.bind(prepared.stmt, i + 1, param);
        } else {
          // Uint8Array
          sqlite.bind_blob(prepared.stmt, i + 1, param);
        }
      }
    }
    const columnCount = sqlite.column_count(prepared.stmt);
    while ((await sqlite.step(prepared.stmt)) === SQLite.SQLITE_ROW) {
      const row: SQLiteRow = [];
      for (let i = 0; i < columnCount; i++) {
        const colType = sqlite.column_type(prepared.stmt, i);
        switch (colType) {
          case SQLite.SQLITE_TEXT:
            row.push(sqlite.column_text(prepared.stmt, i));
            break;
          case SQLite.SQLITE_INTEGER:
          case SQLite.SQLITE_FLOAT:
            row.push(sqlite.column(prepared.stmt, i) as number);
            break;
          case SQLite.SQLITE_BLOB:
            row.push(new Uint8Array(sqlite.column_blob(prepared.stmt, i)));
            break;
          default:
            row.push(null);
            break;
        }
      }
      rows.push(row);
    }
  } finally {
    sqlite.finalize(prepared.stmt);
    sqlite.str_finish(str);
  }
  return rows;
}
