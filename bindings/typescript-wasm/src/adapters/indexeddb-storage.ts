/**
 * {@link IndexedDbStorage} — the durable browser {@link JsStorage}, implementing
 * the synchronous-facade-over-async-mirror pattern the wasm driver mandates
 * (ADR-057 T2; `crates/scp-client-wasm/src/storage.rs`).
 *
 * The driver's `Storage` port is SYNCHRONOUS (it is called inline under
 * `&mut self`), but IndexedDB is asynchronous. The mandated bridge:
 *
 * 1. {@link open} preloads the whole persisted keyspace into an in-memory `Map`.
 * 2. `get` / `set` / `delete` / `listKeys` serve SYNCHRONOUSLY from that mirror.
 * 3. Each mutation is WRITE-BEHIND-flushed to IndexedDB, in FIFO order.
 *
 * ## FIFO is a crash-safety obligation, not an optimization
 *
 * The driver's crash-consistency invariants depend on write ORDER between two
 * keys (join persists the snapshot then deletes the pending blob; close deletes
 * the snapshot before dropping in-memory state). So the write-behind queue is a
 * single serialized chain — on a crash the durable store is always a PREFIX of
 * the issued mutation sequence, never a reordered subset. Losing the un-flushed
 * tail is the accepted "lose the last unpersisted mutation" property; a reorder
 * would corrupt the invariants, so it is structurally prevented here.
 *
 * ## A durable-write fault fails closed on a later call
 *
 * A write-behind flush that faults is captured and re-thrown on the NEXT
 * synchronous call — surfaced as `[SCP-STORAGE-8010]` at the client boundary (the
 * wasm adapter re-codes the thrown exception). The interface only promises "on a
 * LATER call": the fault surfaces on whichever `get`/`set`/`delete`/`listKeys`
 * comes next, which need NOT belong to the same context whose write failed (the
 * write-behind queue is a single cross-context chain). The fault is never
 * swallowed — the driver treats the throw as a durable-write failure and fails
 * closed (poisoning the context it is operating on) rather than believing a lost
 * write landed.
 *
 * Restore fail-closed (corrupt / foreign / unreadable snapshot) is the DRIVER's
 * job (`SCP-STORAGE-8011/8012`) over the faithful bytes this adapter serves; a
 * preload read fault fails the {@link open} construction outright.
 */

import type { JsStorage } from "./types";

/** Options for {@link IndexedDbStorage.open}. */
export interface IndexedDbStorageOptions {
  /** Database name. Default `"scp-client"`. */
  readonly databaseName?: string;
  /** Object-store name. Default `"kv"`. */
  readonly storeName?: string;
  /**
   * The `IDBFactory` to use. Defaults to `globalThis.indexedDB`. Supply one for
   * a non-standard host or to inject a test double (e.g. `fake-indexeddb`).
   */
  readonly indexedDB?: IDBFactory;
}

/** A queued write-behind mutation, applied to IndexedDB in FIFO order. */
type WriteOp =
  | { readonly kind: "put"; readonly key: string; readonly value: Uint8Array }
  | {
      readonly kind: "delete";
      readonly key: string;
    };

function promisifyRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

export class IndexedDbStorage implements JsStorage {
  readonly #db: IDBDatabase;
  readonly #storeName: string;
  readonly #mirror: Map<string, Uint8Array>;

  /** The serialized write-behind chain — guarantees FIFO durable ordering. */
  #flushChain: Promise<void> = Promise.resolve();
  /** A captured durable-write fault, surfaced on the next synchronous call. */
  #pendingFault: unknown;

  private constructor(db: IDBDatabase, storeName: string, mirror: Map<string, Uint8Array>) {
    this.#db = db;
    this.#storeName = storeName;
    this.#mirror = mirror;
  }

  /**
   * Opens the database and preloads its keyspace into the in-memory mirror.
   *
   * Fails closed: if the store cannot be opened or read, the returned promise
   * rejects (no partial/empty mirror is silently served in place of real data).
   */
  static async open(options: IndexedDbStorageOptions = {}): Promise<IndexedDbStorage> {
    const dbName = options.databaseName ?? "scp-client";
    const storeName = options.storeName ?? "kv";
    const factory = options.indexedDB ?? globalThis.indexedDB;
    if (!factory) {
      throw new Error(
        "no IndexedDB is available in this environment — use InMemoryStorage, or pass options.indexedDB.",
      );
    }

    const db = await IndexedDbStorage.#openDatabase(factory, dbName, storeName);
    const mirror = await IndexedDbStorage.#preload(db, storeName);
    return new IndexedDbStorage(db, storeName, mirror);
  }

  static #openDatabase(
    factory: IDBFactory,
    dbName: string,
    storeName: string,
  ): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = factory.open(dbName, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(storeName)) {
          db.createObjectStore(storeName);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
    });
  }

  static async #preload(db: IDBDatabase, storeName: string): Promise<Map<string, Uint8Array>> {
    const tx = db.transaction(storeName, "readonly");
    const store = tx.objectStore(storeName);
    const keys = await promisifyRequest(store.getAllKeys());
    const values = await promisifyRequest(store.getAll());
    const mirror = new Map<string, Uint8Array>();
    for (let i = 0; i < keys.length; i += 1) {
      const key = keys[i];
      const value = values[i];
      if (typeof key === "string" && value !== undefined) {
        mirror.set(key, toBytes(value));
      }
    }
    return mirror;
  }

  get(key: string): Uint8Array | undefined {
    this.#throwIfFaulted();
    return this.#mirror.get(key);
  }

  set(key: string, value: Uint8Array): void {
    this.#throwIfFaulted();
    this.#mirror.set(key, value);
    this.#enqueue({ kind: "put", key, value });
  }

  delete(key: string): void {
    this.#throwIfFaulted();
    this.#mirror.delete(key);
    this.#enqueue({ kind: "delete", key });
  }

  listKeys(prefix: string): string[] {
    this.#throwIfFaulted();
    const out: string[] = [];
    for (const key of this.#mirror.keys()) {
      if (key.startsWith(prefix)) {
        out.push(key);
      }
    }
    return out;
  }

  /**
   * Resolves once every write-behind mutation issued so far has been durably
   * flushed (or rejects with the first flush fault). Useful for a test or an
   * embedder that wants a durability barrier; the driver never awaits it.
   */
  async flushed(): Promise<void> {
    await this.#flushChain;
    this.#throwIfFaulted();
  }

  #throwIfFaulted(): void {
    if (this.#pendingFault !== undefined) {
      const fault = this.#pendingFault;
      // Surface once, then clear: a still-broken backend re-captures on the next
      // failed flush, so the fault is not permanently sticky.
      this.#pendingFault = undefined;
      throw fault instanceof Error ? fault : new Error(String(fault));
    }
  }

  #enqueue(op: WriteOp): void {
    // Chain each op after the previous so durable writes land in issue order
    // (FIFO). A fault is captured — not thrown here (this is fire-and-forget) —
    // and surfaced on the next synchronous call via #throwIfFaulted.
    this.#flushChain = this.#flushChain
      .then(() => this.#runOp(op))
      .catch((err: unknown) => {
        if (this.#pendingFault === undefined) {
          this.#pendingFault = err;
        }
      });
  }

  #runOp(op: WriteOp): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.#db.transaction(this.#storeName, "readwrite");
      const store = tx.objectStore(this.#storeName);
      if (op.kind === "put") {
        store.put(op.value, op.key);
      } else {
        store.delete(op.key);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("IndexedDB write failed"));
      tx.onabort = () => reject(tx.error ?? new Error("IndexedDB write aborted"));
    });
  }
}

/** Normalizes an IndexedDB-stored binary value to a `Uint8Array`. */
function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  // A non-binary stored value cannot be a valid snapshot blob; surface it as
  // empty so the driver's restore fails closed on the malformed bytes rather
  // than this adapter guessing.
  return new Uint8Array(0);
}
