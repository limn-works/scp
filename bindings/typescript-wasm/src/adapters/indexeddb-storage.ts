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
 * ## The durable store is always a strict PREFIX (ordering + sticky poison)
 *
 * The driver's crash-consistency invariants depend on write ORDER between two
 * keys (join persists the snapshot THEN deletes the pending blob; close deletes
 * the snapshot before dropping in-memory state). The durable store must therefore
 * always be a strict PREFIX of the issued mutation sequence — never a gap (a
 * later op landing durably while an earlier one was lost). Two mechanisms
 * together give the prefix:
 *
 * 1. **Serialization → ordering.** The write-behind queue is a single serialized
 *    chain, so ops flush in issue order (no reorder).
 * 2. **Sticky poison → prefix.** A durable-write fault poisons the chain: once any
 *    op faults, NO op issued after it is ever flushed, and the instance fails
 *    every subsequent synchronous call closed. Losing the un-flushed tail from the
 *    first failed op onward is the accepted "lose the last unpersisted mutations"
 *    property. WITHOUT the sticky poison a non-uniform fault (e.g. a quota-exceeded
 *    `put` that aborts, followed by a `delete` that frees space and succeeds) would
 *    land the later op while the earlier was lost — a GAP that corrupts the
 *    driver's write-ordering (deleting a pending blob whose snapshot put was lost →
 *    a consumed KeyPackage with no recoverable context). Skipping every op after a
 *    fault keeps the store a strict prefix by construction.
 *
 * ## A durable-write fault fails closed STICKILY
 *
 * A write-behind flush that faults is captured and re-thrown on the NEXT
 * synchronous call — surfaced as `[SCP-STORAGE-8010]` at the client boundary (the
 * wasm adapter re-codes the thrown exception) — and STAYS surfaced on every call
 * thereafter (sticky, never cleared). The interface only promises "on a LATER
 * call": the fault surfaces on whichever `get`/`set`/`delete`/`listKeys` comes
 * next, which need NOT belong to the same context whose write failed (the
 * write-behind queue is a single cross-context chain; a durable fault like quota
 * is store-wide, so failing the whole instance closed is honest — it is NOT made
 * per-context). The driver treats the throw as a durable-write failure and fails
 * closed (poisoning the context it is operating on). **Recovery is re-opening the
 * store**: a fresh {@link open} re-preloads the durable prefix (all mutations up
 * to, but not including, the first failed op) into a clean, un-poisoned instance.
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
  /**
   * A captured durable-write fault. Once set it stays set (sticky) — every
   * subsequent synchronous call fails closed until a fresh {@link open}.
   */
  #pendingFault: unknown;
  /**
   * Whether the write-behind chain is poisoned by a durable-write fault. Once
   * true, NO further queued op is flushed — so the durable store stays a strict
   * PREFIX of the issued mutation sequence (never a gap). Sticky until re-open.
   */
  #chainPoisoned = false;

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
      // STICKY: do NOT clear the fault. A durable-write fault (e.g. quota) is
      // store-wide, and every op issued after it was NEVER flushed (the chain is
      // poisoned), so the durable store is a strict prefix up to the failed op.
      // Failing every subsequent call closed — until a fresh open() re-preloads
      // that consistent prefix — is the honest crash-safe semantics; clearing the
      // fault would let the caller believe the store recovered when it did not.
      const fault = this.#pendingFault;
      throw fault instanceof Error ? fault : new Error(String(fault));
    }
  }

  #enqueue(op: WriteOp): void {
    // Chain each op after the previous so durable writes land in issue order
    // (FIFO), AND gate the run on the poison flag so once any op faults, no op
    // issued after it is ever flushed. Together these keep the durable store a
    // strict PREFIX (ordering + sticky poison — see the class doc for the worked
    // gap scenario). The fault is captured (fire-and-forget) and surfaced stickily
    // on the next synchronous call via #throwIfFaulted.
    this.#flushChain = this.#flushChain
      .then(() => {
        if (this.#chainPoisoned) {
          return; // skip — keep the durable store a strict prefix
        }
        return this.#runOp(op);
      })
      .catch((err: unknown) => {
        this.#chainPoisoned = true;
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
