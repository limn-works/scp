/**
 * Unit tests for {@link IndexedDbStorage} against `fake-indexeddb`: the
 * synchronous-mirror reads, FIFO write-behind durability, and the fail-closed
 * durable-write fault surfaced on a later call (ADR-057 T2).
 */

import { expect, test } from "bun:test";
import { IDBFactory } from "fake-indexeddb";
import { IndexedDbStorage } from "../src/index";

function bytes(...xs: number[]): Uint8Array {
  return new Uint8Array(xs);
}

test("serves get/set/delete/listKeys synchronously from the mirror", async () => {
  const storage = await IndexedDbStorage.open({
    indexedDB: new IDBFactory(),
    databaseName: "mirror-db",
  });
  expect(storage.get("scp-client/ctx/a")).toBeUndefined();
  storage.set("scp-client/ctx/a", bytes(1, 2, 3));
  storage.set("scp-client/ctx/b", bytes(4));
  storage.set("scp-client/pending/a", bytes(9));
  expect(storage.get("scp-client/ctx/a")).toEqual(bytes(1, 2, 3));
  expect(storage.listKeys("scp-client/ctx/").sort()).toEqual([
    "scp-client/ctx/a",
    "scp-client/ctx/b",
  ]);
  storage.delete("scp-client/ctx/a");
  expect(storage.get("scp-client/ctx/a")).toBeUndefined();
});

test("write-behind persists in FIFO order and reload restores it", async () => {
  const factory = new IDBFactory();
  const s1 = await IndexedDbStorage.open({ indexedDB: factory, databaseName: "durable-db" });
  // A set THEN a delete of the same key: FIFO application means the delete lands
  // after the set, so the key is durably absent (the join/close ordering the
  // driver's crash-consistency invariants depend on).
  s1.set("scp-client/ctx/a", bytes(1, 2, 3));
  s1.set("scp-client/ctx/b", bytes(4));
  s1.set("scp-client/pending/a", bytes(9));
  s1.delete("scp-client/ctx/b");
  await s1.flushed();

  // A fresh instance over the SAME durable store preloads the persisted keyspace.
  const s2 = await IndexedDbStorage.open({ indexedDB: factory, databaseName: "durable-db" });
  expect(s2.get("scp-client/ctx/a")).toEqual(bytes(1, 2, 3));
  expect(s2.get("scp-client/ctx/b")).toBeUndefined(); // delete applied after set (FIFO)
  expect(s2.get("scp-client/pending/a")).toEqual(bytes(9));
  expect(s2.listKeys("scp-client/").sort()).toEqual(["scp-client/ctx/a", "scp-client/pending/a"]);
});

/**
 * Wraps a real `IDBFactory` so each database `transaction(...)` consults a
 * fault-policy predicate: `shouldFault(txArgs)` returns a message to THROW for
 * that transaction, or `undefined` to pass it through to the real store. The
 * caller keeps its arming state local — one helper serves both the uniform and
 * the non-uniform (fail-then-succeed) fault shapes. Faults are injected AFTER
 * open/preload succeed (open uses the same `transaction` path only for the
 * readonly preload, which policies below leave untouched).
 */
function faultingFactory(
  real: IDBFactory,
  shouldFault: (txArgs: unknown[]) => string | undefined,
): IDBFactory {
  const wrapDb = (db: IDBDatabase): IDBDatabase =>
    new Proxy(db, {
      get(target, prop, receiver) {
        if (prop === "transaction") {
          return (...args: unknown[]) => {
            const msg = shouldFault(args);
            if (msg !== undefined) {
              throw new Error(msg);
            }
            return (target.transaction as (...a: unknown[]) => unknown)(...args);
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

  const wrapOpenRequest = (request: IDBOpenDBRequest): IDBOpenDBRequest =>
    new Proxy(request, {
      get(target, prop, receiver) {
        if (prop === "result") {
          return wrapDb(target.result);
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      },
      set(target, prop, value) {
        return Reflect.set(target, prop, value);
      },
    });

  return {
    open: (name: string, version?: number) => wrapOpenRequest(real.open(name, version)),
  } as unknown as IDBFactory;
}

test("a durable-write fault surfaces fail-closed on a later call", async () => {
  // Uniform policy: fault every transaction once armed.
  const arm = { fail: false };
  const storage = await IndexedDbStorage.open({
    indexedDB: faultingFactory(new IDBFactory(), () =>
      arm.fail ? "simulated IndexedDB write fault" : undefined,
    ),
    databaseName: "fault-db",
  });

  // A clean write flushes fine.
  storage.set("scp-client/ctx/a", bytes(1));
  await storage.flushed();

  // Arm the fault: the next write-behind flush faults; it must surface (not be
  // swallowed) on a later synchronous call — the driver then poisons the context
  // rather than trusting a lost write durably landed.
  arm.fail = true;
  storage.set("scp-client/ctx/b", bytes(2));
  await expect(storage.flushed()).rejects.toThrow(/simulated IndexedDB write fault/);
});

test("a NON-UNIFORM fault keeps the durable store a strict PREFIX (sticky, no gap)", async () => {
  const factory = new IDBFactory();
  const dbName = "prefix-db";

  // Seed a pre-existing durable key K on a clean instance.
  const seed = await IndexedDbStorage.open({ indexedDB: factory, databaseName: dbName });
  seed.set("scp-client/ctx/keep", bytes(7, 7, 7));
  await seed.flushed();

  // Open an instance whose FIRST readwrite tx faults; later ops would succeed —
  // the non-uniform crash-consistency trigger (a quota-exceeded `put` that aborts,
  // then a `delete` that frees space and would otherwise land).
  const arm = { failFirstWrite: false };
  const storage = await IndexedDbStorage.open({
    indexedDB: faultingFactory(factory, (args) => {
      if (arm.failFirstWrite && args[1] === "readwrite") {
        arm.failFirstWrite = false; // fault ONLY the first readwrite tx
        return "simulated non-uniform IndexedDB write fault (first write only)";
      }
      return undefined;
    }),
    databaseName: dbName,
  });
  expect(storage.get("scp-client/ctx/keep")).toEqual(bytes(7, 7, 7)); // preloaded prefix

  // Mirror the driver's join write-ordering: persist the new snapshot (put),
  // THEN delete a DIFFERENT pre-existing key. The put faults; if the delete were
  // NOT skipped it would succeed (freeing "space") and remove K — a GAP.
  arm.failFirstWrite = true;
  storage.set("scp-client/ctx/new", bytes(1, 2, 3));
  storage.delete("scp-client/ctx/keep");

  // Drain the write-behind chain (the put faults → chain poisoned → delete skipped).
  await storage.flushed().catch(() => {});

  // (a) The next synchronous call throws (the fault is surfaced) …
  expect(() => storage.get("scp-client/ctx/keep")).toThrow(/non-uniform/);
  // (c) … and a FURTHER call still throws — the fault is STICKY, not cleared.
  expect(() => storage.set("scp-client/ctx/z", bytes(9))).toThrow(/non-uniform/);

  // (b) Re-open a fresh, un-poisoned instance over the same durable store: the
  // delete was SKIPPED (poison gate), so K survives — the store is still a strict
  // prefix — and the faulted put's key is absent. Recovery = re-open re-preloads.
  const reopened = await IndexedDbStorage.open({ indexedDB: factory, databaseName: dbName });
  expect(reopened.get("scp-client/ctx/keep")).toEqual(bytes(7, 7, 7)); // NOT deleted (no gap)
  expect(reopened.get("scp-client/ctx/new")).toBeUndefined(); // put faulted → never landed
});
