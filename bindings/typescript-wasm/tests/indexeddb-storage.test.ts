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
 * Wraps a real `IDBFactory` so the opened database's `transaction()` throws once
 * `arm.fail` is set — a durable-write fault injected AFTER open/preload succeed.
 */
function faultingFactory(real: IDBFactory, arm: { fail: boolean }): IDBFactory {
  const wrapDb = (db: IDBDatabase): IDBDatabase =>
    new Proxy(db, {
      get(target, prop, receiver) {
        if (prop === "transaction") {
          return (...args: unknown[]) => {
            if (arm.fail) {
              throw new Error("simulated IndexedDB write fault");
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
  const arm = { fail: false };
  const storage = await IndexedDbStorage.open({
    indexedDB: faultingFactory(new IDBFactory(), arm),
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
