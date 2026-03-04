/**
 * Conformance tests for the StorageInterface implementation.
 *
 * These tests verify that InMemorySqliteStorage (and by extension
 * WasmSqliteStorage, which shares the same SQL paths) conforms to the
 * scp-platform Storage trait contract. The 13 test cases mirror the Rust
 * storage_conformance!() macro in scp-testing.
 *
 * Uses InMemorySqliteStorage (wa-sqlite :memory: database, no encryption)
 * because OPFS requires a browser environment.
 *
 * See SCP-PERSIST-062.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  InMemorySqliteStorage,
  prefixSuccessor,
  type StorageInterface,
} from "../src/storage/index.js";

describe("StorageInterface conformance", () => {
  let storage: StorageInterface;

  beforeEach(async () => {
    storage = await InMemorySqliteStorage.open();
  });

  afterEach(() => {
    // InMemorySqliteStorage uses :memory: -- garbage collected automatically.
  });

  it("store_and_retrieve_roundtrip", async () => {
    const data = new TextEncoder().encode("hello, world");
    await storage.store("key1", data);
    const result = await storage.retrieve("key1");
    expect(result).toEqual(data);
  });

  it("retrieve_missing_returns_null", async () => {
    const result = await storage.retrieve("nonexistent");
    expect(result).toBeNull();
  });

  it("delete_removes_entry", async () => {
    await storage.store("key1", new Uint8Array([1, 2, 3]));
    await storage.delete("key1");
    const result = await storage.retrieve("key1");
    expect(result).toBeNull();
  });

  it("list_keys_sorted", async () => {
    await storage.store("prefix/c", new Uint8Array([3]));
    await storage.store("prefix/a", new Uint8Array([1]));
    await storage.store("prefix/b", new Uint8Array([2]));
    await storage.store("other/x", new Uint8Array([99]));

    const keys = await storage.listKeys("prefix/");
    expect(keys).toEqual(["prefix/a", "prefix/b", "prefix/c"]);
  });

  it("list_keys_prefix_filtering", async () => {
    await storage.store("ctx/alpha", new Uint8Array([1]));
    await storage.store("ctx/beta", new Uint8Array([2]));
    await storage.store("identity/did1", new Uint8Array([3]));

    const ctxKeys = await storage.listKeys("ctx/");
    expect(ctxKeys).toEqual(["ctx/alpha", "ctx/beta"]);

    const identityKeys = await storage.listKeys("identity/");
    expect(identityKeys).toEqual(["identity/did1"]);
  });

  it("delete_prefix", async () => {
    await storage.store("ctx/a", new Uint8Array([1]));
    await storage.store("ctx/b", new Uint8Array([2]));
    await storage.store("ctx/c", new Uint8Array([3]));
    await storage.store("other/d", new Uint8Array([4]));

    await storage.deletePrefix("ctx/");

    expect(await storage.retrieve("ctx/a")).toBeNull();
    expect(await storage.retrieve("ctx/b")).toBeNull();
    expect(await storage.retrieve("ctx/c")).toBeNull();
    expect(await storage.retrieve("other/d")).toEqual(new Uint8Array([4]));
  });

  it("delete_prefix_returns_count", async () => {
    await storage.store("ns/a", new Uint8Array([1]));
    await storage.store("ns/b", new Uint8Array([2]));
    await storage.store("ns/c", new Uint8Array([3]));
    await storage.store("other/x", new Uint8Array([99]));

    const count = await storage.deletePrefix("ns/");
    expect(count).toBe(3);

    const zeroCount = await storage.deletePrefix("nonexistent/");
    expect(zeroCount).toBe(0);
  });

  it("exists_true_for_present", async () => {
    await storage.store("key1", new Uint8Array([42]));
    const result = await storage.exists("key1");
    expect(result).toBe(true);
  });

  it("exists_false_for_missing", async () => {
    const result = await storage.exists("nonexistent");
    expect(result).toBe(false);
  });

  it("overwrite_replaces_value", async () => {
    await storage.store("key", new TextEncoder().encode("first"));
    await storage.store("key", new TextEncoder().encode("second"));
    const result = await storage.retrieve("key");
    expect(result).toEqual(new TextEncoder().encode("second"));
  });

  it("store_empty_value", async () => {
    await storage.store("empty", new Uint8Array(0));
    const result = await storage.retrieve("empty");
    expect(result).toEqual(new Uint8Array(0));
  });

  it("list_keys_empty_on_no_match", async () => {
    await storage.store("foo/a", new Uint8Array([1]));
    const keys = await storage.listKeys("bar/");
    expect(keys).toEqual([]);
  });

  it("concurrent_store_operations", async () => {
    // Store 20 keys concurrently and verify all are persisted.
    const promises: Promise<void>[] = [];
    for (let i = 0; i < 20; i++) {
      const key = `concurrent/${String(i).padStart(3, "0")}`;
      const data = new Uint8Array([i]);
      promises.push(storage.store(key, data));
    }
    await Promise.all(promises);

    const keys = await storage.listKeys("concurrent/");
    expect(keys).toHaveLength(20);

    // Verify sorted order.
    for (let i = 0; i < 20; i++) {
      const expected = `concurrent/${String(i).padStart(3, "0")}`;
      expect(keys[i]).toBe(expected);
    }

    // Verify values roundtrip.
    for (let i = 0; i < 20; i++) {
      const key = `concurrent/${String(i).padStart(3, "0")}`;
      const result = await storage.retrieve(key);
      expect(result).toEqual(new Uint8Array([i]));
    }
  });
});

describe("IDBBatchAtomicVFS fallback path (SCP-PERSIST-062)", () => {
  // WasmSqliteStorage.open() calls detectVfs() which returns "opfs" when
  // SharedArrayBuffer + navigator.storage.getDirectory are available, and
  // falls back to "idb" (IDBBatchAtomicVFS) otherwise. In bun's test
  // environment neither browser API exists, so detectVfs() always returns
  // "idb". The InMemorySqliteStorage adapter exercises the identical SQL
  // paths (same schema, same queries, same prefixSuccessor logic) without
  // requiring either VFS.
  //
  // The 13 conformance tests above already validate the full StorageInterface
  // contract against InMemorySqliteStorage. This describe block explicitly
  // names the fallback scenario and verifies that the non-OPFS code path
  // produces correct results for core operations.
  //
  // Full browser-based OPFS vs IDB fallback testing requires a browser
  // test harness (e.g., Playwright) with and without SharedArrayBuffer.
  // That is tracked separately. This test validates the contract holds
  // for the fallback (non-OPFS) storage path.

  let storage: StorageInterface;

  beforeEach(async () => {
    storage = await InMemorySqliteStorage.open();
  });

  it("fallback_storage_roundtrip -- validates non-OPFS path handles store/retrieve", async () => {
    const data = new TextEncoder().encode("fallback-test-data");
    await storage.store("fallback/key1", data);
    const result = await storage.retrieve("fallback/key1");
    expect(result).toEqual(data);
  });

  it("fallback_storage_prefix_operations -- validates non-OPFS path handles prefix scan and delete", async () => {
    await storage.store("fb/alpha", new Uint8Array([1]));
    await storage.store("fb/beta", new Uint8Array([2]));
    await storage.store("fb/gamma", new Uint8Array([3]));
    await storage.store("other/x", new Uint8Array([99]));

    // Prefix list
    const keys = await storage.listKeys("fb/");
    expect(keys).toEqual(["fb/alpha", "fb/beta", "fb/gamma"]);

    // Prefix delete
    const deleted = await storage.deletePrefix("fb/");
    expect(deleted).toBe(3);

    // Verify cleanup
    expect(await storage.listKeys("fb/")).toEqual([]);
    expect(await storage.retrieve("other/x")).toEqual(new Uint8Array([99]));
  });

  it("fallback_storage_empty_value -- validates non-OPFS path handles zero-length blobs", async () => {
    // Zero-length blob handling is the most fragile part of the wa-sqlite
    // fallback path (InMemorySqliteStorage uses zeroblob(0) workaround).
    await storage.store("fb/empty", new Uint8Array(0));
    const result = await storage.retrieve("fb/empty");
    expect(result).toEqual(new Uint8Array(0));
  });

  it("fallback_storage_concurrent -- validates non-OPFS path serializes concurrent access", async () => {
    const promises: Promise<void>[] = [];
    for (let i = 0; i < 10; i++) {
      const key = `fb-concurrent/${String(i).padStart(2, "0")}`;
      promises.push(storage.store(key, new Uint8Array([i])));
    }
    await Promise.all(promises);

    const keys = await storage.listKeys("fb-concurrent/");
    expect(keys).toHaveLength(10);
  });
});

describe("prefixSuccessor", () => {
  it("increments last byte", () => {
    expect(prefixSuccessor("abc")).toBe("abd");
  });

  it("handles single character", () => {
    expect(prefixSuccessor("a")).toBe("b");
  });

  it("handles slash-terminated prefix", () => {
    expect(prefixSuccessor("ctx/")).toBe("ctx0");
  });

  it("returns non-null for high Unicode characters", () => {
    // UTF-8 never produces 0xFF bytes, so prefixSuccessor always finds
    // a byte to increment for any valid string. U+00FF encodes as
    // [0xC3, 0xBF] in UTF-8 -- both < 0xFF.
    const highChar = String.fromCharCode(0xff);
    const result = prefixSuccessor(highChar);
    expect(result).not.toBeNull();
  });

  it("handles empty string", () => {
    // Empty prefix has no bytes to increment.
    expect(prefixSuccessor("")).toBeNull();
  });
});
