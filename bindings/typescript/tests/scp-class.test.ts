/**
 * Tests for the `SCP` class exposed by the NAPI bridge (#1549 Phase 4 PR 1).
 *
 * `SCP` is the caller-owned handle that wraps a `NapiBridgeInstance`.
 * Each `SCP` instance has a distinct `instanceId`; `SCP.default()` returns
 * a wrapper around the process-wide default instance so multiple calls
 * share state.
 *
 * The tests verify:
 * - `new SCP()` constructs a fresh instance with a non-zero `instanceId`.
 * - `SCP.default()` returns the same instance id on repeated calls.
 * - Two fresh `new SCP()` instances have distinct `instanceId`s.
 * - Lifecycle operations (`suspend()`, `resume()`, `shutdown()`) end-to-end.
 *
 * These tests run against the native NAPI bridge. If the platform-specific
 * `@limn-works/scp-ts-napi-*` package is not available (e.g. in browser
 * CI), all tests are skipped gracefully.
 */

import { describe, expect, test } from "bun:test";
import { createRequire } from "node:module";

import { __clampShutdownMillisForTests, __serializeStorageConfigForTests } from "../src/scp";

// ---------------------------------------------------------------------------
// Load the raw native addon — `SCP` is exposed directly on the addon, not
// through the `Bridge` interface (which only covers the free-function
// façade). The TypeScript SDK wrapper for `SCP` lands in a subsequent PR.
// ---------------------------------------------------------------------------

// biome-ignore lint/suspicious/noExplicitAny: dynamic native addon loading
let addon: any = null;
let skipReason = "";

try {
  const platform = process.platform;
  const arch = process.arch;
  const platformMap: Record<string, string> = {
    darwin: "darwin",
    linux: "linux",
    win32: "win32",
  };
  const archMap: Record<string, string> = {
    arm64: "arm64",
    x64: "x64",
  };
  const os = platformMap[platform] ?? platform;
  const cpu = archMap[arch] ?? arch;
  const packageName = `@limn-works/scp-ts-napi-${os}-${cpu}`;

  const req = createRequire(import.meta.url);
  addon = req(packageName);

  if (typeof addon.SCP !== "function") {
    throw new Error(
      "SCP class not exported from native addon — rebuild with the Phase 4 PR 1 changes",
    );
  }
} catch (e: unknown) {
  skipReason =
    e instanceof Error ? `native addon unavailable: ${e.message}` : "native addon unavailable";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!addon)(`SCP class (Phase 4 PR 1) [${skipReason}]`, () => {
  test("new SCP() constructs an instance with a non-zero instanceId", () => {
    const scp = new addon.SCP();
    // instanceId is exposed as a string (u64 doesn't fit in a JS number).
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).not.toBe("0");
    expect(scp.instanceId.length).toBeGreaterThan(0);
    // Basic integer shape.
    expect(/^[0-9]+$/.test(scp.instanceId)).toBe(true);
  });

  test("SCP.default() returns the same instance id on repeated calls", () => {
    const a = addon.SCP.default();
    const b = addon.SCP.default();
    expect(a.instanceId).toBe(b.instanceId);
  });

  test("two fresh new SCP() instances have distinct instanceIds", () => {
    const a = new addon.SCP();
    const b = new addon.SCP();
    expect(a.instanceId).not.toBe(b.instanceId);
  });

  test("SCP.withStorage accepts an in-memory config and produces a fresh instance", () => {
    const scp = addon.SCP.withStorage(JSON.stringify({ type: "in_memory" }));
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).not.toBe("0");
  });

  test("SCP.withStorage rejects an unknown storage type", () => {
    expect(() => addon.SCP.withStorage(JSON.stringify({ type: "unknown_type" }))).toThrow(
      /unsupported storage type|SCP-VALID-7005/,
    );
  });

  test("SCP.withPersistence returns a fresh instance", () => {
    const scp = addon.SCP.withPersistence();
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).not.toBe("0");
  });

  test("handles minted through the default bridge are stamped with the default instance id", async () => {
    // PR 1 only mints handles through the default bridge (the free-function
    // façade; per-instance mint methods migrate onto `SCP` in PR 2). This
    // test therefore verifies the *stamping* invariant — every handle
    // carries a base-10 u64 `instanceId` string that matches the default
    // instance's id — not a cross-instance mismatch. Cross-instance
    // rejection lives in the Rust-side affinity test suite
    // (`bridge_instance` tests in `crates/scp-ffi/common`) and will gain
    // a JS-level assertion once PR 2 lands per-instance mint methods.
    if (typeof addon.identityCreate !== "function") {
      // No identity API exposed — can't exercise the affinity path.
      return;
    }
    const defaultInstance = addon.SCP.default();
    const identity = await addon.identityCreate("in_memory");
    expect(typeof identity.instanceId).toBe("string");
    expect(identity.instanceId).not.toBe("0");
    expect(identity.instanceId).toBe(defaultInstance.instanceId);
  });

  test("suspend / resume round-trip succeeds", async () => {
    const scp = new addon.SCP();
    expect(() => scp.suspend()).not.toThrow();
    // `resume()` is async since #1678 — the NAPI bridge chains
    // transport reconnect from pending relay URLs and persisted
    // context restoration before the promise settles.
    await expect(scp.resume()).resolves.toBeUndefined();
  });

  test("SCP.withStorage accepts a sqlite config with Uint8Array key", () => {
    // PR 3 extension — SQLCipher-encrypted filesystem storage
    // (closes #1260, #1491). We only assert the factory accepts the
    // config shape and produces a live instance; the durability
    // round-trip is covered by the Rust-side integration tests.
    const { mkdtempSync } = require("node:fs") as typeof import("node:fs");
    const { tmpdir } = require("node:os") as typeof import("node:os");
    const { join } = require("node:path") as typeof import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "scp-sqlite-"));
    const key = new Uint8Array(32);
    // Deterministic key so the test is reproducible.
    for (let i = 0; i < key.length; i += 1) {
      key[i] = i;
    }
    const keyArray = Array.from(key);
    const scp = addon.SCP.withStorage(JSON.stringify({ type: "sqlite", path: dir, key: keyArray }));
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).not.toBe("0");
  });

  test("SCP.withStorage accepts a sqlite config with a hex-encoded key", () => {
    const { mkdtempSync } = require("node:fs") as typeof import("node:fs");
    const { tmpdir } = require("node:os") as typeof import("node:os");
    const { join } = require("node:path") as typeof import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "scp-sqlite-hex-"));
    // 32 zero bytes as hex.
    const hexKey = "00".repeat(32);
    const scp = addon.SCP.withStorage(JSON.stringify({ type: "sqlite", path: dir, key: hexKey }));
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).not.toBe("0");
  });

  test("shutdown(timeoutMillis) resolves without error", async () => {
    const scp = new addon.SCP();
    // Native `SCP.shutdown` takes unsigned milliseconds after the #1549
    // Phase 4 unit unification — 1000 ms is enough for any pending
    // tasks and short enough to not stall the suite.
    await expect(scp.shutdown(1000)).resolves.toBeUndefined();
  });

  test("shutdown is idempotent — a second call resolves without error", async () => {
    const scp = new addon.SCP();
    await expect(scp.shutdown(1000)).resolves.toBeUndefined();
    // Second call should not throw — AlreadyShutDown maps to a harmless
    // lifecycle observation on the SDK surface.
    await expect(scp.shutdown(1000)).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// SDK-wrapper shutdown clamp — pure-function regression tests
// ---------------------------------------------------------------------------
//
// These tests exercise the float-seconds → millis clamp on the SDK
// wrapper's `shutdown(timeoutSecs)` via the internal
// `__clampShutdownMillisForTests` helper. Pure logic, no native addon
// required — runs on every platform. The clamp ceiling widened from
// `u32::MAX` to `Number.MAX_SAFE_INTEGER` when the NAPI bridge moved to
// `u64` (#1692).
describe("SCP.shutdown timeout clamp (round 5 RED-2001, #1692)", () => {
  const MAX_MILLIS = Number.MAX_SAFE_INTEGER;

  test("shutdown accepts Infinity as wait-forever", () => {
    // Regression for round 5 RED-2001: the previous clamp ordering
    // (`if !isFinite(t) || t <= 0: millis = 0`) caught Infinity in the
    // first branch and aborted the shutdown instead of waiting forever.
    expect(__clampShutdownMillisForTests(Number.POSITIVE_INFINITY)).toBe(MAX_MILLIS);
  });

  test("-Infinity maps to abort (0), not wait-forever", () => {
    // The Infinity-is-wait-forever exemption is deliberately asymmetric.
    expect(__clampShutdownMillisForTests(Number.NEGATIVE_INFINITY)).toBe(0);
  });

  test("NaN maps to abort (0)", () => {
    expect(__clampShutdownMillisForTests(Number.NaN)).toBe(0);
  });

  test("negative values map to abort (0)", () => {
    expect(__clampShutdownMillisForTests(-1.5)).toBe(0);
  });

  test("zero maps to abort (0)", () => {
    expect(__clampShutdownMillisForTests(0)).toBe(0);
  });

  test("MAX_SAFE_INTEGER-overflowing values clamp to MAX_MILLIS (#1692)", () => {
    // 1e20 s * 1000 = 1e23 ms, far beyond MAX_SAFE_INTEGER (~9.007e15).
    // Previously clamped at u32::MAX; after the NAPI u64 widening the
    // ceiling is the JS `number` safe-integer boundary.
    expect(__clampShutdownMillisForTests(1e20)).toBe(MAX_MILLIS);
  });

  test("finite fractional seconds round to nearest ms", () => {
    // 0.25051 s → 250.51 ms → Math.round → 251.
    expect(__clampShutdownMillisForTests(0.25051)).toBe(251);
    // 0.2504 s → 250.4 ms → 250.
    expect(__clampShutdownMillisForTests(0.2504)).toBe(250);
  });

  test("default 5-second timeout resolves to 5000 ms", () => {
    expect(__clampShutdownMillisForTests(5)).toBe(5000);
  });
});

// ---------------------------------------------------------------------------
// StorageConfig wire-format — pure-function tests exercising the
// `serializeStorageConfig` helper used by `new SCP({ storage })`.
//
// No native addon required; these tests assert the JSON that crosses
// the FFI boundary matches what the NAPI `SCP.withStorage` parser
// accepts (hex string OR number[] for `key`). See
// `crates/scp-ffi/napi/src/scp.rs::with_storage` for the accept shape.
// ---------------------------------------------------------------------------

describe("serializeStorageConfig (PR 3 SQLite wire format)", () => {
  test("in_memory passes through unchanged", () => {
    expect(__serializeStorageConfigForTests({ type: "in_memory" })).toBe(
      JSON.stringify({ type: "in_memory" }),
    );
  });

  test("sqlite + Uint8Array key serializes key as a JSON number array", () => {
    // Regression guard — `JSON.stringify` on a `Uint8Array` produces
    // an object shape (`{"0":1,"1":2,...}`) that the NAPI accept
    // path rejects. The serializer must normalize to `number[]`.
    const bytes = new Uint8Array([1, 2, 3, 255]);
    const wire = __serializeStorageConfigForTests({
      type: "sqlite",
      path: "/tmp/scp-db",
      key: bytes,
    });
    const parsed = JSON.parse(wire);
    expect(parsed.type).toBe("sqlite");
    expect(parsed.path).toBe("/tmp/scp-db");
    expect(Array.isArray(parsed.key)).toBe(true);
    expect(parsed.key).toEqual([1, 2, 3, 255]);
  });

  test("sqlite + string key passes through as-is (hex form)", () => {
    const wire = __serializeStorageConfigForTests({
      type: "sqlite",
      path: "/tmp/scp-db-hex",
      key: "deadbeef",
    });
    expect(JSON.parse(wire)).toEqual({
      type: "sqlite",
      path: "/tmp/scp-db-hex",
      key: "deadbeef",
    });
  });
});
