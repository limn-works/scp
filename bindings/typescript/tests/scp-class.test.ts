/**
 * Tests for the `SCP` class exposed by the NAPI bridge (#1549 Phase 4).
 *
 * `SCP` is the caller-owned handle that wraps a `NapiBridgeInstance`.
 * Each `SCP` instance has a distinct `instanceId`. Since PR 4 (ADR-048),
 * there is no process-wide default instance — every caller constructs
 * an explicit `new SCP({ storage: { type: "in_memory" } })`.
 *
 * The tests verify:
 * - `new SCP({ storage: { type: "in_memory" } })` constructs a fresh instance with a non-zero `instanceId`.
 * - Two fresh `new SCP({ storage: { type: "in_memory" } })` instances have distinct `instanceId`s.
 * - Lifecycle operations (`suspend()`, `resume()`, `shutdown()`) end-to-end.
 *
 * These tests run against the native NAPI bridge. If the platform-specific
 * `@limn-works/scp-ts-napi-*` package is not available (e.g. in browser
 * CI), all tests are skipped gracefully.
 */

import { describe, expect, test } from "bun:test";
import { createRequire } from "node:module";

import { ValidationError } from "../src/errors";
import { __clampShutdownMillisForTests, __serializeStorageConfigForTests, SCP } from "../src/scp";

// ---------------------------------------------------------------------------
// Compile-time guard: storage selection is mandatory (spec §17.6).
//
// `new SCP()` with no argument — or with an options object that omits
// `storage` — must be a TYPE error. The `@ts-expect-error` directives
// below fail the typecheck (`tsc --noEmit -p tsconfig.test.json`) if the
// constructor ever again accepts a missing storage selection. This block
// is never executed (it is type-only), so it does not depend on the native
// addon being present.
// ---------------------------------------------------------------------------
function __storageIsRequiredAtCompileTime(): void {
  // @ts-expect-error storage selection is required — `new SCP()` must not compile.
  void (() => new SCP());
  // @ts-expect-error `storage` is a required field of ScpOptions.
  void (() => new SCP({}));
  // A valid explicit selection DOES type-check.
  void (() => new SCP({ storage: { type: "in_memory" } }));
}
void __storageIsRequiredAtCompileTime;

// ---------------------------------------------------------------------------
// Runtime fail-closed guard (spec §17.6): the compile-time guard above only
// protects TS callers. A JS caller — or TS that defeats the types via `any`
// or a type-suppression directive — can still reach the constructor with
// `new SCP()` or `new SCP({})`. The SDK constructor must throw the documented
// `SCP-STORAGE-8000` ValidationError, NOT a cryptic internal TypeError.
// These tests run WITHOUT the native addon — the guard fires before any
// addon load — mirroring the Python wrapper's
// `test_bare_wrapper_construction_is_typeerror`.
// ---------------------------------------------------------------------------
describe("SCP constructor — runtime storage-selection guard (spec §17.6)", () => {
  // The SDK constructor throws a `ValidationError` whose stable `code` is
  // `SCP-STORAGE-8000` (carried in `.code`, not the human-readable message),
  // so we assert on the typed error rather than a message regex.
  function expectStorage8000(construct: () => unknown): void {
    let thrown: unknown;
    try {
      construct();
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(ValidationError);
    expect((thrown as ValidationError).code).toBe("SCP-STORAGE-8000");
  }

  test("new SCP({}) (storage omitted) throws SCP-STORAGE-8000", () => {
    // biome-ignore lint/suspicious/noExplicitAny: defeating the type to exercise the JS-caller path
    expectStorage8000(() => new SCP({} as any));
  });

  test("new SCP() (no argument) throws SCP-STORAGE-8000", () => {
    // biome-ignore lint/suspicious/noExplicitAny: defeating the type to exercise the JS-caller path
    expectStorage8000(() => new (SCP as any)());
  });
});

// ---------------------------------------------------------------------------
// Load the raw native addon — `SCP` is exposed directly on the addon.
// The `Bridge` interface in `internal/bridge.ts` now forwards
// per-instance calls onto the native `SCP` handle; the free-function
// façade that the interface used to wrap was deleted in Phase 4 PR 4
// (#1549, ADR-048). The TypeScript SDK wrapper for `SCP` lives in
// `src/scp.ts`.
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
    throw new Error("SCP class not exported from native addon — rebuild with the Phase 4 changes");
  }
} catch (e: unknown) {
  skipReason =
    e instanceof Error ? `native addon unavailable: ${e.message}` : "native addon unavailable";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!addon)(`SCP class (Phase 4) [${skipReason}]`, () => {
  test("new SCP() constructs an instance with a non-zero instanceId", () => {
    const scp = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    // instanceId is exposed as a string (u64 doesn't fit in a JS number).
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).not.toBe("0");
    expect(scp.instanceId.length).toBeGreaterThan(0);
    // Basic integer shape.
    expect(/^[0-9]+$/.test(scp.instanceId)).toBe(true);
  });

  test("two fresh new SCP() instances have distinct instanceIds", () => {
    const a = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    const b = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    expect(a.instanceId).not.toBe(b.instanceId);
  });

  test("SCP.withStorage accepts an in-memory config and produces a fresh instance", () => {
    const scp = addon.SCP.withStorage(JSON.stringify({ type: "in_memory" }));
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).not.toBe("0");
  });

  test("SCP.withStorage rejects an unknown storage type with SCP-STORAGE-8000", () => {
    // Spec §17.6: an unknown `type` is a storage-SELECTION error, so it
    // carries the same code as a missing `type`, not a field-validation code.
    expect(() => addon.SCP.withStorage(JSON.stringify({ type: "unknown_type" }))).toThrow(
      /SCP-STORAGE-8000/,
    );
  });

  test("storage selection is mandatory — missing 'type' throws SCP-STORAGE-8000", () => {
    // Spec §17.6: a config object with no `type` is rejected fail-closed.
    expect(() => addon.SCP.withStorage(JSON.stringify({}))).toThrow(/SCP-STORAGE-8000/);
  });

  test("the raw NAPI constructor requires a config — empty config throws SCP-STORAGE-8000", () => {
    // The `#[napi(constructor)]` entry point routes to the same fail-closed
    // parser as `withStorage`.
    expect(() => new (addon.SCP as new (c: string) => unknown)(JSON.stringify({}))).toThrow(
      /SCP-STORAGE-8000/,
    );
  });

  // NOTE: per-handle `instanceId` is intentionally NOT host-visible (ADR-048 —
  // "Per-handle host-visible `instanceId` is NOT exposed on any bridge"); only
  // the `SCP` class exposes `instanceId`. Handle affinity is asserted
  // behaviorally below ("handle minted by one SCP is rejected by another
  // (SCP-PERM-3030)"), not by reading a stamped id off the handle.

  test("suspend / resume round-trip succeeds", async () => {
    const scp = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    expect(() => scp.suspend()).not.toThrow();
    // `resume()` is async since #1678 — the NAPI bridge chains
    // transport reconnect from pending relay URLs and persisted
    // context restoration before the promise settles.
    await expect(scp.resume()).resolves.toBeUndefined();
  });

  test("handle minted by one SCP is rejected by another (SCP-PERM-3030)", async () => {
    // Round-2 black-hat finding: the TS parity tests must mint a handle
    // on one SCP and call a method on a DIFFERENT SCP with it so the
    // handle-affinity rejection path is exercised end-to-end, not only
    // in the Rust integration tests.
    const scpA = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    const scpB = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    if (typeof scpA.identityCreate !== "function" || typeof scpB.contextCreate !== "function") {
      return; // addon predates per-instance identity/context — covered in Rust
    }
    expect(scpA.instanceId).not.toBe(scpB.instanceId);
    const identity = await scpA.identityCreate("in_memory");
    // contextCreate takes a NapiIdentity handle. Crossing it over to
    // scpB MUST be rejected with SCP-PERM-3030 before any capability
    // or state work runs.
    const params = JSON.stringify({
      ceiling: ["messages:write"],
      governance: "single_admin",
      memoryScope: "ephemeral",
    });
    await expect(scpB.contextCreate(identity, params)).rejects.toThrow(/SCP-PERM-3030/);
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

  test("SCP.withStorage accepts a sqlite config with a passphrase", () => {
    // Passphrase mode (spec §17.6) — the NAPI layer derives the SQLCipher
    // key via Argon2id. We only assert the factory accepts the shape and
    // produces a live instance; durability + fail-closed round-trips are
    // covered by persistence.test.ts and the Rust-side tests.
    const { mkdtempSync } = require("node:fs") as typeof import("node:fs");
    const { tmpdir } = require("node:os") as typeof import("node:os");
    const { join } = require("node:path") as typeof import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "scp-sqlite-pass-"));
    const scp = addon.SCP.withStorage(
      JSON.stringify({ type: "sqlite", path: dir, passphrase: "correct horse battery staple" }),
    );
    expect(typeof scp.instanceId).toBe("string");
    expect(scp.instanceId).not.toBe("0");
  });

  test("SCP.withStorage rejects a sqlite config with both key and passphrase", () => {
    const { mkdtempSync } = require("node:fs") as typeof import("node:fs");
    const { tmpdir } = require("node:os") as typeof import("node:os");
    const { join } = require("node:path") as typeof import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "scp-sqlite-both-"));
    expect(() =>
      addon.SCP.withStorage(
        JSON.stringify({ type: "sqlite", path: dir, key: "00".repeat(32), passphrase: "p" }),
      ),
    ).toThrow();
  });

  test("SCP.withStorage rejects a sqlite config with neither key nor passphrase", () => {
    const { mkdtempSync } = require("node:fs") as typeof import("node:fs");
    const { tmpdir } = require("node:os") as typeof import("node:os");
    const { join } = require("node:path") as typeof import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "scp-sqlite-neither-"));
    expect(() => addon.SCP.withStorage(JSON.stringify({ type: "sqlite", path: dir }))).toThrow();
  });

  test("shutdown(timeoutMillis) resolves without error", async () => {
    const scp = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    // Native `SCP.shutdown` takes unsigned milliseconds after the #1549
    // Phase 4 unit unification. The NAPI binding widened the parameter
    // to `u64` (#1692), which napi-rs exposes as JS `BigInt` on the
    // wire — raw-addon callers must pass a `bigint` literal; the SDK
    // wrapper (`SCP.shutdown`) performs the `number` → `BigInt`
    // coercion at the public surface. 1000 ms is enough for any pending
    // tasks and short enough to not stall the suite.
    await expect(scp.shutdown(1000n)).resolves.toBeUndefined();
  });

  test("shutdown is idempotent — a second call resolves without error", async () => {
    const scp = new addon.SCP(JSON.stringify({ type: "in_memory" }));
    await expect(scp.shutdown(1000n)).resolves.toBeUndefined();
    // Second call should not throw — AlreadyShutDown maps to a harmless
    // lifecycle observation on the SDK surface.
    await expect(scp.shutdown(1000n)).resolves.toBeUndefined();
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

  test("sqlite + passphrase forwards the passphrase verbatim (no key field)", () => {
    // Passphrase mode (spec §17.6): the serializer forwards `passphrase`
    // unchanged and emits no `key` field, so the NAPI mutual-exclusion
    // guard sees exactly one of key/passphrase.
    const wire = __serializeStorageConfigForTests({
      type: "sqlite",
      path: "/tmp/scp-db-pass",
      passphrase: "correct horse battery staple",
    });
    const parsed = JSON.parse(wire);
    expect(parsed).toEqual({
      type: "sqlite",
      path: "/tmp/scp-db-pass",
      passphrase: "correct horse battery staple",
    });
    expect("key" in parsed).toBe(false);
  });
});
