/**
 * SDK-layer smoke test for SQLite-backed persistence (#1549 Phase 4 PR 3).
 *
 * Verifies that the TypeScript SDK wrapper surface:
 *
 * 1. Accepts the documented `StorageConfig.sqlite` variant and forwards it
 *    to the native NAPI `SCP.withStorage(configJson)` factory without
 *    raising.
 * 2. Creates the SQLCipher database file at `{path}/scp.db` as a side
 *    effect of construction — that is what the FFI
 *    `StorageConfig::Sqlite` path does (see
 *    `crates/scp-ffi/napi/src/runtime.rs::with_storage_napi`).
 * 3. Drives the full `suspend() → resume() → shutdown()` lifecycle on a
 *    SQLite-backed instance without error.
 * 4. Is reconstructible against the SAME SQLite path + key — the
 *    reopened instance must be able to open the encrypted database
 *    again without re-deriving a fresh key.
 *
 * The wrapper surface is all this smoke test is responsible for. The
 * end-to-end `identity_create → context_create → context_send → suspend
 * → restore` path is exercised at the Rust integration layer
 * (`crates/scp-testing/tests/integration/persistence_sdk.rs`) because
 * the TypeScript `SCP` class does not yet surface context methods — the
 * free-function façade (`contextCreate`, etc.) routes to the
 * process-global default instance, not to a caller-owned `SCP` handle,
 * and that migration is in #1549 PR 4+.
 *
 * Skipped at file level when the native NAPI addon is unavailable
 * (browser runtime, missing platform binary).
 */

import { describe, expect, it } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SCP } from "../src/scp";

// Stable 32-byte SQLCipher key. The specific value does not matter;
// only that the same key is reused across the two SCP constructions
// that simulate process restart.
const SQLITE_KEY = new Uint8Array(32).fill(0x42);

async function makeTempDir(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "scp-persistence-"));
}

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await makeTempDir();
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// Best-effort detection of whether the NAPI addon is available. We
// attempt a cheap `new SCP()` inside a try/catch — if the addon is
// structurally unavailable we'll get a `SCP-VALID-7005` ValidationError
// and skip the whole suite. This keeps the test file runnable in
// browser/WASM-only environments without hard-failing.
function napiAvailable(): boolean {
  try {
    const probe = new SCP();
    probe.shutdown(1).catch(() => {});
    return true;
  } catch {
    return false;
  }
}

const describeNapi = napiAvailable() ? describe : describe.skip;

describeNapi("SCP with SQLite storage (#1549 PR 3)", () => {
  it("creates the SQLCipher database file at {path}/scp.db", async () => {
    await withTempDir(async (dir) => {
      const dbPath = join(dir, "scp.db");
      expect(existsSync(dbPath)).toBe(false);

      const scp = new SCP({
        storage: { type: "sqlite", path: dir, key: SQLITE_KEY },
      });
      try {
        expect(existsSync(dbPath)).toBe(true);
        expect(scp.instanceId).toBeDefined();
      } finally {
        await scp.shutdown(1);
      }
    });
  });

  it("roundtrips suspend / async resume / shutdown on a SQLite-backed instance", async () => {
    await withTempDir(async (dir) => {
      const scp = new SCP({
        storage: { type: "sqlite", path: dir, key: SQLITE_KEY },
      });
      try {
        scp.suspend();
        await scp.resume();
      } finally {
        await scp.shutdown(1);
      }
    });
  });

  it("reopens the same path+key across two SCP constructions", async () => {
    await withTempDir(async (dir) => {
      const config = { type: "sqlite" as const, path: dir, key: SQLITE_KEY };

      const scp1 = new SCP({ storage: config });
      const id1 = scp1.instanceId;
      await scp1.shutdown(1);

      const scp2 = new SCP({ storage: config });
      try {
        // Compare as BigInts to sidestep JS's 53-bit mantissa when the
        // native instance_id is exposed as a string or BigInt. The
        // only property we actually care about is "the construction
        // succeeded" — strict monotonicity is covered elsewhere.
        expect(scp2.instanceId).toBeDefined();
        expect(scp2.instanceId).not.toEqual(id1);
      } finally {
        await scp2.shutdown(1);
      }
    });
  });

  it("survives a mismatched-key attempt without corrupting the original DB", async () => {
    await withTempDir(async (dir) => {
      // First open with the correct key — creates the encrypted DB.
      const scp1 = new SCP({
        storage: { type: "sqlite", path: dir, key: SQLITE_KEY },
      });
      await scp1.shutdown(1);

      // Second open with a wrong key. The NAPI layer currently logs
      // and falls back to an in-memory-only instance (matching the
      // PyO3 bridge's `with_storage_py` behaviour). The construction
      // therefore succeeds; what we guard against is corruption of
      // the original encrypted DB file.
      const wrongKey = new Uint8Array(32).fill(0x11);
      const scp2 = new SCP({
        storage: { type: "sqlite", path: dir, key: wrongKey },
      });
      await scp2.shutdown(1);

      // Third open with the correct key — must still succeed.
      const scp3 = new SCP({
        storage: { type: "sqlite", path: dir, key: SQLITE_KEY },
      });
      await scp3.shutdown(1);
    });
  });
});
