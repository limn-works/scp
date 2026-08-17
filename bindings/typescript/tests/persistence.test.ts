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
 * the TypeScript `SCP` class does not yet surface context methods.
 * Phase 4 PR 4 (#1549, ADR-048) deleted the free-function façade
 * (`contextCreate`, etc.) along with the process-wide default bridge
 * it routed through; the remaining SDK wiring to expose those
 * operations on the caller-owned `SCP` handle is tracked as follow-up
 * work.
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
// attempt a cheap `new SCP({ storage: { type: "in_memory" } })` inside a try/catch — if the addon is
// structurally unavailable we'll get a `SCP-VALID-7005` ValidationError
// and skip the whole suite. This keeps the test file runnable in
// environments without the native addon (e.g. an unsupported platform)
// without hard-failing.
function napiAvailable(): boolean {
  try {
    const probe = new SCP({ storage: { type: "in_memory" } });
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

  it("fails closed on a mismatched key without corrupting the original DB", async () => {
    await withTempDir(async (dir) => {
      // First open with the correct key — creates the encrypted DB.
      const scp1 = new SCP({
        storage: { type: "sqlite", path: dir, key: SQLITE_KEY },
      });
      await scp1.shutdown(1);

      // Second open with a WRONG key. FAIL CLOSED (spec §17.6): the NAPI
      // bridge surfaces the SQLCipher key-mismatch as a `SCP-STORAGE-8001`
      // validation error rather than silently returning an in-memory
      // instance. All three bridges report that one code for a failed
      // durable-backend open, so a caller reads the same code whichever
      // binding raised it. The original encrypted DB must survive the failed
      // attempt so the next correct-key open still works.
      const wrongKey = new Uint8Array(32).fill(0x11);
      expect(() => {
        new SCP({
          storage: { type: "sqlite", path: dir, key: wrongKey },
        });
      }).toThrow(/SCP-STORAGE-8001/);

      // Third open with the correct key — must still succeed, proving
      // the failed mismatched-key attempt did not corrupt or truncate
      // the encrypted database file.
      const scp3 = new SCP({
        storage: { type: "sqlite", path: dir, key: SQLITE_KEY },
      });
      await scp3.shutdown(1);
    });
  });

  it("round-trips a passphrase-keyed SQLite instance across two constructions", async () => {
    await withTempDir(async (dir) => {
      const passphrase = "correct horse battery staple";

      // First open with a passphrase — creates the encrypted DB and the
      // persisted Argon2id salt sidecar.
      const scp1 = new SCP({
        storage: { type: "sqlite", path: dir, passphrase },
      });
      expect(scp1.instanceId).toBeDefined();
      await scp1.shutdown(1);

      // Reopen with the SAME passphrase — must succeed (the salt sidecar
      // re-derives the same SQLCipher key).
      const scp2 = new SCP({
        storage: { type: "sqlite", path: dir, passphrase },
      });
      try {
        expect(scp2.instanceId).toBeDefined();
      } finally {
        await scp2.shutdown(1);
      }
    });
  });

  it("fails closed when reopening a passphrase DB with the wrong passphrase", async () => {
    await withTempDir(async (dir) => {
      // Create with the correct passphrase.
      const scp1 = new SCP({
        storage: { type: "sqlite", path: dir, passphrase: "the-right-passphrase" },
      });
      await scp1.shutdown(1);

      // Reopen with the WRONG passphrase. FAIL CLOSED (spec §17.6):
      // SQLCipher rejects the derived key — the NAPI layer must throw,
      // NOT silently open a fresh, empty database.
      expect(() => {
        new SCP({
          storage: { type: "sqlite", path: dir, passphrase: "the-WRONG-passphrase" },
        });
      }).toThrow();
    });
  });

  it("rejects sqlite config that supplies both key and passphrase", () => {
    // The NAPI layer enforces the mutual exclusion at the JSON boundary
    // (SCP-VALID-7005). We bypass the TS union type (which models the two
    // sqlite shapes separately) with a cast to assert the runtime guard.
    expect(() => {
      new SCP({
        storage: {
          type: "sqlite",
          path: "/tmp/scp-both",
          key: SQLITE_KEY,
          passphrase: "also-a-passphrase",
        } as unknown as { type: "sqlite"; path: string; passphrase: string },
      });
    }).toThrow();
  });
});
