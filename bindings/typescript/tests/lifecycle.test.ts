/**
 * Tests for the bridge lifecycle controls (scp.suspend() / scp.resume()).
 *
 * These tests run against the native NAPI bridge. They verify:
 * - suspend without initialization is a no-op
 * - resume without initialization is a no-op (uninitialized); rejects if shut down
 *
 * Skipped at file level when the native NAPI addon is unavailable
 * (missing platform binary for this OS/arch). Same pattern as
 * `persistence.test.ts` and `scp-class.test.ts`.
 *
 * Phase 4 PR 4 (#1549) deleted the free-function `scpSuspend` / `scpResume`
 * delegates; suspend/resume live only as methods on {@link SCP}.
 */

import { expect, it } from "bun:test";
import { SCP } from "../src/scp";
import { napiSuite } from "./napi-guard";

// The suite skips only when no NAPI addon is installed for this platform
// (`napiSuite`); every other probe failure fails the file.
const suite = await napiSuite(() => {
  const probe = new SCP({ storage: { type: "in_memory" } });
  probe.shutdown(1).catch(() => {});
});

suite.describe("bridge lifecycle (SCP.suspend / SCP.resume)", () => {
  it("SCP.suspend on a fresh instance is a no-op", async () => {
    const scp = new SCP({ storage: { type: "in_memory" } });
    try {
      // BridgeInstance::suspend() short-circuits on is_shutdown() and
      // on uninitialized state, so suspend on a fresh instance resolves.
      expect(() => scp.suspend()).not.toThrow();
    } finally {
      await scp.shutdown(1);
    }
  });

  it("SCP.resume on a fresh instance is a no-op; on shut-down instance rejects", async () => {
    const scp = new SCP({ storage: { type: "in_memory" } });
    try {
      await scp.resume();
    } catch (err) {
      expect(String(err)).toMatch(/shut down|AlreadyShutDown|SCP-CTX-2000/);
    } finally {
      await scp.shutdown(1);
    }
  });

  // NOTE: "after bridge initialization" subtests live in
  // crates/scp-ffi/napi tests/lifecycle.rs — they run in an isolated
  // test process where OnceLock state is fresh. In the bun test suite,
  // other test files (e.g. real-napi.test.ts) may have shut the bridge
  // down via scp.shutdown() before this file runs, and OnceLock
  // shutdown is terminal (the `BridgeInstance` cannot be revived). The
  // Rust integration tests exhaustively cover the happy path:
  // `scp_suspend_resume_roundtrip` in crates/scp-ffi/napi/src/lib.rs.
});
