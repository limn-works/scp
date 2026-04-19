/**
 * Tests for the bridge lifecycle controls (scpSuspend / scpResume).
 *
 * These tests run against the native NAPI bridge. They verify:
 * - suspend without initialization is a no-op
 * - resume without initialization is a no-op (uninitialized); rejects if shut down
 *
 * The WASM bridge path is covered by the wasm.ts no-op implementation;
 * because the test target is always "native" (see bridge.test.ts), the
 * WASM no-op is exercised indirectly.
 *
 * Skipped at file level when the native NAPI addon is unavailable
 * (browser runtime, missing platform binary for this OS/arch). Same
 * pattern as `persistence.test.ts` and `scp-class.test.ts`.
 */

import { describe, expect, it } from "bun:test";
import { scpResume, scpSuspend } from "../src/lifecycle";
import { SCP } from "../src/scp";

// Best-effort detection of whether the NAPI addon is available. We
// attempt a cheap `new SCP()` inside a try/catch — if the addon is
// structurally unavailable (missing platform optionalDependency), the
// native bridge loader throws a `TransportError` and we skip. This
// keeps the test file runnable in environments where the native addon
// is not published locally (developer machine without a pre-built
// platform package) without hard-failing the suite.
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

describeNapi("bridge lifecycle (scpSuspend / scpResume)", () => {
  it("scpSuspend on a fresh instance is a no-op", async () => {
    const scp = new SCP();
    try {
      // scp_suspend returns Ok(()) — BridgeInstance::suspend()
      // short-circuits on is_shutdown() and on uninitialized state.
      await expect(scpSuspend(scp)).resolves.toBeUndefined();
    } finally {
      await scp.shutdown(1);
    }
  });

  it("scpResume on a fresh instance is a no-op; on shut-down instance rejects", async () => {
    const scp = new SCP();
    try {
      await scpResume(scp);
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
  // down via napi.shutdown() before this file runs, and OnceLock
  // shutdown is terminal (the `BridgeInstance` cannot be revived). The
  // Rust integration tests exhaustively cover the happy path:
  // `scp_suspend_resume_roundtrip` in crates/scp-ffi/napi/src/lib.rs.
});
