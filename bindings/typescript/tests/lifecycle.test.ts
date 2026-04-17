/**
 * Tests for the bridge lifecycle controls (scpSuspend / scpResume).
 *
 * These tests run against the native NAPI bridge. They verify:
 * - suspend without initialization is a no-op
 * - resume without initialization is a no-op
 * - suspend-then-resume succeeds after initialization (via Identity.create)
 *
 * The WASM bridge path is covered by the wasm.ts no-op implementation;
 * because the test target is always "native" (see bridge.test.ts), the
 * WASM no-op is exercised indirectly.
 */

import { beforeAll, describe, expect, it } from "bun:test";
import { Identity } from "../src/identity";
import { scpResume, scpSuspend } from "../src/lifecycle";

describe("bridge lifecycle (scpSuspend / scpResume)", () => {
  it("scpSuspend without initialization is a no-op", async () => {
    // The NAPI bridge no-ops when BRIDGE_INSTANCE is uninitialized. The
    // test suite may initialize the bridge before this test runs in the
    // same process, so we only assert that the call resolves successfully.
    await expect(scpSuspend()).resolves.toBeUndefined();
  });

  it("scpResume without initialization is a no-op", async () => {
    await expect(scpResume()).resolves.toBeUndefined();
  });

  describe("after bridge initialization", () => {
    beforeAll(async () => {
      // Initializing an identity triggers ensure_bridge_instance in the
      // NAPI bridge, so subsequent scp_suspend/scp_resume operate on a
      // real BridgeInstance rather than the None fallback.
      await Identity.create({ custody: "in_memory" });
    });

    it("scpSuspend succeeds after initialization", async () => {
      await expect(scpSuspend()).resolves.toBeUndefined();
    });

    it("scpResume succeeds after suspend", async () => {
      await scpSuspend();
      await expect(scpResume()).resolves.toBeUndefined();
    });

    it("suspend / resume cycle is idempotent", async () => {
      await scpSuspend();
      await scpSuspend();
      await scpResume();
      await scpResume();
    });
  });
});
