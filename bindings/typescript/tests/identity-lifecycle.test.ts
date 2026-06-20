/**
 * Tests for the identity-lifecycle methods on the {@link SCP} class
 * (`identityRotateKey`, `identityMigrate`, `identityAddAgentKey`,
 * `identityRotateAgentKey`, `identityRemoveAgentKey`).
 *
 * These verify the public SCP wrappers added to restore cross-SDK parity with
 * the Python (`identity_rotate_key`, …) and Swift surfaces. Each takes an
 * {@link Identity}, extracts its native handle (`identity._rawHandle`), routes
 * through the per-instance `Bridge` (`getBridge(this)` — because these are
 * methods on the identity HANDLE, e.g. `handle.rotateKey()`, not on the `Scp`
 * class), and re-wraps the returned `BridgeIdentityHandle` into an
 * {@link Identity}.
 *
 * Two groups:
 *
 * 1. **Surface/routing checks** — confirm each method exists with the right
 *    arity and routes through the bridge (no addon required). Because the
 *    bridge loads the platform addon, calling a wrapper without an addon
 *    surfaces the addon-unavailable error, proving the wrapper does NOT
 *    dispatch to a fabricated `Scp`-class method.
 * 2. **Real NAPI bridge** — round-trips the methods against a live addon when
 *    one is installed, and skips gracefully otherwise.
 *
 * See spec §9.12, ADR-003, and ADR-048.
 */

import { describe, expect, it, test } from "bun:test";
import { IdentityError } from "../src/errors";
import { Identity } from "../src/identity";
import { SCP } from "../src/scp";
import { mountMockScp } from "./mock-bridge";

const LIFECYCLE_METHODS = [
  "identityRotateKey",
  "identityMigrate",
  "identityAddAgentKey",
  "identityRotateAgentKey",
  "identityRemoveAgentKey",
] as const;

// ---------------------------------------------------------------------------
// Surface / routing checks (no addon required)
// ---------------------------------------------------------------------------

describe("SCP identity-lifecycle surface", () => {
  it("each lifecycle method exists on the SCP prototype with arity 1", () => {
    for (const method of LIFECYCLE_METHODS) {
      const fn = SCP.prototype[method];
      expect(typeof fn).toBe("function");
      // Each wrapper takes exactly one parameter: the Identity.
      expect((fn as (...a: unknown[]) => unknown).length).toBe(1);
    }
  });

  for (const method of LIFECYCLE_METHODS) {
    it(`${method} routes through the bridge (not a fabricated Scp-class method)`, async () => {
      // A mock-mounted SCP has no real platform addon. These methods route
      // through `getBridge(this)`, which loads the addon and therefore
      // rejects when none is installed. The key assertion is that the call
      // REACHES the bridge-load path — i.e. it does not silently resolve via a
      // (non-existent) `this.#native.identityRotateKey`, which would throw a
      // TypeError ("undefined is not a function") instead. We accept either a
      // clean rejection (addon missing) or a clean resolution (addon present),
      // but never a synchronous TypeError from calling `undefined`.
      const { scp } = mountMockScp();
      const identity = Identity._fromHandle(scp, {
        did: "did:dht:z6MkRoute",
        custodyType: "in_memory",
      });

      let threwTypeError = false;
      try {
        await (scp[method] as (i: Identity) => Promise<Identity>)(identity);
      } catch (err) {
        // A TypeError here would mean the wrapper tried to invoke a missing
        // `this.#native.<method>` — the regression this test guards against.
        if (err instanceof TypeError) {
          threwTypeError = true;
        }
      }
      expect(threwTypeError).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// Real NAPI bridge (skipped when the platform addon is unavailable)
// ---------------------------------------------------------------------------

let napiAvailable = false;
let skipReason = "";
try {
  const probe = new SCP({ storage: { type: "in_memory" } });
  if (typeof (probe as unknown as Record<string, unknown>).identityRotateKey !== "function") {
    skipReason = "SCP missing identityRotateKey — rebuild with the parity changes";
  } else {
    napiAvailable = true;
  }
  probe.shutdown(1).catch(() => {});
} catch (e: unknown) {
  skipReason = `Native NAPI bridge not available: ${e instanceof Error ? e.message : String(e)}`;
}

if (!napiAvailable) {
  describe("Real NAPI identity lifecycle (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  describe("Real NAPI identity lifecycle", () => {
    test("rotateKey returns an Identity with the same DID", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const identity = await scp.identityCreate("in_memory");
        const rotated = await scp.identityRotateKey(identity);
        expect(rotated).toBeInstanceOf(Identity);
        expect(rotated.did).toBe(identity.did);
      } finally {
        await scp.shutdown(1);
      }
    });

    test("agent-key lifecycle: add, rotate, remove round-trips", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const identity = await scp.identityCreate("in_memory");
        const withAgent = await scp.identityAddAgentKey(identity);
        expect(withAgent.did).toBe(identity.did);
        const rotated = await scp.identityRotateAgentKey(withAgent);
        expect(rotated.did).toBe(identity.did);
        const removed = await scp.identityRemoveAgentKey(rotated);
        expect(removed).toBeInstanceOf(Identity);
        expect(removed.did).toBe(identity.did);
      } finally {
        await scp.shutdown(1);
      }
    });

    test("migrate returns an Identity with a NEW DID (spec §3.2.1)", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const identity = await scp.identityCreate("in_memory");
        const migrated = await scp.identityMigrate(identity);
        expect(migrated).toBeInstanceOf(Identity);
        // Migration creates a new DID — it does NOT preserve the old one.
        // Use identityRotateKey() if the same DID with a new key is needed.
        expect(migrated.did).not.toBe(identity.did);
      } finally {
        await scp.shutdown(1);
      }
    });

    test("migrate drops the #agent key — identityRemoveAgentKey throws on migrated identity", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        // Start with an identity that has an #agent key.
        const identity = await scp.identityAddAgentKey(await scp.identityCreate("in_memory"));
        const migrated = await scp.identityMigrate(identity);
        expect(migrated).toBeInstanceOf(Identity);
        // Migration MUST have dropped the #agent key from the new DID document
        // (spec §3.2.1). Attempting to remove a non-existent agent key produces
        // IdentityError (Rust: IdentityError::AgentKeyNotFound).
        await expect(scp.identityRemoveAgentKey(migrated)).rejects.toBeInstanceOf(IdentityError);
      } finally {
        await scp.shutdown(1);
      }
    });
  });
}
