/**
 * Tests for the identity-lifecycle methods on the {@link SCP} class
 * (`identityRotateKey`, `identityMigrate`, `identityAddAgentKey`,
 * `identityRotateAgentKey`, `identityRemoveAgentKey`).
 *
 * These verify the public SCP wrappers added to restore cross-SDK parity with
 * the Python (`identity_rotate_key`, …) and Swift surfaces. Each takes an
 * {@link Identity}, extracts its native handle (`identity._rawHandle`), routes
 * through the per-instance `Bridge` (`getBridge(this)`), and re-wraps the
 * returned `BridgeIdentityHandle` into an {@link Identity}.
 *
 * Two groups:
 *
 * 1. **Surface/routing checks** — confirm each method exists with the right
 *    arity and routes through the injected bridge spy. Each test injects a
 *    spy `Bridge` via `__setBridgeForTests`, calls the wrapper, and asserts
 *    the spy was invoked with the identity's raw handle — proving the wrapper
 *    dispatches to the bridge rather than to a fabricated `Scp`-class method.
 * 2. **Real NAPI bridge** — round-trips the methods against a live addon when
 *    one is installed, and skips gracefully otherwise.
 *
 * See spec §9.12, ADR-003, and ADR-048.
 */

import { describe, expect, it, test } from "bun:test";
import { IdentityError } from "../src/errors";
import { Identity } from "../src/identity";
import type { Bridge, BridgeIdentityHandle } from "../src/internal/bridge";
import { __setBridgeForTests } from "../src/internal/bridge";
import { SCP } from "../src/scp";
import { mountMockScp } from "./mock-bridge";

const LIFECYCLE_METHODS = [
  "identityRotateKey",
  "identityMigrate",
  "identityAddAgentKey",
  "identityRotateAgentKey",
  "identityRemoveAgentKey",
] as const;

/** Bridge method names on the `Bridge` interface for each lifecycle wrapper. */
const BRIDGE_METHOD: Record<(typeof LIFECYCLE_METHODS)[number], keyof Bridge> = {
  identityRotateKey: "identityRotateKey",
  identityMigrate: "identityMigrate",
  identityAddAgentKey: "identityAddAgentKey",
  identityRotateAgentKey: "identityRotateAgentKey",
  identityRemoveAgentKey: "identityRemoveAgentKey",
} as const;

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

  it("identityMigrate routes through the injected bridge spy and exposes rotationEventJson", async () => {
    // The spy handle includes rotationEventJson — a field the bridge sets only
    // on migrate results. The Identity.rotationEventJson getter must surface it.
    const spyHandle: BridgeIdentityHandle = {
      did: "did:dht:zSpy",
      custodyType: "in_memory",
      rotationEventJson: '{"event":"rotate"}',
    };
    const spyCalls: BridgeIdentityHandle[] = [];

    const PROBE_PROPS = new Set<string | symbol>([
      "then",
      "catch",
      "finally",
      Symbol.toPrimitive,
      Symbol.toStringTag,
      Symbol.iterator,
      Symbol.asyncIterator,
    ]);

    const spyBridge = new Proxy({} as Bridge, {
      get(_t, prop) {
        if (PROBE_PROPS.has(prop)) return undefined;
        if (prop === "identityMigrate") {
          return (handle: BridgeIdentityHandle) => {
            spyCalls.push(handle);
            return Promise.resolve(spyHandle);
          };
        }
        throw new Error(`Spy bridge: unexpected call to Bridge.${String(prop)}`);
      },
    });

    const { scp } = mountMockScp();
    __setBridgeForTests(scp, spyBridge);

    const rawHandle: BridgeIdentityHandle = { did: "did:dht:zInput", custodyType: "in_memory" };
    const identity = Identity._fromHandle(scp, rawHandle);

    const result = await scp.identityMigrate(identity);

    expect(spyCalls).toHaveLength(1);
    expect(spyCalls[0]).toBe(rawHandle);
    expect(result).toBeInstanceOf(Identity);
    expect(result.did).toBe("did:dht:zSpy");
    // rotationEventJson getter must surface the field from the bridge handle.
    expect(result.rotationEventJson).toBe('{"event":"rotate"}');
  });

  for (const method of LIFECYCLE_METHODS) {
    it(`${method} routes through the injected bridge spy`, async () => {
      // Build a spy bridge that records calls to the specific lifecycle method
      // and returns a valid BridgeIdentityHandle so the wrapper can wrap the result.
      const spyHandle: BridgeIdentityHandle = {
        did: "did:dht:zSpy",
        custodyType: "in_memory",
      };
      const spyCalls: BridgeIdentityHandle[] = [];

      const PROBE_PROPS = new Set<string | symbol>([
        "then",
        "catch",
        "finally",
        Symbol.toPrimitive,
        Symbol.toStringTag,
        Symbol.iterator,
        Symbol.asyncIterator,
      ]);

      const bridgeMethod = BRIDGE_METHOD[method];
      const spyBridge = new Proxy({} as Bridge, {
        get(_t, prop) {
          if (PROBE_PROPS.has(prop)) return undefined;
          if (prop === bridgeMethod) {
            return (handle: BridgeIdentityHandle) => {
              spyCalls.push(handle);
              return Promise.resolve(spyHandle);
            };
          }
          throw new Error(`Spy bridge: unexpected call to Bridge.${String(prop)}`);
        },
      });

      const { scp } = mountMockScp();
      __setBridgeForTests(scp, spyBridge);

      const rawHandle: BridgeIdentityHandle = { did: "did:dht:zInput", custodyType: "in_memory" };
      const identity = Identity._fromHandle(scp, rawHandle);

      const result = await (scp[method] as (i: Identity) => Promise<Identity>)(identity);

      // The spy was called exactly once with the identity's raw handle.
      expect(spyCalls).toHaveLength(1);
      expect(spyCalls[0]).toBe(rawHandle);
      // The wrapper returned an Identity wrapping the spy's returned handle.
      expect(result).toBeInstanceOf(Identity);
      expect(result.did).toBe("did:dht:zSpy");
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
    await probe.identityCreate("in_memory");
    napiAvailable = true;
  }
  await probe.shutdown(1).catch(() => {});
} catch (e: unknown) {
  skipReason = `Native NAPI bridge not available or not custody-capable: ${e instanceof Error ? e.message : String(e)}`;
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

    test("migrate returns an Identity with a NEW DID (spec §9.12)", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const identity = await scp.identityCreate("in_memory");
        const migrated = await scp.identityMigrate(identity);
        expect(migrated).toBeInstanceOf(Identity);
        // Migration creates a new DID — it does NOT preserve the old one.
        // Use identityRotateKey() if the same DID with a new key is needed.
        expect(migrated.did).not.toBe(identity.did);
        // Migration must produce a rotation event callers MUST distribute (spec §9.12)
        expect(typeof migrated.rotationEventJson).toBe("string");
        expect(migrated.rotationEventJson?.length).toBeGreaterThan(0);
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
        // (spec §9.12). Attempting to remove a non-existent agent key produces
        // IdentityError (Rust: IdentityError::AgentKeyNotFound).
        let threw = false;
        try {
          await scp.identityRemoveAgentKey(migrated);
        } catch (err) {
          threw = true;
          expect(err).toBeInstanceOf(IdentityError);
        }
        expect(threw).toBe(true);
      } finally {
        await scp.shutdown(1);
      }
    });
  });
}
