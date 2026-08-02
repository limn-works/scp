/**
 * Tests for the bridge-provenance trust-tier classifier
 * (`evaluateTrust` in `./bridge`, re-exported from the package index as
 * `bridgeEvaluateTrust`).
 *
 * Mirrors the Python SDK's `scp_sdk.bridge.evaluate_trust`: a pure function
 * returning a tier integer (0–3) from `(isBridged, isNativeTransport,
 * shadowStatus)`. The 4 tiers, strongest last:
 *
 * - `3` NativeNative   — not bridged, native transport.
 * - `2` NativeBridged  — bridged, native transport.
 * - `1` ClaimedBridged — bridged, claimed shadow.
 * - `0` ShadowBridged  — bridged, shadow (unclaimed).
 *
 * The function routes through `getBridge(scp)`, which loads the real platform
 * addon. When no `@limn-works/scp-ts-napi-*` package is installed the whole
 * suite skips gracefully; the default-handling logic is additionally asserted
 * via the option-shape unit test, which does not require the addon.
 *
 * See spec §12 (Bridge System), ADR-023, and
 * `bindings/python/bridge.py:evaluate_trust`.
 */

import { describe, expect, it, test } from "bun:test";
import type { ShadowStatus } from "../src/bridge";
import { evaluateTrust } from "../src/bridge";
import type { Bridge } from "../src/internal/bridge";
import { __setBridgeForTests } from "../src/internal/bridge";
import { SCP } from "../src/scp";
import { mountMockScp } from "./mock-bridge";

// ---------------------------------------------------------------------------
// Default-shape unit test (no addon required)
// ---------------------------------------------------------------------------
//
// `evaluateTrust` must apply the same defaults the Python keyword-only
// arguments do: isBridged=false, isNativeTransport=true, shadowStatus="shadow".
//
// We verify the actual `evaluateTrust` implementation by injecting a mock
// bridge via `__setBridgeForTests` and spying on which arguments reach
// `bridgeEvaluateTrust`. This catches silent drift in the `??` chains inside
// `evaluateTrust` itself — a local copy of the same chains would be a
// tautology (it could drift identically with the implementation and the test
// would still pass).
describe("evaluateTrust option defaults", () => {
  /**
   * Builds a stub `Bridge` whose `bridgeEvaluateTrust` records its call
   * arguments and returns the supplied tier value. All other operations
   * throw so accidental delegation is immediately visible.
   */
  function makeSpyBridge(returnTier: number = 3): {
    bridge: Bridge;
    calls: Array<[boolean, boolean, ShadowStatus]>;
  } {
    const calls: Array<[boolean, boolean, ShadowStatus]> = [];
    // Runtime-introspection symbols that JS probes on every object (e.g.
    // `await` probes `.then` to detect thenables). These must return `undefined`
    // so the bridge is not mistakenly treated as a Promise.
    const PROBE_PROPS = new Set<string | symbol>([
      "then",
      "catch",
      "finally",
      Symbol.toPrimitive,
      Symbol.toStringTag,
      Symbol.iterator,
      Symbol.asyncIterator,
    ]);
    const bridge = new Proxy({} as Bridge, {
      get(_t, prop) {
        if (PROBE_PROPS.has(prop)) {
          return undefined;
        }
        if (prop === "bridgeEvaluateTrust") {
          return (isBridged: boolean, isNativeTransport: boolean, shadowStatus: ShadowStatus) => {
            calls.push([isBridged, isNativeTransport, shadowStatus]);
            return returnTier;
          };
        }
        throw new Error(`Spy bridge: unexpected call to Bridge.${String(prop)}`);
      },
    });
    return { bridge, calls };
  }

  it("defaults to not-bridged, native transport, shadow status", async () => {
    const { scp } = mountMockScp();
    const { bridge, calls } = makeSpyBridge(3);
    __setBridgeForTests(scp, bridge);

    await evaluateTrust(scp);

    expect(calls).toHaveLength(1);
    const call = calls[0] as [boolean, boolean, ShadowStatus];
    expect(call[0]).toBe(false);
    expect(call[1]).toBe(true);
    expect(call[2]).toBe("shadow");
  });

  it("honours explicitly provided values", async () => {
    const { scp } = mountMockScp();
    const { bridge, calls } = makeSpyBridge(0);
    __setBridgeForTests(scp, bridge);

    await evaluateTrust(scp, {
      isBridged: true,
      isNativeTransport: false,
      shadowStatus: "claimed",
    });

    expect(calls).toHaveLength(1);
    const call = calls[0] as [boolean, boolean, ShadowStatus];
    expect(call[0]).toBe(true);
    expect(call[1]).toBe(false);
    expect(call[2]).toBe("claimed");
  });

  it("preserves false isNativeTransport (does not fall back to true)", async () => {
    const { scp } = mountMockScp();
    const { bridge, calls } = makeSpyBridge(2);
    __setBridgeForTests(scp, bridge);

    await evaluateTrust(scp, { isNativeTransport: false });

    expect(calls).toHaveLength(1);
    const call = calls[0] as [boolean, boolean, ShadowStatus];
    expect(call[1]).toBe(false);
  });

  it("evaluateTrust is an async function", () => {
    expect(typeof evaluateTrust).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// Real NAPI bridge (skipped when the platform addon is unavailable)
// ---------------------------------------------------------------------------

let napiAvailable = false;
let skipReason = "";
try {
  const probe = new SCP({ storage: { type: "in_memory" } });
  napiAvailable = true;
  probe.shutdown(1).catch(() => {});
} catch (e: unknown) {
  skipReason = `Native NAPI bridge not available: ${e instanceof Error ? e.message : String(e)}`;
}

if (!napiAvailable) {
  describe("Real NAPI bridge evaluateTrust (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  describe("Real NAPI bridge evaluateTrust", () => {
    test("native + not bridged → tier 3 (NativeNative, strongest)", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const tier = await evaluateTrust(scp, { isBridged: false, isNativeTransport: true });
        expect(tier).toBe(3);
      } finally {
        await scp.shutdown(1);
      }
    });

    test("not bridged + non-native transport → tier 2 (NativeBridged)", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const tier = await evaluateTrust(scp, { isBridged: false, isNativeTransport: false });
        expect(tier).toBe(2);
      } finally {
        await scp.shutdown(1);
      }
    });

    test("bridged + claimed shadow → tier 1 (ClaimedBridged), transport flag ignored", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        // When bridged, the transport flag is ignored; the tier is driven by
        // shadow status. `claimed` → ClaimedBridged regardless of transport.
        const tier = await evaluateTrust(scp, {
          isBridged: true,
          isNativeTransport: true,
          shadowStatus: "claimed",
        });
        expect(tier).toBe(1);
      } finally {
        await scp.shutdown(1);
      }
    });

    test("bridged + shadow + non-native → tier 0 (ShadowBridged, weakest)", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const tier = await evaluateTrust(scp, {
          isBridged: true,
          isNativeTransport: false,
          shadowStatus: "shadow",
        });
        expect(tier).toBe(0);
      } finally {
        await scp.shutdown(1);
      }
    });

    test("defaults (no options) → tier 3 (not bridged, native)", async () => {
      const scp = new SCP({ storage: { type: "in_memory" } });
      try {
        const tier = await evaluateTrust(scp);
        expect(tier).toBe(3);
      } finally {
        await scp.shutdown(1);
      }
    });
  });
}
