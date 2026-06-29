/**
 * Tests for bridge selection and runtime detection.
 *
 * These tests verify that the bridge detection logic correctly identifies
 * the runtime environment. The SDK has a single in-process backend — the
 * napi-rs native addon — so the bridge target is always `"native"`.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md` and ADR-055.
 */

import { describe, expect, it } from "bun:test";
import { ScpError, UcanPermissionError } from "../src/errors";
import type { Bridge } from "../src/internal/bridge";
import { BRIDGE_TARGET, wrapBridgeErrors } from "../src/internal/bridge";
import { createNativeBridge } from "../src/internal/native";
import { mountMockScp } from "./mock-bridge";

describe("bridge selection", () => {
  it("reports the native bridge target", () => {
    expect(BRIDGE_TARGET).toBe("native");
  });

  it("BRIDGE_TARGET is a string literal type", () => {
    expect(typeof BRIDGE_TARGET).toBe("string");
    expect(["native"]).toContain(BRIDGE_TARGET);
  });
});

// ---------------------------------------------------------------------------
// Single bridge-error chokepoint (ADR-057)
// ---------------------------------------------------------------------------
//
// `wrapBridgeErrors` is the one site that converts raw FFI errors into typed
// ScpError subclasses. createNativeBridge returns its bridge object through it,
// so callers no longer need per-method try/catch around mapBridgeError.

describe("wrapBridgeErrors — single error chokepoint", () => {
  // A minimal fake bridge surface; only the members exercised below matter.
  function fakeBridge(overrides: Partial<Record<string, unknown>>): Bridge {
    return overrides as unknown as Bridge;
  }

  it("maps a synchronous raw FFI throw to the typed subclass", () => {
    const bridge = wrapBridgeErrors(
      fakeBridge({
        syncOp(): never {
          throw new Error("[SCP-PERM-3001] permission error: token revoked");
        },
      }),
    );
    expect.assertions(2);
    try {
      (bridge as unknown as { syncOp(): void }).syncOp();
    } catch (err) {
      expect(err).toBeInstanceOf(UcanPermissionError);
      expect((err as UcanPermissionError).code).toBe("SCP-PERM-3001");
    }
  });

  it("maps an async raw FFI rejection to the typed subclass", async () => {
    const bridge = wrapBridgeErrors(
      fakeBridge({
        async asyncOp(): Promise<void> {
          throw new Error("[SCP-PERM-3001] permission error: capability outside ceiling");
        },
      }),
    );
    await expect(
      (bridge as unknown as { asyncOp(): Promise<void> }).asyncOp(),
    ).rejects.toBeInstanceOf(UcanPermissionError);
  });

  it("maps a guard that throws synchronously before the first await inside an async method", async () => {
    const bridge = wrapBridgeErrors(
      fakeBridge({
        // Declared async at the call site, but the underlying function throws
        // synchronously (an argument guard before any `await`).
        asyncGuard(): Promise<void> {
          throw new Error("[SCP-PERM-3002] permission error: malformed token");
        },
      }),
    );
    // The synchronous throw is caught by the try{} path and re-mapped; because
    // the wrapper returns the (now mapped-and-thrown) value, the caller sees a
    // synchronous throw here too.
    expect.assertions(1);
    try {
      void (bridge as unknown as { asyncGuard(): Promise<void> }).asyncGuard();
    } catch (err) {
      expect(err).toBeInstanceOf(UcanPermissionError);
    }
  });

  it("maps a non-coded raw error to the generic ScpError (SCP-UNKNOWN-0000)", async () => {
    const bridge = wrapBridgeErrors(
      fakeBridge({
        async asyncOp(): Promise<void> {
          throw new Error("some opaque native failure");
        },
      }),
    );
    expect.assertions(2);
    try {
      await (bridge as unknown as { asyncOp(): Promise<void> }).asyncOp();
    } catch (err) {
      expect(err).toBeInstanceOf(ScpError);
      expect((err as ScpError).code).toBe("SCP-UNKNOWN-0000");
    }
  });

  it("passes a successful sync return (e.g. a handle object) through verbatim — no deep-proxy", () => {
    const handle = { rotateKey: () => "ok", did: "did:dht:abc" };
    const bridge = wrapBridgeErrors(
      fakeBridge({
        syncReturnsHandle(): unknown {
          return handle;
        },
      }),
    );
    const out = (bridge as unknown as { syncReturnsHandle(): unknown }).syncReturnsHandle();
    // The handle is returned by identity — NOT wrapped in another Proxy — so
    // its own methods keep their identity for handle-affinity enforcement.
    expect(out).toBe(handle);
    expect((out as { rotateKey(): string }).rotateKey()).toBe("ok");
  });

  it("passes a non-function property through untouched", () => {
    const bridge = wrapBridgeErrors(fakeBridge({ someValue: 42 }));
    expect((bridge as unknown as { someValue: number }).someValue).toBe(42);
  });
});

describe("createNativeBridge — applies the error chokepoint", () => {
  it("surfaces a raw [SCP-PERM-3001] native throw as UcanPermissionError", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("ucanValidate", () => {
      throw new Error("[SCP-PERM-3001] permission error: token revoked");
    });
    const bridge = createNativeBridge(scp);
    await expect(
      bridge.ucanValidate({ contextId: "ctx", state: "active", creatorDid: "did:dht:x" }, "t", "*"),
    ).rejects.toBeInstanceOf(UcanPermissionError);
    await scp.shutdown(0);
  });
});
