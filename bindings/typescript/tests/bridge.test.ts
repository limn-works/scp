/**
 * Tests for bridge selection and runtime detection.
 *
 * These tests verify that the bridge detection logic correctly identifies
 * the runtime environment. In Node.js/Bun test environments, the bridge
 * target should be `"native"`.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

import { describe, expect, it } from "bun:test";
import { EconomicPolicyUnsupportedOnWasm, TransportError } from "../src/errors";
import { BRIDGE_TARGET } from "../src/internal/bridge";
import { createWasmBridge } from "../src/internal/wasm";

describe("bridge selection", () => {
  it("detects native bridge target in Node.js/Bun", () => {
    // In a Node.js or Bun test environment, BRIDGE_TARGET should be "native".
    expect(BRIDGE_TARGET).toBe("native");
  });

  it("BRIDGE_TARGET is a string literal type", () => {
    expect(typeof BRIDGE_TARGET).toBe("string");
    expect(["native", "wasm"]).toContain(BRIDGE_TARGET);
  });
});

// ---------------------------------------------------------------------------
// WASM bridge rejection paths
// ---------------------------------------------------------------------------

describe("WASM bridge rejection paths", () => {
  it("broadcastUnsubscribe with rotateKeys=true throws SCP-TRANS-5003", async () => {
    // The WASM bridge rejects rotateKeys=true before any WASM call,
    // so this test works without WASM module initialization.
    const wasmBridge = createWasmBridge();
    const fakeHandle = { contextId: "ctx-fake", state: "active", creatorDid: "did:dht:fake" };

    await expect(
      wasmBridge.broadcastUnsubscribe(fakeHandle, "did:dht:subscriber", true),
    ).rejects.toThrow(TransportError);

    try {
      await wasmBridge.broadcastUnsubscribe(fakeHandle, "did:dht:subscriber", true);
    } catch (err) {
      expect(err).toBeInstanceOf(TransportError);
      const transportErr = err as TransportError;
      expect(transportErr.code).toBe("SCP-TRANS-5003");
      expect(transportErr.message).toContain("WASM bridge does not support key rotation");
      expect(transportErr.message).toContain("napi-rs");
    }
  });

  it("broadcastUnsubscribe with rotateKeys=false does not throw SCP-TRANS-5003", async () => {
    // With rotateKeys=false (or undefined), the WASM bridge should proceed to
    // the actual WASM call — which will fail because WASM is not initialized.
    // The important thing is it does NOT throw a SCP-TRANS-5003 error.
    expect.assertions(2);
    const wasmBridge = createWasmBridge();
    const fakeHandle = { contextId: "ctx-fake", state: "active", creatorDid: "did:dht:fake" };

    try {
      await wasmBridge.broadcastUnsubscribe(fakeHandle, "did:dht:subscriber", false);
    } catch (err) {
      // Should fail with WASM-not-initialized (SCP-TRANS-5002), not SCP-TRANS-5003.
      expect(err).toBeInstanceOf(TransportError);
      expect((err as TransportError).code).toBe("SCP-TRANS-5002");
    }
  });

  it("broadcastUnsubscribe with rotateKeys=undefined does not throw SCP-TRANS-5003", async () => {
    expect.assertions(2);
    const wasmBridge = createWasmBridge();
    const fakeHandle = { contextId: "ctx-fake", state: "active", creatorDid: "did:dht:fake" };

    try {
      await wasmBridge.broadcastUnsubscribe(fakeHandle, "did:dht:subscriber", undefined);
    } catch (err) {
      // Should fail with WASM-not-initialized (SCP-TRANS-5002), not SCP-TRANS-5003.
      expect(err).toBeInstanceOf(TransportError);
      expect((err as TransportError).code).toBe("SCP-TRANS-5002");
    }
  });

  it("economyVerifyPaymentReceipts throws EconomicPolicyUnsupportedOnWasm with SCP-ECON-12095", () => {
    // The WASM bridge cannot link `scp-runtime`'s async payment adapter
    // (ADR-034), so receipt verification is rejected fail-closed. The throw
    // is synchronous (it short-circuits before any WASM call) and must carry
    // the established economy-unsupported-on-wasm code SCP-ECON-12095 — the
    // code that ERROR_CODE_OVERRIDES maps back to `EconomicPolicyUnsupportedOnWasm`
    // on re-parse. (SCP-ECON-12091 is the native dispatch-failure code and
    // would mis-map to the generic `EconomyError`.)
    expect.assertions(3);
    const wasmBridge = createWasmBridge();

    try {
      wasmBridge.economyVerifyPaymentReceipts(JSON.stringify([]));
    } catch (err) {
      expect(err).toBeInstanceOf(EconomicPolicyUnsupportedOnWasm);
      expect((err as EconomicPolicyUnsupportedOnWasm).code).toBe("SCP-ECON-12095");
      expect((err as EconomicPolicyUnsupportedOnWasm).message).toContain(
        "not supported by the WASM bridge",
      );
    }
  });
});
