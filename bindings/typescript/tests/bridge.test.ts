/**
 * Tests for bridge selection and runtime detection.
 *
 * These tests verify that the bridge detection logic correctly identifies
 * the runtime environment. In Node.js/Bun test environments, the bridge
 * target should be `"native"`.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

import { describe, expect, it } from "vitest";
import { BRIDGE_TARGET } from "../src/internal/bridge.js";

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
