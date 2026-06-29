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
import { BRIDGE_TARGET } from "../src/internal/bridge";

describe("bridge selection", () => {
  it("reports the native bridge target", () => {
    expect(BRIDGE_TARGET).toBe("native");
  });

  it("BRIDGE_TARGET is a string literal type", () => {
    expect(typeof BRIDGE_TARGET).toBe("string");
    expect(["native"]).toContain(BRIDGE_TARGET);
  });
});
