/**
 * Tests for the default-instance deprecation scaffold (#1549 Phase 4 PR 1).
 *
 * Two contracts:
 *
 * 1. Free-function façade calls emit `console.warn` on their *first* call
 *    per function name, and stay silent on subsequent calls.
 * 2. Using the explicit `SCP` class emits NO deprecation warning — it is
 *    the non-deprecated entry point callers are being directed toward.
 *
 * See ADR-048.
 */

import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";

import { _resetEmittedForTests, deprecatedDefaultInstance } from "../src/internal/deprecation";

describe("deprecatedDefaultInstance (one-time warning scaffold)", () => {
  let warnSpy: ReturnType<typeof mock>;
  let originalWarn: typeof console.warn;

  beforeEach(() => {
    _resetEmittedForTests();
    originalWarn = console.warn;
    warnSpy = mock(() => {});
    console.warn = warnSpy as unknown as typeof console.warn;
  });

  afterEach(() => {
    console.warn = originalWarn;
  });

  test("emits one warning on first call, none on subsequent calls", () => {
    deprecatedDefaultInstance("scpSuspend");
    deprecatedDefaultInstance("scpSuspend");
    deprecatedDefaultInstance("scpSuspend");
    expect(warnSpy).toHaveBeenCalledTimes(1);
    // The warning must mention the function name and point to the SCP class.
    const firstCall = warnSpy.mock.calls[0];
    expect(firstCall).toBeDefined();
    const msg = firstCall?.[0] as string;
    expect(msg).toContain("scpSuspend");
    expect(msg).toContain("SCP()");
    expect(msg).toContain("ADR-048");
  });

  test("different function names each warn once", () => {
    deprecatedDefaultInstance("mintUcan");
    deprecatedDefaultInstance("scpidChallenge");
    deprecatedDefaultInstance("mintUcan");
    deprecatedDefaultInstance("scpidChallenge");
    expect(warnSpy).toHaveBeenCalledTimes(2);
    const names = warnSpy.mock.calls.map((c: unknown[]) => c[0] as string);
    expect(names.some((m) => m.includes("mintUcan"))).toBe(true);
    expect(names.some((m) => m.includes("scpidChallenge"))).toBe(true);
  });

  test("_resetEmittedForTests clears the tracker so the next first-call warns again", () => {
    deprecatedDefaultInstance("scpSuspend");
    expect(warnSpy).toHaveBeenCalledTimes(1);

    _resetEmittedForTests();

    deprecatedDefaultInstance("scpSuspend");
    expect(warnSpy).toHaveBeenCalledTimes(2);
  });
});

describe("SCP class imports silently", () => {
  // We import the SCP class directly. Its module-level code must not call
  // `deprecatedDefaultInstance` or emit any `console.warn`. We don't try
  // to construct an instance here because that requires the NAPI addon
  // to be installed — covered by `scp-class.test.ts`.
  test("importing SCP does not emit deprecation warnings", async () => {
    const warnSpy = mock(() => {});
    const originalWarn = console.warn;
    console.warn = warnSpy as unknown as typeof console.warn;
    try {
      await import("../src/scp");
    } finally {
      console.warn = originalWarn;
    }
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
