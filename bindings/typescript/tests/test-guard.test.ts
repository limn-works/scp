/**
 * Tests for the test-guard module.
 *
 * Covers the `_evaluateTestEnv` decision helper (NODE_ENV / BUN_TEST logic and
 * prototype-pollution resistance) and the public `isTestEnvironment` /
 * `assertTestEnvironment` API shapes.
 *
 * The module-level `_IS_TEST_ENVIRONMENT` constant is frozen at import time and
 * cannot be reset between tests, so behavioural correctness of the decision
 * function is verified through `_evaluateTestEnv` directly.
 */

import { describe, expect, it } from "bun:test";
import {
  _evaluateTestEnv,
  assertTestEnvironment,
  isTestEnvironment,
} from "../src/internal/test-guard";

// ---------------------------------------------------------------------------
// _evaluateTestEnv — decision logic
// ---------------------------------------------------------------------------

describe("_evaluateTestEnv", () => {
  it("returns true when NODE_ENV is 'test'", () => {
    expect(_evaluateTestEnv({ NODE_ENV: "test" })).toBe(true);
  });

  it("returns true when NODE_ENV is 'development'", () => {
    expect(_evaluateTestEnv({ NODE_ENV: "development" })).toBe(true);
  });

  it("returns false when NODE_ENV is 'production'", () => {
    expect(_evaluateTestEnv({ NODE_ENV: "production" })).toBe(false);
  });

  it("returns false when NODE_ENV is 'staging'", () => {
    expect(_evaluateTestEnv({ NODE_ENV: "staging" })).toBe(false);
  });

  it("returns false when NODE_ENV is absent", () => {
    expect(_evaluateTestEnv({})).toBe(false);
  });

  it("returns true when BUN_TEST is set to '1'", () => {
    expect(_evaluateTestEnv({ BUN_TEST: "1" })).toBe(true);
  });

  it("returns true when BUN_TEST is any non-empty string (e.g. 'false')", () => {
    // BUN_TEST is checked for presence (non-empty), not for a specific value.
    // "false" has length > 0, so it elevates trust. This is by design — only
    // the bun test runner sets BUN_TEST, so any non-empty value is meaningful.
    expect(_evaluateTestEnv({ BUN_TEST: "false" })).toBe(true);
  });

  it("returns false when BUN_TEST is empty string (not set by the runner)", () => {
    expect(_evaluateTestEnv({ BUN_TEST: "" })).toBe(false);
  });

  it("returns false for undefined env", () => {
    expect(_evaluateTestEnv(undefined)).toBe(false);
  });

  it("is NOT fooled by prototype pollution (Object.prototype.NODE_ENV = 'test')", () => {
    // `polluted.NODE_ENV` reads through the prototype and returns "test",
    // but `Object.hasOwn(polluted, "NODE_ENV")` is false — so the guard
    // must not elevate trust.
    const polluted = Object.create({ NODE_ENV: "test" }) as Record<string, string | undefined>;
    expect(_evaluateTestEnv(polluted)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isTestEnvironment / assertTestEnvironment — public API
// ---------------------------------------------------------------------------

describe("isTestEnvironment", () => {
  it("returns a boolean", () => {
    expect(typeof isTestEnvironment()).toBe("boolean");
  });

  it("returns true in the bun test runner (NODE_ENV=test is set at test-suite load)", () => {
    // bun test sets NODE_ENV=test in process.env before loading modules, so
    // the frozen constant must reflect that. BUN_TEST is NOT set by bun test.
    expect(isTestEnvironment()).toBe(true);
  });
});

describe("assertTestEnvironment", () => {
  it("does not throw in the bun test environment", () => {
    expect(() => assertTestEnvironment("testHook")).not.toThrow();
  });
});
