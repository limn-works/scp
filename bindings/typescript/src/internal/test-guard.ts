/**
 * Evaluate whether a given env object indicates a test or development
 * environment.
 *
 * Extracted from the module-load IIFE so the decision logic can be unit-tested
 * independently of the frozen module-level constant.
 *
 * Uses `Object.hasOwn` to prevent prototype-pollution bypass
 * (`Object.prototype.NODE_ENV = "test"` must not elevate trust).
 *
 * @internal
 */
export function _evaluateTestEnv(env: Record<string, string | undefined> | undefined): boolean {
  if (!env || typeof env !== "object") return false;
  const nodeEnv = Object.hasOwn(env, "NODE_ENV") ? env.NODE_ENV : undefined;
  const bunTest = Object.hasOwn(env, "BUN_TEST") ? env.BUN_TEST : undefined;
  return (
    nodeEnv === "test" || nodeEnv === "development" || (bunTest !== undefined && bunTest.length > 0)
  );
}

// Read process.env once at module load — runtime mutations cannot flip these.
const _ENV_AT_LOAD: Record<string, string | undefined> | undefined = (() => {
  try {
    return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
      ?.env as Record<string, string | undefined> | undefined;
  } catch {
    return undefined;
  }
})();

export const _IS_TEST_ENVIRONMENT: boolean = _evaluateTestEnv(_ENV_AT_LOAD);
const _NODE_ENV_AT_LOAD: string | undefined =
  _ENV_AT_LOAD !== undefined && Object.hasOwn(_ENV_AT_LOAD, "NODE_ENV")
    ? _ENV_AT_LOAD.NODE_ENV
    : undefined;

/**
 * Returns true when the runtime is in a test or development environment.
 * Fail-closed: returns false if process is unavailable (browser, Deno) or
 * when NODE_ENV is absent, "production", "staging", or any other value.
 *
 * The decision is frozen at module load time — runtime mutations to
 * `process.env` cannot flip this after import.
 *
 * Exported for `tests/test-guard.test.ts`, which asserts on the frozen
 * constant value in the current process. No `src/` module consumes this
 * function directly — callers that need the boolean use the module-level
 * `_IS_TEST_ENVIRONMENT` constant or call `assertTestEnvironment`.
 */
export function isTestEnvironment(): boolean {
  return _IS_TEST_ENVIRONMENT;
}

/**
 * Throws unless the runtime is in a test or development environment.
 * Prevents test-only hooks from being called in production.
 */
export function assertTestEnvironment(hookName: string): void {
  if (!_IS_TEST_ENVIRONMENT) {
    throw new Error(
      `${hookName} is a test-only hook and may only be called in test or development ` +
        `environments (NODE_ENV=test|development, or BUN_TEST is set). ` +
        `Current NODE_ENV=${String(_NODE_ENV_AT_LOAD)}. ` +
        `If you're seeing this in legitimate code, your build is mis-configured or a ` +
        `dependency is attempting to swap the SCP native bridge.`,
    );
  }
}
