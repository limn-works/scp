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
  return nodeEnv === "test" || nodeEnv === "development" || bunTest !== undefined;
}

// Evaluated once at import time — runtime mutations to process.env cannot flip this.
const _IS_TEST_ENVIRONMENT: boolean = (() => {
  try {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    return _evaluateTestEnv(proc?.env);
  } catch {
    return false;
  }
})();

// Frozen alongside _IS_TEST_ENVIRONMENT so the error message in
// assertTestEnvironment always reports the value that drove the decision,
// not a potentially-mutated live read of process.env.
const _NODE_ENV_AT_LOAD: string | undefined = (() => {
  try {
    const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    const env = proc?.env;
    return env && typeof env === "object" && Object.hasOwn(env, "NODE_ENV")
      ? env.NODE_ENV
      : undefined;
  } catch {
    return undefined;
  }
})();

/**
 * Returns true when the runtime is in a test or development environment.
 * Fail-closed: returns false if process is unavailable (browser, Deno) or
 * when NODE_ENV is absent, "production", "staging", or any other value.
 *
 * The decision is frozen at module load time — runtime mutations to
 * `process.env` cannot flip this after import.
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
