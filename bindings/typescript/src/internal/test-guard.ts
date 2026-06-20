/**
 * Returns true when the runtime is in a test or development environment.
 * Fail-closed: returns false if process is unavailable (browser, Deno) or
 * when NODE_ENV is absent, "production", "staging", or any other value.
 */
export function isTestEnvironment(): boolean {
  try {
    const proc = (globalThis as { process?: { env?: { NODE_ENV?: string; BUN_TEST?: string } } })
      .process;
    const env = proc?.env?.NODE_ENV;
    return env === "test" || env === "development" || proc?.env?.BUN_TEST !== undefined;
  } catch {
    return false;
  }
}

/**
 * Throws unless the runtime is in a test or development environment.
 * Prevents test-only hooks from being called in production.
 */
export function assertTestEnvironment(hookName: string): void {
  if (!isTestEnvironment()) {
    throw new Error(
      `${hookName} is a test-only hook and may only be called in test or development ` +
        `environments (NODE_ENV=test|development, or BUN_TEST is set). ` +
        `Current NODE_ENV=${String((globalThis as { process?: { env?: { NODE_ENV?: string } } }).process?.env?.NODE_ENV)}. ` +
        `If you're seeing this in legitimate code, your build is mis-configured or a ` +
        `dependency is attempting to swap the SCP native bridge.`,
    );
  }
}
