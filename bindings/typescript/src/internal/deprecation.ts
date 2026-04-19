/**
 * One-time deprecation warnings for the default-instance free-function
 * façade. See ADR-048 ("SCP multi-instance bridge +
 * check-handle-affinity gate").
 *
 * Every free function in the SDK that implicitly operates on the
 * process-wide default `SCP` instance calls {@link deprecatedDefaultInstance}
 * at the top of its body. The first call per function name emits a
 * `console.warn`; subsequent calls for the same function name are
 * silent. This matches the Python SDK's `@deprecated_default_instance`
 * decorator behavior.
 *
 * Removal target: two release cycles after Phase 4 PR 1 merge.
 */

/**
 * Fully-qualified function names that have already emitted their
 * one-time warning in this JS runtime. Keyed by name rather than the
 * function object so we can key across async transformations and
 * bundled module copies.
 */
const emitted = new Set<string>();

/**
 * Emits a one-time `console.warn` pointing callers at the non-deprecated
 * `SCP` class. Call at the top of every free-function façade body
 * before delegating to `getBridge()`.
 *
 * @param fnName The bare function name (e.g. `"scpSuspend"`,
 *   `"mintUcan"`). Do NOT include module path prefixes — the warning
 *   message is phrased around an unqualified SDK-level function.
 */
export function deprecatedDefaultInstance(fnName: string): void {
  if (emitted.has(fnName)) {
    return;
  }
  emitted.add(fnName);
  // `console.warn` is the JS-idiomatic mirror of Python's
  // `DeprecationWarning`. Not using an error class because deprecation
  // is advisory, not blocking. TypeScript ecosystems treat `warn` as
  // the standard surface.
  console.warn(
    `[scp] ${fnName} uses the default SCP instance and is deprecated; ` +
      "construct an explicit `new SCP()` instead. " +
      "Removal target: two release cycles after Phase 4 merge (ADR-048).",
  );
}

/**
 * Test-only helper: clear the one-time-warning tracker.
 *
 * Exposed so tests can exercise the "first call emits, second is
 * silent" contract repeatedly without leaking state across test cases.
 */
export function _resetEmittedForTests(): void {
  emitted.clear();
}
