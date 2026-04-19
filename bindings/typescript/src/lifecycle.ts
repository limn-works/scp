/**
 * Bridge lifecycle controls for the SCP TypeScript SDK.
 *
 * Exposes {@link scpSuspend} and {@link scpResume} which disconnect the bridge
 * from its relay (preserving context state) and clear the suspended flag,
 * respectively.  Use when backgrounding a mobile/desktop app, then call
 * {@link scpResume} plus `Transport.connect(...)` to rejoin.
 *
 * Both functions are no-ops on the WASM bridge (browsers have no
 * long-lived native runtime to suspend).
 *
 * Since ADR-048 (#1549 Phase 4 PR 4), both functions require an
 * {@link SCP} wrapper to target a specific bridge instance. The
 * legacy process-wide default instance fallback was removed in
 * PR 4 demolition.
 */

import type { SCP } from "./scp";

/**
 * Suspend the bridge instance for mobile/desktop backgrounding.
 *
 * Disconnects the transport (clearing the relay connection) and marks
 * the instance as suspended.  Context state is preserved — the
 * instance remains alive but inactive.  Transport-dependent operations
 * will fail until {@link scpResume} is called.
 *
 * After suspension, callers should call {@link scpResume} to re-activate
 * and then re-establish the relay connection via `Transport.connect(...)`.
 *
 * No-op on the WASM bridge.
 *
 * @param scp The {@link SCP} wrapper whose bridge should be suspended.
 *   Required — the legacy process-wide default instance fallback was
 *   removed in Phase 4 PR 4 (#1549) demolition.
 * @throws {TransportError} If transport cleanup fails.
 */
export async function scpSuspend(scp: SCP): Promise<void> {
  scp.suspend();
}

/**
 * Resume a suspended bridge instance.
 *
 * Clears the suspended flag so bridge operations can proceed.  The
 * caller must re-establish the relay connection via
 * `Transport.connect(...)` — resume does not reconnect automatically.
 *
 * No-op on the WASM bridge.
 *
 * @param scp The {@link SCP} wrapper whose bridge should be resumed.
 *   Required — the legacy process-wide default instance fallback was
 *   removed in Phase 4 PR 4 (#1549) demolition.
 * @throws {ContextError} If the bridge has been permanently shut down.
 */
export async function scpResume(scp: SCP): Promise<void> {
  await scp.resume();
}
