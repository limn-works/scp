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
 */

import { getBridge } from "./internal/bridge";

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
 * No-op if the bridge has not been initialized or has already shut down.
 * No-op on the WASM bridge.
 *
 * @throws {TransportError} If transport cleanup fails.
 */
export async function scpSuspend(): Promise<void> {
  const bridge = await getBridge();
  bridge.suspend();
}

/**
 * Resume a suspended bridge instance.
 *
 * Clears the suspended flag so bridge operations can proceed.  The
 * caller must re-establish the relay connection via
 * `Transport.connect(...)` — resume does not reconnect automatically.
 *
 * No-op if the bridge is not initialized.
 * No-op on the WASM bridge.
 *
 * @throws {ContextError} If the bridge has been permanently shut down.
 */
export async function scpResume(): Promise<void> {
  const bridge = await getBridge();
  bridge.resume();
}
