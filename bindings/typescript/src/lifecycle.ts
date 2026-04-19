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
 * Since ADR-048 (#1549 Phase 4 PR 4), both functions accept an
 * optional {@link SCP} wrapper to target a specific bridge instance.
 * Omitting the argument preserves legacy behavior — routing through
 * the process-wide default instance — and emits a one-time
 * deprecation warning.
 */

import { getBridge } from "./internal/bridge";
import { deprecatedDefaultInstance } from "./internal/deprecation";
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
 * No-op if the bridge has not been initialized or has already shut down.
 * No-op on the WASM bridge.
 *
 * @param scp Optional {@link SCP} wrapper whose bridge should be
 *   suspended. When omitted, targets the process-wide default instance
 *   (legacy free-function behavior, emits a one-time deprecation
 *   warning).
 * @throws {TransportError} If transport cleanup fails.
 */
export async function scpSuspend(scp?: SCP): Promise<void> {
  if (scp !== undefined) {
    scp.suspend();
    return;
  }
  deprecatedDefaultInstance("scpSuspend");
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
 * @param scp Optional {@link SCP} wrapper whose bridge should be
 *   resumed. When omitted, targets the process-wide default instance
 *   (legacy free-function behavior, emits a one-time deprecation
 *   warning).
 * @throws {ContextError} If the bridge has been permanently shut down.
 */
export async function scpResume(scp?: SCP): Promise<void> {
  if (scp !== undefined) {
    await scp.resume();
    return;
  }
  deprecatedDefaultInstance("scpResume");
  const bridge = await getBridge();
  // `bridge.resume()` is async since #1678 — on NAPI it chains
  // transport reconnect from pending relay URLs and restoration of
  // persisted context snapshots. Awaiting propagates any
  // `SCP-CTX-2000` (shut-down) rejection to the caller.
  await bridge.resume();
}
