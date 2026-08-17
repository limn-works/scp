/**
 * Bridge connector types and module functions for the SCP TypeScript SDK.
 *
 * Defines bridge-connector wire types (spec §12, ADR-023). The stateful
 * functional entry point (`bridgeCreateShadow`) moved onto the
 * {@link SCP} class in Phase 4 PR 4 (#1549, ADR-048).
 *
 * {@link evaluateTrust} is the pure bridge-provenance trust-tier classifier
 * (spec §12). It is a module function — mirroring the Python SDK's
 * `scp_sdk.bridge.evaluate_trust` — that routes to the bridge's
 * `bridgeEvaluateTrust` operation. It takes an {@link SCP} instance because
 * the per-instance bridge is resolved through `getBridge(scp)` (the same
 * mechanism the discovery-module free functions use); the operation itself
 * is pure (no per-instance state).
 *
 * See spec section 12 (Bridge System) and ADR-023.
 */

import { getBridge } from "./internal/bridge";
import type { SCP } from "./scp";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Bridge operating mode (spec §12). */
export type BridgeMode = "relay" | "puppet" | "api" | "cooperative";

/**
 * Bridge trust tier returned by {@link evaluateTrust} (spec §12).
 *
 * Integer discriminants mirror the Rust `BridgeTrustLevel` enum:
 * - `0` — `ShadowBridged` (weakest): bridged, unclaimed shadow identity.
 * - `1` — `ClaimedBridged`: bridged, shadow identity was claimed.
 * - `2` — `NativeBridged`: bridged action over native SCP transport.
 * - `3` — `NativeNative` (strongest): native action over native transport.
 */
export type BridgeTrustLevel = 0 | 1 | 2 | 3;

/** Shadow identity provenance status. */
export type ShadowStatus = "shadow" | "claimed";

/** Bridge registration result. */
export interface BridgeRegistration {
  readonly bridgeId: string;
  readonly operatorDid: string;
  readonly platform: string;
  readonly mode: BridgeMode;
  readonly status: string;
  readonly contextId: string;
}

/** Shadow identity result. */
export interface ShadowIdentity {
  readonly shadowId: string;
  readonly platformHandle: string;
  readonly bridgeId: string;
  readonly attributedRole: string;
  readonly provenanceStatus: ShadowStatus;
}

/**
 * Bridge credential metadata (spec §12.11).
 *
 * Returned by `SCP.bridgeCredentialProvision` and
 * `SCP.bridgeCredentialRotate`. The encrypted credential bytes never cross
 * the FFI boundary — only this non-secret metadata.
 */
export interface BridgeCredential {
  readonly bridgeId: string;
  readonly credentialType: string;
  /** Unix timestamp (seconds) when the credential was created. */
  readonly createdAt: number;
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/**
 * Optional §12.2.1 registration fields.
 *
 * `platformKey` and `platformKeyId` travel together: cooperative mode requires
 * both, and every other mode rejects both. A platform sends `platformKeyId` in
 * `X-SCP-Platform-Key-Id` on every webhook request, and every webhook signature
 * covers it (spec §12.10.2), so a cooperative bridge registered without both
 * values could never verify a webhook signature.
 */
export interface BridgeRegistrationOptions {
  /** Cooperative mode only: the platform's webhook receiver URL. */
  readonly webhookUrl?: string;
  /** Cooperative mode only: the platform's 32-byte Ed25519 webhook key. */
  readonly platformKey?: Uint8Array;
  /**
   * Cooperative mode only: the platform's identifier for `platformKey`.
   * Spec §12.2.1 accepts 1–128 bytes of printable US-ASCII.
   */
  readonly platformKeyId?: string;
  /** Governance-configured shadow limit for this bridge (default 10,000). */
  readonly maxShadows?: number;
  /** Human-readable name for this bridge. */
  readonly displayName?: string;
  /** Free-text description of what this bridge carries. */
  readonly description?: string;
  /** How to reach this bridge's operator. */
  readonly operatorContact?: string;
}

/**
 * Register a bridge connector for a context (spec §12, ADR-023).
 *
 * Wraps the NAPI `bridge_register` free function exposed on the internal
 * {@link Bridge} surface. The bridge object is resolved per-{@link SCP}
 * instance (ADR-048), so multiple SCP instances register independently.
 *
 * @param scp The SCP instance to register the bridge under.
 * @param contextId The context the bridge serves.
 * @param operatorDid The DID of the bridge operator.
 * @param governanceDid The DID authorizing the registration.
 * @param platform The external platform identifier.
 * @param mode The bridge operating mode.
 * @param options Optional §12.2.1 fields, including the cooperative-mode
 *   platform key and its identifier.
 * @returns A {@link BridgeRegistration} describing the registered bridge.
 * @throws When a cooperative registration omits `platformKey` or
 *   `platformKeyId`, when a non-cooperative registration carries either one,
 *   or when `platformKeyId` breaks the shape spec §12.2.1 requires.
 */
export async function bridgeRegister(
  scp: SCP,
  contextId: string,
  operatorDid: string,
  governanceDid: string,
  platform: string,
  mode: BridgeMode,
  options: BridgeRegistrationOptions = {},
): Promise<BridgeRegistration> {
  const bridge = await getBridge(scp);
  // The internal Bridge returns snake_case keys (matching the Rust wire
  // shape); map to the public camelCase BridgeRegistration.
  const raw = bridge.bridgeRegister(
    contextId,
    operatorDid,
    governanceDid,
    platform,
    mode,
    options.webhookUrl,
    options.platformKey,
    options.platformKeyId,
    options.maxShadows,
    options.displayName,
    options.description,
    options.operatorContact,
  );
  return {
    bridgeId: raw.bridge_id,
    operatorDid: raw.operator_did,
    platform: raw.platform,
    mode: raw.mode,
    status: raw.status,
    contextId: raw.context_id,
  };
}

// ---------------------------------------------------------------------------
// Trust evaluation (bridge provenance)
// ---------------------------------------------------------------------------

/**
 * Options for {@link evaluateTrust}. Mirrors the keyword-only arguments and
 * defaults of the Python SDK's `scp_sdk.bridge.evaluate_trust`.
 */
export interface BridgeTrustOptions {
  /** Whether the action carries bridge provenance. Defaults to `false`. */
  readonly isBridged?: boolean;
  /** Whether the transport is native SCP. Defaults to `true`. */
  readonly isNativeTransport?: boolean;
  /**
   * Shadow provenance status. Only meaningful when `isBridged` is `true`.
   * Defaults to `"shadow"`.
   */
  readonly shadowStatus?: ShadowStatus;
}

/**
 * Evaluates the trust tier for an action based on bridge provenance (spec §12).
 *
 * Returns an integer (0–3) representing the trust tier, strongest last:
 *
 * - `0` — `ShadowBridged` (weakest): bridged action, unclaimed shadow identity.
 * - `1` — `ClaimedBridged`: bridged action whose shadow identity was claimed.
 * - `2` — `NativeBridged`: bridged action over native SCP transport.
 * - `3` — `NativeNative` (strongest): native action over native transport.
 *
 * Mirrors the Python SDK's `scp_sdk.bridge.evaluate_trust`. The operation is
 * pure (no per-instance state); the {@link SCP} argument exists only so the
 * per-instance bridge can be resolved — consistent with the discovery-module
 * free functions (`parseAddress`, `createQuery`, …).
 *
 * @param scp The {@link SCP} instance whose bridge dispatches the call.
 * @param options Provenance inputs; each field defaults per the Python SDK
 *   (`isBridged=false`, `isNativeTransport=true`, `shadowStatus="shadow"`).
 * @returns The trust tier as a {@link BridgeTrustLevel} integer (0–3).
 */
export async function evaluateTrust(
  scp: SCP,
  options: BridgeTrustOptions = {},
): Promise<BridgeTrustLevel> {
  const bridge = await getBridge(scp);
  const isBridged = options.isBridged ?? false;
  const isNativeTransport = options.isNativeTransport ?? true;
  const shadowStatus = options.shadowStatus ?? "shadow";
  return bridge.bridgeEvaluateTrust(isBridged, isNativeTransport, shadowStatus) as BridgeTrustLevel;
}
