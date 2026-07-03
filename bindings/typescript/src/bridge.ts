/**
 * Bridge connector types and entry points for the SCP TypeScript SDK.
 *
 * Defines bridge-connector wire types (spec §12, ADR-023). The
 * `bridgeCreateShadow` entry point lives on the {@link SCP} class
 * (Phase 4 PR 4, ADR-048); {@link bridgeRegister} is the public
 * wrapper over the NAPI `bridge_register` free function
 * (`bridge_connector.rs`), exposed here as a free function that takes an
 * explicit {@link SCP} instance per the ADR-048 multi-instance pattern.
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
 * @returns A {@link BridgeRegistration} describing the registered bridge.
 */
export async function bridgeRegister(
  scp: SCP,
  contextId: string,
  operatorDid: string,
  governanceDid: string,
  platform: string,
  mode: BridgeMode,
): Promise<BridgeRegistration> {
  const bridge = await getBridge(scp);
  // The internal Bridge returns snake_case keys (matching the Rust wire
  // shape); map to the public camelCase BridgeRegistration.
  const raw = bridge.bridgeRegister(contextId, operatorDid, governanceDid, platform, mode);
  return {
    bridgeId: raw.bridge_id,
    operatorDid: raw.operator_did,
    platform: raw.platform,
    mode: raw.mode,
    status: raw.status,
    contextId: raw.context_id,
  };
}

/**
 * Evaluate the trust level for a bridge action (spec §12, ADR-023).
 *
 * Wraps the NAPI `bridge_evaluate_trust` free function. Returns a numeric
 * trust level derived from whether the action is bridged, whether it crossed a
 * native SCP transport, and the shadow-identity provenance status.
 *
 * @param scp The SCP instance to resolve the bridge under.
 * @param isBridged Whether the action originated through a bridge connector.
 * @param isNativeTransport Whether the action used SCP-native transport.
 * @param shadowStatus The shadow identity's provenance status.
 * @returns The evaluated bridge trust level.
 */
export async function bridgeEvaluateTrust(
  scp: SCP,
  isBridged: boolean,
  isNativeTransport: boolean,
  shadowStatus: ShadowStatus,
): Promise<number> {
  const bridge = await getBridge(scp);
  return bridge.bridgeEvaluateTrust(isBridged, isNativeTransport, shadowStatus);
}
