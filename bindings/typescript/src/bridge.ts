/**
 * Bridge connector module for the SCP TypeScript SDK.
 *
 * Provides functions for registering bridge connectors, evaluating bridge
 * trust levels, and creating shadow identities for external platform
 * participants.
 *
 * See spec section 12 (Bridge System) and ADR-023.
 */

import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";

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

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Registers a bridge connector with a context.
 *
 * @param contextId - Context to register the bridge in.
 * @param operatorDid - DID of the human operator.
 * @param governanceDid - DID of the governance authority approving the
 *   registration.  Must differ from `operatorDid` (self-approval is
 *   forbidden per ADR-023).
 * @param platform - External platform name (e.g., `"discord"`).
 * @param mode - Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
 * @returns The bridge registration result.
 * @throws {ValidationError} If mode is not recognized.
 * @throws {ContextError} If governance DID matches operator DID (self-approval).
 */
export async function bridgeRegister(
  contextId: string,
  operatorDid: string,
  governanceDid: string,
  platform: string,
  mode: BridgeMode,
): Promise<BridgeRegistration> {
  try {
    const bridge = await getBridge();
    const raw = bridge.bridgeRegister(contextId, operatorDid, governanceDid, platform, mode);
    return {
      bridgeId: raw.bridge_id,
      operatorDid: raw.operator_did,
      platform: raw.platform,
      mode: raw.mode,
      status: raw.status,
      contextId: raw.context_id,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Evaluates the trust level for an action based on bridge provenance.
 *
 * @param isBridged - Whether the action has bridge provenance.
 * @param isNativeTransport - Whether the transport is native SCP.
 * @param shadowStatus - `"shadow"` or `"claimed"`.
 * @returns Trust tier as an integer (0-3).
 */
export async function bridgeEvaluateTrust(
  isBridged = false,
  isNativeTransport = true,
  shadowStatus: ShadowStatus = "shadow",
): Promise<number> {
  try {
    const bridge = await getBridge();
    return bridge.bridgeEvaluateTrust(isBridged, isNativeTransport, shadowStatus);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Creates a shadow identity for an external platform participant.
 *
 * @param bridgeId - The bridge connector ID.
 * @param platformHandle - External platform handle.
 * @param bridgeMode - Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
 * @param contextId - Context the shadow is being created in.
 * @returns The shadow identity result.
 */
export async function bridgeCreateShadow(
  bridgeId: string,
  platformHandle: string,
  bridgeMode: BridgeMode,
  contextId?: string,
): Promise<ShadowIdentity> {
  try {
    const bridge = await getBridge();
    const raw = bridge.bridgeCreateShadow(bridgeId, platformHandle, bridgeMode, contextId);
    return {
      shadowId: raw.shadow_id,
      platformHandle: raw.platform_handle,
      bridgeId: raw.bridge_id,
      attributedRole: raw.attributed_role,
      provenanceStatus: raw.provenance_status,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}
