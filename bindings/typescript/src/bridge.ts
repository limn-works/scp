/**
 * Bridge connector types for the SCP TypeScript SDK.
 *
 * Defines bridge-connector wire types (spec §12, ADR-023). The
 * functional entry points (`bridgeCreateShadow`) moved onto the
 * {@link SCP} class in Phase 4 PR 4 (#1549, ADR-048); `bridgeRegister`
 * and `bridgeEvaluateTrust` never existed on the NAPI bridge so the
 * free-function shims were deleted outright in the same commit.
 *
 * See spec section 12 (Bridge System) and ADR-023.
 */

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
