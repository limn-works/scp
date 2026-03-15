/**
 * UCAN module for the SCP TypeScript SDK.
 *
 * Provides functions for UCAN token lifecycle management: validation,
 * minting, revocation, and delegation. UCAN tokens are the capability
 * authorization mechanism within SCP contexts.
 *
 * See ADR-016 (UCAN Enforcement) and ADR-022 in `.docs/adrs/phase-4.md`.
 */

import type { Context } from "./context";
import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";
import type { UcanToken } from "./types";

// ---------------------------------------------------------------------------
// UCAN operations
// ---------------------------------------------------------------------------

/**
 * Validates a UCAN token for a required capability within a context.
 *
 * Performs full validation: signature verification, time bounds checking,
 * delegation chain traversal, attenuation enforcement, nonce replay
 * detection, and capability matching.
 *
 * @param ctx - The context the token is presented in.
 * @param token - The encoded UCAN token string (JWT format).
 * @param capability - The required capability URI.
 * @throws {UcanPermissionError} If validation fails.
 */
export async function validateUcan(ctx: Context, token: string, capability: string): Promise<void> {
  try {
    const bridge = await getBridge();
    await bridge.ucanValidate(ctx._handle, token, capability);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Mints a new UCAN token for a context member.
 *
 * Creates a UCAN token granting the specified capabilities to the member.
 * The token is signed by the context admin's key and scoped to this context.
 *
 * @param ctx - The context to mint the token for.
 * @param memberDid - The DID of the member receiving the token.
 * @param capabilities - Capability URIs to grant.
 * @returns The minted UCAN token with metadata.
 * @throws {UcanPermissionError} If minting fails.
 */
export async function mintUcan(
  ctx: Context,
  memberDid: string,
  capabilities: readonly string[],
): Promise<UcanToken> {
  try {
    const bridge = await getBridge();
    return await bridge.ucanMint(ctx._handle, memberDid, capabilities);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Revokes a UCAN token using the full revocation pipeline.
 *
 * Performs authorization (revoker must be the token's issuer or the context
 * creator), adds the token to the context's revocation list, and appends a
 * TokenRevoked event to the context's Merkle event log.
 *
 * @param ctx - The context the token belongs to.
 * @param token - The full encoded JWT string of the token to revoke.
 * @param revokerDid - The DID of the entity requesting the revocation.
 *   Must be the token's issuer or the context creator.
 * @throws {UcanPermissionError} If revocation fails (unauthorized, malformed, etc.).
 */
export async function revokeUcan(
  ctx: Context,
  token: string,
  revokerDid: string,
): Promise<void> {
  try {
    const bridge = await getBridge();
    await bridge.ucanRevoke(ctx._handle, token, revokerDid);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Delegates a UCAN token to another member.
 *
 * Creates a new UCAN token that delegates a subset of the original token's
 * capabilities to another member. The delegator must be the audience of the
 * original token (iss/aud chain linkage). Attenuation rules ensure the
 * delegated token cannot exceed the original's scope.
 *
 * Delegates to the real `bridge.ucanDelegate()` which performs Ed25519
 * signing via the delegator's retained `KeyCustody` and enforces
 * attenuation, iss/aud chain validation, and ceiling compliance.
 *
 * @param ctx - The context to delegate within.
 * @param originalToken - The original token to delegate from (must include `encoded` JWT).
 * @param delegatorDid - The DID of the entity delegating (must match originalToken.audience).
 * @param targetDid - The DID of the delegation target.
 * @param capabilities - Capability URIs to delegate (must be a subset of the original).
 * @returns The delegated UCAN token.
 * @throws {UcanPermissionError} If delegation fails or capabilities exceed the original.
 */
export async function delegateUcan(
  ctx: Context,
  originalToken: UcanToken,
  delegatorDid: string,
  targetDid: string,
  capabilities: readonly string[],
): Promise<UcanToken> {
  try {
    const bridge = await getBridge();
    return await bridge.ucanDelegate(
      ctx._handle,
      delegatorDid,
      targetDid,
      originalToken.encoded,
      capabilities,
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}
