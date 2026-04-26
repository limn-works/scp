/**
 * UCAN module for the SCP TypeScript SDK.
 *
 * Provides functions for UCAN token lifecycle management: validation,
 * minting, revocation, delegation, and §7.3.8 caveat narrowing
 * (SCP-OUT-023). UCAN tokens are the capability authorization mechanism
 * within SCP contexts.
 *
 * See ADR-016 (UCAN Enforcement) and ADR-022 in `.docs/adrs/phase-4.md`.
 */

import type { Context } from "./context";
import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";
import { deprecatedDefaultInstance } from "./internal/deprecation";
import type { InvocationCaveats } from "./outlets";
import type { UcanToken } from "./types";

// ---------------------------------------------------------------------------
// Caveat marshalling — SDK camelCase <-> wire camelCase (§7.3.8).
// ---------------------------------------------------------------------------

/**
 * Serialize an {@link InvocationCaveats} object to its canonical JSON wire
 * form (§7.3.8 vocabulary). The TypeScript SDK already uses camelCase keys
 * matching the wire format, so the only transformation is rate_window
 * normalization (the SDK accepts a number-of-seconds shorthand and the wire
 * form requires the full `{max, windowSecs}` object).
 *
 * Returns `undefined` when `caveats` is `undefined` so callers can pass
 * the result straight into the bridge `caveatsJson` parameter.
 */
function caveatsToJson(caveats: InvocationCaveats | undefined): string | undefined {
  if (caveats === undefined) return undefined;
  // Build wire dict, dropping `undefined` fields and normalizing
  // rate_window int → object form.
  const wire: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(caveats)) {
    if (value === undefined) continue;
    if (key === "rateWindow" && typeof value === "number") {
      wire[key] = { max: 1, windowSecs: value };
    } else {
      wire[key] = value;
    }
  }
  return JSON.stringify(wire);
}

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
  deprecatedDefaultInstance("validateUcan");
  try {
    const bridge = await getBridge();
    await bridge.ucanValidate(ctx._handle, token, capability);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Mints a new UCAN token for a context member, optionally with §7.3.8
 * invocation caveats (SCP-OUT-023).
 *
 * Creates a UCAN token granting the specified capabilities to the member.
 * The token is signed by the context admin's key and scoped to this
 * context. When `caveats` is provided, they are routed into the UCAN
 * payload's `nb` field; mint-limit failures (more than 8 populated non-
 * `originKind` fields, list overflows, schema overflows) reject with
 * `SCP-TOOL-6114` (slug `caveat-mint-limit-exceeded`).
 *
 * @param ctx - The context to mint the token for.
 * @param memberDid - The DID of the member receiving the token.
 * @param capabilities - Capability URIs to grant.
 * @param proofs - Optional parent UCAN tokens to chain as proofs.
 * @param caveats - Optional {@link InvocationCaveats} narrowing the
 *   delegated capability (§7.3.8).
 * @returns The minted UCAN token with metadata.
 * @throws {UcanPermissionError} If minting fails (ceiling violation,
 *   mint-limit exceeded, etc.).
 */
export async function mintUcan(
  ctx: Context,
  memberDid: string,
  capabilities: readonly string[],
  proofs?: readonly string[],
  caveats?: InvocationCaveats,
): Promise<UcanToken> {
  deprecatedDefaultInstance("mintUcan");
  try {
    const bridge = await getBridge();
    return await bridge.ucanMint(
      ctx._handle,
      memberDid,
      capabilities,
      proofs,
      caveatsToJson(caveats),
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Narrows a parent UCAN token by attaching attenuated caveats
 * (SCP-OUT-023, §7.3.8).
 *
 * Re-issues `parentToken` to the same audience with attenuated
 * {@link InvocationCaveats}. Each field's narrowing rule (§7.3.8) is
 * enforced inside the Rust core: numeric ceilings tighten downward,
 * validity windows shift inward, masks subset, lists subset, `originKind`
 * is equality (no widening, no narrowing, no reset).
 *
 * @param ctx - The context the token belongs to.
 * @param parentToken - The parent UCAN to narrow (its `encoded` JWT is
 *   forwarded to the bridge).
 * @param childCaveats - The attenuated caveats; MUST be a strict
 *   attenuation of the parent's caveats per §7.3.8.
 * @returns A new {@link UcanToken} carrying the narrowed caveats.
 * @throws {UcanPermissionError} If the narrow rule rejects (widening
 *   field, origin-kind mismatch, mask-width violation).
 */
export async function narrowUcan(
  ctx: Context,
  parentToken: UcanToken,
  childCaveats: InvocationCaveats,
): Promise<UcanToken> {
  deprecatedDefaultInstance("narrowUcan");
  try {
    const bridge = await getBridge();
    const wireJson = caveatsToJson(childCaveats) ?? "{}";
    return await bridge.ucanNarrow(ctx._handle, parentToken.encoded, wireJson);
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
export async function revokeUcan(ctx: Context, token: string, revokerDid: string): Promise<void> {
  deprecatedDefaultInstance("revokeUcan");
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
  deprecatedDefaultInstance("delegateUcan");
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
