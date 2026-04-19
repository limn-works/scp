/**
 * SCPID authentication for external services (spec section 3.11).
 *
 * Provides challenge-response authentication so that SCP DID holders can
 * prove their identity to external services outside of SCP contexts.
 * Analogous to "Sign in with Ethereum" (EIP-4361) but simpler: no
 * blockchain state, no gas -- the DID document is the identity provider.
 *
 * See `.docs/specs/` section 3.11 and ADR phase-3.
 */

import { mapBridgeError } from "./errors";
import type { Identity } from "./identity";
import { getBridge } from "./internal/bridge";
import type { SCP } from "./scp";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** SCPID challenge issued by a relying party (section 3.11.2). */
export interface ScpIdChallenge {
  /** Protocol identifier and version: `"scpid/1.0"`. */
  readonly protocol: string;
  /** 32-byte CSPRNG nonce (hex-encoded string). */
  readonly nonce: string;
  /** URI identifying the relying party. */
  readonly audience: string;
  /** Unix timestamp (milliseconds) when the challenge was created. */
  readonly issued_at: number;
  /** Unix timestamp (milliseconds) when the challenge expires. */
  readonly expires_at: number;
}

/** SCPID response signed by the client (section 3.11.3). */
export interface ScpIdResponse {
  /** Protocol identifier and version: `"scpid/1.0"`. */
  readonly protocol: string;
  /** The signer's DID (e.g. `"did:dht:z6Mk..."`). */
  readonly did: string;
  /** Which verification method signed: `"#active"` or `"#agent"`. */
  readonly signing_key_id: string;
  /** Echo of the challenge nonce (hex-encoded string). */
  readonly nonce: string;
  /** Echo of the challenge audience URI. */
  readonly audience: string;
  /** Unix timestamp (milliseconds) when the client signed. */
  readonly signed_at: number;
  /** Ed25519 signature (hex-encoded string). */
  readonly signature: string;
}

/** Result of a successful SCPID verification (section 3.11.4 step 11). */
export interface ScpIdAuthentication {
  /** The authenticated DID. */
  readonly did: string;
  /** Which verification method produced the signature. */
  readonly signing_key_id: string;
  /** Unix timestamp (milliseconds) when the client signed. */
  readonly signed_at: number;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate an SCPID challenge for a relying party (section 3.11.8).
 *
 * @param audience - URI identifying the relying party
 *   (e.g. `"https://app.example.com"`).
 * @param ttlSeconds - Challenge validity window in seconds (1-300).
 *   Defaults to 300.
 * @returns A new `ScpIdChallenge`.
 * @throws {ValidationError} If `audience` is empty, exceeds 2048 bytes,
 *   or `ttlSeconds` is 0 or exceeds 300.
 */
export async function scpidChallenge(
  scp: SCP,
  audience: string,
  ttlSeconds = 300,
): Promise<ScpIdChallenge> {
  try {
    const bridge = await getBridge(scp);
    const json = bridge.scpidChallenge(audience, ttlSeconds);
    return JSON.parse(json) as ScpIdChallenge;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Sign an SCPID challenge with a registered identity's key (section 3.11.3).
 *
 * Looks up the identity by DID in the global registry, selects the
 * appropriate signing key, and produces a signed SCPID response.
 *
 * @param identity - An `Identity` instance whose DID is registered.
 * @param signingKeyId - `"#active"` or `"#agent"`.
 * @param challenge - The challenge to sign.
 * @returns A new `ScpIdResponse`.
 * @throws {IdentityError} If the DID is not registered or signing fails.
 * @throws {ValidationError} If `signingKeyId` is invalid or the challenge
 *   is malformed.
 */
export async function scpidSign(
  identity: Identity,
  signingKeyId: string,
  challenge: ScpIdChallenge,
): Promise<ScpIdResponse> {
  try {
    const bridge = await getBridge(identity._scp);
    const json = bridge.scpidSign(identity.did, signingKeyId, JSON.stringify(challenge));
    return JSON.parse(json) as ScpIdResponse;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Verify a signed SCPID response against the original challenge (section 3.11.4).
 *
 * Resolves the signer's DID document via the global DID resolver
 * (initialized during identity creation), then runs the 11-step
 * verification pipeline.
 *
 * **Not available in the WASM bridge.** SCPID verification requires DID
 * document resolution which depends on network access and a full DID
 * resolver. Use the native (napi-rs) bridge instead.
 *
 * @param response - The signed response from the client.
 * @param challenge - The original challenge issued by the relying party.
 * @returns An `ScpIdAuthentication` on success.
 * @throws {IdentityError} If the DID resolver is not initialized, DID
 *   resolution fails, the signature is invalid, the challenge has expired,
 *   or any other verification step fails. Also thrown in WASM mode.
 * @throws {ValidationError} If either JSON structure is malformed.
 */
export async function scpidVerify(
  scp: SCP,
  response: ScpIdResponse,
  challenge: ScpIdChallenge,
): Promise<ScpIdAuthentication> {
  try {
    const bridge = await getBridge(scp);
    const json = bridge.scpidVerify(JSON.stringify(response), JSON.stringify(challenge));
    return JSON.parse(json) as ScpIdAuthentication;
  } catch (error) {
    throw mapBridgeError(error);
  }
}
