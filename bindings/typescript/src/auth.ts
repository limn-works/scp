/**
 * SCPID authentication types for external services (spec section 3.11).
 *
 * Defines the challenge-response wire types used by the SCP bridge so
 * DID holders can authenticate to external services outside of SCP
 * contexts. The functional entry points (`scpidChallenge`, `scpidSign`,
 * `scpidVerify`) moved onto the {@link SCP} class in Phase 4 PR 4
 * (#1549, ADR-048); the free-function shims that predated ADR-048
 * were deleted in the same commit.
 *
 * See `.docs/specs/` section 3.11 and ADR phase-3.
 */

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
