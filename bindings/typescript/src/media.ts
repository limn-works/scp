/**
 * Media module types for the SCP TypeScript SDK.
 *
 * Defines wire types for media session lifecycle and WebRTC signaling.
 * The functional entry points (`mediaInitiateSession`, `mediaCreateOffer`,
 * etc.) moved onto the {@link SCP} class in Phase 4 PR 4 (#1549,
 * ADR-048) as `scp.mediaInitiateSession(...)`,
 * `scp.mediaCreateOffer(...)` and so on. The free-function shims that
 * predated ADR-048 were deleted in the same commit.
 *
 * See ADR-024 in `.docs/adrs/phase-5.md`.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Media session returned by session lifecycle functions. */
export interface MediaSession {
  readonly sessionId: string;
  readonly contextId: string;
  readonly participants: readonly string[];
  readonly capabilities: readonly string[];
  readonly state: "initiating" | "active" | "ended";
  readonly startedAt: number;
}

/** Session metadata returned when ending a media session. */
export interface SessionMetadata {
  readonly sessionId: string;
  readonly contextId: string;
  readonly participants: readonly string[];
  readonly capabilities: readonly string[];
  readonly startedAt: number;
  readonly endedAt: number;
}

/** Result of ending a media session. */
export interface EndSessionResult {
  readonly session: MediaSession;
  readonly metadata: SessionMetadata;
}

/** Signaling message creation result. */
export interface SignalingResult {
  readonly sessionId: string;
  readonly message: string;
}

/** Result of preparing a signaling message for transport. */
export interface SendSignalingResult {
  /** Base64-encoded payload bytes. */
  readonly payload: string;
  /** Message type discriminator (always `"Signaling"`). */
  readonly messageType: string;
}
