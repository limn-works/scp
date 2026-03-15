/**
 * Media module for the SCP TypeScript SDK.
 *
 * Provides functions for media session lifecycle management and WebRTC
 * signaling message construction and verification.
 *
 * See ADR-024 in `.docs/adrs/phase-5.md`.
 */

import { mapBridgeError } from "./errors";
import { getBridge } from "./internal/bridge";
import { safeJsonParse } from "./internal/json-utils";

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseSession(raw: Record<string, unknown>): MediaSession {
  return {
    sessionId: raw.session_id as string,
    contextId: raw.context_id as string,
    participants: raw.participants as readonly string[],
    capabilities: raw.capabilities as readonly string[],
    state: raw.state as "initiating" | "active" | "ended",
    startedAt: raw.started_at as number,
  };
}

function parseMetadata(raw: Record<string, unknown>): SessionMetadata {
  return {
    sessionId: raw.session_id as string,
    contextId: raw.context_id as string,
    participants: raw.participants as readonly string[],
    capabilities: raw.capabilities as readonly string[],
    startedAt: raw.started_at as number,
    endedAt: raw.ended_at as number,
  };
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/**
 * Checks that a media capability is present in the context ceiling.
 *
 * @param ceiling - List of capability name strings from the context ceiling.
 * @param capability - Media capability: `"voice"`, `"video"`, or `"screen_share"`.
 * @returns `true` if the capability is present.
 * @throws {ValidationError} If the capability string is invalid.
 * @throws {ContextError} If the capability is not in the ceiling.
 */
export async function mediaCheckCapability(
  ceiling: string[],
  capability: string,
): Promise<boolean> {
  try {
    const bridge = await getBridge();
    return bridge.mediaCheckCapability(ceiling, capability);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Initiates a media session after validating capabilities against the ceiling.
 *
 * @param contextId - The context hosting this media session.
 * @param ceiling - The context's capability ceiling as capability name strings.
 * @param capabilities - Media capabilities to activate (e.g., `["voice", "video"]`).
 * @param participants - Initial participant DIDs.
 * @param timestamp - Unix timestamp (seconds) for session creation.
 * @returns A MediaSession object.
 * @throws {ValidationError} If any capability string is invalid.
 * @throws {ContextError} If capabilities/participants are empty or capability missing from ceiling.
 */
export async function mediaInitiateSession(
  contextId: string,
  ceiling: string[],
  capabilities: string[],
  participants: string[],
  timestamp: number,
): Promise<MediaSession> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaInitiateSession(
      contextId,
      ceiling,
      capabilities,
      participants,
      timestamp,
    );
    const parsed = safeJsonParse(raw, "mediaInitiateSession") as Record<string, unknown>;
    return parseSession(parsed);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Activates a media session (transitions from Initiating to Active).
 *
 * @param sessionJson - JSON string representing the session.
 * @returns Updated MediaSession.
 * @throws {ContextError} If the session is not in the Initiating state.
 */
export async function mediaActivateSession(sessionJson: string): Promise<MediaSession> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaActivateSession(sessionJson);
    const parsed = safeJsonParse(raw, "mediaActivateSession") as Record<string, unknown>;
    return parseSession(parsed);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Adds a participant to a media session.
 *
 * @param sessionJson - JSON string representing the session.
 * @param participantDid - DID of the participant to add.
 * @returns Updated MediaSession.
 * @throws {ContextError} If the session has ended.
 */
export async function mediaJoinSession(
  sessionJson: string,
  participantDid: string,
): Promise<MediaSession> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaJoinSession(sessionJson, participantDid);
    const parsed = safeJsonParse(raw, "mediaJoinSession") as Record<string, unknown>;
    return parseSession(parsed);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Ends a media session and returns metadata for event log recording.
 *
 * @param sessionJson - JSON string representing the session.
 * @param timestamp - Unix timestamp (seconds) when the session ended.
 * @returns An object with `session` and `metadata` fields.
 * @throws {ContextError} If the session has already ended or timestamp is invalid.
 */
export async function mediaEndSession(
  sessionJson: string,
  timestamp: number,
): Promise<EndSessionResult> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaEndSession(sessionJson, timestamp);
    const parsed = safeJsonParse(raw, "mediaEndSession") as Record<string, unknown>;
    return {
      session: parseSession(parsed.session as Record<string, unknown>),
      metadata: parseMetadata(parsed.metadata as Record<string, unknown>),
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

// ---------------------------------------------------------------------------
// Signaling
// ---------------------------------------------------------------------------

/**
 * Creates an SDP offer signaling message.
 *
 * @param sessionId - The media session ID.
 * @param sdp - Raw SDP payload string.
 * @param senderDid - DID of the participant creating the offer.
 * @returns A SignalingResult with session_id and message.
 */
export async function mediaCreateOffer(
  sessionId: string,
  sdp: string,
  senderDid: string,
): Promise<SignalingResult> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaCreateOffer(sessionId, sdp, senderDid);
    const parsed = safeJsonParse(raw, "mediaCreateOffer") as Record<string, unknown>;
    return {
      sessionId: parsed.session_id as string,
      message: parsed.message as string,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Creates an SDP answer signaling message.
 *
 * @param sessionId - The media session ID.
 * @param sdp - Raw SDP payload string.
 * @param senderDid - DID of the participant creating the answer.
 * @returns A SignalingResult with session_id and message.
 */
export async function mediaCreateAnswer(
  sessionId: string,
  sdp: string,
  senderDid: string,
): Promise<SignalingResult> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaCreateAnswer(sessionId, sdp, senderDid);
    const parsed = safeJsonParse(raw, "mediaCreateAnswer") as Record<string, unknown>;
    return {
      sessionId: parsed.session_id as string,
      message: parsed.message as string,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Creates an ICE candidate signaling message.
 *
 * @param sessionId - The media session ID.
 * @param candidate - ICE candidate attribute string.
 * @param senderDid - DID of the participant who gathered the candidate.
 * @param options - Optional SDP association fields.
 * @returns A SignalingResult with session_id and message.
 */
export async function mediaCreateIceCandidate(
  sessionId: string,
  candidate: string,
  senderDid: string,
  options?: {
    sdpMid?: string;
    sdpMlineIndex?: number;
  },
): Promise<SignalingResult> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaCreateIceCandidate(
      sessionId,
      candidate,
      senderDid,
      options?.sdpMid,
      options?.sdpMlineIndex,
    );
    const parsed = safeJsonParse(raw, "mediaCreateIceCandidate") as Record<string, unknown>;
    return {
      sessionId: parsed.session_id as string,
      message: parsed.message as string,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Creates a session-end signaling message.
 *
 * @param sessionId - The media session ID.
 * @param senderDid - DID of the participant ending the session.
 * @returns A SignalingResult with session_id and message.
 */
export async function mediaCreateSessionEnd(
  sessionId: string,
  senderDid: string,
): Promise<SignalingResult> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaCreateSessionEnd(sessionId, senderDid);
    const parsed = safeJsonParse(raw, "mediaCreateSessionEnd") as Record<string, unknown>;
    return {
      sessionId: parsed.session_id as string,
      message: parsed.message as string,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Serializes a signaling message for transport.
 *
 * @param signalingJson - JSON string representing a signaling message.
 * @returns A SendSignalingResult with payload (base64) and messageType.
 * @throws {ValidationError} If the JSON is not a valid signaling message.
 */
export async function mediaSendSignaling(signalingJson: string): Promise<SendSignalingResult> {
  try {
    const bridge = await getBridge();
    const raw = bridge.mediaSendSignaling(signalingJson);
    const parsed = safeJsonParse(raw, "mediaSendSignaling") as Record<string, unknown>;
    return {
      payload: parsed.payload as string,
      messageType: parsed.message_type as string,
    };
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Verifies that the sender DID in a signaling message matches the envelope sender.
 *
 * @param signalingJson - JSON string representing a signaling message.
 * @param envelopeSenderDid - The DID from the authenticated SCP envelope.
 * @returns `true` if the sender attribution is valid.
 * @throws {ValidationError} If the JSON is invalid.
 * @throws {ContextError} If the sender DID does not match.
 */
export async function mediaVerifySenderAttribution(
  signalingJson: string,
  envelopeSenderDid: string,
): Promise<boolean> {
  try {
    const bridge = await getBridge();
    return bridge.mediaVerifySenderAttribution(signalingJson, envelopeSenderDid);
  } catch (error) {
    throw mapBridgeError(error);
  }
}
