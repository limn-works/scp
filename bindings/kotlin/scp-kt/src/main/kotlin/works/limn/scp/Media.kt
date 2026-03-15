// Media.kt — Kotlin SDK media wrappers (#597)
//
// Wraps media-related UniFFI bridge functions as suspend functions
// with proper dispatcher assignment per ADR-028. All FFI calls are
// dispatched on Dispatchers.IO via the CoroutineBridge.
//
// Provenance: ADR-024 (Media), §10.9

package works.limn.scp

import works.limn.scp.bridge.CoroutineBridge

/**
 * Native binding functions for media operations.
 *
 * All methods are blocking JNA calls into Rust and must be dispatched
 * on [kotlinx.coroutines.Dispatchers.IO].
 */
@Suppress("TooManyFunctions")
interface MediaBindings {
    /**
     * Checks that a media capability is present in the context ceiling.
     *
     * @param ceiling List of capability name strings from the context ceiling.
     * @param capability Media capability: "voice", "video", or "screen_share".
     * @return `true` if the capability is present.
     * @throws BridgeException if capability is invalid or missing from ceiling.
     */
    fun mediaCheckCapability(
        ceiling: List<String>,
        capability: String,
    ): Boolean

    /**
     * Initiates a media session after validating capabilities against the ceiling.
     *
     * @param contextId The context hosting this media session.
     * @param ceiling The context's capability ceiling.
     * @param capabilities Media capabilities to activate.
     * @param participants Initial participant DIDs.
     * @param timestamp Unix timestamp (seconds) for session creation.
     * @return JSON string with session fields.
     * @throws BridgeException on validation failure.
     */
    fun mediaInitiateSession(
        contextId: String,
        ceiling: List<String>,
        capabilities: List<String>,
        participants: List<String>,
        timestamp: Long,
    ): String

    /**
     * Activates a media session (transitions from Initiating to Active).
     *
     * @param sessionJson JSON string representing the session.
     * @return Updated session JSON string.
     * @throws BridgeException if session is not in Initiating state.
     */
    fun mediaActivateSession(sessionJson: String): String

    /**
     * Adds a participant to a media session.
     *
     * @param sessionJson JSON string representing the session.
     * @param participantDid DID of the participant to add.
     * @return Updated session JSON string.
     * @throws BridgeException if session has ended.
     */
    fun mediaJoinSession(sessionJson: String, participantDid: String): String

    /**
     * Ends a media session and returns metadata for event log recording.
     *
     * @param sessionJson JSON string representing the session.
     * @param timestamp Unix timestamp (seconds) when the session ended.
     * @return JSON string with session and metadata keys.
     * @throws BridgeException if session already ended.
     */
    fun mediaEndSession(sessionJson: String, timestamp: Long): String

    /**
     * Creates an SDP offer signaling message.
     *
     * @param sessionId The media session ID.
     * @param sdp Raw SDP payload string.
     * @param senderDid DID of the participant creating the offer.
     * @return JSON string with session_id and message keys.
     */
    fun mediaCreateOffer(sessionId: String, sdp: String, senderDid: String): String

    /**
     * Creates an SDP answer signaling message.
     *
     * @param sessionId The media session ID.
     * @param sdp Raw SDP payload string.
     * @param senderDid DID of the participant creating the answer.
     * @return JSON string with session_id and message keys.
     */
    fun mediaCreateAnswer(sessionId: String, sdp: String, senderDid: String): String

    /**
     * Creates an ICE candidate signaling message.
     *
     * @param sessionId The media session ID.
     * @param candidate ICE candidate attribute string.
     * @param senderDid DID of the participant who gathered the candidate.
     * @param sdpMid Optional SDP media stream identification tag.
     * @param sdpMlineIndex Optional zero-based index of the media description.
     * @return JSON string with session_id and message keys.
     */
    fun mediaCreateIceCandidate(
        sessionId: String,
        candidate: String,
        senderDid: String,
        sdpMid: String?,
        sdpMlineIndex: Int?,
    ): String

    /**
     * Creates a session-end signaling message.
     *
     * @param sessionId The media session ID.
     * @param senderDid DID of the participant ending the session.
     * @return JSON string with session_id and message keys.
     */
    fun mediaCreateSessionEnd(sessionId: String, senderDid: String): String

    /**
     * Serializes a signaling message and returns payload bytes with message type.
     *
     * @param signalingJson JSON string representing a signaling message.
     * @return JSON string with `payload` (base64-encoded bytes) and `message_type` keys.
     * @throws BridgeException if the JSON is invalid or serialization fails.
     */
    fun mediaSendSignaling(signalingJson: String): String

    /**
     * Verifies that the sender DID in a signaling message matches the envelope sender.
     *
     * @param signalingJson JSON string representing a signaling message.
     * @param envelopeSenderDid The DID from the authenticated SCP envelope.
     * @return `true` if valid.
     * @throws BridgeException if sender DID does not match.
     */
    fun mediaVerifySenderAttribution(signalingJson: String, envelopeSenderDid: String): Boolean
}

/**
 * Media operations bridge. Wraps media FFI calls as suspend functions.
 *
 * Media sessions are governed by the context's capability ceiling.
 * Signaling messages (SDP offers/answers, ICE candidates) flow as
 * standard SCP encrypted governed messages. See ADR-024.
 */
@Suppress("TooManyFunctions")
class MediaBridge internal constructor(
    private val bindings: MediaBindings,
    private val bridge: CoroutineBridge,
) {
    /**
     * Checks that a media capability is present in the context ceiling.
     *
     * @param ceiling List of capability name strings from the context ceiling.
     * @param capability Media capability: "voice", "video", or "screen_share".
     * @return `true` if the capability is present.
     */
    suspend fun checkCapability(
        ceiling: List<String>,
        capability: String,
    ): Boolean =
        bridge.ffiCall {
            bindings.mediaCheckCapability(ceiling, capability)
        }

    /**
     * Initiates a media session after validating capabilities against the ceiling.
     *
     * @param contextId The context hosting this media session.
     * @param ceiling The context's capability ceiling.
     * @param capabilities Media capabilities to activate.
     * @param participants Initial participant DIDs.
     * @param timestamp Unix timestamp (seconds) for session creation.
     * @return JSON string with session fields.
     */
    suspend fun initiateSession(
        contextId: String,
        ceiling: List<String>,
        capabilities: List<String>,
        participants: List<String>,
        timestamp: Long,
    ): String =
        bridge.ffiCall {
            bindings.mediaInitiateSession(contextId, ceiling, capabilities, participants, timestamp)
        }

    /**
     * Activates a media session (transitions from Initiating to Active).
     *
     * @param sessionJson JSON string representing the session.
     * @return Updated session JSON string.
     */
    suspend fun activateSession(sessionJson: String): String =
        bridge.ffiCall {
            bindings.mediaActivateSession(sessionJson)
        }

    /**
     * Adds a participant to a media session.
     *
     * @param sessionJson JSON string representing the session.
     * @param participantDid DID of the participant to add.
     * @return Updated session JSON string.
     */
    suspend fun joinSession(sessionJson: String, participantDid: String): String =
        bridge.ffiCall {
            bindings.mediaJoinSession(sessionJson, participantDid)
        }

    /**
     * Ends a media session and returns metadata for event log recording.
     *
     * @param sessionJson JSON string representing the session.
     * @param timestamp Unix timestamp (seconds) when the session ended.
     * @return JSON string with session and metadata keys.
     */
    suspend fun endSession(sessionJson: String, timestamp: Long): String =
        bridge.ffiCall {
            bindings.mediaEndSession(sessionJson, timestamp)
        }

    /**
     * Creates an SDP offer signaling message.
     *
     * @param sessionId The media session ID.
     * @param sdp Raw SDP payload string.
     * @param senderDid DID of the participant creating the offer.
     * @return JSON string with session_id and message keys.
     */
    suspend fun createOffer(sessionId: String, sdp: String, senderDid: String): String =
        bridge.ffiCall {
            bindings.mediaCreateOffer(sessionId, sdp, senderDid)
        }

    /**
     * Creates an SDP answer signaling message.
     *
     * @param sessionId The media session ID.
     * @param sdp Raw SDP payload string.
     * @param senderDid DID of the participant creating the answer.
     * @return JSON string with session_id and message keys.
     */
    suspend fun createAnswer(sessionId: String, sdp: String, senderDid: String): String =
        bridge.ffiCall {
            bindings.mediaCreateAnswer(sessionId, sdp, senderDid)
        }

    /**
     * Creates an ICE candidate signaling message.
     *
     * @param sessionId The media session ID.
     * @param candidate ICE candidate attribute string.
     * @param senderDid DID of the participant who gathered the candidate.
     * @param sdpMid Optional SDP media stream identification tag.
     * @param sdpMlineIndex Optional zero-based index of the media description.
     * @return JSON string with session_id and message keys.
     */
    suspend fun createIceCandidate(
        sessionId: String,
        candidate: String,
        senderDid: String,
        sdpMid: String? = null,
        sdpMlineIndex: Int? = null,
    ): String =
        bridge.ffiCall {
            bindings.mediaCreateIceCandidate(sessionId, candidate, senderDid, sdpMid, sdpMlineIndex)
        }

    /**
     * Creates a session-end signaling message.
     *
     * @param sessionId The media session ID.
     * @param senderDid DID of the participant ending the session.
     * @return JSON string with session_id and message keys.
     */
    suspend fun createSessionEnd(sessionId: String, senderDid: String): String =
        bridge.ffiCall {
            bindings.mediaCreateSessionEnd(sessionId, senderDid)
        }

    /**
     * Serializes a signaling message and returns payload bytes with message type.
     *
     * @param signalingJson JSON string representing a signaling message.
     * @return JSON string with `payload` (base64-encoded bytes) and `message_type` keys.
     */
    suspend fun sendSignaling(signalingJson: String): String =
        bridge.ffiCall {
            bindings.mediaSendSignaling(signalingJson)
        }

    /**
     * Verifies that the sender DID in a signaling message matches the envelope sender.
     *
     * @param signalingJson JSON string representing a signaling message.
     * @param envelopeSenderDid The DID from the authenticated SCP envelope.
     * @return `true` if valid.
     */
    suspend fun verifySenderAttribution(signalingJson: String, envelopeSenderDid: String): Boolean =
        bridge.ffiCall {
            bindings.mediaVerifySenderAttribution(signalingJson, envelopeSenderDid)
        }
}
