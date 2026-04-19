import Foundation

// MARK: - MediaBridge

/// Namespace for UniFFI bridge function references used by media
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See ADR-024 in `.docs/adrs/phase-5.md`.
public enum MediaBridge {
    /// Check media capability in ceiling.
    public typealias CheckCapabilityFn = @Sendable (
        _ ceiling: [String],
        _ capability: String
    ) throws -> Bool

    /// Initiate a media session.
    public typealias InitiateSessionFn = @Sendable (
        _ contextId: String,
        _ ceiling: [String],
        _ capabilities: [String],
        _ participants: [String],
        _ timestamp: UInt64
    ) throws -> String

    /// Activate a media session.
    public typealias ActivateSessionFn = @Sendable (
        _ sessionJson: String
    ) throws -> String

    /// Join a media session.
    public typealias JoinSessionFn = @Sendable (
        _ sessionJson: String,
        _ participantDid: String
    ) throws -> String

    /// End a media session.
    public typealias EndSessionFn = @Sendable (
        _ sessionJson: String,
        _ timestamp: UInt64
    ) throws -> String

    /// Create an SDP offer.
    public typealias CreateOfferFn = @Sendable (
        _ sessionId: String,
        _ sdp: String,
        _ senderDid: String
    ) throws -> String

    /// Create an SDP answer.
    public typealias CreateAnswerFn = @Sendable (
        _ sessionId: String,
        _ sdp: String,
        _ senderDid: String
    ) throws -> String

    /// Create an ICE candidate.
    public typealias CreateIceCandidateFn = @Sendable (
        _ sessionId: String,
        _ candidate: String,
        _ senderDid: String,
        _ sdpMid: String?,
        _ sdpMlineIndex: UInt16?
    ) throws -> String

    /// Create a session end message.
    public typealias CreateSessionEndFn = @Sendable (
        _ sessionId: String,
        _ senderDid: String
    ) throws -> String

    /// Send a signaling message (serialize to payload bytes + message type).
    public typealias SendSignalingFn = @Sendable (
        _ signalingJson: String
    ) throws -> String

    /// Verify sender attribution.
    public typealias VerifySenderAttributionFn = @Sendable (
        _ signalingJson: String,
        _ envelopeSenderDid: String
    ) throws -> Bool

    // Default implementations

    /// Default check capability — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaCheckCapability`` method.
    public static let defaultCheckCapability: CheckCapabilityFn = { ceiling, capability in
        try Scp.defaultInstance().mediaCheckCapability(ceiling: ceiling, capability: capability)
    }

    /// Default initiate session — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaInitiateSession`` method.
    public static let defaultInitiateSession: InitiateSessionFn = { contextId, ceiling, capabilities, participants, timestamp in
        try Scp.defaultInstance().mediaInitiateSession(
            contextId: contextId,
            ceiling: ceiling,
            capabilities: capabilities,
            participants: participants,
            timestamp: timestamp
        )
    }

    /// Default activate session — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaActivateSession`` method.
    public static let defaultActivateSession: ActivateSessionFn = { sessionJson in
        try Scp.defaultInstance().mediaActivateSession(sessionJson: sessionJson)
    }

    /// Default join session — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaJoinSession`` method.
    public static let defaultJoinSession: JoinSessionFn = { sessionJson, participantDid in
        try Scp.defaultInstance().mediaJoinSession(sessionJson: sessionJson, participantDid: participantDid)
    }

    /// Default end session — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaEndSession`` method.
    public static let defaultEndSession: EndSessionFn = { sessionJson, timestamp in
        try Scp.defaultInstance().mediaEndSession(sessionJson: sessionJson, timestamp: timestamp)
    }

    /// Default create offer — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaCreateOffer`` method.
    public static let defaultCreateOffer: CreateOfferFn = { sessionId, sdp, senderDid in
        try Scp.defaultInstance().mediaCreateOffer(sessionId: sessionId, sdp: sdp, senderDid: senderDid)
    }

    /// Default create answer — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaCreateAnswer`` method.
    public static let defaultCreateAnswer: CreateAnswerFn = { sessionId, sdp, senderDid in
        try Scp.defaultInstance().mediaCreateAnswer(sessionId: sessionId, sdp: sdp, senderDid: senderDid)
    }

    /// Default create ICE candidate — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaCreateIceCandidate`` method.
    public static let defaultCreateIceCandidate: CreateIceCandidateFn = { sessionId, candidate, senderDid, sdpMid, sdpMlineIndex in
        try Scp.defaultInstance().mediaCreateIceCandidate(
            sessionId: sessionId,
            candidate: candidate,
            senderDid: senderDid,
            sdpMid: sdpMid,
            sdpMlineIndex: sdpMlineIndex
        )
    }

    /// Default create session end — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaCreateSessionEnd`` method.
    public static let defaultCreateSessionEnd: CreateSessionEndFn = { sessionId, senderDid in
        try Scp.defaultInstance().mediaCreateSessionEnd(sessionId: sessionId, senderDid: senderDid)
    }

    /// Default send signaling — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/mediaSendSignaling`` method.
    public static let defaultSendSignaling: SendSignalingFn = { signalingJson in
        try Scp.defaultInstance().mediaSendSignaling(signalingJson: signalingJson)
    }

    /// Default verify sender attribution — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/mediaVerifySenderAttribution`` method.
    public static let defaultVerifySenderAttribution: VerifySenderAttributionFn = { signalingJson, envelopeSenderDid in
        try Scp.defaultInstance().mediaVerifySenderAttribution(
            signalingJson: signalingJson,
            envelopeSenderDid: envelopeSenderDid
        )
    }
}

// MARK: - Public API — Session Lifecycle

/// Checks that a media capability is present in the context ceiling.
///
/// - Parameters:
///   - ceiling: List of capability name strings from the context ceiling.
///   - capability: Media capability: "voice", "video", or "screen_share".
///   - checkCapabilityFn: Bridge function override for testing.
/// - Returns: `true` if the capability is present.
/// - Throws: ``ScpError/Validation(msg:code:)`` if capability is invalid or missing.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func checkMediaCapability(
    ceiling: [String],
    capability: String,
    checkCapabilityFn: MediaBridge.CheckCapabilityFn = MediaBridge.defaultCheckCapability
) throws -> Bool {
    try checkCapabilityFn(ceiling, capability)
}

/// Initiates a media session after validating capabilities against the ceiling.
///
/// - Parameters:
///   - contextId: The context hosting this media session.
///   - ceiling: The context's capability ceiling.
///   - capabilities: Media capabilities to activate (e.g., ["voice", "video"]).
///   - participants: Initial participant DIDs.
///   - timestamp: Unix timestamp (seconds) for session creation.
///   - initiateSessionFn: Bridge function override for testing.
/// - Returns: A JSON string with session fields.
/// - Throws: ``ScpError/Context(msg:code:)`` on validation failure.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func initiateMediaSession(
    contextId: String,
    ceiling: [String],
    capabilities: [String],
    participants: [String],
    timestamp: UInt64,
    initiateSessionFn: MediaBridge.InitiateSessionFn = MediaBridge.defaultInitiateSession
) throws -> String {
    try initiateSessionFn(contextId, ceiling, capabilities, participants, timestamp)
}

/// Activates a media session (transitions from Initiating to Active).
///
/// - Parameters:
///   - sessionJson: JSON string representing the session.
///   - activateSessionFn: Bridge function override for testing.
/// - Returns: Updated session JSON string.
/// - Throws: ``ScpError/Context(msg:code:)`` if session is not Initiating.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func activateMediaSession(
    sessionJson: String,
    activateSessionFn: MediaBridge.ActivateSessionFn = MediaBridge.defaultActivateSession
) throws -> String {
    try activateSessionFn(sessionJson)
}

/// Adds a participant to a media session.
///
/// - Parameters:
///   - sessionJson: JSON string representing the session.
///   - participantDid: DID of the participant to add.
///   - joinSessionFn: Bridge function override for testing.
/// - Returns: Updated session JSON string.
/// - Throws: ``ScpError/Context(msg:code:)`` if session has ended.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func joinMediaSession(
    sessionJson: String,
    participantDid: String,
    joinSessionFn: MediaBridge.JoinSessionFn = MediaBridge.defaultJoinSession
) throws -> String {
    try joinSessionFn(sessionJson, participantDid)
}

/// Ends a media session and returns metadata for event log recording.
///
/// - Parameters:
///   - sessionJson: JSON string representing the session.
///   - timestamp: Unix timestamp (seconds) when the session ended.
///   - endSessionFn: Bridge function override for testing.
/// - Returns: JSON string with `session` and `metadata` keys.
/// - Throws: ``ScpError/Context(msg:code:)`` if session already ended.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func endMediaSession(
    sessionJson: String,
    timestamp: UInt64,
    endSessionFn: MediaBridge.EndSessionFn = MediaBridge.defaultEndSession
) throws -> String {
    try endSessionFn(sessionJson, timestamp)
}

// MARK: - Public API — Signaling

/// Creates an SDP offer signaling message.
///
/// - Parameters:
///   - sessionId: The media session ID.
///   - sdp: Raw SDP payload string.
///   - senderDid: DID of the participant creating the offer.
///   - createOfferFn: Bridge function override for testing.
/// - Returns: JSON string with `session_id` and `message` keys.
/// - Throws: ``ScpError/Validation(msg:code:)`` on serialization failure.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func createMediaOffer(
    sessionId: String,
    sdp: String,
    senderDid: String,
    createOfferFn: MediaBridge.CreateOfferFn = MediaBridge.defaultCreateOffer
) throws -> String {
    try createOfferFn(sessionId, sdp, senderDid)
}

/// Creates an SDP answer signaling message.
///
/// - Parameters:
///   - sessionId: The media session ID.
///   - sdp: Raw SDP payload string.
///   - senderDid: DID of the participant creating the answer.
///   - createAnswerFn: Bridge function override for testing.
/// - Returns: JSON string with `session_id` and `message` keys.
/// - Throws: ``ScpError/Validation(msg:code:)`` on serialization failure.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func createMediaAnswer(
    sessionId: String,
    sdp: String,
    senderDid: String,
    createAnswerFn: MediaBridge.CreateAnswerFn = MediaBridge.defaultCreateAnswer
) throws -> String {
    try createAnswerFn(sessionId, sdp, senderDid)
}

/// Creates an ICE candidate signaling message.
///
/// - Parameters:
///   - sessionId: The media session ID.
///   - candidate: ICE candidate attribute string.
///   - senderDid: DID of the participant who gathered the candidate.
///   - sdpMid: Optional SDP media stream identification tag.
///   - sdpMlineIndex: Optional zero-based index of the media description.
///   - createIceCandidateFn: Bridge function override for testing.
/// - Returns: JSON string with `session_id` and `message` keys.
/// - Throws: ``ScpError/Validation(msg:code:)`` on serialization failure.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func createMediaIceCandidate(
    sessionId: String,
    candidate: String,
    senderDid: String,
    sdpMid: String? = nil,
    sdpMlineIndex: UInt16? = nil,
    createIceCandidateFn: MediaBridge.CreateIceCandidateFn = MediaBridge.defaultCreateIceCandidate
) throws -> String {
    try createIceCandidateFn(sessionId, candidate, senderDid, sdpMid, sdpMlineIndex)
}

/// Creates a session-end signaling message.
///
/// - Parameters:
///   - sessionId: The media session ID.
///   - senderDid: DID of the participant ending the session.
///   - createSessionEndFn: Bridge function override for testing.
/// - Returns: JSON string with `session_id` and `message` keys.
/// - Throws: ``ScpError/Validation(msg:code:)`` on serialization failure.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func createMediaSessionEnd(
    sessionId: String,
    senderDid: String,
    createSessionEndFn: MediaBridge.CreateSessionEndFn = MediaBridge.defaultCreateSessionEnd
) throws -> String {
    try createSessionEndFn(sessionId, senderDid)
}

/// Serializes a signaling message and returns payload bytes with message type.
///
/// - Parameters:
///   - signalingJson: JSON string representing a signaling message.
///   - sendSignalingFn: Bridge function override for testing.
/// - Returns: JSON string with `payload` (base64-encoded bytes) and `message_type` keys.
/// - Throws: ``ScpError/Validation(msg:code:)`` if the JSON is invalid or serialization fails.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func sendSignaling(
    signalingJson: String,
    sendSignalingFn: MediaBridge.SendSignalingFn = MediaBridge.defaultSendSignaling
) throws -> String {
    try sendSignalingFn(signalingJson)
}

/// Verifies that the sender DID in a signaling message matches the envelope sender.
///
/// - Parameters:
///   - signalingJson: JSON string representing a signaling message.
///   - envelopeSenderDid: The DID from the authenticated SCP envelope.
///   - verifySenderAttributionFn: Bridge function override for testing.
/// - Returns: `true` if the sender attribution is valid.
/// - Throws: ``ScpError/Context(msg:code:)`` if sender DID does not match.
///
/// ## Provenance
///
/// - ADR-024 (Media)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func verifyMediaSenderAttribution(
    signalingJson: String,
    envelopeSenderDid: String,
    verifySenderAttributionFn: MediaBridge.VerifySenderAttributionFn = MediaBridge.defaultVerifySenderAttribution
) throws -> Bool {
    try verifySenderAttributionFn(signalingJson, envelopeSenderDid)
}
