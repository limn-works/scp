//! Media session lifecycle with capability ceiling checks.
//!
//! Implements ADR-024 acceptance criteria 4, 6, 7, 8:
//! - **AC 4**: Capability ceiling check before session initiation.
//! - **AC 6**: Session teardown (explicit `SessionEnd` and member removal).
//! - **AC 7**: No media through SCP relays (architectural — enforced by design).
//! - **AC 8**: Session metadata recorded in context event log.
//!
//! # Lifecycle
//!
//! ```text
//! check_media_capability(ceiling, cap)
//!        |
//!        v
//! initiate_media_session(...) -> MediaSession { state: Initiating }
//!        |
//!        v
//! activate_session(&mut session) -> MediaSession { state: Active }
//!        |
//!        +-- join_media_session(&mut session, did) -- add participants
//!        |
//!        v
//! end_media_session(&mut session, timestamp) -> SessionMetadata
//! ```
//!
//! Session metadata ([`SessionMetadata`]) captures participants, capabilities,
//! start/end times for recording in the context event log (ADR-024 AC 8,
//! ADR-017 participation records).
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

use scp_core::context::params::Capability as ParamCapability;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::MediaError;

use scp_identity::DID;

/// A context identifier string.
pub type ContextId = String;

/// A real-time media session within an SCP context.
///
/// Media sessions are governed by the context's capability ceiling: the
/// requested [`MediaCapability`] variants must be present in the ceiling
/// (e.g., `media.voice`, `media.video`, `media.screenShare`) before a
/// session can be initiated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaSession {
    /// Unique identifier for this media session.
    pub session_id: String,

    /// Context in which this media session takes place.
    pub context_id: ContextId,

    /// DIDs of current session participants.
    pub participants: Vec<DID>,

    /// Media capabilities active in this session.
    pub capabilities: Vec<MediaCapability>,

    /// Current lifecycle state of the session.
    pub state: MediaSessionState,

    /// Unix timestamp (seconds) when the session was created.
    pub started_at: u64,
}

/// A media capability that maps to a context capability-ceiling entry.
///
/// Each variant corresponds to a ceiling key under the `media.*` namespace:
/// - [`Voice`](MediaCapability::Voice) -- `media.voice`
/// - [`Video`](MediaCapability::Video) -- `media.video`
/// - [`ScreenShare`](MediaCapability::ScreenShare) -- `media.screenShare`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaCapability {
    /// Voice-only media. Maps to ceiling entry `media.voice`.
    Voice,

    /// Video media. Maps to ceiling entry `media.video`.
    Video,

    /// Screen sharing. Maps to ceiling entry `media.screenShare`.
    ScreenShare,
}

impl MediaCapability {
    /// Returns the capability ceiling name for this media capability.
    ///
    /// This maps to the `media:*` namespace used in context capability
    /// ceilings (see spec §10.9.1).
    #[must_use]
    pub const fn ceiling_name(&self) -> &'static str {
        match self {
            Self::Voice => "media:voice",
            Self::Video => "media:video",
            Self::ScreenShare => "media:screen_share",
        }
    }
}

/// Lifecycle state of a [`MediaSession`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaSessionState {
    /// Session is being set up (SDP offer/answer exchange in progress).
    Initiating,

    /// Session is active with media flowing over WebRTC/DTLS-SRTP.
    Active,

    /// Session has ended (graceful `SessionEnd` or member removal).
    Ended,
}

impl std::fmt::Display for MediaSessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initiating => write!(f, "Initiating"),
            Self::Active => write!(f, "Active"),
            Self::Ended => write!(f, "Ended"),
        }
    }
}

/// Session metadata for event log recording (ADR-024 AC 8).
///
/// Captures everything needed for participation record derivation (ADR-017):
/// participants, capabilities used, start and end times.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionMetadata {
    /// Session identifier.
    pub session_id: String,

    /// Context the session belonged to.
    pub context_id: ContextId,

    /// DIDs of participants at session end.
    pub participants: Vec<DID>,

    /// Media capabilities that were active.
    pub capabilities: Vec<MediaCapability>,

    /// Unix timestamp (seconds) when the session started.
    pub started_at: u64,

    /// Unix timestamp (seconds) when the session ended.
    pub ended_at: u64,
}

impl SessionMetadata {
    /// Serializes the metadata to JSON bytes for use as an
    /// `scp_event_log::EventPayload`.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::MetadataSerializationFailed`] if serialization fails.
    pub fn to_payload_bytes(&self) -> Result<Vec<u8>, MediaError> {
        serde_json::to_vec(self).map_err(|e| MediaError::MetadataSerializationFailed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Capability ceiling check
// ---------------------------------------------------------------------------

/// Checks that a media capability is present in the context's capability
/// ceiling.
///
/// Media session initiation requires the corresponding `media.*` capability
/// in the context ceiling. For example, a voice session requires
/// `media.voice` in the ceiling.
///
/// # Arguments
///
/// * `ceiling` - The context's capability ceiling (from `ContextParams::ceiling`).
/// * `capability` - The media capability to check.
///
/// # Errors
///
/// Returns [`MediaError::CapabilityNotInCeiling`] if the ceiling does not
/// contain the requested media capability.
///
/// See ADR-024 acceptance criterion 4.
pub fn check_media_capability(
    ceiling: &[ParamCapability],
    capability: &MediaCapability,
) -> Result<(), MediaError> {
    let name = capability.ceiling_name();
    if ceiling.iter().any(|c| c.name() == name) {
        Ok(())
    } else {
        Err(MediaError::CapabilityNotInCeiling(name.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/// Generates a deterministic session ID from context, timestamp, and
/// participants.
fn generate_session_id(context_id: &str, timestamp: u64, participants: &[DID]) -> String {
    let mut hasher = Sha256::new();
    // Length-prefix variable-length fields to prevent concatenation collisions.
    hasher.update((context_id.len() as u64).to_be_bytes());
    hasher.update(context_id.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update((participants.len() as u64).to_be_bytes());
    for p in participants {
        hasher.update((p.len() as u64).to_be_bytes());
        hasher.update(p.as_bytes());
    }
    let hash = hasher.finalize();
    // Use first 16 bytes (128 bits) for a compact but collision-resistant ID.
    let hex: String = hash[..16]
        .iter()
        .fold(String::with_capacity(32), |mut s, b| {
            use core::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
    format!("ms-{hex}")
}

/// Initiates a media session after validating capabilities against the
/// context ceiling.
///
/// All requested [`MediaCapability`] variants must be present in the ceiling.
/// At least one capability and one participant are required.
///
/// # Arguments
///
/// * `context_id` - The context hosting this media session.
/// * `ceiling` - The context's capability ceiling.
/// * `capabilities` - Media capabilities to activate (e.g., Voice, Video).
/// * `participants` - Initial participant DIDs.
/// * `timestamp` - Unix timestamp (seconds) for session creation.
///
/// # Errors
///
/// * [`MediaError::NoCapabilities`] if `capabilities` is empty.
/// * [`MediaError::NoParticipants`] if `participants` is empty.
/// * [`MediaError::CapabilityNotInCeiling`] if any capability is missing
///   from the ceiling.
///
/// See ADR-024 acceptance criterion 4.
pub fn initiate_media_session(
    context_id: ContextId,
    ceiling: &[ParamCapability],
    capabilities: Vec<MediaCapability>,
    participants: Vec<DID>,
    timestamp: u64,
) -> Result<MediaSession, MediaError> {
    if capabilities.is_empty() {
        return Err(MediaError::NoCapabilities);
    }
    if participants.is_empty() {
        return Err(MediaError::NoParticipants);
    }

    // Validate all requested capabilities against the ceiling.
    for cap in &capabilities {
        check_media_capability(ceiling, cap)?;
    }

    let session_id = generate_session_id(&context_id, timestamp, &participants);

    Ok(MediaSession {
        session_id,
        context_id,
        participants,
        capabilities,
        state: MediaSessionState::Initiating,
        started_at: timestamp,
    })
}

/// Transitions a session from [`Initiating`](MediaSessionState::Initiating) to
/// [`Active`](MediaSessionState::Active).
///
/// Call this after the SDP offer/answer exchange completes and media begins
/// flowing over WebRTC/DTLS-SRTP.
///
/// # Errors
///
/// Returns [`MediaError::InvalidSessionState`] if the session is not in the
/// `Initiating` state.
pub fn activate_session(session: &mut MediaSession) -> Result<(), MediaError> {
    if session.state != MediaSessionState::Initiating {
        return Err(MediaError::InvalidSessionState {
            expected: "Initiating".to_owned(),
            actual: session.state.to_string(),
        });
    }
    session.state = MediaSessionState::Active;
    Ok(())
}

/// Adds a participant to an active or initiating session.
///
/// Duplicate DIDs are silently ignored (idempotent).
///
/// # Errors
///
/// Returns [`MediaError::InvalidSessionState`] if the session has ended.
pub fn join_media_session(
    session: &mut MediaSession,
    participant_did: DID,
) -> Result<(), MediaError> {
    if session.state == MediaSessionState::Ended {
        return Err(MediaError::InvalidSessionState {
            expected: "Initiating or Active".to_owned(),
            actual: "Ended".to_owned(),
        });
    }
    if !session.participants.contains(&participant_did) {
        session.participants.push(participant_did);
    }
    Ok(())
}

/// Ends a media session and returns [`SessionMetadata`] for event log
/// recording.
///
/// The returned metadata contains participants, capabilities, and timing
/// information suitable for serialization into an
/// `scp_event_log::EventPayload` (ADR-024 AC 8).
///
/// # Arguments
///
/// * `session` - The session to end. Must be in `Initiating` or `Active`
///   state.
/// * `timestamp` - Unix timestamp (seconds) when the session ended.
///
/// # Errors
///
/// Returns [`MediaError::InvalidSessionState`] if the session has already
/// ended.
///
/// See ADR-024 acceptance criterion 6.
pub fn end_media_session(
    session: &mut MediaSession,
    timestamp: u64,
) -> Result<SessionMetadata, MediaError> {
    if session.state == MediaSessionState::Ended {
        return Err(MediaError::InvalidSessionState {
            expected: "Initiating or Active".to_owned(),
            actual: "Ended".to_owned(),
        });
    }
    if timestamp < session.started_at {
        return Err(MediaError::InvalidSessionState {
            expected: format!("end timestamp >= start timestamp ({})", session.started_at),
            actual: format!("end timestamp {timestamp}"),
        });
    }
    session.state = MediaSessionState::Ended;

    Ok(SessionMetadata {
        session_id: session.session_id.clone(),
        context_id: session.context_id.clone(),
        participants: session.participants.clone(),
        capabilities: session.capabilities.clone(),
        started_at: session.started_at,
        ended_at: timestamp,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn voice_ceiling() -> Vec<ParamCapability> {
        vec![
            ParamCapability::new("messages:read"),
            ParamCapability::new("messages:write"),
            ParamCapability::new("media:voice"),
        ]
    }

    fn video_ceiling() -> Vec<ParamCapability> {
        vec![
            ParamCapability::new("messages:read"),
            ParamCapability::new("media:voice"),
            ParamCapability::new("media:video"),
        ]
    }

    fn full_media_ceiling() -> Vec<ParamCapability> {
        vec![
            ParamCapability::new("messages:read"),
            ParamCapability::new("messages:write"),
            ParamCapability::new("media:voice"),
            ParamCapability::new("media:video"),
            ParamCapability::new("media:screen_share"),
        ]
    }

    fn no_media_ceiling() -> Vec<ParamCapability> {
        vec![
            ParamCapability::new("messages:read"),
            ParamCapability::new("messages:write"),
        ]
    }

    const ALICE: &str = "did:dht:z6MkAlice";
    const BOB: &str = "did:dht:z6MkBob";
    const CAROL: &str = "did:dht:z6MkCarol";
    const CTX: &str = "ctx-test-001";
    const TS_START: u64 = 1_700_000_000;
    const TS_END: u64 = 1_700_003_600;

    // ── MediaCapability::ceiling_name ──────────────────────────────────

    #[test]
    fn ceiling_name_voice() {
        assert_eq!(MediaCapability::Voice.ceiling_name(), "media:voice");
    }

    #[test]
    fn ceiling_name_video() {
        assert_eq!(MediaCapability::Video.ceiling_name(), "media:video");
    }

    #[test]
    fn ceiling_name_screen_share() {
        assert_eq!(
            MediaCapability::ScreenShare.ceiling_name(),
            "media:screen_share"
        );
    }

    // ── check_media_capability ─────────────────────────────────────────

    #[test]
    fn check_capability_voice_in_ceiling_succeeds() {
        let ceiling = voice_ceiling();
        assert!(check_media_capability(&ceiling, &MediaCapability::Voice).is_ok());
    }

    #[test]
    fn check_capability_video_in_ceiling_succeeds() {
        let ceiling = video_ceiling();
        assert!(check_media_capability(&ceiling, &MediaCapability::Video).is_ok());
    }

    #[test]
    fn check_capability_screen_share_in_full_ceiling_succeeds() {
        let ceiling = full_media_ceiling();
        assert!(check_media_capability(&ceiling, &MediaCapability::ScreenShare).is_ok());
    }

    #[test]
    fn check_capability_voice_not_in_ceiling_fails() {
        let ceiling = no_media_ceiling();
        let err = check_media_capability(&ceiling, &MediaCapability::Voice).unwrap_err();
        assert!(
            matches!(err, MediaError::CapabilityNotInCeiling(ref name) if name == "media:voice"),
            "expected CapabilityNotInCeiling(media:voice), got: {err}"
        );
    }

    #[test]
    fn check_capability_video_missing_from_voice_ceiling_fails() {
        let ceiling = voice_ceiling();
        let err = check_media_capability(&ceiling, &MediaCapability::Video).unwrap_err();
        assert!(
            matches!(err, MediaError::CapabilityNotInCeiling(ref name) if name == "media:video")
        );
    }

    #[test]
    fn check_capability_empty_ceiling_fails() {
        let ceiling: Vec<ParamCapability> = vec![];
        assert!(check_media_capability(&ceiling, &MediaCapability::Voice).is_err());
    }

    // ── initiate_media_session ─────────────────────────────────────────

    #[test]
    fn initiate_session_voice_succeeds() {
        let ceiling = voice_ceiling();
        let session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();

        assert!(session.session_id.starts_with("ms-"));
        assert_eq!(session.context_id, CTX);
        assert_eq!(session.participants, vec![ALICE]);
        assert_eq!(session.capabilities, vec![MediaCapability::Voice]);
        assert_eq!(session.state, MediaSessionState::Initiating);
        assert_eq!(session.started_at, TS_START);
    }

    #[test]
    fn initiate_session_multiple_capabilities_succeeds() {
        let ceiling = full_media_ceiling();
        let session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice, MediaCapability::Video],
            vec![ALICE.into(), BOB.into()],
            TS_START,
        )
        .unwrap();

        assert_eq!(session.capabilities.len(), 2);
        assert_eq!(session.participants.len(), 2);
    }

    #[test]
    fn initiate_session_rejects_missing_capability() {
        let ceiling = voice_ceiling();
        let err = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice, MediaCapability::Video],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap_err();

        assert!(
            matches!(err, MediaError::CapabilityNotInCeiling(ref name) if name == "media:video")
        );
    }

    #[test]
    fn initiate_session_rejects_no_media_ceiling() {
        let ceiling = no_media_ceiling();
        let err = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap_err();

        assert!(matches!(err, MediaError::CapabilityNotInCeiling(_)));
    }

    #[test]
    fn initiate_session_rejects_empty_capabilities() {
        let ceiling = voice_ceiling();
        let err = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap_err();

        assert!(matches!(err, MediaError::NoCapabilities));
    }

    #[test]
    fn initiate_session_rejects_empty_participants() {
        let ceiling = voice_ceiling();
        let err = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![],
            TS_START,
        )
        .unwrap_err();

        assert!(matches!(err, MediaError::NoParticipants));
    }

    #[test]
    fn initiate_session_deterministic_id() {
        let ceiling = voice_ceiling();
        let s1 = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        let s2 = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();

        assert_eq!(
            s1.session_id, s2.session_id,
            "same inputs must produce same session ID"
        );
    }

    #[test]
    fn initiate_session_different_inputs_different_ids() {
        let ceiling = voice_ceiling();
        let s1 = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        let s2 = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![BOB.into()],
            TS_START,
        )
        .unwrap();

        assert_ne!(
            s1.session_id, s2.session_id,
            "different participants must produce different IDs"
        );
    }

    // ── activate_session ───────────────────────────────────────────────

    #[test]
    fn activate_from_initiating_succeeds() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();

        assert!(activate_session(&mut session).is_ok());
        assert_eq!(session.state, MediaSessionState::Active);
    }

    #[test]
    fn activate_from_active_fails() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();

        let err = activate_session(&mut session).unwrap_err();
        assert!(matches!(err, MediaError::InvalidSessionState { .. }));
    }

    #[test]
    fn activate_from_ended_fails() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();
        end_media_session(&mut session, TS_END).unwrap();

        let err = activate_session(&mut session).unwrap_err();
        assert!(matches!(err, MediaError::InvalidSessionState { .. }));
    }

    // ── join_media_session ─────────────────────────────────────────────

    #[test]
    fn join_session_adds_participant() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();

        join_media_session(&mut session, BOB.into()).unwrap();
        assert_eq!(session.participants.len(), 2);
        assert!(session.participants.contains(&DID::from(BOB)));
    }

    #[test]
    fn join_session_during_initiating_succeeds() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();

        assert!(join_media_session(&mut session, BOB.into()).is_ok());
    }

    #[test]
    fn join_session_duplicate_is_idempotent() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();

        join_media_session(&mut session, ALICE.into()).unwrap();
        assert_eq!(
            session.participants.len(),
            1,
            "duplicate DID should not be added"
        );
    }

    #[test]
    fn join_ended_session_fails() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();
        end_media_session(&mut session, TS_END).unwrap();

        let err = join_media_session(&mut session, BOB.into()).unwrap_err();
        assert!(matches!(err, MediaError::InvalidSessionState { .. }));
    }

    #[test]
    fn join_multiple_participants() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();

        join_media_session(&mut session, BOB.into()).unwrap();
        join_media_session(&mut session, CAROL.into()).unwrap();
        assert_eq!(session.participants.len(), 3);
    }

    // ── end_media_session ──────────────────────────────────────────────

    #[test]
    fn end_active_session_returns_metadata() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into(), BOB.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();

        let metadata = end_media_session(&mut session, TS_END).unwrap();

        assert_eq!(metadata.session_id, session.session_id);
        assert_eq!(metadata.context_id, CTX);
        assert_eq!(metadata.participants, vec![ALICE, BOB]);
        assert_eq!(metadata.capabilities, vec![MediaCapability::Voice]);
        assert_eq!(metadata.started_at, TS_START);
        assert_eq!(metadata.ended_at, TS_END);
        assert_eq!(session.state, MediaSessionState::Ended);
    }

    #[test]
    fn end_initiating_session_succeeds() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();

        let metadata = end_media_session(&mut session, TS_END).unwrap();
        assert_eq!(metadata.started_at, TS_START);
        assert_eq!(metadata.ended_at, TS_END);
    }

    #[test]
    fn end_session_rejects_timestamp_before_start() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();

        let err = end_media_session(&mut session, TS_START - 1).unwrap_err();
        assert!(matches!(err, MediaError::InvalidSessionState { .. }));
        // Session should NOT have transitioned to Ended on invalid timestamp.
        assert_eq!(session.state, MediaSessionState::Active);
    }

    #[test]
    fn end_already_ended_session_fails() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();
        end_media_session(&mut session, TS_END).unwrap();

        let err = end_media_session(&mut session, TS_END + 100).unwrap_err();
        assert!(matches!(err, MediaError::InvalidSessionState { .. }));
    }

    #[test]
    fn end_session_captures_late_joiners() {
        let ceiling = voice_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();
        join_media_session(&mut session, BOB.into()).unwrap();
        join_media_session(&mut session, CAROL.into()).unwrap();

        let metadata = end_media_session(&mut session, TS_END).unwrap();
        assert_eq!(metadata.participants.len(), 3);
        assert!(metadata.participants.contains(&DID::from(CAROL)));
    }

    // ── SessionMetadata serialization ──────────────────────────────────

    #[test]
    fn session_metadata_to_payload_bytes_roundtrip() {
        let metadata = SessionMetadata {
            session_id: "ms-test".to_owned(),
            context_id: CTX.to_owned(),
            participants: vec![ALICE.into(), BOB.into()],
            capabilities: vec![MediaCapability::Voice, MediaCapability::Video],
            started_at: TS_START,
            ended_at: TS_END,
        };

        let bytes = metadata.to_payload_bytes().unwrap();
        let restored: SessionMetadata = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(metadata, restored);
    }

    #[test]
    fn session_metadata_from_end_session_serializes() {
        let ceiling = full_media_ceiling();
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice, MediaCapability::Video],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        activate_session(&mut session).unwrap();

        let metadata = end_media_session(&mut session, TS_END).unwrap();
        let bytes = metadata.to_payload_bytes().unwrap();
        assert!(!bytes.is_empty());

        let restored: SessionMetadata = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.session_id, metadata.session_id);
        assert_eq!(restored.capabilities.len(), 2);
    }

    // ── Full lifecycle ─────────────────────────────────────────────────

    #[test]
    fn full_lifecycle_initiate_activate_join_end() {
        let ceiling = full_media_ceiling();

        // 1. Initiate
        let mut session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![
                MediaCapability::Voice,
                MediaCapability::Video,
                MediaCapability::ScreenShare,
            ],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();
        assert_eq!(session.state, MediaSessionState::Initiating);

        // 2. Activate (SDP exchange complete)
        activate_session(&mut session).unwrap();
        assert_eq!(session.state, MediaSessionState::Active);

        // 3. Join additional participants
        join_media_session(&mut session, BOB.into()).unwrap();
        join_media_session(&mut session, CAROL.into()).unwrap();
        assert_eq!(session.participants.len(), 3);

        // 4. End
        let metadata = end_media_session(&mut session, TS_END).unwrap();
        assert_eq!(session.state, MediaSessionState::Ended);
        assert_eq!(metadata.participants.len(), 3);
        assert_eq!(metadata.capabilities.len(), 3);
        assert_eq!(metadata.started_at, TS_START);
        assert_eq!(metadata.ended_at, TS_END);

        // 5. Metadata serializable for event log
        let bytes = metadata.to_payload_bytes().unwrap();
        let restored: SessionMetadata = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, metadata);
    }

    // ── MediaSession serde roundtrip ───────────────────────────────────

    #[test]
    fn media_session_serialization_roundtrip() {
        let ceiling = voice_ceiling();
        let session = initiate_media_session(
            CTX.to_owned(),
            &ceiling,
            vec![MediaCapability::Voice],
            vec![ALICE.into()],
            TS_START,
        )
        .unwrap();

        let json = serde_json::to_string(&session).unwrap();
        let restored: MediaSession = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.session_id, session.session_id);
        assert_eq!(restored.context_id, session.context_id);
        assert_eq!(restored.state, session.state);
    }
}
