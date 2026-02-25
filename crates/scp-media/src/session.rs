//! Media session lifecycle types.
//!
//! A [`MediaSession`] represents a real-time media session within an SCP
//! context. Sessions are initiated via SCP signaling messages (SDP
//! offers/answers, ICE candidates) and use WebRTC/DTLS-SRTP for actual
//! media transport. No media data flows through SCP relays.
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};

/// A DID string (e.g., `"did:dht:z6Mk..."`).
///
/// Represented as a plain `String`. Matches the type alias pattern used
/// across `scp-core` modules.
pub type DID = String;

/// A context identifier string.
///
/// Represented as a plain `String`. Matches the type alias pattern used
/// across `scp-core` modules.
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
