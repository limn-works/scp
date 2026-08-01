//! `PyO3` bridge functions for media operations.
//!
//! Exposes SCP media session lifecycle and signaling to Python:
//!
//! - Session lifecycle: [`py_media_initiate_session`], [`py_media_join_session`],
//!   [`PyScp::py_media_activate_session`], [`PyScp::py_media_end_session`]
//! - Signaling: [`py_media_create_offer`], [`py_media_create_answer`],
//!   [`py_media_create_ice_candidate`], [`py_media_create_session_end`],
//!   [`py_media_send_signaling`], [`py_media_verify_sender_attribution`]
//!
//! Key derivation (`export_media_keys`) is NOT exposed through FFI because it
//! requires an `ScpMlsGroup` reference, which is an opaque internal type that
//! cannot cross the FFI boundary. Key derivation is performed internally by
//! `scp-core` when contexts have active MLS groups.
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_ffi_common::error_codes as codes;

use scp_media::session::{
    MediaCapability, MediaSession, MediaSessionState, SessionMetadata, activate_session,
    check_media_capability, end_media_session, initiate_media_session, join_media_session,
};
use scp_media::signaling::{
    create_answer, create_ice_candidate, create_offer, create_session_end, deserialize_signaling,
    send_signaling, serialize_signaling, verify_sender_attribution,
};

use crate::error::ScpPyError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_media_capability(s: &str) -> PyResult<MediaCapability> {
    match s {
        "voice" => Ok(MediaCapability::Voice),
        "video" => Ok(MediaCapability::Video),
        "screen_share" => Ok(MediaCapability::ScreenShare),
        other => Err(ScpPyError::ValidationError {
            message: format!(
                "invalid media capability '{other}': expected 'voice', 'video', or 'screen_share'"
            ),
            code: codes::VALID_7300.to_string(),
        }
        .into()),
    }
}

const fn capability_to_string(cap: &MediaCapability) -> &'static str {
    match cap {
        MediaCapability::Voice => "voice",
        MediaCapability::Video => "video",
        MediaCapability::ScreenShare => "screen_share",
    }
}

const fn state_to_string(state: &MediaSessionState) -> &'static str {
    match state {
        MediaSessionState::Initiating => "initiating",
        MediaSessionState::Active => "active",
        MediaSessionState::Ended => "ended",
    }
}

fn session_to_dict<'py>(py: Python<'py>, session: &MediaSession) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("session_id", &session.session_id)?;
    dict.set_item("context_id", &session.context_id)?;
    dict.set_item(
        "participants",
        session
            .participants
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )?;
    dict.set_item(
        "capabilities",
        session
            .capabilities
            .iter()
            .map(capability_to_string)
            .collect::<Vec<_>>(),
    )?;
    dict.set_item("state", state_to_string(&session.state))?;
    dict.set_item("started_at", session.started_at)?;
    Ok(dict)
}

fn metadata_to_dict<'py>(
    py: Python<'py>,
    metadata: &SessionMetadata,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("session_id", &metadata.session_id)?;
    dict.set_item("context_id", &metadata.context_id)?;
    dict.set_item(
        "participants",
        metadata
            .participants
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )?;
    dict.set_item(
        "capabilities",
        metadata
            .capabilities
            .iter()
            .map(capability_to_string)
            .collect::<Vec<_>>(),
    )?;
    dict.set_item("started_at", metadata.started_at)?;
    dict.set_item("ended_at", metadata.ended_at)?;
    Ok(dict)
}

fn media_error_to_py(e: scp_media::keys::MediaError) -> PyErr {
    ScpPyError::ContextError {
        message: e.to_string(),
        code: codes::CTX_2500.to_string(),
    }
    .into()
}

// ---------------------------------------------------------------------------
// Event log helper — ADR-024 AC 8
// ---------------------------------------------------------------------------

/// Appends a media session event (`MediaSessionStarted` or `MediaSessionEnded`)
/// to the event log for the given context.
///
/// Best-effort: callers log a warning on error rather than failing the
/// session operation. Mirrors the pattern used by `ProvenanceAttached`/
/// `ProvenanceReceived` in `provenance.rs`.
///
/// `actor_did` is the first session participant (the session initiator). When
/// the participant list is empty the DID is set to an empty string so the leaf
/// shape is still uniform.
fn append_media_session_event_py(
    bi: &crate::runtime::PyBridgeInstance,
    context_id: &str,
    actor_did: &str,
    event_type: scp_event_log::EventType,
    payload: scp_event_log::EventPayload,
) -> PyResult<()> {
    let timestamp = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

    crate::runtime::with_context(bi, context_id, |rt| {
        let sequence = scp_event_log::tree::event_count(&rt.event_log);
        let prev_hash = if rt.event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            rt.event_log.leaves()[rt.event_log.leaves().len() - 1]
        };

        let event = scp_event_log::Event {
            event_type,
            actor_did: scp_did::DID::from(actor_did.to_owned()),
            timestamp,
            sequence,
            payload,
            prev_hash,
            signature: Vec::new(),
        };

        scp_event_log::tree::append_unsigned_event(&mut rt.event_log, &event)
            .map(|_| ())
            .map_err(|e| {
                crate::error::ScpPyError::context(format!(
                    "failed to append media session event: {e}"
                ))
            })
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/// Checks that a media capability is present in the context's capability ceiling.
///
/// # Arguments
///
/// * `ceiling` - List of capability name strings from the context ceiling.
/// * `capability` - Media capability to check: `"voice"`, `"video"`, or `"screen_share"`.
///
/// # Returns
///
/// `True` if the capability is in the ceiling.
///
/// # Errors
///
/// Raises `ValidationError` if the capability string is invalid.
/// Raises `ContextError` if the capability is not in the ceiling.
#[pyfunction]
#[pyo3(name = "media_check_capability")]
pub fn py_media_check_capability(ceiling: Vec<String>, capability: &str) -> PyResult<bool> {
    let cap = parse_media_capability(capability)?;
    let param_caps: Vec<scp_core::context::params::Capability> = ceiling
        .iter()
        .map(|s| {
            scp_core::context::params::Capability::new(s).ok_or_else(|| {
                PyErr::from(ScpPyError::ValidationError {
                    message: format!(
                        "invalid capability {s:?} in ceiling (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
                    ),
                    code: codes::VALID_7000.to_string(),
                })
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    check_media_capability(&param_caps, &cap).map_err(media_error_to_py)?;
    Ok(true)
}

/// Initiates a media session after validating capabilities against the ceiling.
///
/// # Arguments
///
/// * `context_id` - The context hosting this media session.
/// * `ceiling` - The context's capability ceiling as a list of capability name strings.
/// * `capabilities` - Media capabilities to activate (e.g., `["voice", "video"]`).
/// * `participants` - Initial participant DIDs.
/// * `timestamp` - Unix timestamp (seconds) for session creation.
///
/// # Returns
///
/// A dict with session fields: `session_id`, `context_id`, `participants`,
/// `capabilities`, `state`, `started_at`.
///
/// # Errors
///
/// Raises `ValidationError` if any capability string is invalid.
/// Raises `ContextError` if capabilities are empty, participants are empty,
/// or any capability is not in the ceiling.
#[pyfunction]
#[pyo3(name = "media_initiate_session")]
pub fn py_media_initiate_session(
    py: Python<'_>,
    context_id: String,
    ceiling: Vec<String>,
    capabilities: Vec<String>,
    participants: Vec<String>,
    timestamp: u64,
) -> PyResult<Bound<'_, PyDict>> {
    let caps: Vec<MediaCapability> = capabilities
        .iter()
        .map(|s| parse_media_capability(s))
        .collect::<PyResult<Vec<_>>>()?;

    let param_caps: Vec<scp_core::context::params::Capability> = ceiling
        .iter()
        .map(|s| {
            scp_core::context::params::Capability::new(s).ok_or_else(|| {
                PyErr::from(ScpPyError::ValidationError {
                    message: format!(
                        "invalid capability {s:?} in ceiling (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
                    ),
                    code: codes::VALID_7000.to_string(),
                })
            })
        })
        .collect::<PyResult<Vec<_>>>()?;

    let session = initiate_media_session(
        context_id,
        &param_caps,
        caps,
        participants.into_iter().map(scp_did::DID::from).collect(),
        timestamp,
    )
    .map_err(media_error_to_py)?;

    session_to_dict(py, &session)
}

/// Adds a participant to a media session.
///
/// # Arguments
///
/// * `session_json` - JSON string representing the session.
/// * `participant_did` - DID of the participant to add.
///
/// # Returns
///
/// A dict with the updated session fields.
///
/// # Errors
///
/// Raises `ContextError` if the session has ended.
#[pyfunction]
#[pyo3(name = "media_join_session")]
pub fn py_media_join_session(
    py: Python<'_>,
    session_json: String,
    participant_did: String,
) -> PyResult<Bound<'_, PyDict>> {
    let mut session: MediaSession =
        serde_json::from_str(&session_json).map_err(|e| ScpPyError::ValidationError {
            message: format!("invalid session JSON: {e}"),
            code: codes::VALID_7301.to_string(),
        })?;

    join_media_session(&mut session, participant_did.into()).map_err(media_error_to_py)?;
    session_to_dict(py, &session)
}

// ---------------------------------------------------------------------------
// Signaling
// ---------------------------------------------------------------------------

/// Creates an SDP offer signaling message.
///
/// # Arguments
///
/// * `session_id` - The media session ID.
/// * `sdp` - Raw SDP payload string.
/// * `sender_did` - DID of the participant creating the offer.
///
/// # Returns
///
/// A dict with `session_id` and `message` (JSON-serialized signaling message).
#[pyfunction]
#[pyo3(name = "media_create_offer")]
pub fn py_media_create_offer(
    py: Python<'_>,
    session_id: String,
    sdp: String,
    sender_did: String,
) -> PyResult<Bound<'_, PyDict>> {
    let (sid, msg) = create_offer(&session_id, sdp, sender_did.into());
    let msg_bytes = serialize_signaling(&msg).map_err(|e| ScpPyError::ValidationError {
        message: format!("failed to serialize signaling message: {e}"),
        code: codes::VALID_7302.to_string(),
    })?;
    let dict = PyDict::new(py);
    dict.set_item("session_id", sid)?;
    dict.set_item("message", String::from_utf8_lossy(&msg_bytes).into_owned())?;
    Ok(dict)
}

/// Creates an SDP answer signaling message.
///
/// # Arguments
///
/// * `session_id` - The media session ID.
/// * `sdp` - Raw SDP payload string.
/// * `sender_did` - DID of the participant creating the answer.
///
/// # Returns
///
/// A dict with `session_id` and `message` (JSON-serialized signaling message).
#[pyfunction]
#[pyo3(name = "media_create_answer")]
pub fn py_media_create_answer(
    py: Python<'_>,
    session_id: String,
    sdp: String,
    sender_did: String,
) -> PyResult<Bound<'_, PyDict>> {
    let (sid, msg) = create_answer(&session_id, sdp, sender_did.into());
    let msg_bytes = serialize_signaling(&msg).map_err(|e| ScpPyError::ValidationError {
        message: format!("failed to serialize signaling message: {e}"),
        code: codes::VALID_7302.to_string(),
    })?;
    let dict = PyDict::new(py);
    dict.set_item("session_id", sid)?;
    dict.set_item("message", String::from_utf8_lossy(&msg_bytes).into_owned())?;
    Ok(dict)
}

/// Creates an ICE candidate signaling message.
///
/// # Arguments
///
/// * `session_id` - The media session ID.
/// * `candidate` - ICE candidate attribute string.
/// * `sdp_mid` - Optional SDP media stream identification tag.
/// * `sdp_mline_index` - Optional zero-based index of the media description.
/// * `sender_did` - DID of the participant who gathered the candidate.
///
/// # Returns
///
/// A dict with `session_id` and `message` (JSON-serialized signaling message).
#[pyfunction]
#[pyo3(name = "media_create_ice_candidate")]
#[pyo3(signature = (session_id, candidate, sender_did, sdp_mid=None, sdp_mline_index=None))]
pub fn py_media_create_ice_candidate(
    py: Python<'_>,
    session_id: String,
    candidate: String,
    sender_did: String,
    sdp_mid: Option<String>,
    sdp_mline_index: Option<u16>,
) -> PyResult<Bound<'_, PyDict>> {
    let (sid, msg) = create_ice_candidate(
        &session_id,
        candidate,
        sdp_mid,
        sdp_mline_index,
        sender_did.into(),
    );
    let msg_bytes = serialize_signaling(&msg).map_err(|e| ScpPyError::ValidationError {
        message: format!("failed to serialize signaling message: {e}"),
        code: codes::VALID_7302.to_string(),
    })?;
    let dict = PyDict::new(py);
    dict.set_item("session_id", sid)?;
    dict.set_item("message", String::from_utf8_lossy(&msg_bytes).into_owned())?;
    Ok(dict)
}

/// Creates a session-end signaling message.
///
/// # Arguments
///
/// * `session_id` - The media session ID.
/// * `sender_did` - DID of the participant ending the session.
///
/// # Returns
///
/// A dict with `session_id` and `message` (JSON-serialized signaling message).
#[pyfunction]
#[pyo3(name = "media_create_session_end")]
pub fn py_media_create_session_end(
    py: Python<'_>,
    session_id: String,
    sender_did: String,
) -> PyResult<Bound<'_, PyDict>> {
    let (sid, msg) = create_session_end(&session_id, sender_did.into());
    let msg_bytes = serialize_signaling(&msg).map_err(|e| ScpPyError::ValidationError {
        message: format!("failed to serialize signaling message: {e}"),
        code: codes::VALID_7302.to_string(),
    })?;
    let dict = PyDict::new(py);
    dict.set_item("session_id", sid)?;
    dict.set_item("message", String::from_utf8_lossy(&msg_bytes).into_owned())?;
    Ok(dict)
}

/// Serializes a signaling message and returns payload bytes with message type.
///
/// # Arguments
///
/// * `signaling_json` - JSON string representing a signaling message.
///
/// # Returns
///
/// A dict with `payload` (base64-encoded bytes) and `message_type` (`"Signaling"`).
///
/// # Errors
///
/// Raises `ValidationError` if the JSON is not a valid signaling message.
#[pyfunction]
#[pyo3(name = "media_send_signaling")]
pub fn py_media_send_signaling(
    py: Python<'_>,
    signaling_json: String,
) -> PyResult<Bound<'_, PyDict>> {
    let msg = deserialize_signaling(signaling_json.as_bytes()).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("invalid signaling JSON: {e}"),
            code: codes::VALID_7303.to_string(),
        }
    })?;
    let (payload, message_type) =
        send_signaling(&msg).map_err(|e| ScpPyError::ValidationError {
            message: format!("failed to serialize signaling: {e}"),
            code: codes::VALID_7302.to_string(),
        })?;

    let dict = PyDict::new(py);
    dict.set_item(
        "payload",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &payload),
    )?;
    dict.set_item("message_type", format!("{message_type:?}"))?;
    Ok(dict)
}

/// Verifies that the sender DID in a signaling message matches the envelope sender.
///
/// # Arguments
///
/// * `signaling_json` - JSON string representing a signaling message.
/// * `envelope_sender_did` - The DID from the authenticated SCP envelope.
///
/// # Returns
///
/// `True` if the sender attribution is valid.
///
/// # Errors
///
/// Raises `ValidationError` if the JSON is invalid.
/// Raises `ContextError` if the sender DID does not match.
#[pyfunction]
#[pyo3(name = "media_verify_sender_attribution")]
pub fn py_media_verify_sender_attribution(
    signaling_json: String,
    envelope_sender_did: String,
) -> PyResult<bool> {
    let msg = deserialize_signaling(signaling_json.as_bytes()).map_err(|e| {
        ScpPyError::ValidationError {
            message: format!("invalid signaling JSON: {e}"),
            code: codes::VALID_7303.to_string(),
        }
    })?;
    verify_sender_attribution(&msg, &envelope_sender_did).map_err(|e| {
        ScpPyError::ContextError {
            message: format!("sender attribution verification failed: {e}"),
            code: codes::CTX_2501.to_string(),
        }
    })?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers media bridge functions on the `_scp_core` module.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub fn register_media(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Session lifecycle
    m.add_function(wrap_pyfunction!(py_media_check_capability, m)?)?;
    m.add_function(wrap_pyfunction!(py_media_initiate_session, m)?)?;
    m.add_function(wrap_pyfunction!(py_media_join_session, m)?)?;
    // Signaling
    m.add_function(wrap_pyfunction!(py_media_create_offer, m)?)?;
    m.add_function(wrap_pyfunction!(py_media_create_answer, m)?)?;
    m.add_function(wrap_pyfunction!(py_media_create_ice_candidate, m)?)?;
    m.add_function(wrap_pyfunction!(py_media_create_session_end, m)?)?;
    m.add_function(wrap_pyfunction!(py_media_send_signaling, m)?)?;
    m.add_function(wrap_pyfunction!(py_media_verify_sender_attribution, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Bridge-instance-aware methods — ADR-024 AC 8
// ---------------------------------------------------------------------------
//
// These `#[pymethods]` on `PyScp` are the canonical implementations of
// `media_activate_session` and `media_end_session`. They perform the session
// state-machine transition and additionally append `MediaSessionStarted` /
// `MediaSessionEnded` events to the context event log, matching the NAPI and
// UniFFI bridge behaviour.

#[pymethods]
impl crate::scp::PyScp {
    /// Activates a media session and appends a `MediaSessionStarted` event to
    /// the context event log (ADR-024 AC 8).
    ///
    /// The event log append is best-effort: if the context is not registered
    /// a warning is emitted but the session state transition still succeeds.
    ///
    /// # Arguments
    ///
    /// * `session_json` – JSON string representing the session (as returned by
    ///   `media_initiate_session`).
    ///
    /// # Returns
    ///
    /// A dict with the updated session fields.
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if the JSON is invalid.
    /// Raises `ContextError` if the session is not in the `Initiating` state.
    #[pyo3(name = "media_activate_session")]
    pub fn py_media_activate_session<'py>(
        &self,
        py: Python<'py>,
        session_json: String,
    ) -> PyResult<Bound<'py, PyDict>> {
        let mut session: MediaSession =
            serde_json::from_str(&session_json).map_err(|e| ScpPyError::ValidationError {
                message: format!("invalid session JSON: {e}"),
                code: codes::VALID_7301.to_string(),
            })?;

        activate_session(&mut session).map_err(media_error_to_py)?;

        // ADR-024 AC 8: record MediaSessionStarted in the context event log.
        let started_payload = scp_event_log::payload::encode_payload(
            &scp_event_log::payload::MediaSessionStartedPayload {
                session_id: session.session_id.clone(),
                context_id: session.context_id.clone(),
                participants: session
                    .participants
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                capabilities: session
                    .capabilities
                    .iter()
                    .map(|c| c.ceiling_name().to_owned())
                    .collect(),
                started_at: session.started_at,
            },
        )
        .map_err(|e| ScpPyError::ContextError {
            message: format!("failed to encode MediaSessionStarted payload: {e}"),
            code: codes::CTX_2500.to_string(),
        })?;

        let actor_did = session.participants.first().map_or("", |d| d.as_ref());

        if let Err(e) = append_media_session_event_py(
            &self.inner,
            &session.context_id,
            actor_did,
            scp_event_log::EventType::MediaSessionStarted,
            started_payload,
        ) {
            tracing::warn!(
                context = %session.context_id,
                session = %session.session_id,
                error = %e,
                "failed to append MediaSessionStarted event to context event log"
            );
        }

        session_to_dict(py, &session)
    }

    /// Ends a media session and appends a `MediaSessionEnded` event to the
    /// context event log (ADR-024 AC 8).
    ///
    /// The event log append is best-effort: if the context is not registered
    /// a warning is emitted but the session teardown still succeeds.
    ///
    /// # Arguments
    ///
    /// * `session_json` – JSON string representing the session.
    /// * `timestamp` – Unix timestamp (seconds) when the session ended.
    ///
    /// # Returns
    ///
    /// A dict with two keys: `session` (updated session) and `metadata`
    /// (session metadata).
    ///
    /// # Errors
    ///
    /// Raises `ValidationError` if the JSON is invalid.
    /// Raises `ContextError` if the session has already ended or the timestamp
    /// is before the session start time.
    #[pyo3(name = "media_end_session")]
    pub fn py_media_end_session<'py>(
        &self,
        py: Python<'py>,
        session_json: String,
        timestamp: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let mut session: MediaSession =
            serde_json::from_str(&session_json).map_err(|e| ScpPyError::ValidationError {
                message: format!("invalid session JSON: {e}"),
                code: codes::VALID_7301.to_string(),
            })?;

        let metadata = end_media_session(&mut session, timestamp).map_err(media_error_to_py)?;

        // ADR-024 AC 8: record MediaSessionEnded in the context event log.
        let ended_payload = scp_event_log::payload::encode_payload(
            &scp_event_log::payload::MediaSessionEndedPayload {
                session_id: metadata.session_id.clone(),
                context_id: metadata.context_id.clone(),
                participants: metadata
                    .participants
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                capabilities: metadata
                    .capabilities
                    .iter()
                    .map(|c| c.ceiling_name().to_owned())
                    .collect(),
                started_at: metadata.started_at,
                ended_at: metadata.ended_at,
            },
        )
        .map_err(|e| ScpPyError::ContextError {
            message: format!("failed to encode MediaSessionEnded payload: {e}"),
            code: codes::CTX_2500.to_string(),
        })?;

        let actor_did = metadata.participants.first().map_or("", |d| d.as_ref());

        if let Err(e) = append_media_session_event_py(
            &self.inner,
            &metadata.context_id,
            actor_did,
            scp_event_log::EventType::MediaSessionEnded,
            ended_payload,
        ) {
            tracing::warn!(
                context = %metadata.context_id,
                session = %metadata.session_id,
                error = %e,
                "failed to append MediaSessionEnded event to context event log"
            );
        }

        let result = PyDict::new(py);
        result.set_item("session", session_to_dict(py, &session)?)?;
        result.set_item("metadata", metadata_to_dict(py, &metadata)?)?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── Event log appends — ADR-024 AC 8 ────────────────────────────────────

    const ALICE_DID: &str = "did:dht:z6MkAlice";
    const TS_START: u64 = 1_700_000_000;
    const TS_END: u64 = 1_700_003_600;

    fn test_bi() -> std::sync::Arc<crate::runtime::PyBridgeInstance> {
        std::sync::Arc::new(crate::runtime::PyBridgeInstance::new_py())
    }

    fn initiating_session_json(context_id: &str) -> String {
        serde_json::json!({
            "session_id": "ms-deadbeef01234567",
            "context_id": context_id,
            "participants": [ALICE_DID],
            "capabilities": [{"Voice": null}],
            "state": "Initiating",
            "started_at": TS_START,
        })
        .to_string()
    }

    fn active_session_json(context_id: &str) -> String {
        // Build in serde's native format (enum-variant `{"Voice": null}`) so
        // MediaSession deserialises correctly regardless of whether it was
        // produced by `session_to_dict` (which uses lowercase strings).
        serde_json::json!({
            "session_id": "ms-deadbeef01234567",
            "context_id": context_id,
            "participants": [ALICE_DID],
            "capabilities": [{"Voice": null}],
            "state": "Active",
            "started_at": TS_START,
        })
        .to_string()
    }

    #[test]
    fn activate_session_with_log_appends_media_session_started_event() {
        // ADR-024 AC 8: MediaSessionStarted must be recorded in the context
        // event log when activate_session transitions the session to Active.
        pyo3::prepare_freethreaded_python();

        let ctx = "ctx-py-media-activate-001";
        let bi = test_bi();
        crate::runtime::register_context(&bi, ctx, ALICE_DID, &[]).unwrap();

        let initial_count = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::event_count(&st.event_log))
        })
        .unwrap();
        assert_eq!(initial_count, 0, "event log must start empty");

        let scp = crate::scp::PyScp { inner: bi.clone() };
        pyo3::Python::with_gil(|py| {
            let result = scp.py_media_activate_session(py, initiating_session_json(ctx));
            assert!(
                result.is_ok(),
                "media_activate_session_with_log should succeed: {result:?}"
            );
        });

        let count = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::event_count(&st.event_log))
        })
        .unwrap();
        assert_eq!(count, 1, "event log must contain 1 event after activation");

        // Verify the Merkle root is non-zero (leaf was actually hashed in).
        let root = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::root(&st.event_log))
        })
        .unwrap();
        assert_ne!(root, [0u8; 32], "Merkle root must be non-zero after append");

        crate::runtime::remove_context(&bi, ctx);
    }

    #[test]
    fn end_session_with_log_appends_media_session_ended_event() {
        // ADR-024 AC 8: MediaSessionEnded must be recorded in the context
        // event log when end_media_session is called.
        pyo3::prepare_freethreaded_python();

        let ctx = "ctx-py-media-end-001";
        let bi = test_bi();
        crate::runtime::register_context(&bi, ctx, ALICE_DID, &[]).unwrap();

        let scp = crate::scp::PyScp { inner: bi.clone() };

        // First: append the Started event so the tree is non-empty.
        pyo3::Python::with_gil(|py| {
            scp.py_media_activate_session(py, initiating_session_json(ctx))
                .unwrap();
        });

        let count_after_start = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::event_count(&st.event_log))
        })
        .unwrap();
        assert_eq!(count_after_start, 1, "1 event (Started) after activation");

        // End the session using a fresh Active-state JSON.
        pyo3::Python::with_gil(|py| {
            let result = scp.py_media_end_session(py, active_session_json(ctx), TS_END);
            assert!(
                result.is_ok(),
                "media_end_session_with_log should succeed: {result:?}"
            );
        });

        let count_after_end = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::event_count(&st.event_log))
        })
        .unwrap();
        assert_eq!(
            count_after_end, 2,
            "event log must contain 2 events (Started + Ended)"
        );

        let root = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::root(&st.event_log))
        })
        .unwrap();
        assert_ne!(root, [0u8; 32], "Merkle root must be non-zero");

        crate::runtime::remove_context(&bi, ctx);
    }

    #[test]
    fn activate_session_with_log_without_registered_context_succeeds() {
        // Best-effort: missing context -> warning only, session op still succeeds.
        pyo3::prepare_freethreaded_python();

        let scp = crate::scp::PyScp { inner: test_bi() };
        pyo3::Python::with_gil(|py| {
            let result = scp
                .py_media_activate_session(py, initiating_session_json("ctx-py-unregistered-act"));
            assert!(
                result.is_ok(),
                "activate must succeed without a registered context"
            );
        });
    }

    #[test]
    fn end_session_with_log_without_registered_context_succeeds() {
        // Best-effort: missing context -> warning only, session op still succeeds.
        pyo3::prepare_freethreaded_python();

        let scp = crate::scp::PyScp { inner: test_bi() };
        let session_json = serde_json::json!({
            "session_id": "ms-py-noctx",
            "context_id": "ctx-py-unregistered-end",
            "participants": [ALICE_DID],
            "capabilities": [{"Voice": null}],
            "state": "Initiating",
            "started_at": TS_START,
        })
        .to_string();
        pyo3::Python::with_gil(|py| {
            let result = scp.py_media_end_session(py, session_json.clone(), TS_END);
            assert!(
                result.is_ok(),
                "end must succeed without a registered context"
            );
        });
    }

    // ── Existing tests ───────────────────────────────────────────────────────

    #[test]
    fn parse_media_capability_valid() {
        assert!(matches!(
            parse_media_capability("voice").unwrap(),
            MediaCapability::Voice
        ));
        assert!(matches!(
            parse_media_capability("video").unwrap(),
            MediaCapability::Video
        ));
        assert!(matches!(
            parse_media_capability("screen_share").unwrap(),
            MediaCapability::ScreenShare
        ));
    }

    #[test]
    fn parse_media_capability_invalid() {
        assert!(parse_media_capability("invalid").is_err());
    }

    #[test]
    fn capability_to_string_roundtrip() {
        assert_eq!(capability_to_string(&MediaCapability::Voice), "voice");
        assert_eq!(capability_to_string(&MediaCapability::Video), "video");
        assert_eq!(
            capability_to_string(&MediaCapability::ScreenShare),
            "screen_share"
        );
    }

    #[test]
    fn state_to_string_values() {
        assert_eq!(
            state_to_string(&MediaSessionState::Initiating),
            "initiating"
        );
        assert_eq!(state_to_string(&MediaSessionState::Active), "active");
        assert_eq!(state_to_string(&MediaSessionState::Ended), "ended");
    }

    #[test]
    fn check_capability_valid() {
        let result = py_media_check_capability(
            vec!["media:voice".to_owned(), "messages:read".to_owned()],
            "voice",
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn check_capability_missing() {
        let result = py_media_check_capability(vec!["messages:read".to_owned()], "voice");
        assert!(result.is_err());
    }

    #[test]
    fn verify_sender_attribution_match() {
        // Create a signaling message and verify it
        let (_, msg) = create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let json = String::from_utf8(serialize_signaling(&msg).unwrap()).unwrap();
        let result = py_media_verify_sender_attribution(json, "did:dht:zAlice".to_owned());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn verify_sender_attribution_mismatch() {
        let (_, msg) = create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let json = String::from_utf8(serialize_signaling(&msg).unwrap()).unwrap();
        let result = py_media_verify_sender_attribution(json, "did:dht:zEve".to_owned());
        assert!(result.is_err());
    }
}
