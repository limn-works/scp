//! napi-rs bridge for media operations.
//!
//! Exposes SCP media session lifecycle and signaling to Node.js/Bun:
//!
//! - Session lifecycle: [`media_initiate_session`], [`media_activate_session`],
//!   [`media_join_session`], [`media_end_session`]
//! - Signaling: [`media_create_offer`], [`media_create_answer`],
//!   [`media_create_ice_candidate`], [`media_create_session_end`],
//!   [`media_send_signaling`], [`media_verify_sender_attribution`]
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

use napi_derive::napi;
use scp_ffi_common::error_codes as codes;

use scp_media::session::{
    MediaCapability, MediaSession, MediaSessionState, activate_session, check_media_capability,
    end_media_session, initiate_media_session, join_media_session,
};
use scp_media::signaling::{
    create_answer, create_ice_candidate, create_offer, create_session_end, deserialize_signaling,
    send_signaling, serialize_signaling, verify_sender_attribution,
};

use crate::error::ScpNapiError;
use crate::runtime::{NapiBridgeInstance, default_bridge_instance};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_media_capability(s: &str) -> napi::Result<MediaCapability> {
    match s {
        "voice" => Ok(MediaCapability::Voice),
        "video" => Ok(MediaCapability::Video),
        "screen_share" => Ok(MediaCapability::ScreenShare),
        other => Err(ScpNapiError::Validation {
            message: format!(
                "invalid media capability '{other}': expected 'voice', 'video', or 'screen_share'"
            ),
            code: codes::VALID_7300.to_owned(),
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

fn media_error_to_napi(e: scp_media::keys::MediaError) -> napi::Error {
    ScpNapiError::Context {
        message: e.to_string(),
        code: codes::CTX_2500.to_owned(),
    }
    .into()
}

fn session_to_json(session: &MediaSession) -> napi::Result<String> {
    serde_json::to_string(&serde_json::json!({
        "session_id": session.session_id,
        "context_id": session.context_id,
        "participants": session.participants,
        "capabilities": session.capabilities.iter().map(capability_to_string).collect::<Vec<_>>(),
        "state": state_to_string(&session.state),
        "started_at": session.started_at,
    }))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize session: {e}"),
            code: codes::VALID_7301.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/// Checks that a media capability is present in the context's capability ceiling.
///
/// Returns `true` if the capability is present.
#[napi]
pub fn media_check_capability(ceiling: Vec<String>, capability: String) -> napi::Result<bool> {
    let bi = default_bridge_instance()?;
    media_check_capability_on(&bi, ceiling, capability)
}

/// Per-bridge-instance implementation of [`media_check_capability`].
///
/// Media capability validation is pure — the `bi` parameter is carried for
/// `_on` helper shape symmetry with the rest of the bridge.
pub(crate) fn media_check_capability_on(
    _bi: &NapiBridgeInstance,
    ceiling: Vec<String>,
    capability: String,
) -> napi::Result<bool> {
    let cap = parse_media_capability(&capability)?;
    let param_caps: Vec<scp_core::context::params::Capability> = ceiling
        .iter()
        .map(scp_core::context::params::Capability::new)
        .collect();
    check_media_capability(&param_caps, &cap).map_err(media_error_to_napi)?;
    Ok(true)
}

/// Initiates a media session after validating capabilities against the ceiling.
///
/// Returns a JSON string with session fields.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn media_initiate_session(
    context_id: String,
    ceiling: Vec<String>,
    capabilities: Vec<String>,
    participants: Vec<String>,
    timestamp: f64,
) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_initiate_session_on(&bi, context_id, ceiling, capabilities, participants, timestamp)
}

/// Per-bridge-instance implementation of [`media_initiate_session`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn media_initiate_session_on(
    _bi: &NapiBridgeInstance,
    context_id: String,
    ceiling: Vec<String>,
    capabilities: Vec<String>,
    participants: Vec<String>,
    timestamp: f64,
) -> napi::Result<String> {
    let caps: Vec<MediaCapability> = capabilities
        .iter()
        .map(|s| parse_media_capability(s))
        .collect::<napi::Result<Vec<_>>>()?;

    let param_caps: Vec<scp_core::context::params::Capability> = ceiling
        .iter()
        .map(scp_core::context::params::Capability::new)
        .collect();

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let ts = timestamp as u64;

    let session = initiate_media_session(
        context_id,
        &param_caps,
        caps,
        participants
            .into_iter()
            .map(scp_identity::DID::from)
            .collect(),
        ts,
    )
    .map_err(media_error_to_napi)?;

    session_to_json(&session)
}

/// Activates a media session (transitions from Initiating to Active).
///
/// Takes a JSON string representing the session and returns the updated session.
#[napi]
pub fn media_activate_session(session_json: String) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_activate_session_on(&bi, session_json)
}

/// Per-bridge-instance implementation of [`media_activate_session`].
pub(crate) fn media_activate_session_on(
    _bi: &NapiBridgeInstance,
    session_json: String,
) -> napi::Result<String> {
    let mut session: MediaSession = serde_json::from_str(&session_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid session JSON: {e}"),
            code: codes::VALID_7301.to_owned(),
        })
    })?;

    activate_session(&mut session).map_err(media_error_to_napi)?;
    session_to_json(&session)
}

/// Adds a participant to a media session.
///
/// Takes a JSON string and returns the updated session.
#[napi]
pub fn media_join_session(session_json: String, participant_did: String) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_join_session_on(&bi, session_json, participant_did)
}

/// Per-bridge-instance implementation of [`media_join_session`].
pub(crate) fn media_join_session_on(
    _bi: &NapiBridgeInstance,
    session_json: String,
    participant_did: String,
) -> napi::Result<String> {
    let mut session: MediaSession = serde_json::from_str(&session_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid session JSON: {e}"),
            code: codes::VALID_7301.to_owned(),
        })
    })?;

    join_media_session(&mut session, participant_did.into()).map_err(media_error_to_napi)?;
    session_to_json(&session)
}

/// Ends a media session and returns metadata for event log recording.
///
/// Returns a JSON string with `session` and `metadata` keys.
#[napi]
pub fn media_end_session(session_json: String, timestamp: f64) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_end_session_on(&bi, session_json, timestamp)
}

/// Per-bridge-instance implementation of [`media_end_session`].
pub(crate) fn media_end_session_on(
    _bi: &NapiBridgeInstance,
    session_json: String,
    timestamp: f64,
) -> napi::Result<String> {
    let mut session: MediaSession = serde_json::from_str(&session_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid session JSON: {e}"),
            code: codes::VALID_7301.to_owned(),
        })
    })?;

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let ts = timestamp as u64;

    let metadata = end_media_session(&mut session, ts).map_err(media_error_to_napi)?;

    serde_json::to_string(&serde_json::json!({
        "session": {
            "session_id": session.session_id,
            "context_id": session.context_id,
            "participants": session.participants,
            "capabilities": session.capabilities.iter().map(capability_to_string).collect::<Vec<_>>(),
            "state": state_to_string(&session.state),
            "started_at": session.started_at,
        },
        "metadata": {
            "session_id": metadata.session_id,
            "context_id": metadata.context_id,
            "participants": metadata.participants,
            "capabilities": metadata.capabilities.iter().map(capability_to_string).collect::<Vec<_>>(),
            "started_at": metadata.started_at,
            "ended_at": metadata.ended_at,
        },
    }))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize result: {e}"),
            code: codes::VALID_7301.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Signaling
// ---------------------------------------------------------------------------

/// Creates an SDP offer signaling message.
///
/// Returns a JSON string with `session_id` and `message` keys.
#[napi]
pub fn media_create_offer(
    session_id: String,
    sdp: String,
    sender_did: String,
) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_create_offer_on(&bi, session_id, sdp, sender_did)
}

/// Per-bridge-instance implementation of [`media_create_offer`].
pub(crate) fn media_create_offer_on(
    _bi: &NapiBridgeInstance,
    session_id: String,
    sdp: String,
    sender_did: String,
) -> napi::Result<String> {
    let (sid, msg) = create_offer(&session_id, sdp, sender_did.into());
    let msg_json = String::from_utf8(serialize_signaling(&msg).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize signaling: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?)
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("signaling bytes are not valid UTF-8: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?;

    serde_json::to_string(&serde_json::json!({
        "session_id": sid,
        "message": msg_json,
    }))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize result: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })
}

/// Creates an SDP answer signaling message.
///
/// Returns a JSON string with `session_id` and `message` keys.
#[napi]
pub fn media_create_answer(
    session_id: String,
    sdp: String,
    sender_did: String,
) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_create_answer_on(&bi, session_id, sdp, sender_did)
}

/// Per-bridge-instance implementation of [`media_create_answer`].
pub(crate) fn media_create_answer_on(
    _bi: &NapiBridgeInstance,
    session_id: String,
    sdp: String,
    sender_did: String,
) -> napi::Result<String> {
    let (sid, msg) = create_answer(&session_id, sdp, sender_did.into());
    let msg_json = String::from_utf8(serialize_signaling(&msg).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize signaling: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?)
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("signaling bytes are not valid UTF-8: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?;

    serde_json::to_string(&serde_json::json!({
        "session_id": sid,
        "message": msg_json,
    }))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize result: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })
}

/// Creates an ICE candidate signaling message.
///
/// Returns a JSON string with `session_id` and `message` keys.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn media_create_ice_candidate(
    session_id: String,
    candidate: String,
    sender_did: String,
    sdp_mid: Option<String>,
    sdp_mline_index: Option<u32>,
) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_create_ice_candidate_on(&bi, session_id, candidate, sender_did, sdp_mid, sdp_mline_index)
}

/// Per-bridge-instance implementation of [`media_create_ice_candidate`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn media_create_ice_candidate_on(
    _bi: &NapiBridgeInstance,
    session_id: String,
    candidate: String,
    sender_did: String,
    sdp_mid: Option<String>,
    sdp_mline_index: Option<u32>,
) -> napi::Result<String> {
    #[allow(clippy::cast_possible_truncation)]
    let mline_index = sdp_mline_index.map(|v| v as u16);
    let (sid, msg) = create_ice_candidate(
        &session_id,
        candidate,
        sdp_mid,
        mline_index,
        sender_did.into(),
    );
    let msg_json = String::from_utf8(serialize_signaling(&msg).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize signaling: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?)
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("signaling bytes are not valid UTF-8: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?;

    serde_json::to_string(&serde_json::json!({
        "session_id": sid,
        "message": msg_json,
    }))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize result: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })
}

/// Creates a session-end signaling message.
///
/// Returns a JSON string with `session_id` and `message` keys.
#[napi]
pub fn media_create_session_end(session_id: String, sender_did: String) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_create_session_end_on(&bi, session_id, sender_did)
}

/// Per-bridge-instance implementation of [`media_create_session_end`].
pub(crate) fn media_create_session_end_on(
    _bi: &NapiBridgeInstance,
    session_id: String,
    sender_did: String,
) -> napi::Result<String> {
    let (sid, msg) = create_session_end(&session_id, sender_did.into());
    let msg_json = String::from_utf8(serialize_signaling(&msg).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize signaling: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?)
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("signaling bytes are not valid UTF-8: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?;

    serde_json::to_string(&serde_json::json!({
        "session_id": sid,
        "message": msg_json,
    }))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize result: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })
}

/// Serializes a signaling message and returns payload with message type.
///
/// Returns a JSON string with `payload` (base64) and `message_type` keys.
#[napi]
pub fn media_send_signaling(signaling_json: String) -> napi::Result<String> {
    let bi = default_bridge_instance()?;
    media_send_signaling_on(&bi, signaling_json)
}

/// Per-bridge-instance implementation of [`media_send_signaling`].
pub(crate) fn media_send_signaling_on(
    _bi: &NapiBridgeInstance,
    signaling_json: String,
) -> napi::Result<String> {
    let msg = deserialize_signaling(signaling_json.as_bytes()).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid signaling JSON: {e}"),
            code: codes::VALID_7303.to_owned(),
        })
    })?;
    let (payload, message_type) = send_signaling(&msg).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize signaling: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })?;

    use base64::Engine;
    serde_json::to_string(&serde_json::json!({
        "payload": base64::engine::general_purpose::STANDARD.encode(&payload),
        "message_type": format!("{message_type:?}"),
    }))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("failed to serialize result: {e}"),
            code: codes::VALID_7302.to_owned(),
        })
    })
}

/// Verifies that the sender DID in a signaling message matches the envelope sender.
///
/// Returns `true` if valid.
#[napi]
pub fn media_verify_sender_attribution(
    signaling_json: String,
    envelope_sender_did: String,
) -> napi::Result<bool> {
    let bi = default_bridge_instance()?;
    media_verify_sender_attribution_on(&bi, signaling_json, envelope_sender_did)
}

/// Per-bridge-instance implementation of [`media_verify_sender_attribution`].
pub(crate) fn media_verify_sender_attribution_on(
    _bi: &NapiBridgeInstance,
    signaling_json: String,
    envelope_sender_did: String,
) -> napi::Result<bool> {
    let msg = deserialize_signaling(signaling_json.as_bytes()).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid signaling JSON: {e}"),
            code: codes::VALID_7303.to_owned(),
        })
    })?;
    verify_sender_attribution(&msg, &envelope_sender_did).map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: format!("sender attribution verification failed: {e}"),
            code: codes::CTX_2501.to_owned(),
        })
    })?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn check_capability_voice_in_ceiling() {
        let result = media_check_capability(
            vec!["media:voice".to_owned(), "messages:read".to_owned()],
            "voice".to_owned(),
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn check_capability_missing_from_ceiling() {
        let result = media_check_capability(vec!["messages:read".to_owned()], "voice".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn verify_attribution_matching() {
        let (_, msg) = create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let json = String::from_utf8(serialize_signaling(&msg).unwrap()).unwrap();
        let result = media_verify_sender_attribution(json, "did:dht:zAlice".to_owned());
        assert!(result.is_ok());
    }

    #[test]
    fn verify_attribution_mismatch() {
        let (_, msg) = create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let json = String::from_utf8(serialize_signaling(&msg).unwrap()).unwrap();
        let result = media_verify_sender_attribution(json, "did:dht:zEve".to_owned());
        assert!(result.is_err());
    }
}
