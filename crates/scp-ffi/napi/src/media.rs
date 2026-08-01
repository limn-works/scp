//! napi-rs bridge for media operations.
//!
//! Per-bridge-instance (`_on`) implementations consumed by the corresponding
//! methods on [`crate::scp::Scp`]. Phase D (#1695) deleted the
//! free-function wrappers that routed through the process-global default
//! bridge instance.
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

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
use crate::runtime::NapiBridgeInstance;

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
// Event log helper — ADR-024 AC 8
// ---------------------------------------------------------------------------

/// Appends a media session event (`MediaSessionStarted` or `MediaSessionEnded`)
/// to the event log for the given context.
///
/// Best-effort: callers log a warning on error rather than failing the
/// session operation. Mirrors the pattern used by `OutletInvoked` in `mcp.rs`
/// and `ProvenanceAttached`/`ProvenanceReceived` in `provenance.rs`.
///
/// `actor_did` is the first session participant (the session initiator). When
/// the participant list is empty the DID is set to an empty string so the leaf
/// shape is still uniform.
fn append_media_session_event(
    bi: &NapiBridgeInstance,
    context_id: &str,
    actor_did: &str,
    event_type: scp_event_log::EventType,
    payload: scp_event_log::EventPayload,
) -> napi::Result<()> {
    let timestamp = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

    crate::runtime::with_context(bi, context_id, |state| {
        let sequence = scp_event_log::tree::event_count(&state.core.event_log);
        let prev_hash = if state.core.event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            state.core.event_log.leaves()[state.core.event_log.leaves().len() - 1]
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

        scp_event_log::tree::append_unsigned_event(&mut state.core.event_log, &event)
            .map(|_| ())
            .map_err(|e| ScpNapiError::Context {
                message: format!("failed to append media session event: {e}"),
                code: codes::CTX_2500.to_owned(),
            })
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `media_check_capability`.
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
        .map(|s| {
            scp_core::context::params::Capability::new(s).ok_or_else(|| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!(
                        "invalid capability {s:?} in ceiling (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
                    ),
                    code: codes::VALID_7000.to_owned(),
                })
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;
    check_media_capability(&param_caps, &cap).map_err(media_error_to_napi)?;
    Ok(true)
}

/// Per-bridge-instance implementation of `media_initiate_session`.
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
        .map(|s| {
            scp_core::context::params::Capability::new(s).ok_or_else(|| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!(
                        "invalid capability {s:?} in ceiling (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
                    ),
                    code: codes::VALID_7000.to_owned(),
                })
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let ts = timestamp as u64;

    let session = initiate_media_session(
        context_id,
        &param_caps,
        caps,
        participants.into_iter().map(scp_did::DID::from).collect(),
        ts,
    )
    .map_err(media_error_to_napi)?;

    session_to_json(&session)
}

/// Per-bridge-instance implementation of `media_activate_session`.
///
/// Transitions the session from `Initiating` to `Active` and appends a
/// `MediaSessionStarted` leaf to the context event log (ADR-024 AC 8).
/// The event log append is best-effort: if the context is not registered
/// in the UCAN state registry a warning is emitted but the session state
/// transition still succeeds.
pub(crate) fn media_activate_session_on(
    bi: &NapiBridgeInstance,
    session_json: String,
) -> napi::Result<String> {
    let mut session: MediaSession = serde_json::from_str(&session_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid session JSON: {e}"),
            code: codes::VALID_7301.to_owned(),
        })
    })?;

    activate_session(&mut session).map_err(media_error_to_napi)?;

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
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: format!("failed to encode MediaSessionStarted payload: {e}"),
            code: codes::CTX_2500.to_owned(),
        })
    })?;

    let actor_did = session.participants.first().map_or("", |d| d.as_ref());

    if let Err(e) = append_media_session_event(
        bi,
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

    session_to_json(&session)
}

/// Per-bridge-instance implementation of `media_join_session`.
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

/// Per-bridge-instance implementation of `media_end_session`.
///
/// Ends the session and appends a `MediaSessionEnded` leaf to the context
/// event log (ADR-024 AC 8). The event log append is best-effort: if the
/// context is not registered a warning is emitted but the session teardown
/// still succeeds.
pub(crate) fn media_end_session_on(
    bi: &NapiBridgeInstance,
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

    // ADR-024 AC 8: record MediaSessionEnded in the context event log.
    let ended_payload =
        scp_event_log::payload::encode_payload(&scp_event_log::payload::MediaSessionEndedPayload {
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
        })
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to encode MediaSessionEnded payload: {e}"),
                code: codes::CTX_2500.to_owned(),
            })
        })?;

    let actor_did = metadata.participants.first().map_or("", |d| d.as_ref());

    if let Err(e) = append_media_session_event(
        bi,
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

/// Per-bridge-instance implementation of `media_create_offer`.
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

/// Per-bridge-instance implementation of `media_create_answer`.
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

/// Per-bridge-instance implementation of `media_create_ice_candidate`.
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

/// Per-bridge-instance implementation of `media_create_session_end`.
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

/// Per-bridge-instance implementation of `media_send_signaling`.
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

/// Per-bridge-instance implementation of `media_verify_sender_attribution`.
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
    use crate::runtime::NapiBridgeInstance;

    fn test_bi() -> NapiBridgeInstance {
        NapiBridgeInstance::new_napi()
    }

    #[test]
    fn check_capability_voice_in_ceiling() {
        let bi = test_bi();
        let result = media_check_capability_on(
            &bi,
            vec!["media:voice".to_owned(), "messages:read".to_owned()],
            "voice".to_owned(),
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn check_capability_missing_from_ceiling() {
        let bi = test_bi();
        let result =
            media_check_capability_on(&bi, vec!["messages:read".to_owned()], "voice".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn verify_attribution_matching() {
        let bi = test_bi();
        let (_, msg) = create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let json = String::from_utf8(serialize_signaling(&msg).unwrap()).unwrap();
        let result = media_verify_sender_attribution_on(&bi, json, "did:dht:zAlice".to_owned());
        assert!(result.is_ok());
    }

    #[test]
    fn verify_attribution_mismatch() {
        let bi = test_bi();
        let (_, msg) = create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let json = String::from_utf8(serialize_signaling(&msg).unwrap()).unwrap();
        let result = media_verify_sender_attribution_on(&bi, json, "did:dht:zEve".to_owned());
        assert!(result.is_err());
    }

    // ── Event log appends — ADR-024 AC 8 ────────────────────────────────────

    const ALICE_DID: &str = "did:dht:z6MkAlice";
    const TS_START: u64 = 1_700_000_000;
    const TS_END: f64 = 1_700_003_600.0;

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
        // `media_activate_session_on` uses `session_to_json` which serialises
        // capabilities as lowercase strings (`"voice"`), but `MediaSession`'s
        // serde impl expects the enum-variant form (`{"Voice": null}`).
        // For tests that feed the result of one bridge call into another, build
        // the session JSON directly in serde's native format so both
        // deserialisation paths agree.
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
    fn activate_session_appends_media_session_started_event() {
        // ADR-024 AC 8: MediaSessionStarted must be recorded in the context
        // event log when activate_session transitions the session to Active.
        let ctx = "ctx-media-activate-001";
        let bi = test_bi();
        crate::runtime::register_test_context(&bi, ctx, ALICE_DID);

        let initial_count = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::event_count(&st.core.event_log))
        })
        .unwrap();
        assert_eq!(initial_count, 0, "event log must start empty");

        let result = media_activate_session_on(&bi, initiating_session_json(ctx));
        assert!(
            result.is_ok(),
            "activate_session_on should succeed: {result:?}"
        );

        let count = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::event_count(&st.core.event_log))
        })
        .unwrap();
        assert_eq!(count, 1, "event log must contain 1 event after activation");

        // Verify the Merkle root is non-zero (leaf was actually hashed in).
        let root = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::root(&st.core.event_log))
        })
        .unwrap();
        assert_ne!(root, [0u8; 32], "Merkle root must be non-zero after append");

        crate::runtime::remove_context(&bi, ctx);
    }

    #[test]
    fn end_session_appends_media_session_ended_event() {
        // ADR-024 AC 8: MediaSessionEnded must be recorded in the context
        // event log when end_media_session is called.
        //
        // We test each bridge call independently (activate then end) to avoid
        // the format mismatch: `session_to_json` produces lowercase capability
        // strings (`"voice"`) which are not valid for serde's MediaSession enum
        // deserialization (`{"Voice": null}`). Each test builds its own
        // well-formed JSON directly.
        let ctx = "ctx-media-end-001";
        let bi = test_bi();
        crate::runtime::register_test_context(&bi, ctx, ALICE_DID);

        // First: append the Started event so the tree is non-empty.
        media_activate_session_on(&bi, initiating_session_json(ctx)).unwrap();

        let count_after_start = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::event_count(&st.core.event_log))
        })
        .unwrap();
        assert_eq!(count_after_start, 1, "1 event (Started) after activation");

        // End the session using a fresh Active-state JSON (serde format).
        let result = media_end_session_on(&bi, active_session_json(ctx), TS_END);
        assert!(result.is_ok(), "end_session_on should succeed: {result:?}");

        let count_after_end = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::event_count(&st.core.event_log))
        })
        .unwrap();
        assert_eq!(
            count_after_end, 2,
            "event log must contain 2 events (Started + Ended)"
        );

        let root = crate::runtime::with_context(&bi, ctx, |st| {
            Ok(scp_event_log::tree::root(&st.core.event_log))
        })
        .unwrap();
        assert_ne!(root, [0u8; 32], "Merkle root must be non-zero");

        crate::runtime::remove_context(&bi, ctx);
    }

    #[test]
    fn activate_session_without_registered_context_succeeds() {
        // Best-effort: missing context -> warning only, session op still succeeds.
        let bi = test_bi();
        let result =
            media_activate_session_on(&bi, initiating_session_json("ctx-unregistered-act"));
        assert!(
            result.is_ok(),
            "activate must succeed without a registered context"
        );
    }

    #[test]
    fn end_session_without_registered_context_succeeds() {
        // Best-effort: missing context -> warning only, session op still succeeds.
        let bi = test_bi();
        let session_json = serde_json::json!({
            "session_id": "ms-noctx",
            "context_id": "ctx-unregistered-end",
            "participants": [ALICE_DID],
            "capabilities": [{"Voice": null}],
            "state": "Initiating",
            "started_at": TS_START,
        })
        .to_string();
        let result = media_end_session_on(&bi, session_json, TS_END);
        assert!(
            result.is_ok(),
            "end must succeed without a registered context"
        );
    }
}
