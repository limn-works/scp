//! Shared marshalling helpers for `InvocationCaveats` (§7.3.8, SCP-OUT-023).
//!
//! Each FFI bridge defines its own concrete record type to surface caveats
//! to its host language idiomatically (`PyO3` dataclass, `NAPI` object, `UniFFI`
//! Record, WASM JSON). This module provides the JSON ↔
//! [`scp_protocol::trust::caveats::InvocationCaveats`] conversion layer that
//! every bridge funnels through, plus the canonical
//! `caveat-mint-limit-exceeded` slug used by callers when surfacing
//! [`SCP-TOOL-6114`](crate::error_codes::TOOL_6114).
//!
//! # Wire format
//!
//! The JSON encoding matches the spec §7.3.8 vocabulary verbatim
//! (`amountMaxPerCall`, `validFrom`, `hoursOfDay`, …) — see
//! [`scp_protocol::trust::caveats::InvocationCaveats`] for the field-level
//! contract. Because the protocol type owns the serde rename map, every
//! bridge that delegates to [`caveats_from_json`] /
//! [`caveats_to_json`] gets the identical wire layout for free.
//!
//! # Round-trip contract
//!
//! `caveats_to_json(caveats_from_json(json)?)` is byte-equal to the input
//! when the input is canonical JSON; round-trip stability is required for
//! the SCP-OUT-023 conformance test (build caveats in SDK, mint, decode JWT,
//! assert `nb` field matches input).
//!
//! # Errors
//!
//! [`caveats_from_json`] returns the underlying `serde_json::Error` as a
//! string so each bridge can map it to its idiomatic error envelope.
//! Mint-limit failures surfaced by
//! [`scp_protocol::trust::caveats::InvocationCaveats::try_new`] are NOT
//! thrown by these helpers — they are runtime-time errors that surface from
//! the mint path itself; the helpers only validate JSON structure.

use scp_protocol::trust::caveats::InvocationCaveats;

/// Canonical slug for [`SCP-TOOL-6114`](crate::error_codes::TOOL_6114) when
/// caveat mint-time structural limits are exceeded (§7.3.8 mint-limits).
///
/// SDK conformance tests assert that mint-limit errors surface this exact
/// slug as part of the error envelope. Bridges that own the error mapping
/// must use this constant rather than re-spelling the string.
pub const CAVEAT_MINT_LIMIT_EXCEEDED_SLUG: &str = "caveat-mint-limit-exceeded";

/// Parses an [`InvocationCaveats`] record from its canonical JSON form
/// (§7.3.8 wire vocabulary).
///
/// All 12 fields (the 11 typed caveats plus `originKind`) are optional. An
/// empty JSON object `{}` decodes to [`InvocationCaveats::empty`]. Unknown
/// top-level keys are rejected (the protocol type carries
/// `#[serde(deny_unknown_fields)]`) so SDKs cannot silently emit junk into
/// the `nb` field.
///
/// # Errors
///
/// Returns the wrapped `serde_json::Error` as a string. The bridge layer
/// is responsible for mapping the string into its idiomatic error envelope
/// (`ScpPyError::Validation`, `ScpNapiError::Validation`,
/// `ScpError::Validation`, `ScpWasmError::Validation`).
pub fn caveats_from_json(json: &str) -> Result<InvocationCaveats, String> {
    serde_json::from_str(json).map_err(|e| format!("invalid InvocationCaveats JSON: {e}"))
}

/// Serializes an [`InvocationCaveats`] to its canonical JSON form
/// (§7.3.8 wire vocabulary).
///
/// Output is a single-line JSON object using camelCase keys
/// (`amountMaxPerCall`, `validFrom`, …). Absent fields are omitted, not
/// serialized as `null`.
///
/// # Errors
///
/// Returns the wrapped `serde_json::Error` as a string. The only practical
/// failure mode is embedded non-finite floats inside `input_schema`; the
/// caveat type's `try_new` constructor rejects such values at mint time so
/// this error is unreachable from validated input.
pub fn caveats_to_json(caveats: &InvocationCaveats) -> Result<String, String> {
    serde_json::to_string(caveats)
        .map_err(|e| format!("InvocationCaveats serialization failed: {e}"))
}

/// Resolves the §7.3.8 effective invocation caveats and CID from an
/// already-validated action UCAN token (single-shot outlet invoke).
///
/// The non-streaming outlet invoke must enforce the SAME §7.3.8 post-input
/// caveat gate the streaming path enforces. The action UCAN's
/// validated-narrowed `nb` field IS the effective caveat set; its CID forms
/// half of the durable counter-store key (`(context_id, ucan_cid,
/// caveat_kind)`). Each native bridge (PyO3, NAPI, UniFFI) validates the
/// token through the full 11-step ADR-016 pipeline, then calls this helper to
/// recover the caveat set + CID so it can build a
/// [`scp_core::context::manager::CaveatEnforcement`] bundle. Centralizing the
/// parse here means a single source of truth for what "effective caveats"
/// means across the three native bridges — a bridge cannot drift by parsing
/// differently.
///
/// `nb == None` (no invocation caveats minted) decodes to
/// [`InvocationCaveats::empty`], for which
/// [`InvocationCaveats::requires_post_input_check`] is `false` and the caller
/// builds no enforcement bundle — identical to the streaming path's gate.
///
/// # Errors
///
/// Returns the wrapped parse error as a string. In practice this is
/// unreachable: the caller has already validated the same token string
/// through the ADR-016 pipeline (which parses it). Bridges map the string
/// into their idiomatic UCAN/permission error envelope rather than unwrap.
#[cfg(feature = "resolvers")]
pub fn resolve_action_caveats(ucan_token: &str) -> Result<(InvocationCaveats, String), String> {
    let parsed = scp_core::crypto::ucan::validate::parse_ucan(ucan_token)
        .map_err(|e| format!("failed to parse action UCAN: {e}"))?;
    let effective = parsed
        .payload
        .nb
        .clone()
        .unwrap_or_else(InvocationCaveats::empty);
    let cid = scp_core::crypto::ucan::mint::compute_cid(&parsed);
    Ok((effective, cid))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use super::*;
    use scp_protocol::economy::types::Amount;
    use scp_protocol::trust::caveats::{DaysOfWeekMask, HoursOfDayMask, RateWindow};

    #[test]
    fn empty_round_trip() {
        let caveats = InvocationCaveats::empty();
        let json = caveats_to_json(&caveats).unwrap();
        assert_eq!(json, "{}");
        let back = caveats_from_json(&json).unwrap();
        assert_eq!(back, caveats);
    }

    #[test]
    fn populated_round_trip_preserves_every_field() {
        let caveats = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(100)),
            amount_max_cumulative: Some(Amount::new(1000)),
            valid_from: Some(1_700_000_000),
            valid_until: Some(1_700_003_600),
            hours_of_day: Some(HoursOfDayMask::from_bits(0x00FF_FFFF).unwrap()),
            days_of_week: Some(DaysOfWeekMask::from_bits(0x7F).unwrap()),
            max_calls: Some(42),
            rate_window: Some(RateWindow {
                max: 5,
                window_secs: 60,
            }),
            input_schema: Some(serde_json::json!({"type": "object"})),
            allowed_adapters: Some(vec![]),
            allowed_target_dids: Some(vec![]),
            origin_kind: None,
        };

        let json = caveats_to_json(&caveats).unwrap();
        let back = caveats_from_json(&json).unwrap();
        assert_eq!(back, caveats);
    }

    #[test]
    fn unknown_field_rejected() {
        let json = r#"{"amountMaxPerCall":100,"unknown":42}"#;
        let result = caveats_from_json(json);
        assert!(result.is_err(), "unknown field must reject");
    }

    #[test]
    fn slug_constant_matches_spec() {
        assert_eq!(
            CAVEAT_MINT_LIMIT_EXCEEDED_SLUG,
            "caveat-mint-limit-exceeded"
        );
    }
}
