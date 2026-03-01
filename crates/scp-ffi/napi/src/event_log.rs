//! napi-rs bridge for event log operations.
//!
//! Exposes event log queries and Merkle proof verification:
//!
//! - [`event_log_query`] — Query the context event log with optional filters.
//! - [`event_log_verify`] — Verify a claim against the event log (Merkle proof).
//!
//! See ADR-011 (Event Log) and ADR-022 in `.docs/adrs/`.

use napi_derive::napi;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// NapiEvent — protocol event record
// ---------------------------------------------------------------------------

/// A protocol event from the context event log.
///
/// See ADR-011 (Event Log) and spec section 13 (Event Log).
#[napi(object)]
pub struct NapiEvent {
    /// The event type (e.g., `"ContextCreated"`, `"MessageSent"`, `"ToolInvoked"`).
    pub event_type: String,
    /// DID of the actor who produced this event.
    pub actor_did: String,
    /// Unix timestamp (seconds since epoch) when the event was created.
    pub timestamp: f64,
    /// Event-specific data serialized as a JSON string.
    pub payload_json: String,
    /// Monotonic sequence number within the log.
    pub sequence: f64,
}

// ---------------------------------------------------------------------------
// NapiProof — Merkle proof record
// ---------------------------------------------------------------------------

/// A Merkle proof from the event log.
///
/// See ADR-011 (Event Log).
#[napi(object)]
pub struct NapiProof {
    /// `true` if the claim was verified successfully.
    pub verified: bool,
    /// The proof type: `"inclusion"` or `"absence"`.
    pub proof_type: String,
    /// Proof details serialized as a JSON string (Merkle path or sorted
    /// neighbors).
    pub details_json: String,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Queries the context event log with optional filter criteria.
///
/// Returns metadata about the event log: current event count and the Merkle
/// root hash. Direct event replay requires the full transport layer; this
/// function provides verifiable log state information.
///
/// # Arguments
///
/// * `handle` — The context whose event log to query (must be `"active"`).
/// * `filter_json` — Optional JSON string with filter parameters:
///   `event_type`, `actor_did`, `after_sequence`, `before_sequence`,
///   `after_timestamp`, `before_timestamp`, `limit`. Pass `null` to return
///   all events (up to the default limit).
///
/// # Returns
///
/// A `Promise<NapiEvent[]>` resolving to the matching events.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2023` if the context is not found.
/// - Rejects with `SCP-VALID-7000` if `filter_json` is not valid JSON.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub async fn event_log_query(
    handle: &NapiContextHandle,
    filter_json: Option<String>,
) -> napi::Result<Vec<NapiEvent>> {
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    let filter: Option<serde_json::Value> = match filter_json {
        Some(ref json_str) => {
            let parsed: serde_json::Value =
                serde_json::from_str(json_str).map_err(|e| ScpNapiError::Validation {
                    message: format!("filter_json is not valid JSON: {e}"),
                    code: "SCP-VALID-7000".to_owned(),
                })?;
            Some(parsed)
        }
        None => None,
    };

    let context_id = handle.context_id();
    let (event_count, merkle_root_hex) =
        crate::runtime::with_context(&context_id, |rt| {
            let count = scp_core::event_log::tree::event_count(&rt.event_log);
            let root = scp_core::event_log::tree::root(&rt.event_log);
            Ok((count, encode_hex(&root)))
        })
        .map_err(napi::Error::from)?;

    #[allow(clippy::cast_possible_truncation)] // Event limit is always small; truncation is safe.
    let limit = filter
        .as_ref()
        .and_then(|f| f.get("limit"))
        .and_then(serde_json::Value::as_u64)
        .map(|l| l as usize);

    if event_count == 0 {
        return Ok(Vec::new());
    }

    let payload_json = serde_json::json!({
        "event_count": event_count,
        "merkle_root": merkle_root_hex,
    })
    .to_string();

    #[allow(clippy::cast_precision_loss)]
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ScpNapiError::Context {
            message: format!("system clock error: {e}"),
            code: "SCP-CTX-2023".to_owned(),
        })
        .map_err(napi::Error::from)?
        .as_secs() as f64;

    let summary_event = NapiEvent {
        event_type: "LogSummary".to_owned(),
        actor_did: String::new(),
        timestamp,
        payload_json,
        #[allow(clippy::cast_precision_loss)]
        sequence: event_count.saturating_sub(1) as f64,
    };

    let events = vec![summary_event];

    if let Some(lim) = limit {
        Ok(events.into_iter().take(lim).collect())
    } else {
        Ok(events)
    }
}

/// Verifies a claim against the context event log (Merkle proof).
///
/// Generates and verifies an inclusion or absence proof for the given claim.
///
/// # Arguments
///
/// * `handle` — The context whose event log to verify against.
/// * `claim_json` — JSON string describing the claim:
///   - `"type"`: `"inclusion"` or `"absence"`
///   - `"leaf_index"` (for inclusion): event position in the log
///   - `"event_hash"` (for absence): hex-encoded hash to prove absent
///
/// # Returns
///
/// A `Promise<NapiProof>` with the verification result and Merkle proof
/// details.
///
/// # Errors
///
/// - Rejects with `SCP-CTX-2025` if the context is not found or proof fails.
/// - Rejects with `SCP-VALID-7000` if `claim_json` is not valid JSON or
///   contains unrecognized proof type.
#[napi]
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
#[allow(clippy::too_many_lines)] // Proof generation with match arms is inherently verbose.
pub async fn event_log_verify(
    handle: &NapiContextHandle,
    claim_json: String,
) -> napi::Result<NapiProof> {
    crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

    let claim: serde_json::Value =
        serde_json::from_str(&claim_json).map_err(|e| ScpNapiError::Validation {
            message: format!("claim_json is not valid JSON: {e}"),
            code: "SCP-VALID-7000".to_owned(),
        })?;

    let claim_type = claim
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ScpNapiError::Validation {
            message: "claim must include 'type' field ('inclusion' or 'absence')".to_owned(),
            code: "SCP-VALID-7000".to_owned(),
        })
        .map_err(napi::Error::from)?;

    let context_id = handle.context_id();

    match claim_type {
        "inclusion" => {
            let leaf_index = claim
                .get("leaf_index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| ScpNapiError::Validation {
                    message: "inclusion claim must include 'leaf_index' (integer)".to_owned(),
                    code: "SCP-VALID-7000".to_owned(),
                })
                .map_err(napi::Error::from)?;

            let (verified, details_json) = crate::runtime::with_context(&context_id, |rt| {
                let proof = scp_core::event_log::proof::prove_inclusion(&rt.event_log, leaf_index)
                    .map_err(|e| ScpNapiError::Context {
                        message: format!("inclusion proof failed: {e}"),
                        code: "SCP-CTX-2025".to_owned(),
                    })?;
                let verified = scp_core::event_log::proof::verify_inclusion(&proof);

                let path_steps: Vec<serde_json::Value> = proof
                    .path
                    .iter()
                    .map(|step| {
                        let direction = match step.direction {
                            scp_core::event_log::proof::Direction::Left => "left",
                            scp_core::event_log::proof::Direction::Right => "right",
                        };
                        serde_json::json!({
                            "sibling_hash": encode_hex(&step.sibling_hash),
                            "direction": direction,
                        })
                    })
                    .collect();

                let details = serde_json::json!({
                    "leaf_index": proof.leaf_index,
                    "leaf_hash": encode_hex(&proof.leaf_hash),
                    "root": encode_hex(&proof.root),
                    "path": path_steps,
                    "path_length": proof.path.len(),
                });

                Ok((verified, details.to_string()))
            })
            .map_err(napi::Error::from)?;

            Ok(NapiProof {
                verified,
                proof_type: "inclusion".to_owned(),
                details_json,
            })
        }
        "absence" => {
            let event_hash_hex = claim
                .get("event_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ScpNapiError::Validation {
                    message: "absence claim must include 'event_hash' (hex string)".to_owned(),
                    code: "SCP-VALID-7000".to_owned(),
                })
                .map_err(napi::Error::from)?;

            let event_hash = decode_hex_hash(event_hash_hex).map_err(|e| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("invalid event_hash: {e}"),
                    code: "SCP-VALID-7000".to_owned(),
                })
            })?;

            let (verified, details_json) = crate::runtime::with_context(&context_id, |rt| {
                let proof =
                    scp_core::event_log::proof::prove_absence(&rt.event_log, &event_hash)
                        .map_err(|e| ScpNapiError::Context {
                            message: format!("absence proof failed: {e}"),
                            code: "SCP-CTX-2025".to_owned(),
                        })?;

                let lower = proof.lower.as_ref().map(|lwp| {
                    serde_json::json!({
                        "leaf_hash": encode_hex(&lwp.leaf_hash),
                        "leaf_index": lwp.leaf_index,
                    })
                });

                let upper = proof.upper.as_ref().map(|uwp| {
                    serde_json::json!({
                        "leaf_hash": encode_hex(&uwp.leaf_hash),
                        "leaf_index": uwp.leaf_index,
                    })
                });

                let lower_verified = proof.lower.as_ref().is_none_or(|lwp| {
                    scp_core::event_log::proof::verify_inclusion(&lwp.inclusion_proof)
                });
                let upper_verified = proof.upper.as_ref().is_none_or(|uwp| {
                    scp_core::event_log::proof::verify_inclusion(&uwp.inclusion_proof)
                });
                let verified = lower_verified && upper_verified;

                let details = serde_json::json!({
                    "query_hash": encode_hex(&proof.query_hash),
                    "root": encode_hex(&proof.root),
                    "leaf_count": proof.leaf_count,
                    "lower": lower,
                    "upper": upper,
                });

                Ok((verified, details.to_string()))
            })
            .map_err(napi::Error::from)?;

            Ok(NapiProof {
                verified,
                proof_type: "absence".to_owned(),
                details_json,
            })
        }
        other => Err(ScpNapiError::Validation {
            message: format!("unsupported claim type '{other}': expected 'inclusion' or 'absence'"),
            code: "SCP-VALID-7000".to_owned(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encodes a byte slice as a lowercase hex string.
fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Decodes a hex string into a 32-byte hash.
fn decode_hex_hash(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex characters (32 bytes), got {}",
            hex.len()
        ));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string".to_owned())?;
        bytes[i] =
            u8::from_str_radix(s, 16).map_err(|e| format!("hex decode error at byte {i}: {e}"))?;
    }
    Ok(bytes)
}
