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
    let (event_count, merkle_root_hex) = crate::runtime::with_context(&context_id, |rt| {
        let count = scp_event_log::tree::event_count(&rt.event_log);
        let root = scp_event_log::tree::root(&rt.event_log);
        Ok((count, hex::encode(root)))
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

    // Unix timestamp seconds fit in f64 mantissa for centuries.
    #[allow(clippy::cast_precision_loss)]
    let timestamp = scp_core::time::now_secs()
        .map_err(|e| ScpNapiError::Context {
            message: format!("{e}"),
            code: "SCP-CTX-2023".to_owned(),
        })
        .map_err(napi::Error::from)? as f64;

    let summary_event = NapiEvent {
        event_type: "LogSummary".to_owned(),
        actor_did: String::new(),
        timestamp,
        payload_json,
        // Sequence number is a small counter; precision loss is negligible.
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
                let proof = scp_event_log::proof::prove_inclusion(&rt.event_log, leaf_index)
                    .map_err(|e| ScpNapiError::Context {
                        message: format!("inclusion proof failed: {e}"),
                        code: "SCP-CTX-2025".to_owned(),
                    })?;
                let verified = scp_event_log::proof::verify_inclusion(&proof);

                let path_steps: Vec<serde_json::Value> = proof
                    .path
                    .iter()
                    .map(|step| {
                        let direction = match step.direction {
                            scp_event_log::proof::Direction::Left => "left",
                            scp_event_log::proof::Direction::Right => "right",
                        };
                        serde_json::json!({
                            "sibling_hash": hex::encode(step.sibling_hash),
                            "direction": direction,
                        })
                    })
                    .collect();

                let details = serde_json::json!({
                    "leaf_index": proof.leaf_index,
                    "leaf_hash": hex::encode(proof.leaf_hash),
                    "root": hex::encode(proof.root),
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

            let (verified, details_json) =
                crate::runtime::with_context(&context_id, |rt| {
                    let proof = scp_event_log::proof::prove_absence(&rt.event_log, &event_hash)
                        .map_err(|e| ScpNapiError::Context {
                            message: format!("absence proof failed: {e}"),
                            code: "SCP-CTX-2025".to_owned(),
                        })?;

                    let lower = proof.lower.as_ref().map(|lwp| {
                        serde_json::json!({
                            "leaf_hash": hex::encode(lwp.leaf_hash),
                            "leaf_index": lwp.leaf_index,
                        })
                    });

                    let upper = proof.upper.as_ref().map(|uwp| {
                        serde_json::json!({
                            "leaf_hash": hex::encode(uwp.leaf_hash),
                            "leaf_index": uwp.leaf_index,
                        })
                    });

                    let lower_verified = proof.lower.as_ref().is_none_or(|lwp| {
                        scp_event_log::proof::verify_inclusion(&lwp.inclusion_proof)
                    });
                    let upper_verified = proof.upper.as_ref().is_none_or(|uwp| {
                        scp_event_log::proof::verify_inclusion(&uwp.inclusion_proof)
                    });
                    let verified = lower_verified && upper_verified;

                    let details = serde_json::json!({
                        "query_hash": hex::encode(proof.query_hash),
                        "root": hex::encode(proof.root),
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
// NapiCheckpoint — consistency checkpoint record
// ---------------------------------------------------------------------------

/// A signed consistency checkpoint from the context event log.
///
/// See ADR-011 acceptance criterion 8 and ADR-030.
#[napi(object)]
pub struct NapiCheckpoint {
    /// The context this checkpoint belongs to.
    pub context_id: String,
    /// The DID of the member who generated this checkpoint.
    pub sender_did: String,
    /// The number of events in the log at checkpoint time.
    pub event_count: f64,
    /// The Merkle root hash at checkpoint time, hex-encoded.
    pub merkle_root: String,
    /// Current MLS epoch. `null` for Broadcast contexts.
    pub epoch: Option<f64>,
    /// Unix timestamp (seconds) when the checkpoint was generated.
    pub timestamp: f64,
    /// Ed25519 signature over the canonical checkpoint fields, hex-encoded.
    pub signature: String,
}

/// Generates a signed consistency checkpoint from the current event log state.
///
/// Creates a snapshot of the event log's Merkle root and event count, signs it
/// with the caller's identity key, and returns the checkpoint. Checkpoints
/// enable equivocation detection: members exchange signed Merkle roots and
/// compare them to detect relay misbehavior.
///
/// # Arguments
///
/// * `handle` — The context whose event log to checkpoint.
/// * `identity` — The identity generating the checkpoint (used for signing).
/// * `epoch` — The current MLS epoch (pass 0 for Broadcast contexts).
///
/// # Returns
///
/// A `Promise<NapiCheckpoint>` containing the signed checkpoint data.
///
/// # Errors
///
/// - Rejects with `SCP-PERM-3023` if key custody is not available.
/// - Rejects with `SCP-CTX-2023` if the context is not found.
///
/// See ADR-011 acceptance criterion 8 and ADR-030.
#[napi]
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned types
pub fn event_log_checkpoint(
    handle: &NapiContextHandle,
    identity: &crate::identity::NapiIdentity,
    epoch: f64,
) -> napi::Result<NapiCheckpoint> {
    #[cfg(not(feature = "allow_in_memory_custody"))]
    {
        let _ = (&handle, &identity, &epoch);
        return Err(napi::Error::from(ScpNapiError::Permission {
            message: "event log checkpoint requires key custody -- the in_memory custody path \
                       is not available in this build. Enable allow_in_memory_custody \
                       for dev/desktop use."
                .to_owned(),
            code: "SCP-PERM-3023".to_owned(),
        }));
    }

    #[cfg(feature = "allow_in_memory_custody")]
    {
        crate::runtime::ensure_registered(handle).map_err(napi::Error::from)?;

        let custody = identity.inner.in_memory_custody.as_ref().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Permission {
                message: "event log checkpoint requires key custody — create the identity \
                      with in_memory custody (identity_create(\"in_memory\"))"
                    .to_owned(),
                code: "SCP-PERM-3023".to_owned(),
            })
        })?;
        let scp_id = identity.inner.scp_identity.as_ref().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Identity {
                message: "event log checkpoint requires retained identity state — the identity \
                          was externally loaded"
                    .to_owned(),
                code: "SCP-IDENT-1007".to_owned(),
            })
        })?;

        let context_id = handle.context_id();
        let sender_did = scp_identity::DID(identity.inner.did.clone());
        let epoch_u64 = validate_non_negative_epoch(epoch)?;

        let checkpoint = crate::runtime::with_context(&context_id, |rt| {
            let signer = scp_core::event_log::KeyCustodySigner {
                custody: &custody.0,
                key: &scp_id.active_signing_key,
            };

            // generate_checkpoint is async — this sync NAPI function runs on
            // a libuv worker thread (not inside tokio), so we use the stored
            // runtime to block_on the future.
            crate::runtime().block_on(async {
                scp_event_log::checkpoint::generate_checkpoint(
                    &rt.event_log,
                    &sender_did,
                    epoch_u64,
                    &signer,
                )
                .await
                .map_err(|e| ScpNapiError::Context {
                    message: format!("checkpoint generation failed: {e}"),
                    code: "SCP-CTX-2023".to_owned(),
                })
            })
        })
        .map_err(napi::Error::from)?;

        #[allow(clippy::cast_precision_loss)]
        Ok(NapiCheckpoint {
            context_id: checkpoint.context_id,
            sender_did: checkpoint.sender_did.0,
            event_count: checkpoint.event_count as f64,
            merkle_root: hex::encode(checkpoint.merkle_root),
            epoch: checkpoint.epoch.map(|e| e as f64),
            timestamp: checkpoint.timestamp as f64,
            signature: hex::encode(checkpoint.signature),
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validates that an f64 epoch value is non-negative and returns it as u64.
///
/// Returns `napi::Error` with `SCP-VALID-7040` if the value is negative.
fn validate_non_negative_epoch(epoch: f64) -> napi::Result<u64> {
    if epoch < 0.0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("epoch must be non-negative, got {epoch}"),
            code: "SCP-VALID-7040".to_owned(),
        }));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(epoch as u64)
}

/// Decodes a hex string into a 32-byte hash.
///
/// Used by absence proof verification to decode the `event_hash` field from
/// the claim JSON. Rejects strings that are not exactly 64 hex characters
/// (32 bytes).
#[allow(dead_code)] // Will be used when event_log_verify is wired to scp-core.
pub(crate) fn decode_hex_hash(hex: &str) -> Result<[u8; 32], String> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // decode_hex_hash
    // -----------------------------------------------------------------------

    #[test]
    fn decode_hex_hash_valid_32_bytes() {
        // 64 hex characters representing 32 zero bytes.
        let hex = "0".repeat(64);
        let result = decode_hex_hash(&hex).unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn decode_hex_hash_valid_nonzero() {
        // Known 32-byte value encoded as hex.
        let mut expected = [0u8; 32];
        expected[0] = 0xab;
        expected[1] = 0xcd;
        expected[31] = 0xef;
        let hex = format!("abcd{}ef", "00".repeat(29));
        let result = decode_hex_hash(&hex).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn decode_hex_hash_rejects_short_input() {
        // 62 hex chars (31 bytes) — too short.
        let hex = "ab".repeat(31);
        let result = decode_hex_hash(&hex);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("expected 64 hex characters"),
            "error should mention expected length, got: {err}"
        );
    }

    #[test]
    fn decode_hex_hash_rejects_long_input() {
        // 66 hex chars (33 bytes) — too long.
        let hex = "ab".repeat(33);
        let result = decode_hex_hash(&hex);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("expected 64 hex characters"),
            "error should mention expected length, got: {err}"
        );
    }

    #[test]
    fn decode_hex_hash_rejects_non_hex_characters() {
        // 64 characters but containing 'gg' which is not valid hex.
        let hex = format!("gg{}", "00".repeat(31));
        let result = decode_hex_hash(&hex);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("hex decode error"),
            "error should mention hex decode failure, got: {err}"
        );
    }

    #[test]
    fn decode_hex_hash_rejects_empty_input() {
        let result = decode_hex_hash("");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_non_negative_epoch
    // -----------------------------------------------------------------------

    #[test]
    fn validate_epoch_accepts_zero() {
        assert_eq!(validate_non_negative_epoch(0.0).unwrap(), 0);
    }

    #[test]
    fn validate_epoch_accepts_positive() {
        assert_eq!(validate_non_negative_epoch(42.0).unwrap(), 42);
    }

    #[test]
    fn validate_epoch_rejects_negative() {
        let result = validate_non_negative_epoch(-1.0);
        assert!(result.is_err(), "negative epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_negative_infinity() {
        let result = validate_non_negative_epoch(f64::NEG_INFINITY);
        assert!(result.is_err(), "NEG_INFINITY epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_f64_min() {
        let result = validate_non_negative_epoch(f64::MIN);
        assert!(result.is_err(), "f64::MIN epoch should error");
    }

    #[test]
    fn validate_epoch_negative_error_contains_code() {
        let result = validate_non_negative_epoch(-42.0);
        let err = result.unwrap_err();
        // The napi::Error's Display impl includes the reason string, which
        // contains the SCP-VALID-7040 code from ScpNapiError::Validation.
        let msg = format!("{err}");
        assert!(
            msg.contains("SCP-VALID-7040"),
            "error should contain SCP-VALID-7040, got: {msg}"
        );
    }
}
