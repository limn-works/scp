//! napi-rs bridge for event log operations.
//!
//! Exposes event log queries and Merkle proof verification:
//!
//! - `event_log_query` — Query the context event log with optional filters.
//! - `event_log_verify` — Verify a claim against the event log (Merkle proof).
//!
//! See ADR-011 (Event Log) and ADR-022 in `.docs/adrs/`.

use napi_derive::napi;
use scp_ffi_common::error_codes as codes;
use scp_primitives::Clock;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

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

/// Per-bridge-instance implementation of [`event_log_query`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub(crate) async fn event_log_query_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    filter_json: Option<String>,
) -> napi::Result<Vec<NapiEvent>> {
    crate::napi_check_handle!(&bi.core, handle);
    crate::runtime::ensure_registered(bi, handle).map_err(napi::Error::from)?;

    let filter: Option<serde_json::Value> = match filter_json {
        Some(ref json_str) => {
            let parsed: serde_json::Value =
                serde_json::from_str(json_str).map_err(|e| ScpNapiError::Validation {
                    message: format!("filter_json is not valid JSON: {e}"),
                    code: codes::VALID_7000.to_owned(),
                })?;
            Some(parsed)
        }
        None => None,
    };

    #[allow(clippy::cast_possible_truncation)] // Event limit is always small; truncation is safe.
    let limit = filter
        .as_ref()
        .and_then(|f| f.get("limit"))
        .and_then(serde_json::Value::as_u64)
        .map(|l| l as usize);

    let event_type_filter = filter
        .as_ref()
        .and_then(|f| f.get("event_type").or_else(|| f.get("eventType")))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let actor_did_filter = filter
        .as_ref()
        .and_then(|f| f.get("actor_did").or_else(|| f.get("actorDid")))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let after_sequence_filter = filter
        .as_ref()
        .and_then(|f| f.get("after_sequence").or_else(|| f.get("afterSequence")))
        .and_then(serde_json::Value::as_u64);
    let before_sequence_filter = filter
        .as_ref()
        .and_then(|f| f.get("before_sequence").or_else(|| f.get("beforeSequence")))
        .and_then(serde_json::Value::as_u64);

    // Query the per-instance Supervisor's event log provider for real
    // Merkle entries. The UCAN state event log is a separate per-context
    // instance; the supervisor-owned `MerkleEventLogProvider` is the
    // authoritative source.
    let context_id_str = handle.context_id();
    // ADR-056: resolve the context-id string to its 32-byte digest via the
    // canonical chokepoint (NOT the raw SHA-256 routing primitive, which
    // double-hashes a real 64-hex id and queries the wrong event-log key).
    let ctx_id_bytes = scp_core::context::state::context_id_to_bytes(&context_id_str);

    let manager_entries = crate::runtime::supervisor(bi)
        .ok()
        .and_then(|supervisor| supervisor.event_log_entries(&ctx_id_bytes).ok().flatten());

    if let Some(entries) = manager_entries
        && !entries.is_empty()
    {
        // Canonical filter — pinned across PyO3/NAPI/UniFFI by
        // `scp_ffi_common::event_log::filter_manager_entries` so the three
        // bridges cannot drift on `after_sequence` / `before_sequence` /
        // `event_type` / `actor_did` / `limit`. Each bridge still owns its
        // `Event`/`NapiEvent`/`PyEvent` mapping; the helper only encodes the
        // filter contract. Filter semantics: `after_sequence` /
        // `before_sequence` exclusive on both ends (matches UniFFI reference).
        let filter = scp_ffi_common::event_log::EventLogFilter {
            after_sequence: after_sequence_filter,
            before_sequence: before_sequence_filter,
            event_type: event_type_filter.as_deref(),
            actor_did: actor_did_filter.as_deref(),
            limit,
        };
        let filtered = scp_ffi_common::event_log::filter_manager_entries(&entries, &filter);

        #[allow(clippy::cast_precision_loss)]
        let mut events: Vec<NapiEvent> = Vec::with_capacity(filtered.len());
        for (seq, entry) in filtered {
            let leaf_hash = scp_event_log::tree::leaf_hash(entry).map_err(|e| {
                napi::Error::from(ScpNapiError::Context {
                    message: format!("event leaf hash failed: {e}"),
                    code: codes::CTX_2000.to_owned(),
                })
            })?;
            // Project the typed payload's bridge-facing fields (e.g.
            // `target_did` for governance/access-revocation events,
            // `subject_did` for role/membership events) through the single
            // shared decoder so all four bridges surface byte-identical values.
            // Each key is omitted when the projection yields `None`.
            let projection =
                scp_event_log::payload::project_payload(&entry.event_type, &entry.payload);
            let mut payload_value = serde_json::json!({
                "hash": hex::encode(leaf_hash),
            });
            if let Some(target_did) = projection.target_did {
                payload_value["target_did"] = serde_json::Value::String(target_did);
            }
            if let Some(subject_did) = projection.subject_did {
                payload_value["subject_did"] = serde_json::Value::String(subject_did);
            }
            #[allow(clippy::cast_precision_loss)]
            events.push(NapiEvent {
                event_type: scp_ffi_common::event_log::event_type_label(&entry.event_type),
                actor_did: entry.actor_did.0.clone(),
                timestamp: entry.timestamp as f64,
                payload_json: payload_value.to_string(),
                sequence: seq as f64,
            });
        }

        return Ok(events);
    }

    // Fallback: read from the per-context UCAN state event log.
    let (event_count, merkle_root_hex) = crate::runtime::with_context(bi, &context_id_str, |rt| {
        let count = scp_event_log::tree::event_count(&rt.core.event_log);
        let root = scp_event_log::tree::root(&rt.core.event_log);
        Ok((count, hex::encode(root)))
    })
    .map_err(napi::Error::from)?;

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
    let timestamp = scp_primitives::SystemClock.now_secs() as f64;

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

/// Per-bridge-instance implementation of [`event_log_verify`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
#[allow(clippy::too_many_lines)] // Proof generation with match arms is inherently verbose.
pub(crate) async fn event_log_verify_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    claim_json: String,
) -> napi::Result<NapiProof> {
    crate::napi_check_handle!(&bi.core, handle);
    crate::runtime::ensure_registered(bi, handle).map_err(napi::Error::from)?;

    let claim: serde_json::Value =
        serde_json::from_str(&claim_json).map_err(|e| ScpNapiError::Validation {
            message: format!("claim_json is not valid JSON: {e}"),
            code: codes::VALID_7000.to_owned(),
        })?;

    let claim_type = claim
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ScpNapiError::Validation {
            message: "claim must include 'type' field ('inclusion' or 'absence')".to_owned(),
            code: codes::VALID_7000.to_owned(),
        })
        .map_err(napi::Error::from)?;

    let context_id = handle.context_id();

    // Sync the supervisor's Merkle event log entries into the UCAN-state
    // EventLog so that prove_inclusion / prove_absence operate on the same
    // tree that tracks lifecycle events. The UCAN-state EventLog starts
    // empty; this populates it from the authoritative MerkleEventLogProvider.
    // ADR-056: resolve the context-id string to its 32-byte digest via the
    // canonical chokepoint (NOT the raw SHA-256 routing primitive, which
    // double-hashes a real 64-hex id and queries the wrong event-log key).
    let ctx_id_bytes = scp_core::context::state::context_id_to_bytes(&context_id);
    if let Some(entries) = crate::runtime::supervisor(bi)
        .ok()
        .and_then(|supervisor| supervisor.event_log_entries(&ctx_id_bytes).ok().flatten())
    {
        // Precompute the canonical leaf hash for each source event
        // (`SHA-256(0x00 ‖ rmp_serde(Event))`) via the substrate helper so the
        // synced UCAN-state tree commits to byte-identical leaves.
        let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(entries.len());
        for entry in &entries {
            leaf_hashes.push(scp_event_log::tree::leaf_hash(entry).map_err(|e| {
                napi::Error::from(ScpNapiError::Context {
                    message: format!("event leaf hash failed: {e}"),
                    code: codes::CTX_2000.to_owned(),
                })
            })?);
        }

        crate::runtime::with_context(bi, &context_id, |rt| {
            let existing_leaves = rt.core.event_log.leaves();
            let existing_count = existing_leaves.len();

            // Prefix consistency check: if existing leaves diverge from the
            // source (e.g. after reimport), clear and re-sync the entire tree.
            let prefix_matches = existing_leaves
                .iter()
                .zip(leaf_hashes.iter())
                .all(|(leaf, hash)| leaf == hash);

            if !prefix_matches && existing_count > 0 {
                // Leaves diverge — rebuild from scratch.
                let ctx_id = rt.core.event_log.context_id().to_owned();
                rt.core.event_log = scp_event_log::EventLog::new(ctx_id);
                for hash in &leaf_hashes {
                    rt.core.event_log.push_leaf_raw(*hash);
                }
            } else {
                // Append-only: push entries that haven't been synced yet.
                for hash in leaf_hashes.iter().skip(existing_count) {
                    rt.core.event_log.push_leaf_raw(*hash);
                }
            }
            Ok(())
        })
        .map_err(napi::Error::from)?;
    }

    match claim_type {
        "inclusion" => {
            let leaf_index = claim
                .get("leaf_index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| ScpNapiError::Validation {
                    message: "inclusion claim must include 'leaf_index' (integer)".to_owned(),
                    code: codes::VALID_7000.to_owned(),
                })
                .map_err(napi::Error::from)?;

            let (verified, details_json) = crate::runtime::with_context(bi, &context_id, |rt| {
                let proof = scp_event_log::proof::prove_inclusion(&rt.core.event_log, leaf_index)
                    .map_err(|e| ScpNapiError::Context {
                    message: format!("inclusion proof failed: {e}"),
                    code: codes::CTX_2025.to_owned(),
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
                    code: codes::VALID_7000.to_owned(),
                })
                .map_err(napi::Error::from)?;

            let event_hash = decode_hex_hash(event_hash_hex).map_err(|e| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("invalid event_hash: {e}"),
                    code: codes::VALID_7000.to_owned(),
                })
            })?;

            let (verified, details_json) = crate::runtime::with_context(bi, &context_id, |rt| {
                let proof = scp_event_log::proof::prove_absence(&rt.core.event_log, &event_hash)
                    .map_err(|e| ScpNapiError::Context {
                        message: format!("absence proof failed: {e}"),
                        code: codes::CTX_2025.to_owned(),
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

                let lower_verified = proof
                    .lower
                    .as_ref()
                    .is_none_or(|lwp| scp_event_log::proof::verify_inclusion(&lwp.inclusion_proof));
                let upper_verified = proof
                    .upper
                    .as_ref()
                    .is_none_or(|uwp| scp_event_log::proof::verify_inclusion(&uwp.inclusion_proof));
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
            code: codes::VALID_7000.to_owned(),
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

/// Per-bridge-instance implementation of [`event_log_checkpoint`].
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned types
pub(crate) fn event_log_checkpoint_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    identity: &crate::identity::NapiIdentity,
    epoch: f64,
) -> napi::Result<NapiCheckpoint> {
    crate::napi_check_handle!(&bi.core, handle, identity);
    {
        crate::runtime::ensure_registered(bi, handle).map_err(napi::Error::from)?;

        let custody = identity.inner.in_memory_custody.as_ref().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Identity {
                message: "event log checkpoint requires retained signing custody — this identity \
                      has no retained custody (it was externally loaded)"
                    .to_owned(),
                code: codes::IDENT_1017.to_owned(),
            })
        })?;
        let scp_id = identity.inner.scp_identity.as_ref().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Identity {
                message: "event log checkpoint requires retained identity state — the identity \
                          was externally loaded"
                    .to_owned(),
                code: codes::IDENT_1007.to_owned(),
            })
        })?;

        let context_id = handle.context_id();
        let sender_did = scp_identity::DID(identity.inner.did.clone());
        let epoch_u64 = validate_non_negative_epoch(epoch)?;

        let checkpoint = crate::runtime::with_context(bi, &context_id, |rt| {
            let signer = scp_core::event_log::KeyCustodySigner {
                custody: custody.as_ref(),
                key: &scp_id.active_signing_key,
            };

            // generate_checkpoint is async — this sync NAPI function runs on
            // a libuv worker thread (not inside tokio), so we use the stored
            // runtime to block_on the future.
            crate::runtime().block_on(async {
                scp_event_log::checkpoint::generate_checkpoint(
                    &rt.core.event_log,
                    &sender_did,
                    epoch_u64,
                    &signer,
                )
                .await
                .map_err(|e| ScpNapiError::Context {
                    message: format!("checkpoint generation failed: {e}"),
                    code: codes::CTX_2023.to_owned(),
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

/// Per-bridge-instance implementation of [`event_log_checkpoint_by_did`].
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned types
pub(crate) fn event_log_checkpoint_by_did_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    did: String,
    epoch: f64,
) -> napi::Result<NapiCheckpoint> {
    crate::napi_check_handle!(&bi.core, handle);
    {
        crate::runtime::ensure_registered(bi, handle).map_err(napi::Error::from)?;

        let (scp_id, custody) = crate::runtime::with_identity(bi, &did, |entry| {
            Ok((
                entry.identity.clone(),
                std::sync::Arc::clone(&entry.custody),
            ))
        })
        .map_err(napi::Error::from)?;

        let context_id = handle.context_id();
        let sender_did = scp_identity::DID(did);
        let epoch_u64 = validate_non_negative_epoch(epoch)?;

        let checkpoint = crate::runtime::with_context(bi, &context_id, |rt| {
            let signer = scp_core::event_log::KeyCustodySigner {
                custody: custody.as_ref(),
                key: &scp_id.active_signing_key,
            };

            crate::runtime().block_on(async {
                scp_event_log::checkpoint::generate_checkpoint(
                    &rt.core.event_log,
                    &sender_did,
                    epoch_u64,
                    &signer,
                )
                .await
                .map_err(|e| ScpNapiError::Context {
                    message: format!("checkpoint generation failed: {e}"),
                    code: codes::CTX_2023.to_owned(),
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
    if epoch < 0.0 || !epoch.is_finite() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("epoch must be non-negative, got {epoch}"),
            code: codes::VALID_7040.to_owned(),
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

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

    // -----------------------------------------------------------------------
    // Missing-signing-custody → SCP-IDENT-1017
    //
    // An identity that retains no custody (externally loaded: `in_memory_custody`
    // is `None`) must reject an event-log checkpoint with the canonical
    // missing-signing-custody code.
    // -----------------------------------------------------------------------

    #[test]
    fn event_log_checkpoint_without_retained_custody_returns_ident_1017() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let instance_id = bi.instance_id();
        let handle = crate::context::NapiContextHandle::test_active_on(
            &bi,
            "ctx-no-custody-checkpoint".to_owned(),
            "did:dht:z6MkCreatorNoCustody".to_owned(),
        );

        // Externally-loaded identity: no retained custody, no signing key state.
        let identity = crate::identity::NapiIdentity {
            inner: std::sync::Arc::new(crate::identity::NapiIdentityInner {
                did: "did:dht:z6MkCreatorNoCustody".to_owned(),
                custody_type: "external".to_owned(),
                scp_identity: None,
                in_memory_custody: None,
                document: None,
                bi: std::sync::Arc::clone(&bi),
                verifying_key_hex: None,
                instance_id,
                rotation_event_json: None,
            }),
        };

        let Err(err) = event_log_checkpoint_on(&bi, &handle, &identity, 1.0) else {
            panic!("checkpoint without retained custody must fail")
        };
        let reason = err.reason.clone();
        assert!(
            reason.contains("SCP-IDENT-1017"),
            "expected SCP-IDENT-1017, got: {reason}"
        );
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
            msg.contains(codes::VALID_7040),
            "error should contain SCP-VALID-7040, got: {msg}"
        );
    }

    #[test]
    fn validate_epoch_rejects_nan() {
        let result = validate_non_negative_epoch(f64::NAN);
        assert!(result.is_err(), "NaN epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_positive_infinity() {
        let result = validate_non_negative_epoch(f64::INFINITY);
        assert!(result.is_err(), "INFINITY epoch should error");
    }
}
