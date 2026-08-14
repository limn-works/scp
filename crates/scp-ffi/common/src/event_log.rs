//! Shared event-log filtering used by all FFI bridges.
//!
//! Canonical filter semantics for `ContextManager::event_log_entries`
//! queries live here so PyO3/NAPI/UniFFI stay in lock-step by
//! construction rather than by parity-harness enforcement.
//!
//! The five filter clauses — `after_sequence`, `before_sequence`,
//! `event_type`, `actor_did`, `limit` — were previously open-coded
//! identically in three bridges. The cross-bridge parity harness
//! (`OP_EVENT_LOG_FILTERED`, ADR-046) is the runtime anchor; this
//! helper is the structural anchor.
//!
//! Semantics (`PyO3` reference — see `scp-ffi/src/event_log.rs::query_manager_entries`):
//!
//! 1. `after_sequence`: **exclusive** lower bound (entries with
//!    `seq <= after` are skipped).
//! 2. `before_sequence`: **exclusive** upper bound (entries with
//!    `seq >= before` are skipped).
//! 3. `event_type`: equality match on the event's type rendered via
//!    [`event_type_label`] (e.g. `"MessageSent"`), matching the bridge's
//!    surfaced `event_type` string.
//! 4. `actor_did`: equality match on `Event::actor_did` (the inner DID string).
//! 5. `limit`: applied **after** the entry is accepted (push-then-check);
//!    once `out.len() >= lim`, iteration breaks.
//!
//! Sequence numbers are 0-indexed positions within the input slice
//! (`idx as u64`). Mapping [`scp_event_log::Event`] → native bridge struct
//! (`PyEvent` / `NapiEvent` / `UniFFI` `Event`) is the caller's
//! responsibility — the helper only encodes the filter contract.

use scp_event_log::Event;

/// Renders an event type as its canonical label string (the `Debug` form,
/// e.g. `"MessageSent"`).
///
/// This is the single source of truth for the `event_type` string surfaced
/// across all FFI bridges and matched by the `event_type` filter clause, so
/// the filter and the surfaced value stay in lock-step by construction.
#[must_use]
pub fn event_type_label(event_type: &scp_event_log::EventType) -> String {
    format!("{event_type:?}")
}

/// Injects a typed event payload's bridge-facing projection fields into a JSON object.
///
/// The fields are `target_did` (governance / access-revocation events) and
/// `subject_did` (role / membership events), decoded via the single shared
/// [`scp_event_log::payload::project_payload`].
///
/// Each key is inserted ONLY when the projection yields a value, so every bridge
/// surfaces byte-identical event payloads from one decoder rather than
/// re-implementing the field selection per call site. `value` must be a
/// `serde_json::Value::Object` (e.g. the `{"hash": ...}` map the event-log query
/// paths build); a non-object value is left untouched.
pub fn inject_projection(
    value: &mut serde_json::Value,
    event_type: &scp_event_log::EventType,
    payload: &scp_event_log::EventPayload,
) {
    let projection = scp_event_log::payload::project_payload(event_type, payload);
    let Some(map) = value.as_object_mut() else {
        return;
    };
    if let Some(target_did) = projection.target_did {
        map.insert(
            "target_did".to_owned(),
            serde_json::Value::String(target_did),
        );
    }
    if let Some(subject_did) = projection.subject_did {
        map.insert(
            "subject_did".to_owned(),
            serde_json::Value::String(subject_did),
        );
    }
}

/// The five canonical filter clauses applied to manager event-log entries.
///
/// Borrowed fields so callers can pass string slices from their own
/// parsed filter JSON without extra allocation. All fields are optional
/// — a default-constructed `EventLogFilter` matches every entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct EventLogFilter<'a> {
    /// Exclusive lower bound on sequence number.
    pub after_sequence: Option<u64>,
    /// Exclusive upper bound on sequence number.
    pub before_sequence: Option<u64>,
    /// Equality match on the event-type label (see [`event_type_label`]).
    pub event_type: Option<&'a str>,
    /// Equality match on `Event::actor_did` (the inner DID string).
    pub actor_did: Option<&'a str>,
    /// Maximum number of entries to return. Applied post-push.
    pub limit: Option<usize>,
}

/// Applies the canonical filter contract to a slice of entries.
///
/// Returns `(sequence_number, entry)` pairs. Each bridge maps the pair
/// into its own native `Event`/`NapiEvent`/`PyEvent` struct — this
/// helper does not touch bridge-specific fields (e.g. `payload_json`
/// encoding, hex formatting, timestamp-f64 coercion).
///
/// Iteration order matches the input slice; the returned `Vec` is
/// allocated with capacity equal to `limit` when set (saves one
/// reallocation in the common "limit=N" path).
#[must_use]
pub fn filter_manager_entries<'a>(
    entries: &'a [Event],
    filter: &EventLogFilter<'a>,
) -> Vec<(u64, &'a Event)> {
    let mut out: Vec<(u64, &'a Event)> = filter
        .limit
        .map_or_else(Vec::new, |lim| Vec::with_capacity(lim.min(entries.len())));
    for (idx, entry) in entries.iter().enumerate() {
        let seq = idx as u64;
        if let Some(after) = filter.after_sequence
            && seq <= after
        {
            continue;
        }
        if let Some(before) = filter.before_sequence
            && seq >= before
        {
            continue;
        }
        if let Some(et) = filter.event_type
            && event_type_label(&entry.event_type) != et
        {
            continue;
        }
        if let Some(did) = filter.actor_did
            && entry.actor_did.0 != did
        {
            continue;
        }
        out.push((seq, entry));
        if let Some(lim) = filter.limit
            && out.len() >= lim
        {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Merkle proof → JSON (shared by all three bridges)
// ---------------------------------------------------------------------------

/// Renders an RFC 6962 inclusion proof as the bridge-facing JSON object.
///
/// One shape for every proof a bridge surfaces — the top-level `"inclusion"`
/// answer AND the neighbour proofs carried by an absence answer — so a caller
/// re-verifying off-box parses one structure:
///
/// ```json
/// {
///   "leaf_index": 3,
///   "leaf_hash": "<hex>",
///   "root": "<hex>",
///   "path": [{ "sibling_hash": "<hex>", "direction": "left" | "right" }],
///   "path_length": 1
/// }
/// ```
///
/// `direction` is the SIBLING's side, matching
/// [`scp_event_log::proof::Direction`].
///
/// # Why the neighbour proofs are included
///
/// An absence answer used to ship only each neighbour's `leaf_hash` +
/// `leaf_index`, with no path — so nothing in it could be checked by the
/// recipient, while the response nonetheless carried a `verified` flag the
/// producer had set. Shipping the full neighbour paths is what makes the
/// neighbour-inclusion half of the claim independently checkable against the
/// reported `root`.
///
/// This closes the neighbour-inclusion HALF only: the append-order root does
/// NOT commit to sorted adjacency, so an absence answer is not a self-contained,
/// off-box non-membership proof (a sorted/sparse tree is the real fix; see
/// #2314).
#[must_use]
pub fn inclusion_proof_json(proof: &scp_event_log::proof::InclusionProof) -> serde_json::Value {
    let path: Vec<serde_json::Value> = proof
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

    serde_json::json!({
        "leaf_index": proof.leaf_index,
        "leaf_hash": hex::encode(proof.leaf_hash),
        "root": hex::encode(proof.root),
        "path_length": path.len(),
        "path": path,
    })
}

/// Renders one side of an absence proof — the neighbour leaf plus its full
/// inclusion proof — as the bridge-facing JSON object.
///
/// `None` (no lower neighbour below the query hash, or no upper neighbour above
/// it) maps to JSON `null`.
#[must_use]
pub fn absence_neighbor_json(
    neighbor: Option<&scp_event_log::proof::LeafWithProof>,
) -> serde_json::Value {
    neighbor.map_or(serde_json::Value::Null, |n| {
        serde_json::json!({
            "leaf_hash": hex::encode(n.leaf_hash),
            "leaf_index": n.leaf_index,
            "inclusion_proof": inclusion_proof_json(&n.inclusion_proof),
        })
    })
}

/// Builds the MCP `context_events` metadata JSON over the AUTHORITATIVE event
/// log (GitHub #1933).
///
/// The MCP `events` resource (`scp://{context_id}/events`, read through
/// `ContextProvider::context_events`) and the `mcp_context_events` bridge
/// method both publish the event-log summary through THIS single helper, so the
/// `(event_count, merkle_root)` pair is byte-identical across all three bridges
/// and identical to the commitment `event_log_verify` / `event_log_checkpoint`
/// take over the SAME `Supervisor::authoritative_event_log` snapshot. The MCP
/// tool previously computed its root over each bridge's own
/// caller-influenceable bridge-local tree — the exact forgeable-root class
/// #1933 severs on the verify / checkpoint / query paths, left live on the
/// agent-facing MCP surface.
///
/// `log` is the authoritative-log fetch result. On success the summary is the
/// real `(count, root)` of that snapshot. On failure it FAILS CLOSED to an
/// honest absent state carrying [`crate::error_codes::CTX_2138`] — it does NOT
/// fabricate a `[0u8; 32]` root or a `0` count, which a consumer could not
/// distinguish from a genuinely-empty log. This mirrors the `SCP-CTX-2138`
/// the verify / checkpoint paths raise when the authoritative log is
/// unreachable; those paths raise a typed error, and this resource-shaped
/// surface (which returns a JSON `Value`, never raising) carries the same code
/// in an honest absent object instead.
#[must_use]
pub fn context_events_metadata_json<E: core::fmt::Display>(
    context_id: &str,
    log: Result<&scp_event_log::EventLog, E>,
) -> serde_json::Value {
    match log {
        Ok(log) => serde_json::json!({
            "event_count": scp_event_log::tree::event_count(log),
            "merkle_root": hex::encode(scp_event_log::tree::root(log)),
        }),
        Err(detail) => serde_json::json!({
            "error": format!(
                "event log metadata cannot reach the authoritative log for \
                 context '{context_id}': {detail}"
            ),
            "code": crate::error_codes::CTX_2138,
        }),
    }
}

#[cfg(test)]
// Test-only: the proof round-trip fixtures assert on well-formed values they
// just built, so a `None`/`Err` there IS the test failure. Mirrors the
// `#[allow]` set every other bridge test module carries.
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(event_type: scp_event_log::EventType, actor: &str) -> Event {
        Event {
            event_type,
            actor_did: scp_did::DID(actor.to_owned()),
            timestamp: 0,
            sequence: 0,
            payload: scp_event_log::EventPayload::default(),
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        }
    }

    fn corpus() -> Vec<Event> {
        use scp_event_log::EventType;
        vec![
            entry(EventType::ContextCreated, "did:example:alice"),
            entry(EventType::MemberJoined, "did:example:bob"),
            entry(EventType::MessageSent, "did:example:alice"),
            entry(EventType::MessageSent, "did:example:bob"),
            entry(EventType::MemberLeft, "did:example:alice"),
        ]
    }

    #[test]
    fn empty_filter_returns_all() {
        let c = corpus();
        let out = filter_manager_entries(&c, &EventLogFilter::default());
        assert_eq!(out.len(), c.len());
        assert_eq!(out[0].0, 0);
        assert_eq!(out[4].0, 4);
    }

    #[test]
    fn after_sequence_is_exclusive() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                after_sequence: Some(1),
                ..Default::default()
            },
        );
        // seq 0 and 1 are excluded.
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0, 2);
    }

    #[test]
    fn before_sequence_is_exclusive() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                before_sequence: Some(3),
                ..Default::default()
            },
        );
        // seq 3 and 4 are excluded.
        assert_eq!(out.len(), 3);
        assert_eq!(out[2].0, 2);
    }

    #[test]
    fn event_type_equality() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                event_type: Some("MessageSent"),
                ..Default::default()
            },
        );
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|(_, e)| e.event_type == scp_event_log::EventType::MessageSent)
        );
    }

    #[test]
    fn actor_did_equality() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                actor_did: Some("did:example:alice"),
                ..Default::default()
            },
        );
        assert_eq!(out.len(), 3);
        assert!(
            out.iter()
                .all(|(_, e)| e.actor_did.0 == "did:example:alice")
        );
    }

    #[test]
    fn limit_is_post_push() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                limit: Some(2),
                ..Default::default()
            },
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, 0);
        assert_eq!(out[1].0, 1);
    }

    #[test]
    fn all_clauses_compose() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                after_sequence: Some(0),
                before_sequence: Some(4),
                event_type: Some("MessageSent"),
                actor_did: Some("did:example:bob"),
                limit: Some(10),
            },
        );
        // seq 1..=3, event==MessageSent, actor==bob → seq 3 only.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 3);
    }

    #[test]
    fn limit_zero_returns_empty() {
        let c = corpus();
        let out = filter_manager_entries(
            &c,
            &EventLogFilter {
                limit: Some(0),
                ..Default::default()
            },
        );
        // limit=0 is post-push: first entry pushes, then len==1 >= 0 breaks.
        // Matches legacy PyO3/NAPI/UniFFI behavior (none of them special-cased zero).
        assert_eq!(out.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Merkle proof → JSON
    //
    // The bridges' `Proof` no longer carries a `verified` boolean (it was a
    // producer-set constant). These pin that the JSON they DO ship is complete
    // enough for a recipient to re-derive the root itself.
    // -----------------------------------------------------------------------

    /// Builds a real 5-leaf log so the proofs below have non-trivial paths.
    ///
    /// `corpus()` events are filter fixtures with a flat `sequence: 0` /
    /// genesis `prev_hash`; `append_unsigned_event` enforces the hash chain, so
    /// the sequence and `prev_hash` are stamped here as the appender would.
    fn proof_corpus() -> scp_event_log::EventLog {
        let mut log = scp_event_log::EventLog::new("ctx-proof".to_owned());
        let mut prev_hash = [0u8; 32];
        for (i, mut event) in corpus().into_iter().enumerate() {
            event.sequence = i as u64;
            event.prev_hash = prev_hash;
            scp_event_log::tree::append_unsigned_event(&mut log, &event).unwrap();
            prev_hash = scp_event_log::tree::leaf_hash(&event).unwrap();
        }
        log
    }

    #[test]
    fn inclusion_json_carries_everything_needed_to_recompute_the_root() {
        let log = proof_corpus();
        let root = scp_event_log::tree::root(&log);

        for leaf_index in 0..scp_event_log::tree::event_count(&log) {
            let proof = scp_event_log::proof::prove_inclusion(&log, leaf_index).unwrap();
            let json = inclusion_proof_json(&proof);

            assert_eq!(json["leaf_index"].as_u64(), Some(leaf_index));
            assert_eq!(
                json["leaf_hash"].as_str(),
                Some(hex::encode(proof.leaf_hash).as_str())
            );
            assert_eq!(json["root"].as_str(), Some(hex::encode(root).as_str()));
            let path = json["path"].as_array().expect("path is an array");
            assert_eq!(json["path_length"].as_u64(), Some(path.len() as u64));
            assert_eq!(path.len(), proof.path.len());

            // Rebuild from the JSON alone and re-verify — the off-box path.
            let rebuilt = scp_event_log::proof::InclusionProof {
                leaf_index: json["leaf_index"].as_u64().unwrap(),
                leaf_hash: decode32(json["leaf_hash"].as_str().unwrap()),
                root: decode32(json["root"].as_str().unwrap()),
                path: path
                    .iter()
                    .map(|step| scp_event_log::proof::ProofStep {
                        sibling_hash: decode32(step["sibling_hash"].as_str().unwrap()),
                        direction: match step["direction"].as_str().unwrap() {
                            "left" => scp_event_log::proof::Direction::Left,
                            "right" => scp_event_log::proof::Direction::Right,
                            other => panic!("unknown direction {other:?}"),
                        },
                    })
                    .collect(),
            };
            assert!(
                scp_event_log::proof::verify_inclusion(&rebuilt),
                "leaf {leaf_index}: the shipped JSON must re-verify on its own"
            );
        }
    }

    #[test]
    fn absence_neighbors_ship_their_full_inclusion_proofs() {
        let log = proof_corpus();
        let absent = [0xEEu8; 32];
        let proof = scp_event_log::proof::prove_absence(&log, &absent).unwrap();
        assert!(
            proof.lower.is_some() || proof.upper.is_some(),
            "precondition: at least one bracketing neighbour exists"
        );

        for side in [proof.lower.as_ref(), proof.upper.as_ref()] {
            let json = absence_neighbor_json(side);
            let Some(neighbor) = side else {
                assert!(json.is_null(), "a missing neighbour maps to JSON null");
                continue;
            };
            assert_eq!(json["leaf_index"].as_u64(), Some(neighbor.leaf_index));
            assert_eq!(
                json["leaf_hash"].as_str(),
                Some(hex::encode(neighbor.leaf_hash).as_str())
            );
            // The neighbour's OWN inclusion proof is present and complete —
            // this is what the absence arm used to omit entirely.
            let inclusion = &json["inclusion_proof"];
            assert_eq!(
                inclusion["root"].as_str(),
                Some(hex::encode(proof.root).as_str()),
                "the neighbour must prove against the SAME root the absence answer reports"
            );
            assert!(inclusion["path"].is_array());
            assert_eq!(
                inclusion["leaf_hash"].as_str(),
                Some(hex::encode(neighbor.leaf_hash).as_str())
            );
        }
    }

    fn decode32(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str)
            .expect("hex")
            .try_into()
            .expect("32 bytes")
    }
}
