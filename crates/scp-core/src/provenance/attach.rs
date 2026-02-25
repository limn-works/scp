//! Provenance attachment at cross-context boundaries.
//!
//! Provides [`attach_provenance`] for automatic provenance tagging when data
//! crosses context boundaries, and [`check_chain_depth`] for enforcing the
//! protocol maximum hop count. Chain path management utilities track the
//! ordered list of intermediary context IDs.
//!
//! See ADR-019 acceptance criteria 2-3, 6.

use std::time::Duration;

use crate::context::MemoryScope;

use super::{ContextId, DID, DataProvenance, DiscoveryMethod, ProvenanceError, SourceType};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Protocol default maximum chain depth (3 hops). Cross-context data flows
/// beyond this limit are rejected to prevent accountability laundering.
///
/// See ADR-019: "The protocol default of 3 hops bounds this."
pub const DEFAULT_MAX_CHAIN_DEPTH: u8 = 3;

// ---------------------------------------------------------------------------
// SourceContextInfo
// ---------------------------------------------------------------------------

/// Provides the source context state needed for provenance attachment.
///
/// Accepts all context state required by [`attach_provenance`] without
/// depending on a full `ContextHandle`. Callers construct this from whatever
/// context representation they use.
///
/// # Fields
///
/// - `context_id` -- Identifier of the source context.
/// - `source_type` -- Current data availability status of the source context.
/// - `memory_scope` -- Memory scope (Ephemeral, Summary, Full) of the source.
/// - `members` -- Current membership roster DIDs at the time of data flow.
/// - `discovery_method` -- How the source was discovered by the receiver.
/// - `data_age` -- Age of the data at the time provenance is being attached.
/// - `purpose` -- Optional human-readable description of why this data is
///   being shared cross-context.
#[derive(Debug, Clone)]
pub struct SourceContextInfo {
    /// Identifier of the source context.
    pub context_id: ContextId,
    /// Current data availability status of the source context.
    pub source_type: SourceType,
    /// Memory scope of the source context.
    pub memory_scope: MemoryScope,
    /// Current membership roster DIDs at the time of data flow.
    pub members: Vec<DID>,
    /// How the data source was discovered.
    pub discovery_method: DiscoveryMethod,
    /// Age of the data at the time provenance is attached.
    pub data_age: Duration,
    /// Optional purpose description for this cross-context data flow.
    pub purpose: Option<String>,
}

// ---------------------------------------------------------------------------
// attach_provenance
// ---------------------------------------------------------------------------

/// Attaches provenance metadata when data crosses a context boundary.
///
/// Called automatically by the protocol on cross-context tool interface calls
/// and structured messages. Populates all [`DataProvenance`] fields from the
/// source context state and increments `chain_depth` from any existing
/// provenance on the data.
///
/// # Arguments
///
/// - `source` -- Source context state at the time of data flow.
/// - `target_context` -- Identifier of the target context receiving the data.
/// - `existing_provenance` -- Provenance already attached to the data from a
///   previous cross-context hop, if any. When `Some`, chain depth is
///   incremented and the chain path is extended.
///
/// # Returns
///
/// A new [`DataProvenance`] recording the data's origin and transit history.
///
/// # Chain depth and chain path
///
/// - When `existing_provenance` is `None`, `chain_depth` starts at 0 and
///   `chain_path` is `None` (first hop, no intermediaries).
/// - When `existing_provenance` is `Some`, `chain_depth` is incremented by 1
///   and `chain_path` records the ordered list of intermediary context IDs
///   (the previous source contexts the data has traversed).
#[must_use]
pub fn attach_provenance(
    source: &SourceContextInfo,
    _target_context: &ContextId,
    existing_provenance: Option<&DataProvenance>,
) -> DataProvenance {
    let (chain_depth, chain_path) = compute_chain(source, existing_provenance);

    DataProvenance {
        source_context: source.context_id.clone(),
        source_type: source.source_type,
        counterparties: source.members.clone(),
        purpose: source.purpose.clone(),
        discovery_method: source.discovery_method.clone(),
        age: source.data_age,
        memory_scope: source.memory_scope,
        chain_depth,
        chain_path,
    }
}

// ---------------------------------------------------------------------------
// check_chain_depth
// ---------------------------------------------------------------------------

/// Checks whether the provenance chain depth is within the allowed limit.
///
/// The protocol default maximum is [`DEFAULT_MAX_CHAIN_DEPTH`] (3 hops). At
/// the maximum depth, data cannot trigger further cross-context calls. This
/// prevents accountability laundering -- data traversing enough contexts that
/// its origin becomes meaningless.
///
/// # Arguments
///
/// - `provenance` -- The provenance record to check.
/// - `max_depth` -- Maximum allowed chain depth. Use
///   [`DEFAULT_MAX_CHAIN_DEPTH`] for the protocol default.
///
/// # Errors
///
/// Returns [`ProvenanceError::ChainDepthExceeded`] if the provenance's chain
/// depth exceeds `max_depth`.
pub const fn check_chain_depth(
    provenance: &DataProvenance,
    max_depth: u8,
) -> Result<(), ProvenanceError> {
    if provenance.chain_depth > max_depth {
        return Err(ProvenanceError::ChainDepthExceeded {
            depth: provenance.chain_depth,
            max_depth,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes chain depth and chain path from existing provenance.
///
/// When `existing` is `None`, this is the first hop: depth 0, no path.
/// When `existing` is `Some`, depth is incremented by 1 and the previous
/// source context is appended to the chain path.
fn compute_chain(
    source: &SourceContextInfo,
    existing: Option<&DataProvenance>,
) -> (u8, Option<Vec<ContextId>>) {
    let Some(prev) = existing else {
        // First cross-context hop: no chain history
        return (0, None);
    };

    let new_depth = prev.chain_depth.saturating_add(1);

    // Build the chain path: take the previous path (if any), then append the
    // previous source context to record the intermediary.
    let mut path = prev.chain_path.clone().unwrap_or_default();
    path.push(source.context_id.clone());

    (new_depth, Some(path))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Creates a basic [`SourceContextInfo`] for testing.
    fn make_source(context_id: &str, members: Vec<&str>) -> SourceContextInfo {
        SourceContextInfo {
            context_id: context_id.to_string(),
            source_type: SourceType::Persistent,
            memory_scope: MemoryScope::Full,
            members: members.into_iter().map(String::from).collect(),
            discovery_method: DiscoveryMethod::None,
            data_age: Duration::from_secs(60),
            purpose: None,
        }
    }

    /// Creates a [`DataProvenance`] with the given chain state for testing.
    fn make_provenance_with_chain(
        source_ctx: &str,
        depth: u8,
        path: Option<Vec<&str>>,
    ) -> DataProvenance {
        DataProvenance {
            source_context: source_ctx.to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec!["did:dht:z6MkAlice".to_string()],
            purpose: None,
            discovery_method: DiscoveryMethod::None,
            age: Duration::from_secs(30),
            memory_scope: MemoryScope::Full,
            chain_depth: depth,
            chain_path: path.map(|p| p.into_iter().map(String::from).collect()),
        }
    }

    // -----------------------------------------------------------------------
    // attach_provenance -- first hop (no existing provenance)
    // -----------------------------------------------------------------------

    #[test]
    fn attach_provenance_first_hop_sets_depth_zero() {
        let source = make_source("ctx-source", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(prov.chain_depth, 0);
    }

    #[test]
    fn attach_provenance_first_hop_has_no_chain_path() {
        let source = make_source("ctx-source", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert!(prov.chain_path.is_none());
    }

    #[test]
    fn attach_provenance_populates_source_context_from_source_info() {
        let source = make_source("ctx-origin-abc", vec![]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(prov.source_context, "ctx-origin-abc");
    }

    #[test]
    fn attach_provenance_populates_source_type() {
        let mut source = make_source("ctx-src", vec![]);
        source.source_type = SourceType::Ephemeral;
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(prov.source_type, SourceType::Ephemeral);
    }

    #[test]
    fn attach_provenance_populates_memory_scope() {
        let mut source = make_source("ctx-src", vec![]);
        source.memory_scope = MemoryScope::Summary;
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(prov.memory_scope, MemoryScope::Summary);
    }

    #[test]
    fn attach_provenance_populates_counterparties_from_membership() {
        let source = make_source(
            "ctx-src",
            vec![
                "did:dht:z6MkAlice",
                "did:dht:z6MkBob",
                "did:dht:z6MkCharlie",
            ],
        );
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(prov.counterparties.len(), 3);
        assert_eq!(prov.counterparties[0], "did:dht:z6MkAlice");
        assert_eq!(prov.counterparties[1], "did:dht:z6MkBob");
        assert_eq!(prov.counterparties[2], "did:dht:z6MkCharlie");
    }

    #[test]
    fn attach_provenance_populates_discovery_method() {
        let mut source = make_source("ctx-src", vec![]);
        source.discovery_method = DiscoveryMethod::SharedContext("ctx-shared".to_string());
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(
            prov.discovery_method,
            DiscoveryMethod::SharedContext("ctx-shared".to_string())
        );
    }

    #[test]
    fn attach_provenance_populates_age() {
        let mut source = make_source("ctx-src", vec![]);
        source.data_age = Duration::from_secs(300);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(prov.age, Duration::from_secs(300));
    }

    #[test]
    fn attach_provenance_populates_purpose_when_provided() {
        let mut source = make_source("ctx-src", vec![]);
        source.purpose = Some("recipe sharing".to_string());
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(prov.purpose.as_deref(), Some("recipe sharing"));
    }

    #[test]
    fn attach_provenance_purpose_none_when_not_provided() {
        let source = make_source("ctx-src", vec![]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert!(prov.purpose.is_none());
    }

    // -----------------------------------------------------------------------
    // attach_provenance -- chain depth incrementing
    // -----------------------------------------------------------------------

    #[test]
    fn attach_provenance_increments_chain_depth_from_existing() {
        let source = make_source("ctx-hop-2", vec!["did:dht:z6MkBob"]);
        let target = "ctx-target".to_string();
        let existing = make_provenance_with_chain("ctx-hop-1", 0, None);

        let prov = attach_provenance(&source, &target, Some(&existing));

        assert_eq!(prov.chain_depth, 1);
    }

    #[test]
    fn attach_provenance_increments_depth_from_deeper_chain() {
        let source = make_source("ctx-hop-3", vec!["did:dht:z6MkCharlie"]);
        let target = "ctx-target".to_string();
        let existing =
            make_provenance_with_chain("ctx-hop-2", 2, Some(vec!["ctx-hop-1", "ctx-hop-2"]));

        let prov = attach_provenance(&source, &target, Some(&existing));

        assert_eq!(prov.chain_depth, 3);
    }

    #[test]
    fn attach_provenance_saturates_at_u8_max() {
        let source = make_source("ctx-overflow", vec![]);
        let target = "ctx-target".to_string();
        let existing = make_provenance_with_chain("ctx-prev", u8::MAX, None);

        let prov = attach_provenance(&source, &target, Some(&existing));

        assert_eq!(prov.chain_depth, u8::MAX);
    }

    // -----------------------------------------------------------------------
    // attach_provenance -- chain path recording
    // -----------------------------------------------------------------------

    #[test]
    fn attach_provenance_records_chain_path_on_second_hop() {
        let source = make_source("ctx-hop-2", vec!["did:dht:z6MkBob"]);
        let target = "ctx-target".to_string();
        let existing = make_provenance_with_chain("ctx-origin", 0, None);

        let prov = attach_provenance(&source, &target, Some(&existing));

        assert!(prov.chain_path.is_some());
        let path = prov.chain_path.unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path[0], "ctx-hop-2");
    }

    #[test]
    fn attach_provenance_extends_existing_chain_path() {
        let source = make_source("ctx-hop-3", vec![]);
        let target = "ctx-target".to_string();
        let existing = make_provenance_with_chain("ctx-hop-2", 1, Some(vec!["ctx-hop-1"]));

        let prov = attach_provenance(&source, &target, Some(&existing));

        let path = prov.chain_path.as_ref().unwrap();
        assert_eq!(path.len(), 2);
        assert_eq!(path[0], "ctx-hop-1");
        assert_eq!(path[1], "ctx-hop-3");
    }

    #[test]
    fn attach_provenance_chain_path_records_full_traversal() {
        // Simulate 3 hops: origin -> hop1 -> hop2 -> target
        let source_1 = make_source("ctx-hop-1", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        // First hop: origin -> hop1
        let prov_0 = make_provenance_with_chain("ctx-origin", 0, None);
        let prov_1 = attach_provenance(&source_1, &target, Some(&prov_0));
        assert_eq!(prov_1.chain_depth, 1);

        // Second hop: hop1 -> hop2
        let source_2 = make_source("ctx-hop-2", vec!["did:dht:z6MkBob"]);
        let prov_2 = attach_provenance(&source_2, &target, Some(&prov_1));
        assert_eq!(prov_2.chain_depth, 2);

        // Third hop: hop2 -> hop3
        let source_3 = make_source("ctx-hop-3", vec!["did:dht:z6MkCharlie"]);
        let prov_3 = attach_provenance(&source_3, &target, Some(&prov_2));
        assert_eq!(prov_3.chain_depth, 3);

        let path = prov_3.chain_path.as_ref().unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], "ctx-hop-1");
        assert_eq!(path[1], "ctx-hop-2");
        assert_eq!(path[2], "ctx-hop-3");
    }

    #[test]
    fn attach_provenance_no_chain_path_for_first_hop() {
        let source = make_source("ctx-origin", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert!(
            prov.chain_path.is_none(),
            "first hop should not have chain_path"
        );
    }

    // -----------------------------------------------------------------------
    // attach_provenance -- counterparty population
    // -----------------------------------------------------------------------

    #[test]
    fn attach_provenance_empty_membership_produces_empty_counterparties() {
        let source = make_source("ctx-empty", vec![]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert!(prov.counterparties.is_empty());
    }

    #[test]
    fn attach_provenance_single_member_counterparty() {
        let source = make_source("ctx-solo", vec!["did:dht:z6MkSolo"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);

        assert_eq!(prov.counterparties, vec!["did:dht:z6MkSolo".to_string()]);
    }

    #[test]
    fn attach_provenance_uses_current_membership_not_existing_counterparties() {
        let source = make_source("ctx-new", vec!["did:dht:z6MkNew1", "did:dht:z6MkNew2"]);
        let target = "ctx-target".to_string();
        let existing = make_provenance_with_chain("ctx-prev", 0, None);

        let prov = attach_provenance(&source, &target, Some(&existing));

        // Counterparties should come from the current source, not from existing provenance
        assert_eq!(prov.counterparties.len(), 2);
        assert_eq!(prov.counterparties[0], "did:dht:z6MkNew1");
        assert_eq!(prov.counterparties[1], "did:dht:z6MkNew2");
    }

    // -----------------------------------------------------------------------
    // check_chain_depth
    // -----------------------------------------------------------------------

    #[test]
    fn check_chain_depth_allows_zero_depth() {
        let prov = make_provenance_with_chain("ctx-src", 0, None);

        let result = check_chain_depth(&prov, DEFAULT_MAX_CHAIN_DEPTH);

        assert!(result.is_ok());
    }

    #[test]
    fn check_chain_depth_allows_depth_within_limit() {
        let prov = make_provenance_with_chain("ctx-src", 2, Some(vec!["ctx-1", "ctx-2"]));

        let result = check_chain_depth(&prov, DEFAULT_MAX_CHAIN_DEPTH);

        assert!(result.is_ok());
    }

    #[test]
    fn check_chain_depth_allows_depth_at_exact_limit() {
        let prov = make_provenance_with_chain("ctx-src", 3, Some(vec!["ctx-1", "ctx-2", "ctx-3"]));

        let result = check_chain_depth(&prov, DEFAULT_MAX_CHAIN_DEPTH);

        assert!(result.is_ok());
    }

    #[test]
    fn check_chain_depth_rejects_depth_exceeding_limit() {
        let prov = make_provenance_with_chain(
            "ctx-src",
            4,
            Some(vec!["ctx-1", "ctx-2", "ctx-3", "ctx-4"]),
        );

        let result = check_chain_depth(&prov, DEFAULT_MAX_CHAIN_DEPTH);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ProvenanceError::ChainDepthExceeded { depth, max_depth } => {
                assert_eq!(depth, 4);
                assert_eq!(max_depth, 3);
            }
        }
    }

    #[test]
    fn check_chain_depth_with_custom_max_depth() {
        let prov = make_provenance_with_chain("ctx-src", 2, Some(vec!["ctx-1", "ctx-2"]));

        // Custom max of 1 should reject depth 2
        let result = check_chain_depth(&prov, 1);

        assert!(result.is_err());
    }

    #[test]
    fn check_chain_depth_custom_max_allows_within_limit() {
        let prov = make_provenance_with_chain("ctx-src", 5, None);

        // Custom max of 10 should allow depth 5
        let result = check_chain_depth(&prov, 10);

        assert!(result.is_ok());
    }

    #[test]
    fn check_chain_depth_zero_max_rejects_any_depth() {
        let prov = make_provenance_with_chain("ctx-src", 1, Some(vec!["ctx-1"]));

        let result = check_chain_depth(&prov, 0);

        assert!(result.is_err());
    }

    #[test]
    fn check_chain_depth_zero_max_allows_depth_zero() {
        let prov = make_provenance_with_chain("ctx-src", 0, None);

        let result = check_chain_depth(&prov, 0);

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // DEFAULT_MAX_CHAIN_DEPTH
    // -----------------------------------------------------------------------

    #[test]
    fn default_max_chain_depth_is_three() {
        assert_eq!(DEFAULT_MAX_CHAIN_DEPTH, 3);
    }

    // -----------------------------------------------------------------------
    // Integration: attach then check
    // -----------------------------------------------------------------------

    #[test]
    fn attach_then_check_first_hop_passes() {
        let source = make_source("ctx-src", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);
        let result = check_chain_depth(&prov, DEFAULT_MAX_CHAIN_DEPTH);

        assert!(result.is_ok());
    }

    #[test]
    fn attach_chain_to_max_depth_then_check_passes() {
        // Build a chain of exactly DEFAULT_MAX_CHAIN_DEPTH hops
        let mut prev: Option<DataProvenance> = None;
        for i in 0..DEFAULT_MAX_CHAIN_DEPTH {
            let ctx_name = format!("ctx-hop-{i}");
            let source = make_source(&ctx_name, vec!["did:dht:z6MkMember"]);
            let target = "ctx-final".to_string();
            prev = Some(attach_provenance(&source, &target, prev.as_ref()));
        }

        let final_prov = prev.unwrap();
        assert_eq!(final_prov.chain_depth, DEFAULT_MAX_CHAIN_DEPTH - 1);
        assert!(check_chain_depth(&final_prov, DEFAULT_MAX_CHAIN_DEPTH).is_ok());
    }

    #[test]
    fn attach_chain_beyond_max_depth_then_check_fails() {
        // Build a chain one hop beyond DEFAULT_MAX_CHAIN_DEPTH
        let mut prev: Option<DataProvenance> = None;
        for i in 0..=DEFAULT_MAX_CHAIN_DEPTH {
            let ctx_name = format!("ctx-hop-{i}");
            let source = make_source(&ctx_name, vec!["did:dht:z6MkMember"]);
            let target = "ctx-final".to_string();
            prev = Some(attach_provenance(&source, &target, prev.as_ref()));
        }

        let final_prov = prev.unwrap();
        assert_eq!(final_prov.chain_depth, DEFAULT_MAX_CHAIN_DEPTH);

        // One more hop pushes past the limit
        let source_extra = make_source("ctx-one-too-many", vec![]);
        let target = "ctx-final".to_string();
        let over_limit = attach_provenance(&source_extra, &target, Some(&final_prov));

        assert!(check_chain_depth(&over_limit, DEFAULT_MAX_CHAIN_DEPTH).is_err());
    }

    // -----------------------------------------------------------------------
    // SourceContextInfo construction
    // -----------------------------------------------------------------------

    #[test]
    fn source_context_info_all_fields_populated() {
        let info = SourceContextInfo {
            context_id: "ctx-full".to_string(),
            source_type: SourceType::Summary,
            memory_scope: MemoryScope::Ephemeral,
            members: vec!["did:dht:z6MkA".to_string(), "did:dht:z6MkB".to_string()],
            discovery_method: DiscoveryMethod::Registry("ctx-reg".to_string()),
            data_age: Duration::from_secs(120),
            purpose: Some("testing".to_string()),
        };

        let target = "ctx-target".to_string();
        let prov = attach_provenance(&info, &target, None);

        assert_eq!(prov.source_context, "ctx-full");
        assert_eq!(prov.source_type, SourceType::Summary);
        assert_eq!(prov.memory_scope, MemoryScope::Ephemeral);
        assert_eq!(prov.counterparties.len(), 2);
        assert_eq!(
            prov.discovery_method,
            DiscoveryMethod::Registry("ctx-reg".to_string())
        );
        assert_eq!(prov.age, Duration::from_secs(120));
        assert_eq!(prov.purpose.as_deref(), Some("testing"));
    }

    // -----------------------------------------------------------------------
    // Provenance recorded in both contexts
    // -----------------------------------------------------------------------

    #[test]
    fn attach_provenance_result_is_independent_of_target_for_recording() {
        // The same provenance should be recordable in both source and target
        // event logs. This test verifies that the returned DataProvenance is a
        // self-contained value that can be cloned for dual recording.
        let source = make_source("ctx-src", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None);
        let prov_for_source = prov.clone();
        let prov_for_target = prov;

        assert_eq!(
            prov_for_source.source_context,
            prov_for_target.source_context
        );
        assert_eq!(prov_for_source.chain_depth, prov_for_target.chain_depth);
    }
}
