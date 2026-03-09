//! Provenance attachment at cross-context boundaries.
//!
//! Provides [`attach_provenance`] for automatic provenance tagging when data
//! crosses context boundaries, and [`check_chain_depth`] for enforcing the
//! protocol maximum hop count. Chain path management utilities track the
//! ordered list of intermediary context IDs.
//!
//! See ADR-019 acceptance criteria 2-3, 6.

use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::context::MemoryScope;
use crate::economy::types::Amount;

use super::{
    ContextId, CounterpartyPolicy, DID, DataProvenance, DiscoveryMethod, ProvenanceError,
    SourceType,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Protocol default maximum chain depth (3 hops). Cross-context data flows
/// beyond this limit are rejected to prevent accountability laundering.
///
/// Contexts may override this via `ContextParams::max_chain_depth`, but the
/// effective limit is always clamped to [`PROTOCOL_HARD_MAX_CHAIN_DEPTH`].
///
/// See spec §24.4 and ADR-019.
pub const DEFAULT_MAX_CHAIN_DEPTH: u8 = 3;

/// Protocol hard maximum chain depth (5 hops).
///
/// No context may configure a `max_chain_depth` higher than this value.
/// The effective limit is always
/// `min(context.max_chain_depth.unwrap_or(DEFAULT_MAX_CHAIN_DEPTH), PROTOCOL_HARD_MAX_CHAIN_DEPTH)`.
///
/// This bounds the worst-case amplification factor for cross-context tool
/// call chains regardless of per-context configuration.
pub const PROTOCOL_HARD_MAX_CHAIN_DEPTH: u8 = 5;

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
/// - `counterparty_policy` -- How counterparty DIDs are handled when
///   provenance crosses context boundaries (§7.7.1, §24.3.1).
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
    /// Counterparty privacy policy (§7.7.1, §24.3.1).
    ///
    /// Controls how membership DIDs appear in the provenance record:
    /// - `Full` — real DIDs included.
    /// - `Pseudonymized` — replaced with context-scoped pseudonyms.
    /// - `Redacted` — empty list (default for cross-context export).
    pub counterparty_policy: CounterpartyPolicy,
}

// ---------------------------------------------------------------------------
// PaymentInfo (§24.3.4)
// ---------------------------------------------------------------------------

/// Economic provenance information for cross-context data flows (§24.3.4).
///
/// When a cross-context data flow involves a payment, these fields carry the
/// economic provenance so receiving contexts can see what data cost to produce.
#[derive(Debug, Clone, Default)]
pub struct PaymentInfo {
    /// Cost of producing this data, if any (§19.6).
    pub amount: Option<Amount>,
    /// Payment adapter used (e.g., "lightning", "stripe").
    pub adapter: Option<String>,
    /// Receipt ID for verification (32 bytes).
    pub receipt_id: Option<[u8; 32]>,
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
/// The source context's [`CounterpartyPolicy`] is applied to the counterparties
/// field (§7.7.1, §24.3.1):
/// - `Full` — real membership DIDs are included.
/// - `Pseudonymized` — DIDs are replaced with context-scoped pseudonyms
///   derived from `pseudonym_key` (which MUST be `Some` when the policy is
///   `Pseudonymized`; if `None`, falls back to `Redacted`).
/// - `Redacted` — counterparties is set to an empty list.
///
/// # Arguments
///
/// - `source` -- Source context state at the time of data flow.
/// - `target_context` -- Identifier of the target context receiving the data.
/// - `existing_provenance` -- Provenance already attached to the data from a
///   previous cross-context hop, if any. When `Some`, chain depth is
///   incremented and the chain path is extended.
/// - `pseudonym_key` -- Optional pseudonym derivation key (§9.10.4). Required
///   when `source.counterparty_policy` is `Pseudonymized`.
/// - `payment` -- Optional economic provenance (§24.3.4).
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
    pseudonym_key: Option<&[u8]>,
    payment: Option<&PaymentInfo>,
) -> DataProvenance {
    let (chain_depth, chain_path) = compute_chain(source, existing_provenance);

    let counterparties = apply_counterparty_policy(
        &source.members,
        source.counterparty_policy,
        &source.context_id,
        pseudonym_key,
    );

    DataProvenance {
        source_context: source.context_id.clone(),
        source_type: source.source_type,
        counterparties,
        purpose: source.purpose.clone(),
        discovery_method: source.discovery_method.clone(),
        age: source.data_age,
        memory_scope: source.memory_scope,
        chain_depth,
        chain_path,
        payment_amount: payment.and_then(|p| p.amount),
        payment_adapter: payment.and_then(|p| p.adapter.clone()),
        payment_receipt_id: payment.and_then(|p| p.receipt_id),
    }
}

// ---------------------------------------------------------------------------
// Counterparty policy application (§7.7.1, §24.3.1)
// ---------------------------------------------------------------------------

/// Applies the counterparty policy to a list of member DIDs (§7.7.1).
///
/// - `Full` — returns the DIDs unchanged.
/// - `Pseudonymized` — replaces each DID with a context-scoped pseudonym.
/// - `Redacted` — returns an empty list.
#[must_use]
fn apply_counterparty_policy(
    members: &[DID],
    policy: CounterpartyPolicy,
    context_id: &str,
    pseudonym_key: Option<&[u8]>,
) -> Vec<DID> {
    match policy {
        CounterpartyPolicy::Full => members.to_vec(),
        CounterpartyPolicy::Pseudonymized => {
            let Some(key) = pseudonym_key else {
                // No pseudonym key provided — fall back to redacted for safety.
                return Vec::new();
            };
            members
                .iter()
                .map(|did| pseudonymize_did(did, context_id, key))
                .collect()
        }
        CounterpartyPolicy::Redacted => Vec::new(),
    }
}

/// Derives a context-scoped pseudonym for a DID (§9.10.4).
///
/// `pseudonym = "did:pseudo:" || hex(SHA-256(pseudonym_key || context_id || did_string))`
///
/// The pseudonym is deterministic for the same (key, context, DID) triple,
/// so the same real DID always maps to the same pseudonym within a context.
/// Without the pseudonym key, the mapping is computationally irreversible.
///
/// Each variable-length field is length-prefixed (4-byte big-endian) to
/// prevent domain separation collisions where concatenation of different
/// inputs could produce the same byte sequence.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // String/key lengths never exceed u32
fn pseudonymize_did(did: &DID, context_id: &str, pseudonym_key: &[u8]) -> DID {
    let did_bytes = (*did).as_bytes();
    let mut hasher = Sha256::new();
    hasher.update((pseudonym_key.len() as u32).to_be_bytes());
    hasher.update(pseudonym_key);
    hasher.update((context_id.len() as u32).to_be_bytes());
    hasher.update(context_id.as_bytes());
    hasher.update((did_bytes.len() as u32).to_be_bytes());
    hasher.update(did_bytes);
    let hash = hasher.finalize();
    DID::from(format!("did:pseudo:{}", hex::encode(hash)))
}

// ---------------------------------------------------------------------------
// Provenance store counterparty operations (§24.3.5)
// ---------------------------------------------------------------------------

/// Redacts counterparties from a provenance record (§24.3.5).
///
/// Replaces the `counterparties` field with an empty list. This is a
/// destructive, irreversible operation used when a context's
/// `counterparty_policy` changes to `Redacted` and existing records must
/// be retroactively updated.
pub fn redact_counterparties(provenance: &mut DataProvenance) {
    provenance.counterparties = Vec::new();
}

/// Pseudonymizes counterparties in a provenance record (§24.3.5).
///
/// Replaces real DIDs with context-scoped pseudonyms derived using the
/// provided pseudonym derivation key. This is a one-way operation —
/// the pseudonym key is held only by the source context.
pub fn pseudonymize_counterparties(provenance: &mut DataProvenance, pseudonym_key: &[u8]) {
    let context_id = provenance.source_context.clone();
    provenance.counterparties = provenance
        .counterparties
        .iter()
        .map(|did| pseudonymize_did(did, &context_id, pseudonym_key))
        .collect();
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

/// Computes the effective maximum chain depth for a context.
///
/// The effective limit is `min(context_max.unwrap_or(DEFAULT_MAX_CHAIN_DEPTH), PROTOCOL_HARD_MAX_CHAIN_DEPTH)`.
/// This ensures:
/// - Contexts without an explicit setting use the protocol default (3).
/// - No context can exceed the protocol hard maximum (5).
///
/// # Arguments
///
/// - `context_max_chain_depth` -- The context's configured `max_chain_depth`,
///   or `None` to use the protocol default.
#[must_use]
pub const fn effective_max_chain_depth(context_max_chain_depth: Option<u8>) -> u8 {
    let context_or_default = match context_max_chain_depth {
        Some(v) => v,
        None => DEFAULT_MAX_CHAIN_DEPTH,
    };
    if context_or_default < PROTOCOL_HARD_MAX_CHAIN_DEPTH {
        context_or_default
    } else {
        PROTOCOL_HARD_MAX_CHAIN_DEPTH
    }
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;

    /// Creates a basic [`SourceContextInfo`] for testing.
    ///
    /// Default `counterparty_policy` is `Full` for test convenience (so
    /// existing tests that check counterparty contents continue to work).
    fn make_source(context_id: &str, members: Vec<&str>) -> SourceContextInfo {
        SourceContextInfo {
            context_id: context_id.to_string(),
            source_type: SourceType::Persistent,
            memory_scope: MemoryScope::Full,
            members: members.into_iter().map(DID::from).collect(),
            discovery_method: DiscoveryMethod::None,
            data_age: Duration::from_secs(60),
            purpose: None,
            counterparty_policy: CounterpartyPolicy::Full,
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
            counterparties: vec!["did:dht:z6MkAlice".into()],
            purpose: None,
            discovery_method: DiscoveryMethod::None,
            age: Duration::from_secs(30),
            memory_scope: MemoryScope::Full,
            chain_depth: depth,
            chain_path: path.map(|p| p.into_iter().map(String::from).collect()),
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        }
    }

    // -----------------------------------------------------------------------
    // attach_provenance -- first hop (no existing provenance)
    // -----------------------------------------------------------------------

    #[test]
    fn attach_provenance_first_hop_sets_depth_zero() {
        let source = make_source("ctx-source", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert_eq!(prov.chain_depth, 0);
    }

    #[test]
    fn attach_provenance_first_hop_has_no_chain_path() {
        let source = make_source("ctx-source", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert!(prov.chain_path.is_none());
    }

    #[test]
    fn attach_provenance_populates_source_context_from_source_info() {
        let source = make_source("ctx-origin-abc", vec![]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert_eq!(prov.source_context, "ctx-origin-abc");
    }

    #[test]
    fn attach_provenance_populates_source_type() {
        let mut source = make_source("ctx-src", vec![]);
        source.source_type = SourceType::Ephemeral;
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert_eq!(prov.source_type, SourceType::Ephemeral);
    }

    #[test]
    fn attach_provenance_populates_memory_scope() {
        let mut source = make_source("ctx-src", vec![]);
        source.memory_scope = MemoryScope::Summary;
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

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

        let prov = attach_provenance(&source, &target, None, None, None);

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

        let prov = attach_provenance(&source, &target, None, None, None);

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

        let prov = attach_provenance(&source, &target, None, None, None);

        assert_eq!(prov.age, Duration::from_secs(300));
    }

    #[test]
    fn attach_provenance_populates_purpose_when_provided() {
        let mut source = make_source("ctx-src", vec![]);
        source.purpose = Some("recipe sharing".to_string());
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert_eq!(prov.purpose.as_deref(), Some("recipe sharing"));
    }

    #[test]
    fn attach_provenance_purpose_none_when_not_provided() {
        let source = make_source("ctx-src", vec![]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

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

        let prov = attach_provenance(&source, &target, Some(&existing), None, None);

        assert_eq!(prov.chain_depth, 1);
    }

    #[test]
    fn attach_provenance_increments_depth_from_deeper_chain() {
        let source = make_source("ctx-hop-3", vec!["did:dht:z6MkCharlie"]);
        let target = "ctx-target".to_string();
        let existing =
            make_provenance_with_chain("ctx-hop-2", 2, Some(vec!["ctx-hop-1", "ctx-hop-2"]));

        let prov = attach_provenance(&source, &target, Some(&existing), None, None);

        assert_eq!(prov.chain_depth, 3);
    }

    #[test]
    fn attach_provenance_saturates_at_u8_max() {
        let source = make_source("ctx-overflow", vec![]);
        let target = "ctx-target".to_string();
        let existing = make_provenance_with_chain("ctx-prev", u8::MAX, None);

        let prov = attach_provenance(&source, &target, Some(&existing), None, None);

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

        let prov = attach_provenance(&source, &target, Some(&existing), None, None);

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

        let prov = attach_provenance(&source, &target, Some(&existing), None, None);

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
        let prov_1 = attach_provenance(&source_1, &target, Some(&prov_0), None, None);
        assert_eq!(prov_1.chain_depth, 1);

        // Second hop: hop1 -> hop2
        let source_2 = make_source("ctx-hop-2", vec!["did:dht:z6MkBob"]);
        let prov_2 = attach_provenance(&source_2, &target, Some(&prov_1), None, None);
        assert_eq!(prov_2.chain_depth, 2);

        // Third hop: hop2 -> hop3
        let source_3 = make_source("ctx-hop-3", vec!["did:dht:z6MkCharlie"]);
        let prov_3 = attach_provenance(&source_3, &target, Some(&prov_2), None, None);
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

        let prov = attach_provenance(&source, &target, None, None, None);

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

        let prov = attach_provenance(&source, &target, None, None, None);

        assert!(prov.counterparties.is_empty());
    }

    #[test]
    fn attach_provenance_single_member_counterparty() {
        let source = make_source("ctx-solo", vec!["did:dht:z6MkSolo"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert_eq!(prov.counterparties, vec!["did:dht:z6MkSolo".to_string()]);
    }

    #[test]
    fn attach_provenance_uses_current_membership_not_existing_counterparties() {
        let source = make_source("ctx-new", vec!["did:dht:z6MkNew1", "did:dht:z6MkNew2"]);
        let target = "ctx-target".to_string();
        let existing = make_provenance_with_chain("ctx-prev", 0, None);

        let prov = attach_provenance(&source, &target, Some(&existing), None, None);

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
    // DEFAULT_MAX_CHAIN_DEPTH / PROTOCOL_HARD_MAX_CHAIN_DEPTH
    // -----------------------------------------------------------------------

    #[test]
    fn default_max_chain_depth_is_three() {
        assert_eq!(DEFAULT_MAX_CHAIN_DEPTH, 3);
    }

    #[test]
    fn protocol_hard_max_chain_depth_is_five() {
        assert_eq!(PROTOCOL_HARD_MAX_CHAIN_DEPTH, 5);
    }

    #[test]
    fn default_does_not_exceed_hard_max() {
        assert!(DEFAULT_MAX_CHAIN_DEPTH <= PROTOCOL_HARD_MAX_CHAIN_DEPTH);
    }

    // -----------------------------------------------------------------------
    // effective_max_chain_depth
    // -----------------------------------------------------------------------

    #[test]
    fn effective_max_uses_default_when_none() {
        assert_eq!(effective_max_chain_depth(None), DEFAULT_MAX_CHAIN_DEPTH);
    }

    #[test]
    fn effective_max_uses_context_value_when_within_hard_max() {
        assert_eq!(effective_max_chain_depth(Some(4)), 4);
    }

    #[test]
    fn effective_max_clamps_to_hard_max_when_context_exceeds() {
        assert_eq!(
            effective_max_chain_depth(Some(10)),
            PROTOCOL_HARD_MAX_CHAIN_DEPTH
        );
    }

    #[test]
    fn effective_max_allows_zero() {
        assert_eq!(effective_max_chain_depth(Some(0)), 0);
    }

    #[test]
    fn effective_max_allows_exact_hard_max() {
        assert_eq!(
            effective_max_chain_depth(Some(PROTOCOL_HARD_MAX_CHAIN_DEPTH)),
            PROTOCOL_HARD_MAX_CHAIN_DEPTH
        );
    }

    #[test]
    fn effective_max_allows_one() {
        assert_eq!(effective_max_chain_depth(Some(1)), 1);
    }

    // -----------------------------------------------------------------------
    // Integration: attach then check
    // -----------------------------------------------------------------------

    #[test]
    fn attach_then_check_first_hop_passes() {
        let source = make_source("ctx-src", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);
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
            prev = Some(attach_provenance(
                &source,
                &target,
                prev.as_ref(),
                None,
                None,
            ));
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
            prev = Some(attach_provenance(
                &source,
                &target,
                prev.as_ref(),
                None,
                None,
            ));
        }

        let final_prov = prev.unwrap();
        assert_eq!(final_prov.chain_depth, DEFAULT_MAX_CHAIN_DEPTH);

        // One more hop pushes past the limit
        let source_extra = make_source("ctx-one-too-many", vec![]);
        let target = "ctx-final".to_string();
        let over_limit = attach_provenance(&source_extra, &target, Some(&final_prov), None, None);

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
            members: vec!["did:dht:z6MkA".into(), "did:dht:z6MkB".into()],
            discovery_method: DiscoveryMethod::Registry("ctx-reg".to_string()),
            data_age: Duration::from_secs(120),
            purpose: Some("testing".to_string()),
            counterparty_policy: CounterpartyPolicy::Full,
        };

        let target = "ctx-target".to_string();
        let prov = attach_provenance(&info, &target, None, None, None);

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

        let prov = attach_provenance(&source, &target, None, None, None);
        let prov_for_source = prov.clone();
        let prov_for_target = prov;

        assert_eq!(
            prov_for_source.source_context,
            prov_for_target.source_context
        );
        assert_eq!(prov_for_source.chain_depth, prov_for_target.chain_depth);
    }

    // -----------------------------------------------------------------------
    // CounterpartyPolicy application (§7.7.1, §24.3.1)
    // -----------------------------------------------------------------------

    #[test]
    fn counterparty_policy_full_includes_real_dids() {
        let mut source = make_source("ctx-src", vec!["did:dht:z6MkAlice", "did:dht:z6MkBob"]);
        source.counterparty_policy = CounterpartyPolicy::Full;
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert_eq!(prov.counterparties.len(), 2);
        assert_eq!(prov.counterparties[0], "did:dht:z6MkAlice");
        assert_eq!(prov.counterparties[1], "did:dht:z6MkBob");
    }

    #[test]
    fn counterparty_policy_redacted_produces_empty_list() {
        let mut source = make_source("ctx-src", vec!["did:dht:z6MkAlice", "did:dht:z6MkBob"]);
        source.counterparty_policy = CounterpartyPolicy::Redacted;
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert!(
            prov.counterparties.is_empty(),
            "redacted policy must produce empty counterparties"
        );
    }

    #[test]
    fn counterparty_policy_pseudonymized_replaces_dids() {
        let mut source = make_source("ctx-src", vec!["did:dht:z6MkAlice", "did:dht:z6MkBob"]);
        source.counterparty_policy = CounterpartyPolicy::Pseudonymized;
        let target = "ctx-target".to_string();
        let pseudonym_key = b"test-pseudonym-key-32-bytes!!!!!";

        let prov = attach_provenance(&source, &target, None, Some(pseudonym_key.as_slice()), None);

        assert_eq!(prov.counterparties.len(), 2);
        // Pseudonyms must be deterministic
        for cp in &prov.counterparties {
            assert!(
                (*cp).starts_with("did:pseudo:"),
                "pseudonymized DID must start with did:pseudo:"
            );
        }
        // Must differ from original DIDs
        assert_ne!(prov.counterparties[0], DID::from("did:dht:z6MkAlice"));
        assert_ne!(prov.counterparties[1], DID::from("did:dht:z6MkBob"));
    }

    #[test]
    fn counterparty_policy_pseudonymized_deterministic() {
        let mut source = make_source("ctx-src", vec!["did:dht:z6MkAlice"]);
        source.counterparty_policy = CounterpartyPolicy::Pseudonymized;
        let target = "ctx-target".to_string();
        let key = b"test-key";

        let prov1 = attach_provenance(&source, &target, None, Some(key.as_slice()), None);
        let prov2 = attach_provenance(&source, &target, None, Some(key.as_slice()), None);

        assert_eq!(
            prov1.counterparties, prov2.counterparties,
            "same inputs must produce same pseudonyms"
        );
    }

    #[test]
    fn counterparty_policy_pseudonymized_no_key_falls_back_to_redacted() {
        let mut source = make_source("ctx-src", vec!["did:dht:z6MkAlice"]);
        source.counterparty_policy = CounterpartyPolicy::Pseudonymized;
        let target = "ctx-target".to_string();

        // No pseudonym key provided — should produce empty list
        let prov = attach_provenance(&source, &target, None, None, None);

        assert!(
            prov.counterparties.is_empty(),
            "pseudonymized without key must fall back to redacted"
        );
    }

    #[test]
    fn counterparty_policy_pseudonymized_differs_by_context() {
        let key = b"shared-key";

        let mut source_a = make_source("ctx-a", vec!["did:dht:z6MkAlice"]);
        source_a.counterparty_policy = CounterpartyPolicy::Pseudonymized;

        let mut source_b = make_source("ctx-b", vec!["did:dht:z6MkAlice"]);
        source_b.counterparty_policy = CounterpartyPolicy::Pseudonymized;

        let target = "ctx-target".to_string();

        let prov_a = attach_provenance(&source_a, &target, None, Some(key.as_slice()), None);
        let prov_b = attach_provenance(&source_b, &target, None, Some(key.as_slice()), None);

        assert_ne!(
            prov_a.counterparties[0], prov_b.counterparties[0],
            "same DID in different contexts must produce different pseudonyms"
        );
    }

    // -----------------------------------------------------------------------
    // Provenance store counterparty operations (§24.3.5)
    // -----------------------------------------------------------------------

    #[test]
    fn redact_counterparties_clears_list() {
        let mut prov = make_provenance_with_chain("ctx-src", 0, None);
        assert!(!prov.counterparties.is_empty());

        redact_counterparties(&mut prov);

        assert!(prov.counterparties.is_empty());
    }

    #[test]
    fn pseudonymize_counterparties_replaces_dids() {
        let mut prov = make_provenance_with_chain("ctx-src", 0, None);
        let original_dids = prov.counterparties.clone();
        let key = b"pseudonym-key";

        pseudonymize_counterparties(&mut prov, key);

        assert_eq!(prov.counterparties.len(), original_dids.len());
        for (i, cp) in prov.counterparties.iter().enumerate() {
            assert!((*cp).starts_with("did:pseudo:"));
            assert_ne!(cp, &original_dids[i]);
        }
    }

    // -----------------------------------------------------------------------
    // Economic provenance (§24.3.4)
    // -----------------------------------------------------------------------

    #[test]
    fn attach_provenance_with_payment_info() {
        let source = make_source("ctx-src", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();
        let payment = PaymentInfo {
            amount: Some(Amount::new(1000)),
            adapter: Some("lightning".to_string()),
            receipt_id: Some([0xAA; 32]),
        };

        let prov = attach_provenance(&source, &target, None, None, Some(&payment));

        assert_eq!(prov.payment_amount, Some(Amount::new(1000)));
        assert_eq!(prov.payment_adapter.as_deref(), Some("lightning"));
        assert_eq!(prov.payment_receipt_id, Some([0xAA; 32]));
    }

    #[test]
    fn attach_provenance_without_payment_info() {
        let source = make_source("ctx-src", vec!["did:dht:z6MkAlice"]);
        let target = "ctx-target".to_string();

        let prov = attach_provenance(&source, &target, None, None, None);

        assert!(prov.payment_amount.is_none());
        assert!(prov.payment_adapter.is_none());
        assert!(prov.payment_receipt_id.is_none());
    }

    // -----------------------------------------------------------------------
    // CounterpartyPolicy tests
    // -----------------------------------------------------------------------

    #[test]
    fn counterparty_policy_default_is_redacted() {
        assert_eq!(CounterpartyPolicy::default(), CounterpartyPolicy::Redacted);
    }

    #[test]
    fn counterparty_policy_serialization_roundtrip() {
        let policies = [
            CounterpartyPolicy::Full,
            CounterpartyPolicy::Pseudonymized,
            CounterpartyPolicy::Redacted,
        ];
        for policy in &policies {
            let json = serde_json::to_string(policy).unwrap();
            let decoded: CounterpartyPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, &decoded);
        }
    }

    #[test]
    fn counterparty_policy_variants_distinct() {
        assert_ne!(CounterpartyPolicy::Full, CounterpartyPolicy::Pseudonymized);
        assert_ne!(CounterpartyPolicy::Full, CounterpartyPolicy::Redacted);
        assert_ne!(
            CounterpartyPolicy::Pseudonymized,
            CounterpartyPolicy::Redacted
        );
    }
}
