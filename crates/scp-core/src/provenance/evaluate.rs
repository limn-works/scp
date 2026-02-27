//! Provenance quality evaluation logic.
//!
//! Provides [`evaluate_quality`] for mapping a [`DataProvenance`] record to a
//! [`ProvenanceQuality`] tier, and [`update_source_type`] for updating the
//! source type when the source context's state changes.
//!
//! See ADR-019 acceptance criteria 4-5, 8.

use super::{DataProvenance, ProvenanceQuality, SourceType};

// ---------------------------------------------------------------------------
// SourceContextState
// ---------------------------------------------------------------------------

/// Represents the current operational state of a source context for provenance
/// evaluation purposes.
///
/// This reflects the *current* state of the context, which may differ from its
/// state at the time provenance was originally generated. Provenance quality
/// is evaluated against the current state, not the historical state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceContextState {
    /// Source context is persistent and still active — data can be independently
    /// verified against the source context's event log.
    Active,
    /// Source context closed with summary scope. The `summary_verified` field
    /// tracks whether the summary has been verified against the event log.
    ClosedWithSummary {
        /// Whether the summary has been verified against the source event log.
        summary_verified: bool,
    },
    /// Source context was ephemeral — keys have been destroyed.
    ClosedEphemeral,
    /// Source context state cannot be determined. Data was introduced without
    /// protocol-level origin tracking.
    Unknown,
}

// ---------------------------------------------------------------------------
// evaluate_quality
// ---------------------------------------------------------------------------

/// Evaluates the provenance quality tier for data based on its provenance
/// record and the current state of its source context.
///
/// # Quality tiers (highest to lowest)
///
/// - [`ProvenanceQuality::PersistentVerifiable`] — source context is persistent
///   and still active.
/// - [`ProvenanceQuality::SummaryVerified`] — source context closed with a
///   verified summary.
/// - [`ProvenanceQuality::EphemeralKnownParties`] — source context was
///   ephemeral, keys destroyed, but counterparties are known.
/// - [`ProvenanceQuality::NoProvenance`] — no protocol-level origin tracking.
///   This is the lowest tier, not an error (ADR-019 criterion 8).
///
/// # Arguments
///
/// - `provenance` — The provenance record to evaluate. `None` means no
///   provenance is available, which always maps to `NoProvenance`.
/// - `context_state` — The current operational state of the source context.
#[must_use]
pub fn evaluate_quality(
    provenance: Option<&DataProvenance>,
    context_state: &SourceContextState,
) -> ProvenanceQuality {
    let Some(prov) = provenance else {
        // No provenance → lowest tier (absence is a signal, not an error)
        return ProvenanceQuality::NoProvenance;
    };

    match context_state {
        SourceContextState::Active => {
            if prov.source_type == SourceType::Persistent {
                ProvenanceQuality::PersistentVerifiable
            } else {
                // Active context but source type isn't Persistent — inconsistent
                // state; degrade gracefully
                ProvenanceQuality::EphemeralKnownParties
            }
        }
        SourceContextState::ClosedWithSummary { summary_verified } => {
            if *summary_verified {
                ProvenanceQuality::SummaryVerified
            } else if !prov.counterparties.is_empty() {
                // Unverified summary but known counterparties
                ProvenanceQuality::EphemeralKnownParties
            } else {
                ProvenanceQuality::NoProvenance
            }
        }
        SourceContextState::ClosedEphemeral => {
            if prov.counterparties.is_empty() {
                // Ephemeral with no known counterparties — no provenance
                ProvenanceQuality::NoProvenance
            } else {
                ProvenanceQuality::EphemeralKnownParties
            }
        }
        SourceContextState::Unknown => ProvenanceQuality::NoProvenance,
    }
}

// ---------------------------------------------------------------------------
// update_source_type
// ---------------------------------------------------------------------------

/// Updates the source type of a provenance record to reflect the current
/// operational state of the source context.
///
/// Source type reflects current state, not creation-time setting (ADR-019
/// criterion 5). This function should be called when the source context's
/// state changes (e.g., context closes after provenance was generated).
///
/// When `new_state` is [`SourceContextState::Unknown`], the source type is
/// preserved as-is (no-op).
pub const fn update_source_type(provenance: &mut DataProvenance, new_state: &SourceContextState) {
    match new_state {
        SourceContextState::Active => provenance.source_type = SourceType::Persistent,
        SourceContextState::ClosedWithSummary { .. } => {
            provenance.source_type = SourceType::Summary;
        }
        SourceContextState::ClosedEphemeral => {
            provenance.source_type = SourceType::Ephemeral;
        }
        SourceContextState::Unknown => {
            // Preserve existing source type when state is unknown
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::context::MemoryScope;
    use crate::identity::DID;
    use crate::provenance::DiscoveryMethod;

    fn make_provenance(source_type: SourceType, counterparties: Vec<DID>) -> DataProvenance {
        DataProvenance {
            source_context: "ctx-test".to_string(),
            source_type,
            counterparties,
            purpose: None,
            discovery_method: DiscoveryMethod::None,
            age: Duration::from_secs(60),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        }
    }

    // -----------------------------------------------------------------------
    // evaluate_quality — PersistentVerifiable
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_quality_returns_persistent_verifiable_when_active_and_persistent() {
        let prov = make_provenance(SourceType::Persistent, vec!["did:dht:z6MkAlice".into()]);
        let result = evaluate_quality(Some(&prov), &SourceContextState::Active);
        assert_eq!(result, ProvenanceQuality::PersistentVerifiable);
    }

    #[test]
    fn evaluate_quality_persistent_verifiable_with_single_counterparty() {
        let prov = make_provenance(SourceType::Persistent, vec!["did:dht:z6MkBob".into()]);
        let result = evaluate_quality(Some(&prov), &SourceContextState::Active);
        assert_eq!(result, ProvenanceQuality::PersistentVerifiable);
    }

    // -----------------------------------------------------------------------
    // evaluate_quality — SummaryVerified
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_quality_returns_summary_verified_when_closed_with_verified_summary() {
        let prov = make_provenance(SourceType::Summary, vec!["did:dht:z6MkAlice".into()]);
        let state = SourceContextState::ClosedWithSummary {
            summary_verified: true,
        };
        let result = evaluate_quality(Some(&prov), &state);
        assert_eq!(result, ProvenanceQuality::SummaryVerified);
    }

    #[test]
    fn evaluate_quality_unverified_summary_degrades_to_ephemeral_if_parties_known() {
        let prov = make_provenance(SourceType::Summary, vec!["did:dht:z6MkAlice".into()]);
        let state = SourceContextState::ClosedWithSummary {
            summary_verified: false,
        };
        let result = evaluate_quality(Some(&prov), &state);
        assert_eq!(result, ProvenanceQuality::EphemeralKnownParties);
    }

    #[test]
    fn evaluate_quality_unverified_summary_no_parties_degrades_to_no_provenance() {
        let prov = make_provenance(SourceType::Summary, vec![]);
        let state = SourceContextState::ClosedWithSummary {
            summary_verified: false,
        };
        let result = evaluate_quality(Some(&prov), &state);
        assert_eq!(result, ProvenanceQuality::NoProvenance);
    }

    // -----------------------------------------------------------------------
    // evaluate_quality — EphemeralKnownParties
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_quality_returns_ephemeral_known_parties_when_closed_ephemeral_with_parties() {
        let prov = make_provenance(
            SourceType::Ephemeral,
            vec!["did:dht:z6MkAlice".into(), "did:dht:z6MkBob".into()],
        );
        let result = evaluate_quality(Some(&prov), &SourceContextState::ClosedEphemeral);
        assert_eq!(result, ProvenanceQuality::EphemeralKnownParties);
    }

    #[test]
    fn evaluate_quality_ephemeral_no_parties_degrades_to_no_provenance() {
        let prov = make_provenance(SourceType::Ephemeral, vec![]);
        let result = evaluate_quality(Some(&prov), &SourceContextState::ClosedEphemeral);
        assert_eq!(result, ProvenanceQuality::NoProvenance);
    }

    // -----------------------------------------------------------------------
    // evaluate_quality — NoProvenance
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_quality_returns_no_provenance_when_none_provenance() {
        let result = evaluate_quality(None, &SourceContextState::Active);
        assert_eq!(result, ProvenanceQuality::NoProvenance);
    }

    #[test]
    fn evaluate_quality_returns_no_provenance_for_unknown_state() {
        let prov = make_provenance(SourceType::Persistent, vec!["did:dht:z6MkAlice".into()]);
        let result = evaluate_quality(Some(&prov), &SourceContextState::Unknown);
        assert_eq!(result, ProvenanceQuality::NoProvenance);
    }

    #[test]
    fn evaluate_quality_no_provenance_is_not_an_error() {
        // ADR-019 criterion 8: absence evaluates as NoProvenance, not an error
        let result = evaluate_quality(None, &SourceContextState::Unknown);
        assert_eq!(result, ProvenanceQuality::NoProvenance);
        // No panic, no error type — just the lowest quality tier
    }

    // -----------------------------------------------------------------------
    // evaluate_quality — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_quality_active_context_with_non_persistent_source_degrades() {
        // Inconsistent state: active context but source_type is Ephemeral
        let prov = make_provenance(SourceType::Ephemeral, vec!["did:dht:z6MkAlice".into()]);
        let result = evaluate_quality(Some(&prov), &SourceContextState::Active);
        assert_eq!(result, ProvenanceQuality::EphemeralKnownParties);
    }

    #[test]
    fn evaluate_quality_active_context_with_summary_source_degrades() {
        let prov = make_provenance(SourceType::Summary, vec!["did:dht:z6MkAlice".into()]);
        let result = evaluate_quality(Some(&prov), &SourceContextState::Active);
        assert_eq!(result, ProvenanceQuality::EphemeralKnownParties);
    }

    #[test]
    fn evaluate_quality_none_provenance_with_all_states() {
        for state in [
            SourceContextState::Active,
            SourceContextState::ClosedWithSummary {
                summary_verified: true,
            },
            SourceContextState::ClosedEphemeral,
            SourceContextState::Unknown,
        ] {
            let result = evaluate_quality(None, &state);
            assert_eq!(
                result,
                ProvenanceQuality::NoProvenance,
                "None provenance should always be NoProvenance regardless of state {state:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // update_source_type
    // -----------------------------------------------------------------------

    #[test]
    fn update_source_type_to_persistent_when_active() {
        let mut prov = make_provenance(SourceType::Ephemeral, vec![]);
        update_source_type(&mut prov, &SourceContextState::Active);
        assert_eq!(prov.source_type, SourceType::Persistent);
    }

    #[test]
    fn update_source_type_to_summary_when_closed_with_summary() {
        let mut prov = make_provenance(SourceType::Persistent, vec![]);
        let state = SourceContextState::ClosedWithSummary {
            summary_verified: true,
        };
        update_source_type(&mut prov, &state);
        assert_eq!(prov.source_type, SourceType::Summary);
    }

    #[test]
    fn update_source_type_to_ephemeral_when_closed_ephemeral() {
        let mut prov = make_provenance(SourceType::Persistent, vec![]);
        update_source_type(&mut prov, &SourceContextState::ClosedEphemeral);
        assert_eq!(prov.source_type, SourceType::Ephemeral);
    }

    #[test]
    fn update_source_type_preserves_on_unknown() {
        let mut prov = make_provenance(SourceType::Summary, vec![]);
        update_source_type(&mut prov, &SourceContextState::Unknown);
        assert_eq!(prov.source_type, SourceType::Summary);
    }

    #[test]
    fn update_source_type_sequential_state_changes() {
        let mut prov = make_provenance(SourceType::Persistent, vec!["did:dht:z6MkAlice".into()]);

        // Context is still active
        update_source_type(&mut prov, &SourceContextState::Active);
        assert_eq!(prov.source_type, SourceType::Persistent);

        // Context closes with summary
        let state = SourceContextState::ClosedWithSummary {
            summary_verified: true,
        };
        update_source_type(&mut prov, &state);
        assert_eq!(prov.source_type, SourceType::Summary);

        // Later becomes ephemeral (keys destroyed)
        update_source_type(&mut prov, &SourceContextState::ClosedEphemeral);
        assert_eq!(prov.source_type, SourceType::Ephemeral);
    }

    #[test]
    fn update_source_type_does_not_modify_other_fields() {
        let mut prov = DataProvenance {
            source_context: "ctx-original".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec!["did:dht:z6MkAlice".into()],
            purpose: Some("test purpose".to_string()),
            discovery_method: DiscoveryMethod::SharedContext("ctx-shared".into()),
            age: Duration::from_secs(42),
            memory_scope: MemoryScope::Full,
            chain_depth: 2,
            chain_path: Some(vec!["ctx-hop".into()]),
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        update_source_type(&mut prov, &SourceContextState::ClosedEphemeral);

        // source_type changed
        assert_eq!(prov.source_type, SourceType::Ephemeral);
        // all other fields preserved
        assert_eq!(prov.source_context, "ctx-original");
        assert_eq!(prov.counterparties, vec!["did:dht:z6MkAlice".to_string()]);
        assert_eq!(prov.purpose.as_deref(), Some("test purpose"));
        assert_eq!(prov.age, Duration::from_secs(42));
        assert_eq!(prov.memory_scope, MemoryScope::Full);
        assert_eq!(prov.chain_depth, 2);
        assert_eq!(prov.chain_path.as_ref().map(Vec::len), Some(1));
    }

    // -----------------------------------------------------------------------
    // Integration: evaluate_quality reflects updated source type
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_quality_reflects_updated_source_type() {
        let mut prov = make_provenance(SourceType::Persistent, vec!["did:dht:z6MkAlice".into()]);

        // Initially active and persistent
        let q1 = evaluate_quality(Some(&prov), &SourceContextState::Active);
        assert_eq!(q1, ProvenanceQuality::PersistentVerifiable);

        // Context closes with verified summary
        let state = SourceContextState::ClosedWithSummary {
            summary_verified: true,
        };
        update_source_type(&mut prov, &state);
        let q2 = evaluate_quality(Some(&prov), &state);
        assert_eq!(q2, ProvenanceQuality::SummaryVerified);
    }

    #[test]
    fn full_lifecycle_persistent_to_summary_to_ephemeral() {
        let mut prov = make_provenance(
            SourceType::Persistent,
            vec!["did:dht:z6MkAlice".into(), "did:dht:z6MkBob".into()],
        );

        // Phase 1: Active
        let q = evaluate_quality(Some(&prov), &SourceContextState::Active);
        assert_eq!(q, ProvenanceQuality::PersistentVerifiable);

        // Phase 2: Closed with summary
        let state = SourceContextState::ClosedWithSummary {
            summary_verified: true,
        };
        update_source_type(&mut prov, &state);
        let q = evaluate_quality(Some(&prov), &state);
        assert_eq!(q, ProvenanceQuality::SummaryVerified);

        // Phase 3: Ephemeral (keys destroyed)
        update_source_type(&mut prov, &SourceContextState::ClosedEphemeral);
        let q = evaluate_quality(Some(&prov), &SourceContextState::ClosedEphemeral);
        assert_eq!(q, ProvenanceQuality::EphemeralKnownParties);
    }

    // -----------------------------------------------------------------------
    // SourceContextState type tests
    // -----------------------------------------------------------------------

    #[test]
    fn source_context_state_variants_are_distinct() {
        let states = [
            SourceContextState::Active,
            SourceContextState::ClosedWithSummary {
                summary_verified: true,
            },
            SourceContextState::ClosedWithSummary {
                summary_verified: false,
            },
            SourceContextState::ClosedEphemeral,
            SourceContextState::Unknown,
        ];
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "states at indices {i} and {j} should differ");
                }
            }
        }
    }
}
