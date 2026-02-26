//! Context promotion from ephemeral to persistent.
//!
//! Implements ADR-018 (`.docs/adrs/phase-4.md`), acceptance criterion 4:
//!
//! - Only `Promotable` contexts can be promoted. `NoPromotion` contexts reject
//!   promotion proposals.
//! - Requires unanimous member consent (not just governance majority).
//! - On promotion: TTL removed, memory scope transitions to `Full`, existing
//!   event log and key material preserved.
//! - Promotion is a context event in the Merkle log.
//!
//! # Promotion as Contract Change
//!
//! Moving from ephemeral to persistent changes what members opted into.
//! Unanimous consent (not just governance majority) is required because the
//! original scope was part of the opt-in contract visible before joining
//! (protocol tenet: legibility before opt-in).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::MemoryScope;
use crate::identity::DID;
use super::memory_scope::ContextId;
use super::params::PromotionPolicy;

// ---------------------------------------------------------------------------
// PromotionError
// ---------------------------------------------------------------------------

/// Errors produced by context promotion operations.
#[derive(Debug, thiserror::Error)]
pub enum PromotionError {
    /// The context's promotion policy is `NoPromotion`, so promotion proposals
    /// are rejected.
    #[error("context promotion policy is NoPromotion; promotion not allowed")]
    NotPromotable,

    /// The context is not in Active state. Promotion can only be proposed for
    /// active contexts.
    #[error("context must be in Active state to propose promotion")]
    ContextNotActive,

    /// Unanimous consent has not been reached. All members must consent before
    /// promotion can be executed.
    #[error("unanimous consent required: {received} of {required} consents received")]
    ConsentNotUnanimous {
        /// Number of consents received so far.
        received: usize,
        /// Total number of consents required (all members).
        required: usize,
    },

    /// A promotion proposal is already in progress for this context.
    #[error("a promotion proposal is already in progress")]
    ProposalAlreadyActive,

    /// The member is not a participant in this context.
    #[error("member {0} is not a participant in this context")]
    NotAMember(String),
}

// ---------------------------------------------------------------------------
// PromotionProposal
// ---------------------------------------------------------------------------

/// A proposal to promote a context from ephemeral to persistent.
///
/// Promotion requires unanimous member consent because it changes the opt-in
/// contract. The proposal tracks which members have consented and validates
/// that the context's `PromotionPolicy` permits promotion.
///
/// See ADR-018 acceptance criterion 4.
#[derive(Debug, Clone)]
pub struct PromotionProposal {
    /// The context being proposed for promotion.
    context_id: ContextId,
    /// DID of the member who proposed the promotion.
    proposer_did: DID,
    /// DIDs that have consented to the promotion.
    consents: HashSet<DID>,
    /// Total member count required for unanimity.
    required_count: usize,
}

impl PromotionProposal {
    /// Returns the context ID for this proposal.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the DID of the proposer.
    #[must_use]
    pub fn proposer_did(&self) -> &str {
        &self.proposer_did
    }

    /// Returns the number of consents received so far.
    #[must_use]
    pub fn consent_count(&self) -> usize {
        self.consents.len()
    }

    /// Returns the total number of consents required (all members).
    #[must_use]
    pub const fn required_count(&self) -> usize {
        self.required_count
    }

    /// Returns the number of consents still needed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.required_count.saturating_sub(self.consents.len())
    }

    /// Returns `true` if all members have consented (unanimous).
    #[must_use]
    pub fn is_unanimous(&self) -> bool {
        self.consents.len() >= self.required_count
    }

    /// Returns `true` if the given member has already consented.
    #[must_use]
    pub fn has_consented(&self, member_did: &str) -> bool {
        self.consents.contains(member_did)
    }
}

// ---------------------------------------------------------------------------
// PromotionEvent -- Merkle log event for promotion
// ---------------------------------------------------------------------------

/// A promotion event recorded in the context's Merkle log (ADR-011).
///
/// This event captures the promotion state transition: the proposer, the
/// set of members who consented, the previous memory scope, and the
/// resulting scope (`Full`).
///
/// See ADR-018 acceptance criterion 4: "Promotion is a context event in the
/// Merkle log."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvent {
    /// The context that was promoted.
    pub context_id: ContextId,
    /// DID of the member who proposed the promotion.
    pub proposer_did: DID,
    /// DIDs of all members who consented (should include all members).
    pub consenting_members: Vec<DID>,
    /// The memory scope before promotion.
    pub previous_memory_scope: MemoryScope,
    /// The memory scope after promotion (always `Full`).
    pub new_memory_scope: MemoryScope,
    /// Whether TTL was removed during promotion.
    pub ttl_removed: bool,
    /// Unix timestamp (seconds) when the promotion was executed.
    pub promoted_at: u64,
}

// ---------------------------------------------------------------------------
// PromotionResult -- output of a successful promotion
// ---------------------------------------------------------------------------

/// The result of a successful context promotion.
///
/// Contains the event to be recorded in the Merkle log and the new context
/// state (TTL removed, memory scope set to `Full`).
#[derive(Debug, Clone)]
pub struct PromotionResult {
    /// The promotion event to record in the Merkle log.
    pub event: PromotionEvent,
}

// ---------------------------------------------------------------------------
// propose_promotion -- creates a promotion proposal
// ---------------------------------------------------------------------------

/// Creates a promotion proposal for the given context.
///
/// Validates that the context's `PromotionPolicy` is `Promotable` and that
/// the context is in the `Active` state. The proposer's consent is
/// automatically recorded.
///
/// # Arguments
///
/// * `context_id` -- The context to propose promotion for.
/// * `proposer_did` -- The DID of the member proposing the promotion.
/// * `promotion_policy` -- The context's promotion policy (from
///   `ContextParams`).
/// * `is_active` -- Whether the context is currently in the `Active` state.
/// * `member_count` -- Total number of members in the context.
///
/// # Errors
///
/// Returns [`PromotionError::NotPromotable`] if the context's promotion
/// policy is `NoPromotion`.
///
/// Returns [`PromotionError::ContextNotActive`] if the context is not in
/// the `Active` state.
pub fn propose_promotion(
    context_id: ContextId,
    proposer_did: DID,
    promotion_policy: PromotionPolicy,
    is_active: bool,
    member_count: usize,
) -> Result<PromotionProposal, PromotionError> {
    // Reject if promotion policy is NoPromotion.
    if promotion_policy == PromotionPolicy::NoPromotion {
        return Err(PromotionError::NotPromotable);
    }

    // Reject if context is not active.
    if !is_active {
        return Err(PromotionError::ContextNotActive);
    }

    // Create the proposal with the proposer's consent already recorded.
    let mut consents = HashSet::new();
    consents.insert(proposer_did.clone());

    Ok(PromotionProposal {
        context_id,
        proposer_did,
        consents,
        required_count: member_count,
    })
}

// ---------------------------------------------------------------------------
// record_consent -- records a member's consent
// ---------------------------------------------------------------------------

/// Records a member's consent for a promotion proposal.
///
/// Returns `true` if this was a new consent (the member had not previously
/// consented). Returns `false` if the member had already consented
/// (idempotent).
///
/// # Arguments
///
/// * `proposal` -- The promotion proposal to record consent for.
/// * `member_did` -- The DID of the consenting member.
/// * `is_member` -- Whether the DID is a current member of the context.
///
/// # Errors
///
/// Returns [`PromotionError::NotAMember`] if the DID is not a member of the
/// context.
pub fn record_consent(
    proposal: &mut PromotionProposal,
    member_did: DID,
    is_member: bool,
) -> Result<bool, PromotionError> {
    if !is_member {
        return Err(PromotionError::NotAMember(member_did.to_string()));
    }
    Ok(proposal.consents.insert(member_did))
}

// ---------------------------------------------------------------------------
// execute_promotion -- executes the promotion state transition
// ---------------------------------------------------------------------------

/// Executes the promotion state transition.
///
/// Checks that unanimous consent has been reached, then produces a
/// [`PromotionResult`] containing the event to record in the Merkle log.
/// On promotion:
///
/// 1. TTL is removed (set to `None`).
/// 2. Memory scope transitions to `Full`.
/// 3. Existing event log and key material are preserved (no destruction).
///
/// The caller is responsible for:
/// - Recording the [`PromotionEvent`] in the context's Merkle log.
/// - Updating the context's `ContextParams` (TTL and memory scope).
/// - Cancelling any active TTL timer.
///
/// # Arguments
///
/// * `proposal` -- The promotion proposal with collected consents.
/// * `previous_memory_scope` -- The context's current memory scope before
///   promotion.
/// * `had_ttl` -- Whether the context had a TTL before promotion.
/// * `now` -- Current Unix timestamp (seconds).
///
/// # Errors
///
/// Returns [`PromotionError::ConsentNotUnanimous`] if not all members have
/// consented.
pub fn execute_promotion(
    proposal: &PromotionProposal,
    previous_memory_scope: MemoryScope,
    had_ttl: bool,
    now: u64,
) -> Result<PromotionResult, PromotionError> {
    // Verify unanimous consent.
    if !proposal.is_unanimous() {
        return Err(PromotionError::ConsentNotUnanimous {
            received: proposal.consents.len(),
            required: proposal.required_count,
        });
    }

    // Build the sorted list of consenting members for deterministic output.
    let mut consenting_members: Vec<DID> = proposal.consents.iter().cloned().collect();
    consenting_members.sort();

    let event = PromotionEvent {
        context_id: proposal.context_id.clone(),
        proposer_did: proposal.proposer_did.clone(),
        consenting_members,
        previous_memory_scope,
        new_memory_scope: MemoryScope::Full,
        ttl_removed: had_ttl,
        promoted_at: now,
    };

    Ok(PromotionResult { event })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper: create a standard promotable proposal
    // -----------------------------------------------------------------------

    fn make_promotable_proposal(member_count: usize) -> PromotionProposal {
        propose_promotion(
            "ctx-1".to_owned(),
            "did:key:alice".into(),
            PromotionPolicy::Promotable,
            true,
            member_count,
        )
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // PromotionPolicy validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn propose_promotion_succeeds_for_promotable_context() {
        let proposal = propose_promotion(
            "ctx-1".to_owned(),
            "did:key:alice".into(),
            PromotionPolicy::Promotable,
            true,
            3,
        );
        assert!(proposal.is_ok());
        let proposal = proposal.unwrap();
        assert_eq!(proposal.context_id(), "ctx-1");
        assert_eq!(proposal.proposer_did(), "did:key:alice");
        assert_eq!(proposal.required_count(), 3);
    }

    #[test]
    fn propose_promotion_rejects_no_promotion_policy() {
        let result = propose_promotion(
            "ctx-1".to_owned(),
            "did:key:alice".into(),
            PromotionPolicy::NoPromotion,
            true,
            3,
        );
        assert!(result.is_err());
        match result {
            Err(PromotionError::NotPromotable) => {}
            _ => panic!("expected NotPromotable error"),
        }
    }

    #[test]
    fn propose_promotion_rejects_non_active_context() {
        let result = propose_promotion(
            "ctx-1".to_owned(),
            "did:key:alice".into(),
            PromotionPolicy::Promotable,
            false,
            3,
        );
        assert!(result.is_err());
        match result {
            Err(PromotionError::ContextNotActive) => {}
            _ => panic!("expected ContextNotActive error"),
        }
    }

    // -----------------------------------------------------------------------
    // Proposer consent auto-recorded
    // -----------------------------------------------------------------------

    #[test]
    fn propose_promotion_auto_records_proposer_consent() {
        let proposal = make_promotable_proposal(3);
        assert_eq!(proposal.consent_count(), 1);
        assert!(proposal.has_consented("did:key:alice"));
    }

    // -----------------------------------------------------------------------
    // Consent collection tests
    // -----------------------------------------------------------------------

    #[test]
    fn record_consent_adds_new_member() {
        let mut proposal = make_promotable_proposal(3);
        let result = record_consent(&mut proposal, "did:key:bob".into(), true);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(proposal.consent_count(), 2);
        assert!(proposal.has_consented("did:key:bob"));
    }

    #[test]
    fn record_consent_is_idempotent() {
        let mut proposal = make_promotable_proposal(3);
        record_consent(&mut proposal, "did:key:bob".into(), true).unwrap();

        // Second consent from the same member returns false (already recorded).
        let result = record_consent(&mut proposal, "did:key:bob".into(), true);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(proposal.consent_count(), 2);
    }

    #[test]
    fn record_consent_rejects_non_member() {
        let mut proposal = make_promotable_proposal(3);
        let result = record_consent(&mut proposal, "did:key:stranger".into(), false);
        assert!(result.is_err());
        match result {
            Err(PromotionError::NotAMember(did)) => {
                assert_eq!(did, "did:key:stranger");
            }
            _ => panic!("expected NotAMember error"),
        }
    }

    // -----------------------------------------------------------------------
    // Unanimity tracking tests
    // -----------------------------------------------------------------------

    #[test]
    fn proposal_not_unanimous_with_partial_consent() {
        let proposal = make_promotable_proposal(3);
        assert!(!proposal.is_unanimous());
        assert_eq!(proposal.remaining(), 2);
    }

    #[test]
    fn proposal_becomes_unanimous_with_all_consents() {
        let mut proposal = make_promotable_proposal(3);
        record_consent(&mut proposal, "did:key:bob".into(), true).unwrap();
        assert!(!proposal.is_unanimous());
        assert_eq!(proposal.remaining(), 1);

        record_consent(&mut proposal, "did:key:charlie".into(), true).unwrap();
        assert!(proposal.is_unanimous());
        assert_eq!(proposal.remaining(), 0);
    }

    #[test]
    fn proposal_unanimous_for_single_member_context() {
        let proposal = make_promotable_proposal(1);
        // Proposer's consent is auto-recorded, so single-member is immediately
        // unanimous.
        assert!(proposal.is_unanimous());
        assert_eq!(proposal.remaining(), 0);
    }

    // -----------------------------------------------------------------------
    // execute_promotion tests
    // -----------------------------------------------------------------------

    #[test]
    fn execute_promotion_succeeds_with_unanimous_consent() {
        let mut proposal = make_promotable_proposal(2);
        record_consent(&mut proposal, "did:key:bob".into(), true).unwrap();

        let result = execute_promotion(&proposal, MemoryScope::Ephemeral, true, 1_700_000_000);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.event.context_id, "ctx-1");
        assert_eq!(result.event.proposer_did, "did:key:alice");
        assert_eq!(result.event.previous_memory_scope, MemoryScope::Ephemeral);
        assert_eq!(result.event.new_memory_scope, MemoryScope::Full);
        assert!(result.event.ttl_removed);
        assert_eq!(result.event.promoted_at, 1_700_000_000);
        assert_eq!(result.event.consenting_members.len(), 2);
    }

    #[test]
    fn execute_promotion_fails_without_unanimous_consent() {
        let proposal = make_promotable_proposal(3);
        // Only proposer's consent recorded (1 of 3).

        let result = execute_promotion(&proposal, MemoryScope::Ephemeral, true, 1_700_000_000);
        assert!(result.is_err());
        match result {
            Err(PromotionError::ConsentNotUnanimous { received, required }) => {
                assert_eq!(received, 1);
                assert_eq!(required, 3);
            }
            _ => panic!("expected ConsentNotUnanimous error"),
        }
    }

    #[test]
    fn execute_promotion_sets_memory_scope_to_full() {
        let proposal = make_promotable_proposal(1);
        // Single member, already unanimous.

        let result = execute_promotion(&proposal, MemoryScope::Summary, false, 1_700_000_000);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.event.new_memory_scope, MemoryScope::Full);
        assert_eq!(result.event.previous_memory_scope, MemoryScope::Summary);
    }

    #[test]
    fn execute_promotion_records_ttl_removed_flag() {
        let proposal = make_promotable_proposal(1);

        // With TTL.
        let result = execute_promotion(&proposal, MemoryScope::Ephemeral, true, 1_000);
        assert!(result.unwrap().event.ttl_removed);

        // Without TTL.
        let result = execute_promotion(&proposal, MemoryScope::Ephemeral, false, 1_000);
        assert!(!result.unwrap().event.ttl_removed);
    }

    #[test]
    fn execute_promotion_consenting_members_are_sorted() {
        let mut proposal = make_promotable_proposal(3);
        // Add consents in non-alphabetical order.
        record_consent(&mut proposal, "did:key:charlie".into(), true).unwrap();
        record_consent(&mut proposal, "did:key:bob".into(), true).unwrap();

        let result = execute_promotion(&proposal, MemoryScope::Ephemeral, true, 1_000).unwrap();

        assert_eq!(
            result.event.consenting_members,
            vec![
                DID::from("did:key:alice"),
                DID::from("did:key:bob"),
                DID::from("did:key:charlie"),
            ]
        );
    }

    // -----------------------------------------------------------------------
    // PromotionEvent serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn promotion_event_serialization_roundtrip() {
        let event = PromotionEvent {
            context_id: "ctx-42".to_owned(),
            proposer_did: "did:key:alice".into(),
            consenting_members: vec!["did:key:alice".into(), "did:key:bob".into()],
            previous_memory_scope: MemoryScope::Ephemeral,
            new_memory_scope: MemoryScope::Full,
            ttl_removed: true,
            promoted_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PromotionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event);
    }

    // -----------------------------------------------------------------------
    // Error display messages
    // -----------------------------------------------------------------------

    #[test]
    fn promotion_error_display_messages() {
        let err = PromotionError::NotPromotable;
        assert_eq!(
            format!("{err}"),
            "context promotion policy is NoPromotion; promotion not allowed"
        );

        let err = PromotionError::ContextNotActive;
        assert_eq!(
            format!("{err}"),
            "context must be in Active state to propose promotion"
        );

        let err = PromotionError::ConsentNotUnanimous {
            received: 1,
            required: 3,
        };
        assert_eq!(
            format!("{err}"),
            "unanimous consent required: 1 of 3 consents received"
        );

        let err = PromotionError::ProposalAlreadyActive;
        assert_eq!(
            format!("{err}"),
            "a promotion proposal is already in progress"
        );

        let err = PromotionError::NotAMember("did:key:stranger".into());
        assert_eq!(
            format!("{err}"),
            "member did:key:stranger is not a participant in this context"
        );
    }

    // -----------------------------------------------------------------------
    // Full promotion flow (end-to-end)
    // -----------------------------------------------------------------------

    #[test]
    fn full_promotion_flow_bilateral() {
        // Step 1: Propose promotion in a bilateral (2-member) context.
        let mut proposal = propose_promotion(
            "ctx-bilateral".to_owned(),
            "did:key:alice".into(),
            PromotionPolicy::Promotable,
            true,
            2,
        )
        .unwrap();
        assert_eq!(proposal.consent_count(), 1);
        assert!(!proposal.is_unanimous());

        // Step 2: Record the other member's consent.
        record_consent(&mut proposal, "did:key:bob".into(), true).unwrap();
        assert!(proposal.is_unanimous());

        // Step 3: Execute promotion.
        let result =
            execute_promotion(&proposal, MemoryScope::Ephemeral, true, 1_700_000_000).unwrap();

        // Verify the resulting event.
        assert_eq!(result.event.context_id, "ctx-bilateral");
        assert_eq!(result.event.new_memory_scope, MemoryScope::Full);
        assert!(result.event.ttl_removed);
        assert_eq!(result.event.consenting_members.len(), 2);
    }

    #[test]
    fn full_promotion_flow_multi_party() {
        // Step 1: Propose promotion in a multi-party (5-member) context.
        let mut proposal = propose_promotion(
            "ctx-group".to_owned(),
            "did:key:alice".into(),
            PromotionPolicy::Promotable,
            true,
            5,
        )
        .unwrap();

        // Step 2: Collect all consents (unanimous required).
        record_consent(&mut proposal, "did:key:bob".into(), true).unwrap();
        record_consent(&mut proposal, "did:key:charlie".into(), true).unwrap();
        record_consent(&mut proposal, "did:key:dave".into(), true).unwrap();
        assert!(!proposal.is_unanimous());
        assert_eq!(proposal.remaining(), 1);

        record_consent(&mut proposal, "did:key:eve".into(), true).unwrap();
        assert!(proposal.is_unanimous());

        // Step 3: Execute promotion.
        let result =
            execute_promotion(&proposal, MemoryScope::Summary, true, 1_700_000_000).unwrap();

        assert_eq!(result.event.context_id, "ctx-group");
        assert_eq!(result.event.previous_memory_scope, MemoryScope::Summary);
        assert_eq!(result.event.new_memory_scope, MemoryScope::Full);
        assert_eq!(result.event.consenting_members.len(), 5);
    }

    #[test]
    fn promotion_from_full_scope_preserves_full() {
        // Even if the context already has Full scope, promotion sets it to
        // Full (no-op on scope but still removes TTL and records the event).
        let proposal = make_promotable_proposal(1);

        let result = execute_promotion(&proposal, MemoryScope::Full, true, 1_000).unwrap();

        assert_eq!(result.event.previous_memory_scope, MemoryScope::Full);
        assert_eq!(result.event.new_memory_scope, MemoryScope::Full);
        assert!(result.event.ttl_removed);
    }
}
