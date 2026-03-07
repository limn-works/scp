//! Per-member budget tracking for economic governance.
//!
//! Tracks cumulative spending per member against their governance-approved
//! spending limits. Unlike the rolling-window [`BudgetTracker`] in
//! `crypto::ucan::spending`, this tracker enforces lifetime budget caps
//! set by governance via [`GovernanceAction::ApproveSpend`].
//!
//! See spec section 19.5 and ADR-033.

use std::collections::HashMap;

use scp_identity::DID;

use super::types::Amount;

// ---------------------------------------------------------------------------
// MemberBudgetTracker
// ---------------------------------------------------------------------------

/// Per-member cumulative budget tracker for governance-approved spending.
///
/// Each member starts with a limit of zero (no spending allowed). Governance
/// grants are additive via [`grant`]. Spending is recorded via [`record_spend`]
/// and checked via [`remaining`].
///
/// # Thread safety
///
/// Not `Sync` -- callers must hold the context lock before mutating.
///
/// See spec section 19.5, ADR-033.
#[derive(Debug, Clone)]
pub struct MemberBudgetTracker {
    /// Per-member spending limits (governance-approved).
    limits: HashMap<DID, Amount>,
    /// Per-member cumulative spending recorded so far.
    spent: HashMap<DID, Amount>,
}

/// Errors from budget operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BudgetError {
    /// The member has no spending budget (no governance approval).
    #[error("no budget allocated for {did}")]
    NoBudget {
        /// The DID with no budget.
        did: DID,
    },

    /// The spend would exceed the member's remaining budget.
    #[error("budget exceeded for {did}: requested {requested}, remaining {remaining}")]
    BudgetExceeded {
        /// The DID that attempted the spend.
        did: DID,
        /// The amount requested.
        requested: Amount,
        /// The amount remaining in the budget.
        remaining: Amount,
    },
}

impl MemberBudgetTracker {
    /// Creates a new tracker with no budgets.
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            spent: HashMap::new(),
        }
    }

    /// Grants additional spending budget to a member.
    ///
    /// Governance calls this when [`GovernanceAction::ApproveSpend`] is
    /// executed. Amounts are additive: granting 100 twice gives a total
    /// limit of 200.
    pub fn grant(&mut self, did: &DID, amount: Amount) {
        let current = self.limits.entry(did.clone()).or_insert(Amount::new(0));
        *current = current.saturating_add(amount);
    }

    /// Records a spend against a member's budget.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::NoBudget`] if the member has no governance-
    /// approved budget. Returns [`BudgetError::BudgetExceeded`] if the
    /// spend would exceed the remaining budget.
    pub fn record_spend(&mut self, did: &DID, amount: Amount) -> Result<(), BudgetError> {
        let limit = self
            .limits
            .get(did)
            .ok_or_else(|| BudgetError::NoBudget { did: did.clone() })?;

        let current_spent = self.spent.get(did).copied().unwrap_or(Amount::new(0));
        let remaining = limit.saturating_sub(current_spent);

        if amount > remaining {
            return Err(BudgetError::BudgetExceeded {
                did: did.clone(),
                requested: amount,
                remaining,
            });
        }

        let new_spent = current_spent.saturating_add(amount);
        self.spent.insert(did.clone(), new_spent);
        Ok(())
    }

    /// Returns the remaining budget for a member.
    ///
    /// Returns `Amount(0)` if the member has no budget.
    #[must_use]
    pub fn remaining(&self, did: &DID) -> Amount {
        let limit = self.limits.get(did).copied().unwrap_or(Amount::new(0));
        let spent = self.spent.get(did).copied().unwrap_or(Amount::new(0));
        limit.saturating_sub(spent)
    }

    /// Returns `true` if the member has any governance-approved budget.
    #[must_use]
    pub fn has_budget(&self, did: &DID) -> bool {
        self.limits.contains_key(did)
    }

    /// Returns the total spending limit for a member.
    #[must_use]
    pub fn limit(&self, did: &DID) -> Amount {
        self.limits.get(did).copied().unwrap_or(Amount::new(0))
    }

    /// Returns the total amount spent by a member.
    #[must_use]
    pub fn total_spent(&self, did: &DID) -> Amount {
        self.spent.get(did).copied().unwrap_or(Amount::new(0))
    }
}

impl Default for MemberBudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_did(name: &str) -> DID {
        DID::from(format!("did:dht:z6Mk{name}"))
    }

    #[test]
    fn new_tracker_has_no_budgets() {
        let tracker = MemberBudgetTracker::new();
        let did = test_did("Alice");
        assert_eq!(tracker.remaining(&did), Amount::new(0));
        assert!(!tracker.has_budget(&did));
    }

    #[test]
    fn grant_creates_budget() {
        let mut tracker = MemberBudgetTracker::new();
        let did = test_did("Alice");
        tracker.grant(&did, Amount::new(1000));
        assert!(tracker.has_budget(&did));
        assert_eq!(tracker.remaining(&did), Amount::new(1000));
        assert_eq!(tracker.limit(&did), Amount::new(1000));
    }

    #[test]
    fn grants_are_additive() {
        let mut tracker = MemberBudgetTracker::new();
        let did = test_did("Alice");
        tracker.grant(&did, Amount::new(500));
        tracker.grant(&did, Amount::new(300));
        assert_eq!(tracker.limit(&did), Amount::new(800));
        assert_eq!(tracker.remaining(&did), Amount::new(800));
    }

    #[test]
    fn record_spend_succeeds_within_budget() {
        let mut tracker = MemberBudgetTracker::new();
        let did = test_did("Alice");
        tracker.grant(&did, Amount::new(1000));
        assert!(tracker.record_spend(&did, Amount::new(400)).is_ok());
        assert_eq!(tracker.remaining(&did), Amount::new(600));
        assert_eq!(tracker.total_spent(&did), Amount::new(400));
    }

    #[test]
    fn record_spend_exact_budget() {
        let mut tracker = MemberBudgetTracker::new();
        let did = test_did("Alice");
        tracker.grant(&did, Amount::new(500));
        assert!(tracker.record_spend(&did, Amount::new(500)).is_ok());
        assert_eq!(tracker.remaining(&did), Amount::new(0));
    }

    #[test]
    fn record_spend_exceeds_budget() {
        let mut tracker = MemberBudgetTracker::new();
        let did = test_did("Alice");
        tracker.grant(&did, Amount::new(100));
        let err = tracker.record_spend(&did, Amount::new(150)).unwrap_err();
        assert!(matches!(err, BudgetError::BudgetExceeded { .. }));
        // Budget should not be modified on failure.
        assert_eq!(tracker.remaining(&did), Amount::new(100));
        assert_eq!(tracker.total_spent(&did), Amount::new(0));
    }

    #[test]
    fn record_spend_no_budget() {
        let mut tracker = MemberBudgetTracker::new();
        let did = test_did("Alice");
        let err = tracker.record_spend(&did, Amount::new(10)).unwrap_err();
        assert!(matches!(err, BudgetError::NoBudget { .. }));
    }

    #[test]
    fn multiple_members_independent() {
        let mut tracker = MemberBudgetTracker::new();
        let alice = test_did("Alice");
        let bob = test_did("Bob");
        tracker.grant(&alice, Amount::new(1000));
        tracker.grant(&bob, Amount::new(500));

        tracker.record_spend(&alice, Amount::new(300)).unwrap();

        assert_eq!(tracker.remaining(&alice), Amount::new(700));
        assert_eq!(tracker.remaining(&bob), Amount::new(500));
    }

    #[test]
    fn cumulative_spending_tracked() {
        let mut tracker = MemberBudgetTracker::new();
        let did = test_did("Alice");
        tracker.grant(&did, Amount::new(1000));
        tracker.record_spend(&did, Amount::new(200)).unwrap();
        tracker.record_spend(&did, Amount::new(300)).unwrap();
        assert_eq!(tracker.remaining(&did), Amount::new(500));
        assert_eq!(tracker.total_spent(&did), Amount::new(500));

        // One more spend that would exceed
        let err = tracker.record_spend(&did, Amount::new(600)).unwrap_err();
        assert!(matches!(err, BudgetError::BudgetExceeded { .. }));
        // Original remaining unchanged
        assert_eq!(tracker.remaining(&did), Amount::new(500));
    }

    #[test]
    fn default_is_empty() {
        let tracker = MemberBudgetTracker::default();
        assert_eq!(tracker.remaining(&test_did("Anyone")), Amount::new(0));
    }

    #[test]
    fn budget_error_display() {
        let err = BudgetError::NoBudget {
            did: test_did("Alice"),
        };
        assert!(err.to_string().contains("no budget allocated"));

        let err = BudgetError::BudgetExceeded {
            did: test_did("Alice"),
            requested: Amount::new(500),
            remaining: Amount::new(100),
        };
        assert!(err.to_string().contains("budget exceeded"));
        assert!(err.to_string().contains("500"));
        assert!(err.to_string().contains("100"));
    }
}
