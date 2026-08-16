//! One name per governance outcome, shared by every FFI bridge.
//!
//! `PyO3`, napi-rs, and `UniFFI` each hand a caller a string naming what a
//! governance execution did. Each bridge used to build that string itself, and
//! they diverged: two wrote an exhaustive match over
//! [`GovernanceActionResult`], while napi-rs wrote `format!("{result:?}")`,
//! whose payload-carrying variants render as a Rust debug dump
//! (`MigrationProposed(MigrationProposedResult { .. })`) that no SDK enum
//! matches. Every bridge now calls [`governance_action_result_name`], so one
//! outcome carries one name on every bridge.
//!
//! [`governance_action_result_name`] matches every variant with no wildcard
//! arm, so adding a variant to [`GovernanceActionResult`] stops this crate from
//! compiling until someone names it. A wildcard arm here would instead ship a
//! new outcome under an old name.

use scp_core::context::state::GovernanceActionResult;

/// Returns whichever name a caller reads for `result`.
///
/// Each name matches its Rust variant name exactly, which is what Python,
/// Swift, and TypeScript SDK enums store as their values.
#[must_use]
pub const fn governance_action_result_name(result: &GovernanceActionResult) -> &'static str {
    match result {
        GovernanceActionResult::MemberAdded { .. } => "MemberAdded",
        GovernanceActionResult::MemberRemoved => "MemberRemoved",
        GovernanceActionResult::RoleChanged => "RoleChanged",
        GovernanceActionResult::OutletRegistered => "OutletRegistered",
        GovernanceActionResult::OutletRemoved => "OutletRemoved",
        GovernanceActionResult::CeilingModified => "CeilingModified",
        GovernanceActionResult::ContextClosed => "ContextClosed",
        GovernanceActionResult::TtlExtended => "TtlExtended",
        GovernanceActionResult::PruningPolicyModified => "PruningPolicyModified",
        GovernanceActionResult::AdminTransferred => "AdminTransferred",
        GovernanceActionResult::SignerAdded => "SignerAdded",
        GovernanceActionResult::SignerRemoved => "SignerRemoved",
        GovernanceActionResult::ThresholdModified => "ThresholdModified",
        GovernanceActionResult::ChildContextCreated => "ChildContextCreated",
        GovernanceActionResult::OutletInterfaceEstablished => "OutletInterfaceEstablished",
        GovernanceActionResult::MemberReset => "MemberReset",
        GovernanceActionResult::ConflictResolved => "ConflictResolved",
        GovernanceActionResult::ContextPromoted => "ContextPromoted",
        GovernanceActionResult::MemberSuspended(_) => "MemberSuspended",
        GovernanceActionResult::AccessRevoked(_) => "AccessRevoked",
        GovernanceActionResult::AccessRestored(_) => "AccessRestored",
        GovernanceActionResult::ContentKeysRotated(_) => "ContentKeysRotated",
        GovernanceActionResult::GovernanceReconfigured(_) => "GovernanceReconfigured",
        GovernanceActionResult::SubscriberBanned(_) => "SubscriberBanned",
        GovernanceActionResult::SubscriberUnbanned { .. } => "SubscriberUnbanned",
        GovernanceActionResult::Executed => "Executed",
        GovernanceActionResult::MigrationProposed(_) => "MigrationProposed",
        GovernanceActionResult::MigrationCancelled => "MigrationCancelled",
        GovernanceActionResult::ContextTombstoned => "ContextTombstoned",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Each name a bridge hands a caller is exactly its Rust variant name, so
    /// an SDK enum whose values mirror those variant names parses every one.
    #[test]
    fn payload_carrying_variants_report_a_bare_variant_name() {
        assert_eq!(
            governance_action_result_name(&GovernanceActionResult::MigrationCancelled),
            "MigrationCancelled"
        );
        assert_eq!(
            governance_action_result_name(&GovernanceActionResult::ContextTombstoned),
            "ContextTombstoned"
        );
        assert_eq!(
            governance_action_result_name(&GovernanceActionResult::Executed),
            "Executed"
        );
    }

    /// A name never carries debug punctuation. `format!("{result:?}")` — what
    /// one bridge did before this module existed — renders
    /// `MemberAdded { welcome_bytes: …, commit_bytes: … }`, which no SDK enum
    /// matches, so this asserts what that rendering would violate.
    #[test]
    fn a_name_carries_no_debug_punctuation() {
        for result in [
            GovernanceActionResult::MemberRemoved,
            GovernanceActionResult::RoleChanged,
            GovernanceActionResult::MigrationCancelled,
        ] {
            let name = governance_action_result_name(&result);
            assert!(
                !name.contains('{') && !name.contains('(') && !name.contains(' '),
                "governance outcome name must be a bare variant name, got {name}"
            );
        }
    }
}
