//! Per-context durable state types — `PerContextState`,
//! `ContextSnapshot`, `BroadcastSnapshot`, generation tokens, governance
//! result types, plus pseudonym + commit-retry primitives.
//!
//! Hoisted to its own module in ADR-049 commit 12 ahead of the
//! `manager/` directory deletion. Re-exports the types from the
//! transitional location so downstream callers (FFI bridges, helpers,
//! actor handlers) need not change paths in the same commit.
//!
//! Once `manager/` is deleted, this module becomes the authoritative
//! home of these types.

// Public re-exports (cross-crate visible).
pub use crate::context::manager::{
    CommitFaultMarker, CommitOperation, ContextSnapshot, GovernanceActionResult,
    MAX_COMMIT_AGE_SECS, MAX_COMMIT_RETRIES, MAX_PENDING_COMMITS, MigrationProposedResult,
    MigrationState, PendingCeilingModification, PendingCommit, PendingEconomicPolicyChange,
    ProposalOutcome, RestoreAccessResult, RevokeResult, SuspendMemberResult,
    VelocityTrackerSnapshot, commit_retry_backoff,
};

// Crate-internal re-exports (used by helpers + supervisor).
pub(crate) use crate::context::manager::{
    COMMIT_RETRY_BACKOFFS, ContentKeysRotatedResult, ContextGeneration, EXECUTED_PROPOSALS_TTL_SECS,
    GovernanceReconfiguredResult, PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement,
    build_governance_engine, context_id_to_bytes, create_governance_engine, mint_governance_tokens,
    push_welcome_event, require_active, require_migrating_out,
    restore_governance_engine_from_snapshot, restore_grace_store_from_snapshot,
    strip_event_payload, validate_governance_consistency, validate_governance_model,
};
