//! Supervisor module — cross-actor coordination surfaces.
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §3).
//!
//! This module houses the durable saga coordinator and — in later commits —
//! the supervisor struct, identity-capability token, and actor registry.
//! Commit 4 lands only the saga journal; later commits grow the module.

pub mod saga_journal;

pub use saga_journal::{
    JournalEntry, JournalError, ProtocolRepositorySagaJournal, SAGA_JOURNAL_KEY_PREFIX, SagaId,
    SagaJournal, SagaState, SagaTerminalState,
};
