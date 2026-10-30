//! The event-log Merkle root a cached participation record binds, and the
//! cached record itself (ADR-017 acceptance criterion 1; spec 17 §17.3 "Event
//! log write failures").
//!
//! A participation record's `event_log_root` claims the log state the record
//! was computed from. A root that failed to read must never stand in for one:
//! an all-zero root bound to real participation facts reads as a record of a
//! real log state. Two types make that impossible by construction:
//!
//! - [`ParticipationRoot`] is built only by [`ParticipationRoot::read`], which
//!   returns the provider's error when the read fails. A participation path
//!   reads it before its irreversible step and refuses the step on failure.
//! - [`RootedParticipationRecord`], the only value type the participation cache
//!   holds, is built only by [`ParticipationRoot::record`]. A record computed
//!   from any other root, a zero literal among them, cannot enter the cache.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::ops::Deref;

use scp_protocol::context::ContextError;
use scp_protocol::trust::TrustError;
use scp_protocol::trust::participation::{ParticipationRecord, compute_participation_record};
use serde::{Deserialize, Serialize};

use crate::context::builder::ContextEventLogProvider;
use crate::context::state::context_id_to_bytes;

/// The Merkle root of a context's durable event log, as read before a
/// participation path's irreversible step.
///
/// The field is private and [`Self::read`] is the only constructor, so every
/// value holds a root the provider returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParticipationRoot([u8; 32]);

impl ParticipationRoot {
    /// Reads the Merkle root of `context_id`'s event log.
    ///
    /// # Errors
    ///
    /// The provider's error: [`ContextError::EventLogFailed`] when the log is
    /// absent, unreadable, or the provider computes no root, or
    /// [`ContextError::ContextNotRegistered`]. The caller refuses its step.
    pub fn read(
        context_id: &str,
        event_log: &dyn ContextEventLogProvider,
    ) -> Result<Self, ContextError> {
        event_log
            .event_log_merkle_root(&context_id_to_bytes(context_id))
            .map(Self)
    }

    /// Computes `subject_did`'s participation record over `events`, bound to
    /// this root.
    ///
    /// The accessible-attestation set is empty: `attestation_count` is a
    /// credential-layer, verifier-relative fact (§7.3.2), and the cache gates
    /// only on `participation_count`.
    ///
    /// # Errors
    ///
    /// [`TrustError::EmptyEventLog`] when `events` is empty.
    pub fn record(
        self,
        events: &[scp_event_log::Event],
        subject_did: &str,
        context_id: &str,
        computed_at: u64,
    ) -> Result<RootedParticipationRecord, TrustError> {
        compute_participation_record(events, subject_did, context_id, self.0, computed_at, &[])
            .map(RootedParticipationRecord)
    }

    /// Replaces `subject_did`'s cached record with one computed over `events`
    /// and bound to this root. An empty `events` leaves the cache unchanged.
    pub fn refresh<S: BuildHasher>(
        self,
        cache: &mut HashMap<String, RootedParticipationRecord, S>,
        events: &[scp_event_log::Event],
        subject_did: &str,
        context_id: &str,
        computed_at: u64,
    ) {
        if let Ok(record) = self.record(events, subject_did, context_id, computed_at) {
            cache.insert(subject_did.to_owned(), record);
        }
    }
}

/// A participation record whose `event_log_root` came from a
/// [`ParticipationRoot`]: the value type of the participation cache.
///
/// [`ParticipationRoot::record`] builds it at runtime. Deserialization rebuilds
/// one that a snapshot stored, which was built the same way before it was
/// persisted; the serialized form is the bare [`ParticipationRecord`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RootedParticipationRecord(ParticipationRecord);

impl Deref for RootedParticipationRecord {
    type Target = ParticipationRecord;

    fn deref(&self) -> &ParticipationRecord {
        &self.0
    }
}

/// Roots for fixtures that hold no log of their own.
#[cfg(any(test, feature = "testing"))]
pub mod test_support {
    use scp_protocol::context::ContextError;
    use scp_protocol::context::builder::ContextCreationError;

    use super::ParticipationRoot;
    use crate::context::builder::{
        ContextEventLogProvider, EventLogRestore, UnitAppendError, UnitAppended, UnitWriteGuard,
    };
    use crate::context::providers::event_log::MerkleEventLogProvider;

    /// The Merkle root of an empty log (spec section 25.8, vector 15), for a
    /// fixture provider that holds no entry.
    #[must_use]
    pub fn empty_tree_root() -> [u8; 32] {
        scp_event_log::tree::root(&scp_event_log::EventLog::new(String::new()))
    }

    /// A provider whose every context holds an empty log.
    struct EmptyLog;

    #[async_trait::async_trait]
    impl ContextEventLogProvider for EmptyLog {
        fn event_log_entries(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
            Ok(Some(Vec::new()))
        }

        fn event_log_merkle_root(&self, _context_id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
            Ok(empty_tree_root())
        }

        async fn init_event_log(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        async fn append_event(
            &self,
            _context_id: &[u8; 32],
            _event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            Err(ContextCreationError::EventLogFailed(
                "the empty-log fixture holds no entry".to_owned(),
            ))
        }

        async fn destroy_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    /// A Merkle event log that serves every read and write except the root,
    /// which it refuses as a provider that computes no root does.
    pub struct RootRefusingLog(pub MerkleEventLogProvider);

    #[async_trait::async_trait]
    impl ContextEventLogProvider for RootRefusingLog {
        async fn init_event_log(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.0.init_event_log(context_id).await
        }

        async fn append_event(
            &self,
            context_id: &[u8; 32],
            event_type: scp_event_log::EventType,
            actor_did: &str,
            payload: scp_event_log::EventPayload,
            timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            self.0
                .append_event(context_id, event_type, actor_did, payload, timestamp_secs)
                .await
        }

        async fn destroy_event_log(
            &self,
            context_id: &[u8; 32],
        ) -> Result<(), ContextCreationError> {
            self.0.destroy_event_log(context_id).await
        }

        async fn lock_for_unit(
            &self,
            context_id: &[u8; 32],
        ) -> Result<UnitWriteGuard, ContextCreationError> {
            self.0.lock_for_unit(context_id).await
        }

        async fn append_unit(
            &self,
            guard: UnitWriteGuard,
            base_seq: u64,
            leaves: &[crate::context::state::LeafSpec],
        ) -> Result<UnitAppended, UnitAppendError> {
            self.0.append_unit(guard, base_seq, leaves).await
        }

        fn set_units_pending(&self, context_id: &[u8; 32], pending: bool) {
            self.0.set_units_pending(context_id, pending);
        }

        fn release_event_log(&self, context_id: &[u8; 32]) {
            self.0.release_event_log(context_id);
        }

        fn event_log_entries(
            &self,
            context_id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
            self.0.event_log_entries(context_id)
        }

        fn event_log_merkle_root(&self, _context_id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
            Err(ContextError::EventLogFailed(
                "fixture: the Merkle root read fails".to_owned(),
            ))
        }

        fn event_log_summary(
            &self,
            context_id: &[u8; 32],
        ) -> Result<(usize, [u8; 32]), ContextError> {
            self.0.event_log_summary(context_id)
        }

        async fn restore_event_log(
            &self,
            context_id: &[u8; 32],
        ) -> Result<EventLogRestore, ContextCreationError> {
            self.0.restore_event_log(context_id).await
        }
    }

    /// The root of an empty log, read through [`ParticipationRoot::read`].
    ///
    /// # Errors
    ///
    /// None in practice: the fixture's root read always succeeds.
    pub fn empty_log_root() -> Result<ParticipationRoot, ContextError> {
        ParticipationRoot::read("", &EmptyLog)
    }
}
