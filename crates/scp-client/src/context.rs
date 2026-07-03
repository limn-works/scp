//! Per-context participant state.
//!
//! [`PerContextState`] is the driver's per-context record: the crypto state
//! ([`ContextCryptoState`]), the canonical event log
//! ([`scp_event_log::EventLog`]), the membership set with per-member message
//! sequence counters, and the pull-based receive buffer of
//! [`ContextEvent`](scp_protocol::context::membership::ContextEvent)s.
//!
//! It restores the deleted WASM bridge's `PerContextState` shape — a pull-based
//! `drain_events` model and a committer-assigned event-log timestamp — while
//! holding only the **participant message-path** fields (ADR-057 scope fence:
//! no governance/economy/tools/broadcast state).

use std::collections::{HashMap, VecDeque};

use scp_did::DID;
use scp_event_log::tree::{GENESIS_PREV_HASH, append_unsigned_event, event_count, root};
use scp_event_log::{Event, EventLog, EventPayload, EventType};
use scp_protocol::context::membership::ContextEvent;

use crate::crypto_state::ContextCryptoState;

/// Maximum events held in the pull-based receive buffer before the oldest is
/// dropped (FIFO overflow). Mirrors the deleted bridge's `WASM_EVENT_BUFFER_CAP`
/// and the native `PyO3` channel capacity, so a slow drainer cannot grow memory
/// without bound.
pub const EVENT_BUFFER_CAP: usize = 1000;

/// Participant state for a single context.
pub struct PerContextState {
    /// MLS + sender-key crypto state (the §9.16 double-encryption pipeline).
    pub crypto: ContextCryptoState,
    /// Canonical Merkle event log (shared `scp-event-log` implementation). The
    /// convergence property the MVP test asserts is a property of THIS log
    /// being driven by shared append logic on both members.
    pub event_log: EventLog,
    /// Membership set: member DIDs in the context.
    ///
    /// Insertion-ordered is not required for convergence (the event log carries
    /// order); a `Vec` keeps the set small and cheap for the MVP. Membership is
    /// authoritative at the driver level for "who is in the context"; the MLS
    /// tree is authoritative for who can derive keys.
    pub members: Vec<String>,
    /// Per-member next-outgoing message sequence number, keyed by member DID.
    ///
    /// This is ENCRYPTION state (the next sequence each sender will stamp), not
    /// membership state. Seeded to 0 when a member joins/is added, and
    /// incremented after each `send_message`.
    pub member_sequence_numbers: HashMap<String, u64>,
    /// Pull-based receive buffer. Drained by `ScpClient::drain_events`.
    pub event_buffer: VecDeque<ContextEvent>,
}

impl PerContextState {
    /// Creates fresh per-context state around an already-built crypto state and
    /// a fresh event log for `context_id`, with `creator_did` as the sole
    /// initial member (sequence 0).
    #[must_use]
    pub fn new(context_id: &str, creator_did: &str, crypto: ContextCryptoState) -> Self {
        let mut member_sequence_numbers = HashMap::new();
        member_sequence_numbers.insert(creator_did.to_owned(), 0);
        Self {
            crypto,
            event_log: EventLog::new(context_id.to_owned()),
            members: vec![creator_did.to_owned()],
            member_sequence_numbers,
            event_buffer: VecDeque::new(),
        }
    }

    /// Creates fresh per-context state with an EMPTY event log and EMPTY
    /// membership, for a joiner that will replay the adder's stream and adopt
    /// the adder's membership snapshot.
    #[must_use]
    pub fn new_empty(context_id: &str, crypto: ContextCryptoState) -> Self {
        Self {
            crypto,
            event_log: EventLog::new(context_id.to_owned()),
            members: Vec::new(),
            member_sequence_numbers: HashMap::new(),
            event_buffer: VecDeque::new(),
        }
    }

    /// Records a member in the context's membership set and seeds their
    /// outgoing-sequence counter. A no-op if the member is already present.
    pub fn add_member_record(&mut self, member_did: &str) {
        if !self.members.iter().any(|m| m == member_did) {
            self.members.push(member_did.to_owned());
        }
        self.member_sequence_numbers
            .entry(member_did.to_owned())
            .or_insert(0);
    }

    /// Returns and post-increments this member's next outgoing sequence number.
    ///
    /// Returns 0 (and seeds the counter) if the member has no counter yet.
    pub fn next_sequence(&mut self, member_did: &str) -> u64 {
        let entry = self
            .member_sequence_numbers
            .entry(member_did.to_owned())
            .or_insert(0);
        let seq = *entry;
        *entry = entry.saturating_add(1);
        seq
    }

    /// Pushes an event onto the receive buffer, evicting the oldest at capacity.
    pub fn push_event(&mut self, event: ContextEvent) {
        if self.event_buffer.len() >= EVENT_BUFFER_CAP {
            self.event_buffer.pop_front();
        }
        self.event_buffer.push_back(event);
    }

    /// Drains all buffered receive events in FIFO order.
    pub fn drain_events(&mut self) -> Vec<ContextEvent> {
        self.event_buffer.drain(..).collect()
    }

    /// Returns the current event-log Merkle root.
    #[must_use]
    pub fn event_log_root(&self) -> [u8; 32] {
        root(&self.event_log)
    }

    /// Returns the number of leaves (events) in the event log.
    #[must_use]
    pub const fn event_log_leaf_count(&self) -> u64 {
        event_count(&self.event_log)
    }

    /// Returns a clone of the full ordered event stream.
    ///
    /// Used by the join path to hand a newly-added member the adder's prior log
    /// so they can replay it and converge (§7.3.1 context-state import).
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        self.event_log.events().to_vec()
    }

    /// Replays a verbatim event onto the log via the canonical append path.
    ///
    /// Unlike [`Self::append_log_event`], this does NOT recompute `sequence` or
    /// `prev_hash` — it appends the event exactly as received, so the canonical
    /// append validation ([`append_unsigned_event`]) enforces that the replayed
    /// event chains correctly onto the current log. Replaying the adder's full
    /// prior log this way reconstructs a byte-identical log on the joiner
    /// (identical leaves and identical root), which is the §9.9.3 convergence
    /// property realized by shared append code.
    ///
    /// # Errors
    ///
    /// Returns [`scp_event_log::EventLogError`] if the event does not chain onto
    /// the current log (sequence or `prev_hash` mismatch) — i.e. the replay
    /// stream is out of order or does not start from this log's current head.
    pub fn replay_event(&mut self, event: &Event) -> Result<(), scp_event_log::EventLogError> {
        append_unsigned_event(&mut self.event_log, event)?;
        Ok(())
    }

    /// Returns the event-log leaf hashes in sequence order.
    ///
    /// Each entry is the canonical leaf hash of the event at that sequence
    /// position. Two members that recorded the same logical event with the same
    /// committer-assigned inputs produce byte-identical leaf hashes here — the
    /// per-leaf form of the §9.9.3 convergence property the participant driver
    /// must satisfy across native and wasm32.
    #[must_use]
    pub fn event_log_leaf_hashes(&self) -> Vec<[u8; 32]> {
        self.event_log.leaves().to_vec()
    }

    /// Appends a protocol event to the context's event log.
    ///
    /// Constructs a full [`Event`] with the correct sequence number and
    /// `prev_hash` chain link, then delegates to
    /// [`append_unsigned_event`]. The leaf carries an empty signature: the
    /// driver MVP does not yet thread the on-device signing key into the leaf
    /// (the leaf-signing seam is a later custody slice). The leaf *preimage*
    /// (which excludes the signature) is what feeds the Merkle root, so an
    /// unsigned leaf still converges byte-for-byte across members.
    ///
    /// `timestamp_secs` is the **committer-assigned** convergent leaf timestamp
    /// (Unix seconds), matching the native runtime: every member that records
    /// the same logical event stamps the SAME timestamp (the creator's, copied
    /// by peers), NEVER each member's local `now()`. Per-member `now()` would
    /// diverge the leaf preimage and break the equal-count / equal-root
    /// convergence property a browser member and a native member must both
    /// satisfy (§7.3.1, §9.9.3).
    ///
    /// # Errors
    ///
    /// Returns [`scp_event_log::EventLogError`] if the append fails (sequence
    /// or `prev_hash` mismatch — unreachable here because both are computed
    /// from the current log state).
    pub fn append_log_event(
        &mut self,
        event_type: EventType,
        actor_did: &str,
        payload: Vec<u8>,
        timestamp_secs: u64,
    ) -> Result<(), scp_event_log::EventLogError> {
        let sequence = event_count(&self.event_log);
        let leaves = self.event_log.leaves();
        let prev_hash = leaves.last().copied().unwrap_or(GENESIS_PREV_HASH);
        let event = Event {
            event_type,
            actor_did: DID::from(actor_did.to_owned()),
            timestamp: timestamp_secs,
            sequence,
            payload: EventPayload { data: payload },
            prev_hash,
            signature: vec![],
        };
        append_unsigned_event(&mut self.event_log, &event)?;
        Ok(())
    }
}
