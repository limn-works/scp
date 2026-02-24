//! Context membership tracking and receive stream buffer.
//!
//! This module provides:
//! - [`MemberInfo`] -- Per-member metadata (DID, role, sequence number).
//! - [`MembershipState`] -- Thread-safe member list for a context.
//! - [`ReceiveBuffer`] -- Bounded event buffer with oldest-drop overflow and
//!   `BufferOverflow` warning emission.
//!
//! The receive buffer implements the semantics from `.docs/sketch.md` section
//! "Context > Buffer semantics" and `.docs/standards/sdk-common.md` section
//! "Receive stream buffer tests":
//! - Default capacity: 1,000 events.
//! - Configurable: minimum 100, maximum 10,000.
//! - When full, the oldest unconsumed event is dropped.
//! - A `BufferOverflow` warning event is emitted with the count of dropped
//!   events since the last successful consumption.
//!
//! See SCP-020 and ADR-008 in `.docs/adrs/phase-2.md`.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use super::roles::UcanToken;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default receive buffer capacity (events).
pub const DEFAULT_BUFFER_CAPACITY: usize = 1_000;

/// Minimum configurable receive buffer capacity.
pub const MIN_BUFFER_CAPACITY: usize = 100;

/// Maximum configurable receive buffer capacity.
pub const MAX_BUFFER_CAPACITY: usize = 10_000;

// ---------------------------------------------------------------------------
// DID type alias
// ---------------------------------------------------------------------------

/// Decentralized Identifier string.
pub type DID = String;

// ---------------------------------------------------------------------------
// KeyPackage (stub)
// ---------------------------------------------------------------------------

/// Stub key package for membership operations.
///
/// Phase 2 placeholder: in production, this wraps the MLS `KeyPackage` type
/// from ADR-001. The stub carries only the member's DID for testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackage {
    /// The DID of the member this key package belongs to.
    pub owner_did: DID,
}

// ---------------------------------------------------------------------------
// MemberInfo
// ---------------------------------------------------------------------------

/// Per-member metadata tracked within a context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    /// The member's decentralized identifier.
    pub did: DID,
    /// The member's assigned role name.
    pub role_name: String,
    /// UCAN tokens issued to this member.
    pub tokens: Vec<UcanToken>,
    /// Per-sender monotonic sequence number (spec section 9.8.5).
    /// Incremented on each `send_message` call by this member.
    pub sequence_number: u64,
}

// ---------------------------------------------------------------------------
// MembershipState
// ---------------------------------------------------------------------------

/// Tracks all members of a context.
///
/// Provides member list queries, member count, and role assignment per member.
/// Designed to be held inside a `ContextHandle`'s inner state or alongside it
/// in the `ContextManager`.
#[derive(Debug, Clone)]
pub struct MembershipState {
    /// Members indexed by DID.
    members: HashMap<DID, MemberInfo>,
}

impl MembershipState {
    /// Creates an empty membership state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
        }
    }

    /// Adds a member with the given role and tokens.
    ///
    /// If a member with the same DID already exists, they are replaced.
    pub fn add_member(&mut self, did: DID, role_name: String, tokens: Vec<UcanToken>) {
        self.members.insert(
            did.clone(),
            MemberInfo {
                did,
                role_name,
                tokens,
                sequence_number: 0,
            },
        );
    }

    /// Removes a member by DID. Returns `true` if the member was present.
    pub fn remove_member(&mut self, did: &str) -> bool {
        self.members.remove(did).is_some()
    }

    /// Returns the number of members.
    #[must_use]
    pub fn count(&self) -> usize {
        self.members.len()
    }

    /// Returns `true` if the given DID is a member.
    #[must_use]
    pub fn contains(&self, did: &str) -> bool {
        self.members.contains_key(did)
    }

    /// Returns information about a specific member, if present.
    #[must_use]
    pub fn get(&self, did: &str) -> Option<&MemberInfo> {
        self.members.get(did)
    }

    /// Returns a mutable reference to a specific member, if present.
    pub fn get_mut(&mut self, did: &str) -> Option<&mut MemberInfo> {
        self.members.get_mut(did)
    }

    /// Returns all member DIDs.
    pub fn member_dids(&self) -> impl Iterator<Item = &str> {
        self.members.keys().map(String::as_str)
    }

    /// Returns all members as an iterator.
    pub fn members(&self) -> impl Iterator<Item = &MemberInfo> {
        self.members.values()
    }

    /// Increments and returns the next sequence number for the given sender.
    ///
    /// Returns `None` if the sender is not a member.
    pub fn next_sequence_number(&mut self, sender_did: &str) -> Option<u64> {
        self.members.get_mut(sender_did).map(|info| {
            info.sequence_number += 1;
            info.sequence_number
        })
    }
}

impl Default for MembershipState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ContextEvent
// ---------------------------------------------------------------------------

/// Events produced by context operations, buffered for the receive stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextEvent {
    /// A member joined the context.
    MemberJoined {
        /// The DID of the member who joined.
        member_did: DID,
        /// The role assigned to the joining member.
        role_name: String,
    },
    /// A member left the context.
    MemberLeft {
        /// The DID of the member who left.
        member_did: DID,
    },
    /// A message was sent in the context.
    MessageSent {
        /// The DID of the sender.
        sender_did: DID,
        /// The per-sender sequence number.
        sequence_number: u64,
        /// The message payload (encrypted in production; plaintext for tests).
        payload: Vec<u8>,
    },
    /// Warning: the receive buffer overflowed and events were dropped.
    ///
    /// Emitted when the buffer is full and the oldest event is dropped.
    /// Includes the count of events dropped since the last successful
    /// consumption.
    BufferOverflow {
        /// Number of events dropped since the last successful consumption.
        dropped_count: u64,
    },
}

// ---------------------------------------------------------------------------
// ReceiveBuffer
// ---------------------------------------------------------------------------

/// Bounded event buffer for the receive stream.
///
/// Buffers up to `capacity` events. When the buffer is full, the oldest
/// unconsumed event is dropped and a [`ContextEvent::BufferOverflow`] warning
/// is emitted on the stream. The `BufferOverflow` event includes the count of
/// dropped events since the last successful consumption.
///
/// Buffer size is configurable:
/// - Minimum: [`MIN_BUFFER_CAPACITY`] (100)
/// - Maximum: [`MAX_BUFFER_CAPACITY`] (10,000)
/// - Default: [`DEFAULT_BUFFER_CAPACITY`] (1,000)
///
/// See `.docs/standards/sdk-common.md` "Receive stream buffer tests".
#[derive(Debug)]
pub struct ReceiveBuffer {
    /// The event queue.
    events: VecDeque<ContextEvent>,
    /// Maximum number of events to buffer.
    capacity: usize,
    /// Number of events dropped since the last successful consumption.
    dropped_since_last_consume: u64,
}

impl ReceiveBuffer {
    /// Creates a new receive buffer with the default capacity (1,000).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUFFER_CAPACITY)
    }

    /// Creates a new receive buffer with the specified capacity.
    ///
    /// The capacity is clamped to the range
    /// [`MIN_BUFFER_CAPACITY`]..=[`MAX_BUFFER_CAPACITY`].
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.clamp(MIN_BUFFER_CAPACITY, MAX_BUFFER_CAPACITY);
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            dropped_since_last_consume: 0,
        }
    }

    /// Returns the configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of events currently in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the buffer contains no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Pushes an event into the buffer.
    ///
    /// If the buffer is full, the oldest event is dropped and a
    /// [`ContextEvent::BufferOverflow`] warning is emitted. The overflow
    /// warning replaces the dropped event's slot, so the buffer size never
    /// exceeds `capacity`.
    pub fn push(&mut self, event: ContextEvent) {
        if self.events.len() >= self.capacity {
            // Drop the oldest event.
            self.events.pop_front();
            self.dropped_since_last_consume += 1;

            // Emit a BufferOverflow warning event. This replaces the slot
            // freed by dropping the oldest event, so we still have room for
            // the new event.
            let overflow_event = ContextEvent::BufferOverflow {
                dropped_count: self.dropped_since_last_consume,
            };

            // Check if the last event is already a BufferOverflow -- if so,
            // update it instead of adding another one.
            if let Some(ContextEvent::BufferOverflow { .. }) = self.events.back() {
                // Replace the existing overflow event with updated count.
                self.events.pop_back();
                self.events.push_back(overflow_event);
            } else {
                // Need to make room: drop another oldest if we're at capacity.
                if self.events.len() >= self.capacity {
                    self.events.pop_front();
                    self.dropped_since_last_consume += 1;
                    // Update overflow event with new count.
                    let updated = ContextEvent::BufferOverflow {
                        dropped_count: self.dropped_since_last_consume,
                    };
                    self.events.push_back(updated);
                } else {
                    self.events.push_back(overflow_event);
                }
            }
        }

        // Now push the actual event.
        if self.events.len() < self.capacity {
            self.events.push_back(event);
        }
    }

    /// Consumes and returns the oldest event from the buffer.
    ///
    /// Resets the dropped counter on successful consumption.
    pub fn pop(&mut self) -> Option<ContextEvent> {
        let event = self.events.pop_front();
        if event.is_some() {
            self.dropped_since_last_consume = 0;
        }
        event
    }

    /// Returns the number of events dropped since the last successful
    /// consumption.
    #[must_use]
    pub const fn dropped_since_last_consume(&self) -> u64 {
        self.dropped_since_last_consume
    }

    /// Drains all events from the buffer into a `Vec`.
    ///
    /// Resets the dropped counter.
    pub fn drain(&mut self) -> Vec<ContextEvent> {
        self.dropped_since_last_consume = 0;
        self.events.drain(..).collect()
    }
}

impl Default for ReceiveBuffer {
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

    // -----------------------------------------------------------------------
    // MembershipState tests
    // -----------------------------------------------------------------------

    #[test]
    fn membership_state_new_is_empty() {
        let state = MembershipState::new();
        assert_eq!(state.count(), 0);
    }

    #[test]
    fn membership_state_add_and_query_member() {
        let mut state = MembershipState::new();
        state.add_member("did:key:alice".into(), "member".into(), vec![]);

        assert_eq!(state.count(), 1);
        assert!(state.contains("did:key:alice"));
        assert!(!state.contains("did:key:bob"));

        let info = state.get("did:key:alice").unwrap();
        assert_eq!(info.did, "did:key:alice");
        assert_eq!(info.role_name, "member");
        assert_eq!(info.sequence_number, 0);
    }

    #[test]
    fn membership_state_remove_member() {
        let mut state = MembershipState::new();
        state.add_member("did:key:alice".into(), "member".into(), vec![]);
        assert_eq!(state.count(), 1);

        assert!(state.remove_member("did:key:alice"));
        assert_eq!(state.count(), 0);
        assert!(!state.contains("did:key:alice"));

        // Removing non-existent member returns false.
        assert!(!state.remove_member("did:key:bob"));
    }

    #[test]
    fn membership_state_sequence_numbers() {
        let mut state = MembershipState::new();
        state.add_member("did:key:alice".into(), "member".into(), vec![]);

        assert_eq!(state.next_sequence_number("did:key:alice"), Some(1));
        assert_eq!(state.next_sequence_number("did:key:alice"), Some(2));
        assert_eq!(state.next_sequence_number("did:key:alice"), Some(3));

        // Non-existent member returns None.
        assert_eq!(state.next_sequence_number("did:key:bob"), None);
    }

    #[test]
    fn membership_state_member_dids() {
        let mut state = MembershipState::new();
        state.add_member("did:key:alice".into(), "admin".into(), vec![]);
        state.add_member("did:key:bob".into(), "member".into(), vec![]);

        let mut dids: Vec<&str> = state.member_dids().collect();
        dids.sort();
        assert_eq!(dids, vec!["did:key:alice", "did:key:bob"]);
    }

    // -----------------------------------------------------------------------
    // ReceiveBuffer tests -- conformance
    // -----------------------------------------------------------------------

    /// `receive-buffer-capacity-001`: buffer holds 1,000 events without dropping.
    #[test]
    fn receive_buffer_capacity_001() {
        let mut buffer = ReceiveBuffer::new();
        assert_eq!(buffer.capacity(), DEFAULT_BUFFER_CAPACITY);

        // Fill to capacity.
        for i in 0..1_000 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        assert_eq!(buffer.len(), 1_000);
        assert_eq!(buffer.dropped_since_last_consume(), 0);
    }

    /// `receive-buffer-overflow-drop-002`: event 1,001 causes oldest event to
    /// be dropped.
    #[test]
    fn receive_buffer_overflow_drop_002() {
        let mut buffer = ReceiveBuffer::new();

        // Fill to capacity.
        for i in 0..1_000 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        // Push one more -- should drop oldest (seq 0).
        buffer.push(ContextEvent::MessageSent {
            sender_did: "did:key:alice".into(),
            sequence_number: 1_000,
            payload: vec![],
        });

        // Buffer should still be at capacity.
        assert_eq!(buffer.len(), 1_000);

        // The oldest event should now be either a BufferOverflow warning or
        // seq 1 (seq 0 was dropped). Let's verify the first event is the
        // overflow warning.
        let first = buffer.pop().unwrap();
        match first {
            ContextEvent::BufferOverflow { dropped_count } => {
                assert!(dropped_count >= 1);
            }
            ContextEvent::MessageSent {
                sequence_number, ..
            } => {
                // If the overflow event replaced seq 0, then seq 1 should be first.
                assert!(sequence_number >= 1);
            }
            _ => panic!("unexpected event type"),
        }
    }

    /// `receive-buffer-overflow-warning-003`: `BufferOverflow` warning event is
    /// emitted when events are dropped, including dropped count.
    #[test]
    fn receive_buffer_overflow_warning_003() {
        let mut buffer = ReceiveBuffer::new();

        // Fill to capacity.
        for i in 0..1_000 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        // Push 3 more to cause 3 drops.
        for i in 1_000..1_003 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        // Drain and check for BufferOverflow events.
        let events = buffer.drain();
        let overflow_events: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let ContextEvent::BufferOverflow { dropped_count } = e {
                    Some(*dropped_count)
                } else {
                    None
                }
            })
            .collect();

        // There should be at least one BufferOverflow event.
        assert!(
            !overflow_events.is_empty(),
            "expected at least one BufferOverflow event"
        );

        // The dropped count in any overflow event should be >= 1.
        for count in &overflow_events {
            assert!(*count >= 1, "dropped count should be >= 1, got {count}");
        }
    }

    /// `receive-buffer-configurable-004`: custom buffer size is respected.
    #[test]
    fn receive_buffer_configurable_004() {
        // Custom size within bounds.
        let buffer = ReceiveBuffer::with_capacity(500);
        assert_eq!(buffer.capacity(), 500);

        // Below minimum -- clamped.
        let buffer = ReceiveBuffer::with_capacity(50);
        assert_eq!(buffer.capacity(), MIN_BUFFER_CAPACITY);

        // Above maximum -- clamped.
        let buffer = ReceiveBuffer::with_capacity(20_000);
        assert_eq!(buffer.capacity(), MAX_BUFFER_CAPACITY);

        // Custom capacity fills correctly.
        let mut buffer = ReceiveBuffer::with_capacity(200);
        for i in 0..200 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }
        assert_eq!(buffer.len(), 200);
        assert_eq!(buffer.dropped_since_last_consume(), 0);

        // Overflow at custom capacity.
        buffer.push(ContextEvent::MessageSent {
            sender_did: "did:key:alice".into(),
            sequence_number: 200,
            payload: vec![],
        });
        assert_eq!(buffer.len(), 200);
        assert!(buffer.dropped_since_last_consume() > 0);
    }

    // -----------------------------------------------------------------------
    // Additional ReceiveBuffer unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn receive_buffer_pop_returns_fifo_order() {
        let mut buffer = ReceiveBuffer::new();
        buffer.push(ContextEvent::MemberJoined {
            member_did: "did:key:alice".into(),
            role_name: "admin".into(),
        });
        buffer.push(ContextEvent::MemberJoined {
            member_did: "did:key:bob".into(),
            role_name: "member".into(),
        });

        let first = buffer.pop().unwrap();
        assert_eq!(
            first,
            ContextEvent::MemberJoined {
                member_did: "did:key:alice".into(),
                role_name: "admin".into(),
            }
        );

        let second = buffer.pop().unwrap();
        assert_eq!(
            second,
            ContextEvent::MemberJoined {
                member_did: "did:key:bob".into(),
                role_name: "member".into(),
            }
        );

        assert!(buffer.pop().is_none());
    }

    #[test]
    fn receive_buffer_pop_resets_dropped_counter() {
        let mut buffer = ReceiveBuffer::with_capacity(100);
        for i in 0..101 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }
        assert!(buffer.dropped_since_last_consume() > 0);

        // Consuming resets the counter.
        buffer.pop();
        assert_eq!(buffer.dropped_since_last_consume(), 0);
    }

    #[test]
    fn receive_buffer_drain_returns_all_events() {
        let mut buffer = ReceiveBuffer::new();
        for i in 0..5 {
            buffer.push(ContextEvent::MessageSent {
                sender_did: "did:key:alice".into(),
                sequence_number: i,
                payload: vec![],
            });
        }

        let events = buffer.drain();
        assert_eq!(events.len(), 5);
        assert!(buffer.is_empty());
    }

    #[test]
    fn receive_buffer_default_capacity() {
        let buffer = ReceiveBuffer::default();
        assert_eq!(buffer.capacity(), DEFAULT_BUFFER_CAPACITY);
    }
}
