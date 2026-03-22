//! Sync alert types for event verification during reconciliation.
//!
//! Implements alert types raised during event log reconciliation (spec §23.13)
//! when per-event signature verification, sequence ordering, or hash chain
//! continuity checks detect anomalies.
//!
//! These alerts are reported to the application layer as part of the
//! reconnection protocol's Phase 3 (event log sync). They indicate
//! potential relay compromise, peer impersonation, or data tampering.

use serde::{Deserialize, Serialize};

use scp_identity::DID;

// ---------------------------------------------------------------------------
// Type aliases (match sync/mod.rs pattern)
// ---------------------------------------------------------------------------

/// A context identifier string.
pub type ContextId = String;

// ---------------------------------------------------------------------------
// EventSignatureFailure (§23.13, criterion 1-2)
// ---------------------------------------------------------------------------

/// Alert raised when a received event fails per-event signature verification
/// during reconciliation.
///
/// Each received event MUST be verified against the claimed sender's signing
/// key before being accepted into the local event log. If more than 3 events
/// from the same peer fail verification in a single reconciliation session,
/// the SDK MUST abort reconciliation with that peer.
///
/// See spec §23.13 criterion 1-2, §23.15 `EventSignatureFailure`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSignatureFailure {
    /// The context where the signature failure occurred.
    pub context_id: ContextId,
    /// The sequence number of the event that failed verification.
    pub event_sequence: u64,
    /// The DID claimed as the event's signer.
    pub expected_signer: DID,
    /// The raw signature bytes that failed verification.
    #[serde(with = "serde_bytes")]
    pub received_signature: Vec<u8>,
}

impl std::fmt::Display for EventSignatureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EventSignatureFailure in context {} at sequence {}: \
             signature from {} failed verification",
            self.context_id, self.event_sequence, self.expected_signer,
        )
    }
}

// ---------------------------------------------------------------------------
// EventGapDetected (§23.13, criterion 3-4)
// ---------------------------------------------------------------------------

/// Alert raised when a gap in event sequence numbers cannot be filled
/// during reconciliation.
///
/// If a peer provides events with gaps in the sequence (e.g., event 5 and
/// event 8 but not events 6 and 7), the client requests the missing events.
/// If no peer can provide them within the reconnection timeout, the events
/// after the gap are discarded and this alert is raised.
///
/// See spec §23.13 criterion 3-4, §23.15 `EventGapDetected`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventGapDetected {
    /// The context where the gap was detected.
    pub context_id: ContextId,
    /// The range of missing sequence numbers (inclusive start, inclusive end).
    pub missing_range: (u64, u64),
    /// The DID of the peer that provided the events surrounding the gap.
    pub peer_did: DID,
}

impl std::fmt::Display for EventGapDetected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EventGapDetected in context {}: missing sequences {}-{} \
             (peer: {})",
            self.context_id, self.missing_range.0, self.missing_range.1, self.peer_did,
        )
    }
}

// ---------------------------------------------------------------------------
// EventChainTampered (§23.13, criterion 5-6)
// ---------------------------------------------------------------------------

/// Alert raised when hash chain continuity is broken during reconciliation,
/// indicating tampering or data loss.
///
/// Each event's `prev_hash` field must chain to the hash of the immediately
/// preceding event. When a break is detected, the SDK rejects the event and
/// all subsequent events from that peer, then attempts to obtain a consistent
/// chain from a different peer. If no peer can provide one, the context's
/// event log is marked as `Unverified`.
///
/// See spec §23.13 criterion 5-6, §23.15 `EventChainTampered`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventChainTampered {
    /// The context where the chain break was detected.
    pub context_id: ContextId,
    /// The sequence number at which the hash chain breaks.
    pub break_point_sequence: u64,
    /// The expected `prev_hash` (hash of the event at `sequence - 1`).
    pub expected_prev_hash: [u8; 32],
    /// The `prev_hash` value in the received event that does not match.
    pub received_prev_hash: [u8; 32],
}

impl std::fmt::Display for EventChainTampered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EventChainTampered in context {} at sequence {}: \
             expected prev_hash {:?}, received {:?}",
            self.context_id,
            self.break_point_sequence,
            &self.expected_prev_hash[..4],
            &self.received_prev_hash[..4],
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn event_signature_failure_serialization_roundtrip() {
        let alert = EventSignatureFailure {
            context_id: "ctx-1".to_owned(),
            event_sequence: 42,
            expected_signer: DID::from("did:dht:zMallory"),
            received_signature: vec![0xAA; 64],
        };
        let json = serde_json::to_string(&alert).unwrap();
        let deserialized: EventSignatureFailure = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.context_id, "ctx-1");
        assert_eq!(deserialized.event_sequence, 42);
        assert_eq!(deserialized.expected_signer, DID::from("did:dht:zMallory"));
        assert_eq!(deserialized.received_signature.len(), 64);
    }

    #[test]
    fn event_signature_failure_display() {
        let alert = EventSignatureFailure {
            context_id: "ctx-1".to_owned(),
            event_sequence: 42,
            expected_signer: DID::from("did:dht:zMallory"),
            received_signature: vec![0u8; 64],
        };
        let s = alert.to_string();
        assert!(s.contains("ctx-1"));
        assert!(s.contains("42"));
        assert!(s.contains("did:dht:zMallory"));
    }

    #[test]
    fn event_gap_detected_serialization_roundtrip() {
        let alert = EventGapDetected {
            context_id: "ctx-2".to_owned(),
            missing_range: (6, 7),
            peer_did: DID::from("did:dht:zBob"),
        };
        let json = serde_json::to_string(&alert).unwrap();
        let deserialized: EventGapDetected = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.context_id, "ctx-2");
        assert_eq!(deserialized.missing_range, (6, 7));
        assert_eq!(deserialized.peer_did, DID::from("did:dht:zBob"));
    }

    #[test]
    fn event_gap_detected_display() {
        let alert = EventGapDetected {
            context_id: "ctx-2".to_owned(),
            missing_range: (6, 7),
            peer_did: DID::from("did:dht:zBob"),
        };
        let s = alert.to_string();
        assert!(s.contains("ctx-2"));
        assert!(s.contains('6'));
        assert!(s.contains('7'));
        assert!(s.contains("did:dht:zBob"));
    }

    #[test]
    fn event_chain_tampered_serialization_roundtrip() {
        let alert = EventChainTampered {
            context_id: "ctx-3".to_owned(),
            break_point_sequence: 100,
            expected_prev_hash: [0xAA; 32],
            received_prev_hash: [0xBB; 32],
        };
        let json = serde_json::to_string(&alert).unwrap();
        let deserialized: EventChainTampered = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.context_id, "ctx-3");
        assert_eq!(deserialized.break_point_sequence, 100);
        assert_eq!(deserialized.expected_prev_hash, [0xAA; 32]);
        assert_eq!(deserialized.received_prev_hash, [0xBB; 32]);
    }

    #[test]
    fn event_chain_tampered_display() {
        let alert = EventChainTampered {
            context_id: "ctx-3".to_owned(),
            break_point_sequence: 100,
            expected_prev_hash: [0xAA; 32],
            received_prev_hash: [0xBB; 32],
        };
        let s = alert.to_string();
        assert!(s.contains("ctx-3"));
        assert!(s.contains("100"));
    }

    #[test]
    fn event_gap_single_missing_sequence() {
        let alert = EventGapDetected {
            context_id: "ctx-1".to_owned(),
            missing_range: (5, 5),
            peer_did: DID::from("did:dht:zPeer"),
        };
        assert_eq!(alert.missing_range.0, alert.missing_range.1);
    }

    #[test]
    fn event_chain_tampered_at_sequence_one() {
        let alert = EventChainTampered {
            context_id: "ctx-1".to_owned(),
            break_point_sequence: 1,
            expected_prev_hash: [0u8; 32],
            received_prev_hash: [1u8; 32],
        };
        assert_eq!(
            alert.break_point_sequence, 1,
            "chain break at sequence 1 means the very first link is tampered"
        );
    }
}
