//! Payment receipt verification and history queries.
//!
//! Provides the [`PaymentVerifier`] trait for verifying payment receipts
//! against payment adapters, and the [`payment_history`] function for
//! retrieving receipts from a context's event log.
//!
//! See spec section 19.6 (Payment Receipts and Provenance) and ADR-033.

use serde::{Deserialize, Serialize};

use super::adapter::{PaymentError, PaymentReceipt, VerificationResult};
use crate::event_log::{Event, EventType};

// ---------------------------------------------------------------------------
// PaymentVerifier
// ---------------------------------------------------------------------------

/// Trait for verifying payment receipts against a payment adapter.
///
/// Implementations check the adapter-specific proof (on-chain state, preimage
/// hash, etc.) to confirm the payment actually occurred. This is the
/// verification half of the adapter contract, extracted for use by receipt
/// consumers that do not need the full [`super::adapter::PaymentAdapter`]
/// trait.
///
/// See spec section 19.6.
pub trait PaymentVerifier: Send + Sync {
    /// Returns the adapter identifier this verifier handles.
    fn adapter_id(&self) -> &str;

    /// Verifies a payment receipt against the payment rail.
    ///
    /// Checks the adapter-specific proof (on-chain transaction hash, preimage,
    /// transaction signature, etc.) to confirm the payment actually occurred
    /// and the receipt fields match.
    fn verify(
        &self,
        receipt: &PaymentReceipt,
    ) -> impl std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send;
}

// ---------------------------------------------------------------------------
// ReceiptFilter
// ---------------------------------------------------------------------------

/// Optional filter criteria for [`payment_history`] queries.
///
/// All fields are optional. When `None`, no filtering is applied for that
/// field. When multiple fields are set, they are AND-composed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiptFilter {
    /// Filter by payer DID.
    pub payer: Option<String>,
    /// Filter by payee DID.
    pub payee: Option<String>,
    /// Only return receipts with timestamp >= this value.
    pub after_timestamp: Option<u64>,
    /// Only return receipts with timestamp <= this value.
    pub before_timestamp: Option<u64>,
}

// ---------------------------------------------------------------------------
// payment_history
// ---------------------------------------------------------------------------

/// Retrieves payment receipts from a context's event log.
///
/// Scans the given events for [`EventType::PaymentReceived`] events and
/// deserializes their payloads into [`PaymentReceipt`] records. Events that
/// fail deserialization are silently skipped (they may be from a different
/// protocol version).
///
/// The optional `filter` parameter allows narrowing results by payer, payee,
/// or time range.
///
/// Corresponds to the SDK surface `SCP.Economy.paymentHistory(context)`
/// (spec section 19.11).
#[must_use] 
pub fn payment_history(events: &[Event], filter: Option<&ReceiptFilter>) -> Vec<PaymentReceipt> {
    let mut receipts = Vec::new();

    for event in events {
        if event.event_type != EventType::PaymentReceived {
            continue;
        }

        // Attempt to deserialize the receipt from the event payload.
        let receipt: PaymentReceipt = match serde_json::from_slice(&event.payload.data) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Apply optional filter.
        if let Some(f) = filter {
            if let Some(ref payer) = f.payer
                && receipt.payer.as_ref() != payer.as_str() {
                    continue;
                }
            if let Some(ref payee) = f.payee
                && receipt.payee.as_ref() != payee.as_str() {
                    continue;
                }
            if let Some(after) = f.after_timestamp
                && receipt.timestamp < after {
                    continue;
                }
            if let Some(before) = f.before_timestamp
                && receipt.timestamp > before {
                    continue;
                }
        }

        receipts.push(receipt);
    }

    receipts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
)]
mod tests {
    use super::*;
    use crate::economy::types::{Amount, CurrencyCode, PaidActionType};
    use crate::event_log::{EventPayload, EventType};
    use crate::identity::DID;

    /// Creates a test `PaymentReceipt`.
    fn make_receipt(payer: &str, payee: &str, amount: u64, timestamp: u64) -> PaymentReceipt {
        PaymentReceipt {
            receipt_id: [0xAA; 32],
            payer: DID::from(payer),
            payee: DID::from(payee),
            amount: Amount::new(amount),
            currency: CurrencyCode::from("USD"),
            action_type: PaidActionType::MessageSend,
            context_id: Some("ctx-test".to_string()),
            adapter_id: "test".to_string(),
            adapter_proof: vec![0x01, 0x02],
            timestamp,
            signature: vec![0xFF; 64],
        }
    }

    /// Creates an `Event` with a `PaymentReceived` type carrying a serialized
    /// receipt in its payload.
    fn make_payment_event(receipt: &PaymentReceipt, sequence: u64) -> Event {
        let payload_data = serde_json::to_vec(receipt).unwrap();
        Event {
            event_type: EventType::PaymentReceived,
            actor_did: receipt.payer.clone(),
            timestamp: receipt.timestamp,
            sequence,
            payload: EventPayload { data: payload_data },
            prev_hash: [0u8; 32],
            signature: vec![0xFF; 64],
        }
    }

    /// Creates a non-payment event.
    fn make_message_event(sequence: u64) -> Event {
        Event {
            event_type: EventType::MessageSent,
            actor_did: DID::from("did:dht:z6MkAlice"),
            timestamp: 1_000_000,
            sequence,
            payload: EventPayload {
                data: b"hello".to_vec(),
            },
            prev_hash: [0u8; 32],
            signature: vec![0xFF; 64],
        }
    }

    // -------------------------------------------------------------------
    // PaymentReceipt serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn payment_receipt_serde_roundtrip() {
        let receipt = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 1000, 1_700_000_000);
        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: PaymentReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.receipt_id, deserialized.receipt_id);
        assert_eq!(receipt.payer, deserialized.payer);
        assert_eq!(receipt.payee, deserialized.payee);
        assert_eq!(receipt.amount, deserialized.amount);
        assert_eq!(receipt.currency, deserialized.currency);
        assert_eq!(receipt.action_type, deserialized.action_type);
        assert_eq!(receipt.context_id, deserialized.context_id);
        assert_eq!(receipt.adapter_id, deserialized.adapter_id);
        assert_eq!(receipt.adapter_proof, deserialized.adapter_proof);
        assert_eq!(receipt.timestamp, deserialized.timestamp);
        assert_eq!(receipt.signature, deserialized.signature);
    }

    // -------------------------------------------------------------------
    // payment_history returns receipts from PaymentReceived events
    // -------------------------------------------------------------------

    #[test]
    fn payment_history_returns_receipts_from_payment_events() {
        let receipt1 = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 100, 1_000_000);
        let receipt2 = make_receipt("did:dht:z6MkBob", "did:dht:z6MkAlice", 200, 1_000_001);

        let events = vec![
            make_payment_event(&receipt1, 0),
            make_message_event(1),
            make_payment_event(&receipt2, 2),
        ];

        let history = payment_history(&events, None);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].amount, Amount::new(100));
        assert_eq!(history[1].amount, Amount::new(200));
    }

    // -------------------------------------------------------------------
    // payment_history skips non-payment events
    // -------------------------------------------------------------------

    #[test]
    fn payment_history_skips_non_payment_events() {
        let events = vec![
            make_message_event(0),
            make_message_event(1),
            make_message_event(2),
        ];

        let history = payment_history(&events, None);
        assert!(history.is_empty());
    }

    // -------------------------------------------------------------------
    // payment_history returns empty for empty event list
    // -------------------------------------------------------------------

    #[test]
    fn payment_history_returns_empty_for_no_events() {
        let history = payment_history(&[], None);
        assert!(history.is_empty());
    }

    // -------------------------------------------------------------------
    // payment_history filters by payer
    // -------------------------------------------------------------------

    #[test]
    fn payment_history_filters_by_payer() {
        let receipt_alice = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 100, 1_000_000);
        let receipt_bob = make_receipt("did:dht:z6MkBob", "did:dht:z6MkAlice", 200, 1_000_001);

        let events = vec![
            make_payment_event(&receipt_alice, 0),
            make_payment_event(&receipt_bob, 1),
        ];

        let filter = ReceiptFilter {
            payer: Some("did:dht:z6MkAlice".to_string()),
            ..Default::default()
        };

        let history = payment_history(&events, Some(&filter));
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].payer, DID::from("did:dht:z6MkAlice"));
    }

    // -------------------------------------------------------------------
    // payment_history filters by payee
    // -------------------------------------------------------------------

    #[test]
    fn payment_history_filters_by_payee() {
        let receipt1 = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 100, 1_000_000);
        let receipt2 = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkCharlie", 200, 1_000_001);

        let events = vec![
            make_payment_event(&receipt1, 0),
            make_payment_event(&receipt2, 1),
        ];

        let filter = ReceiptFilter {
            payee: Some("did:dht:z6MkCharlie".to_string()),
            ..Default::default()
        };

        let history = payment_history(&events, Some(&filter));
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].payee, DID::from("did:dht:z6MkCharlie"));
    }

    // -------------------------------------------------------------------
    // payment_history filters by time range
    // -------------------------------------------------------------------

    #[test]
    fn payment_history_filters_by_time_range() {
        let receipt1 = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 100, 1_000_000);
        let receipt2 = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 200, 2_000_000);
        let receipt3 = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 300, 3_000_000);

        let events = vec![
            make_payment_event(&receipt1, 0),
            make_payment_event(&receipt2, 1),
            make_payment_event(&receipt3, 2),
        ];

        let filter = ReceiptFilter {
            after_timestamp: Some(1_500_000),
            before_timestamp: Some(2_500_000),
            ..Default::default()
        };

        let history = payment_history(&events, Some(&filter));
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].amount, Amount::new(200));
    }

    // -------------------------------------------------------------------
    // payment_history with combined filters
    // -------------------------------------------------------------------

    #[test]
    fn payment_history_combined_filters() {
        let receipt1 = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 100, 1_000_000);
        let receipt2 = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 200, 2_000_000);
        let receipt3 = make_receipt("did:dht:z6MkBob", "did:dht:z6MkAlice", 300, 2_000_000);

        let events = vec![
            make_payment_event(&receipt1, 0),
            make_payment_event(&receipt2, 1),
            make_payment_event(&receipt3, 2),
        ];

        let filter = ReceiptFilter {
            payer: Some("did:dht:z6MkAlice".to_string()),
            after_timestamp: Some(1_500_000),
            ..Default::default()
        };

        let history = payment_history(&events, Some(&filter));
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].amount, Amount::new(200));
    }

    // -------------------------------------------------------------------
    // payment_history skips malformed payloads gracefully
    // -------------------------------------------------------------------

    #[test]
    fn payment_history_skips_malformed_payloads() {
        let good_receipt = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 100, 1_000_000);

        let bad_event = Event {
            event_type: EventType::PaymentReceived,
            actor_did: DID::from("did:dht:z6MkAlice"),
            timestamp: 1_000_000,
            sequence: 0,
            payload: EventPayload {
                data: b"not valid json".to_vec(),
            },
            prev_hash: [0u8; 32],
            signature: vec![0xFF; 64],
        };

        let events = vec![bad_event, make_payment_event(&good_receipt, 1)];

        let history = payment_history(&events, None);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].amount, Amount::new(100));
    }

    // -------------------------------------------------------------------
    // DataProvenance extension with payment fields
    // -------------------------------------------------------------------

    #[test]
    fn data_provenance_payment_fields_roundtrip() {
        use crate::context::MemoryScope;
        use crate::provenance::{DataProvenance, DiscoveryMethod, SourceType};
        use std::time::Duration;

        let provenance = DataProvenance {
            source_context: "ctx-paid".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec![DID::from("did:dht:z6MkAlice")],
            purpose: Some("paid tool output".to_string()),
            discovery_method: DiscoveryMethod::None,
            age: Duration::from_secs(60),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: Some(Amount::new(500)),
            payment_adapter: Some("x402".to_string()),
            payment_receipt_id: Some([0xBB; 32]),
        };

        let json = serde_json::to_string(&provenance).unwrap();
        let deserialized: DataProvenance = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.payment_amount, Some(Amount::new(500)));
        assert_eq!(deserialized.payment_adapter.as_deref(), Some("x402"));
        assert_eq!(deserialized.payment_receipt_id, Some([0xBB; 32]));
    }

    // -------------------------------------------------------------------
    // DataProvenance payment fields default to None
    // -------------------------------------------------------------------

    #[test]
    fn data_provenance_payment_fields_default_none() {
        use crate::context::MemoryScope;
        use crate::provenance::{DataProvenance, DiscoveryMethod, SourceType};
        use std::time::Duration;

        let provenance = DataProvenance {
            source_context: "ctx-free".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec![],
            purpose: None,
            discovery_method: DiscoveryMethod::None,
            age: Duration::from_secs(0),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        assert!(provenance.payment_amount.is_none());
        assert!(provenance.payment_adapter.is_none());
        assert!(provenance.payment_receipt_id.is_none());
    }

    // -------------------------------------------------------------------
    // Event log integration: economic event types have stable tags
    // -------------------------------------------------------------------

    #[test]
    fn economic_event_types_are_distinct() {
        assert_ne!(EventType::PaymentReceived, EventType::EconomicPolicyChanged);
        assert_ne!(EventType::PaymentReceived, EventType::SpendingUcanGranted);
        assert_ne!(EventType::PaymentReceived, EventType::SpendingUcanRevoked);
        assert_ne!(
            EventType::EconomicPolicyChanged,
            EventType::SpendingUcanGranted
        );
        assert_ne!(
            EventType::EconomicPolicyChanged,
            EventType::SpendingUcanRevoked
        );
        assert_ne!(
            EventType::SpendingUcanGranted,
            EventType::SpendingUcanRevoked
        );
    }

    // -------------------------------------------------------------------
    // Economic event types serialize/deserialize correctly
    // -------------------------------------------------------------------

    #[test]
    fn economic_event_types_serde_roundtrip() {
        let event_types = [
            EventType::PaymentReceived,
            EventType::EconomicPolicyChanged,
            EventType::SpendingUcanGranted,
            EventType::SpendingUcanRevoked,
        ];

        for event_type in &event_types {
            let json = serde_json::to_string(event_type).unwrap();
            let deserialized: EventType = serde_json::from_str(&json).unwrap();
            assert_eq!(*event_type, deserialized);
        }
    }
}
