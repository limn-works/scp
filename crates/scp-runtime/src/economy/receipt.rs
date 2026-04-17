//! Payment receipt verification and history queries.
//!
//! Provides the [`PaymentVerifier`] trait for verifying payment receipts
//! against payment adapters, the [`verify_receipts`] function for batch
//! verification of receipts against registered verifiers, and the
//! [`payment_history`] function for retrieving receipts from a context's
//! event log.
//!
//! See spec section 19.2.1 (Adapter Trait), 19.6 (Payment Receipts and
//! Provenance), and ADR-033.

use serde::{Deserialize, Serialize};

use super::adapter::{PaymentAdapter, PaymentError, PaymentReceipt, VerificationResult};
use scp_event_log::{Event, EventType};

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
/// See spec section 19.2.1 (Adapter Trait).
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
// Blanket impl: PaymentAdapter -> PaymentVerifier
// ---------------------------------------------------------------------------

/// Every [`PaymentAdapter`] automatically implements [`PaymentVerifier`].
///
/// The `PaymentVerifier` trait is the verification-only subset of
/// `PaymentAdapter`, extracted so receipt consumers that do not need
/// authorize/capture/void/refund can accept a narrower interface. This
/// blanket impl ensures adapters satisfy both traits without manual wiring.
impl<T: PaymentAdapter> PaymentVerifier for T {
    fn adapter_id(&self) -> &str {
        PaymentAdapter::adapter_id(self)
    }

    fn verify(
        &self,
        receipt: &PaymentReceipt,
    ) -> impl std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send {
        PaymentAdapter::verify(self, receipt)
    }
}

// ---------------------------------------------------------------------------
// ReceiptVerificationError
// ---------------------------------------------------------------------------

/// Error returned by [`verify_receipts`] when verification of a receipt fails.
///
/// Distinguishes between adapter-level verification failures and the absence
/// of a verifier for a receipt's adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptVerificationError {
    /// No verifier registered for this receipt's `adapter_id`.
    NoVerifierForAdapter {
        /// The receipt that could not be verified.
        receipt_id: [u8; 32],
        /// The adapter identifier from the receipt.
        adapter_id: String,
    },
    /// The verifier returned an error.
    VerificationFailed {
        /// The receipt that failed verification.
        receipt_id: [u8; 32],
        /// The underlying adapter error.
        error: PaymentError,
    },
}

impl std::fmt::Display for ReceiptVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoVerifierForAdapter {
                adapter_id,
                receipt_id,
            } => write!(
                f,
                "no verifier for adapter {adapter_id:?} (receipt {receipt_id:02x?})"
            ),
            Self::VerificationFailed { receipt_id, error } => {
                write!(
                    f,
                    "verification failed for receipt {receipt_id:02x?}: {error}"
                )
            }
        }
    }
}

impl std::error::Error for ReceiptVerificationError {}

// ---------------------------------------------------------------------------
// ReceiptVerification
// ---------------------------------------------------------------------------

/// Result of verifying a single receipt.
#[derive(Clone, Debug)]
pub struct ReceiptVerification {
    /// The receipt that was verified.
    pub receipt_id: [u8; 32],
    /// The verification result from the adapter.
    ///
    /// **Important:** A successful verification (`Ok`) does NOT guarantee
    /// the receipt is valid. You MUST check [`VerificationResult::valid`]
    /// to determine whether the payment proof actually verified against the
    /// payment rail. `Ok` only means the adapter was found and did not
    /// return a transport/protocol error.
    pub result: VerificationResult,
}

/// Returns `true` if every result in the slice is `Ok` with
/// [`VerificationResult::valid`] == `true`.
///
/// Returns `false` if any result is `Err` or has `valid == false`.
/// Returns `true` for an empty slice (vacuously).
#[must_use]
pub fn all_receipts_valid(
    results: &[Result<ReceiptVerification, ReceiptVerificationError>],
) -> bool {
    results
        .iter()
        .all(|r| r.as_ref().is_ok_and(|v| v.result.valid))
}

// ---------------------------------------------------------------------------
// verify_receipts
// ---------------------------------------------------------------------------

/// Verifies a batch of payment receipts against registered verifiers.
///
/// For each receipt, selects the verifier whose `adapter_id()` matches the
/// receipt's `adapter_id` field, then calls `verify()`. Returns a
/// per-receipt `Result` so that individual failures do not prevent other
/// receipts from being verified (no fail-fast).
///
/// **Important:** An `Ok` result does NOT mean the receipt is valid.
/// You MUST check [`VerificationResult::valid`] on each successful result.
/// Use [`all_receipts_valid`] as a convenience check across the full batch.
///
/// This function wires [`PaymentVerifier`] into the receipt verification
/// flow, enabling receipt consumers to verify receipts from
/// [`payment_history`] without needing a full [`PaymentAdapter`].
///
/// See spec section 19.2.1 (Adapter Trait).
pub async fn verify_receipts<V: PaymentVerifier>(
    verifiers: &[&V],
    receipts: &[PaymentReceipt],
) -> Vec<Result<ReceiptVerification, ReceiptVerificationError>> {
    let mut results = Vec::with_capacity(receipts.len());

    for receipt in receipts {
        let verifier = verifiers
            .iter()
            .find(|v| v.adapter_id() == receipt.adapter_id);

        match verifier {
            None => {
                results.push(Err(ReceiptVerificationError::NoVerifierForAdapter {
                    receipt_id: receipt.receipt_id,
                    adapter_id: receipt.adapter_id.clone(),
                }));
            }
            Some(v) => match v.verify(receipt).await {
                Ok(result) => {
                    results.push(Ok(ReceiptVerification {
                        receipt_id: receipt.receipt_id,
                        result,
                    }));
                }
                Err(e) => {
                    results.push(Err(ReceiptVerificationError::VerificationFailed {
                        receipt_id: receipt.receipt_id,
                        error: e,
                    }));
                }
            },
        }
    }

    results
}

/// Verifies a batch of payment receipts against heterogeneous verifiers.
///
/// Like [`verify_receipts`], but accepts verifiers as trait objects
/// (`&dyn PaymentVerifierDyn`), allowing different verifier types for
/// different adapters. Returns per-receipt results (no fail-fast).
///
/// **Important:** An `Ok` result does NOT mean the receipt is valid.
/// You MUST check [`VerificationResult::valid`] on each successful result.
/// Use [`all_receipts_valid`] as a convenience check across the full batch.
///
/// See spec section 19.2.1 (Adapter Trait).
pub async fn verify_receipts_dyn(
    verifiers: &[&dyn PaymentVerifierDyn],
    receipts: &[PaymentReceipt],
) -> Vec<Result<ReceiptVerification, ReceiptVerificationError>> {
    let mut results = Vec::with_capacity(receipts.len());

    for receipt in receipts {
        let verifier = verifiers
            .iter()
            .find(|v| v.adapter_id() == receipt.adapter_id);

        match verifier {
            None => {
                results.push(Err(ReceiptVerificationError::NoVerifierForAdapter {
                    receipt_id: receipt.receipt_id,
                    adapter_id: receipt.adapter_id.clone(),
                }));
            }
            Some(v) => match v.verify_dyn(receipt).await {
                Ok(result) => {
                    results.push(Ok(ReceiptVerification {
                        receipt_id: receipt.receipt_id,
                        result,
                    }));
                }
                Err(e) => {
                    results.push(Err(ReceiptVerificationError::VerificationFailed {
                        receipt_id: receipt.receipt_id,
                        error: e,
                    }));
                }
            },
        }
    }

    results
}

// ---------------------------------------------------------------------------
// PaymentVerifierDyn — object-safe variant
// ---------------------------------------------------------------------------

/// Object-safe variant of [`PaymentVerifier`] for use with trait objects.
///
/// The base [`PaymentVerifier`] trait uses RPITIT (return-position impl
/// trait in trait), which prevents `dyn PaymentVerifier`. This trait uses
/// boxed futures instead, enabling `&dyn PaymentVerifierDyn` in
/// [`verify_receipts_dyn`].
pub trait PaymentVerifierDyn: Send + Sync {
    /// Returns the adapter identifier this verifier handles.
    fn adapter_id(&self) -> &str;

    /// Verifies a payment receipt against the payment rail.
    fn verify_dyn<'a>(
        &'a self,
        receipt: &'a PaymentReceipt,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send + 'a>,
    >;
}

/// Blanket impl: every [`PaymentVerifier`] is also [`PaymentVerifierDyn`].
impl<T: PaymentVerifier> PaymentVerifierDyn for T {
    fn adapter_id(&self) -> &str {
        PaymentVerifier::adapter_id(self)
    }

    fn verify_dyn<'a>(
        &'a self,
        receipt: &'a PaymentReceipt,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send + 'a>,
    > {
        Box::pin(PaymentVerifier::verify(self, receipt))
    }
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
                && receipt.payer.as_ref() != payer.as_str()
            {
                continue;
            }
            if let Some(ref payee) = f.payee
                && receipt.payee.as_ref() != payee.as_str()
            {
                continue;
            }
            if let Some(after) = f.after_timestamp
                && receipt.timestamp < after
            {
                continue;
            }
            if let Some(before) = f.before_timestamp
                && receipt.timestamp > before
            {
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
    clippy::similar_names
)]
mod tests {
    use super::*;
    use scp_event_log::{EventPayload, EventType};
    use scp_identity::DID;
    use scp_protocol::economy::types::{Amount, CurrencyCode, PaidActionType};

    /// Creates a test `PaymentReceipt` with a configurable `receipt_id`.
    fn make_receipt_with_id(
        receipt_id: [u8; 32],
        payer: &str,
        payee: &str,
        amount: u64,
        timestamp: u64,
    ) -> PaymentReceipt {
        PaymentReceipt {
            receipt_id,
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

    /// Creates a test `PaymentReceipt` with the default `receipt_id` `[0xAA; 32]`.
    fn make_receipt(payer: &str, payee: &str, amount: u64, timestamp: u64) -> PaymentReceipt {
        make_receipt_with_id([0xAA; 32], payer, payee, amount, timestamp)
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
        use scp_protocol::context::MemoryScope;
        use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
        use std::time::Duration;

        let provenance = DataProvenance {
            source_context: "ctx-paid".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec![DID::from("did:dht:z6MkAlice")],
            purpose: Some("paid tool output".to_string()),
            discovery_method: DiscoveryMethod::OutOfBand,
            age: Duration::from_mins(1),
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
        use scp_protocol::context::MemoryScope;
        use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
        use std::time::Duration;

        let provenance = DataProvenance {
            source_context: "ctx-free".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec![],
            purpose: None,
            discovery_method: DiscoveryMethod::OutOfBand,
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

    // ===================================================================
    // PaymentVerifier + verify_receipts tests
    // ===================================================================

    use crate::economy::adapter::{
        AdapterCapabilities, PaymentAuthorization, PaymentMetadata, RefundConfirmation,
    };

    /// Controls the verification behavior of [`StubAdapter`].
    #[derive(Clone, Copy)]
    enum StubVerifyMode {
        /// `verify` returns `Ok(VerificationResult { valid: true, .. })`.
        ValidTrue,
        /// `verify` returns `Ok(VerificationResult { valid: false, .. })`.
        ValidFalse,
        /// `verify` returns `Err(PaymentError::InvalidReceipt(..))`.
        Error,
    }

    /// Minimal test adapter that implements `PaymentAdapter` (and therefore
    /// `PaymentVerifier` via the blanket impl).
    struct StubAdapter {
        id: &'static str,
        /// Controls verify behavior.
        verify_mode: StubVerifyMode,
    }

    impl PaymentAdapter for StubAdapter {
        fn adapter_id(&self) -> &str {
            self.id
        }

        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities {
                supported_currencies: vec![CurrencyCode::from("USD")],
                supports_streaming: false,
                supports_batch_auth: false,
                supports_single_step: false,
                min_amount: None,
                max_amount: None,
                typical_settlement_ms: 0,
                requires_facilitator: false,
            }
        }

        async fn authorize(
            &self,
            _payer: &DID,
            _payee: &DID,
            _amount: Amount,
            _currency: CurrencyCode,
            _metadata: PaymentMetadata,
        ) -> Result<PaymentAuthorization, PaymentError> {
            Err(PaymentError::AdapterError("not implemented".into()))
        }

        async fn capture(
            &self,
            _auth: &PaymentAuthorization,
        ) -> Result<PaymentReceipt, PaymentError> {
            Err(PaymentError::AdapterError("not implemented".into()))
        }

        async fn void(&self, _auth: &PaymentAuthorization) -> Result<(), PaymentError> {
            Err(PaymentError::AdapterError("not implemented".into()))
        }

        async fn verify_authorization(
            &self,
            _auth: &PaymentAuthorization,
        ) -> Result<(), PaymentError> {
            Err(PaymentError::AdapterError("not implemented".into()))
        }

        async fn verify(
            &self,
            receipt: &PaymentReceipt,
        ) -> Result<VerificationResult, PaymentError> {
            match self.verify_mode {
                StubVerifyMode::ValidTrue => Ok(VerificationResult {
                    valid: true,
                    adapter_id: self.id.to_string(),
                    verified_amount: receipt.amount,
                    verified_currency: receipt.currency,
                    verification_timestamp: receipt.timestamp,
                }),
                StubVerifyMode::ValidFalse => Ok(VerificationResult {
                    valid: false,
                    adapter_id: self.id.to_string(),
                    verified_amount: receipt.amount,
                    verified_currency: receipt.currency,
                    verification_timestamp: receipt.timestamp,
                }),
                StubVerifyMode::Error => Err(PaymentError::InvalidReceipt("stub failure".into())),
            }
        }

        async fn refund(
            &self,
            _receipt: &PaymentReceipt,
            _amount: Option<Amount>,
        ) -> Result<RefundConfirmation, PaymentError> {
            Err(PaymentError::AdapterError("not implemented".into()))
        }
    }

    // -------------------------------------------------------------------
    // PaymentVerifier blanket impl: adapter_id delegates correctly
    // -------------------------------------------------------------------

    #[test]
    fn blanket_payment_verifier_adapter_id() {
        let adapter = StubAdapter {
            id: "test-rail",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        let verifier: &dyn PaymentVerifierDyn = &adapter;
        assert_eq!(verifier.adapter_id(), "test-rail");
    }

    // -------------------------------------------------------------------
    // verify_receipts: single receipt, single verifier, success
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_single_success() {
        let adapter = StubAdapter {
            id: "test",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        let receipt = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 500, 1_000_000);

        let results = verify_receipts(&[&adapter], &[receipt]).await;
        assert_eq!(results.len(), 1);
        let v = results[0].as_ref().unwrap();
        assert!(v.result.valid);
        assert_eq!(v.receipt_id, [0xAA; 32]);
    }

    // -------------------------------------------------------------------
    // verify_receipts: no matching verifier → per-receipt error
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_no_matching_verifier() {
        let adapter = StubAdapter {
            id: "lightning",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        // Receipt has adapter_id "test", but our verifier is "lightning".
        let receipt = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 500, 1_000_000);

        let results = verify_receipts(&[&adapter], &[receipt]).await;
        assert_eq!(results.len(), 1);
        match &results[0] {
            Err(ReceiptVerificationError::NoVerifierForAdapter { adapter_id, .. }) => {
                assert_eq!(adapter_id, "test");
            }
            other => panic!("expected NoVerifierForAdapter, got: {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // verify_receipts: adapter verify error → per-receipt error
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_verification_error() {
        let adapter = StubAdapter {
            id: "test",
            verify_mode: StubVerifyMode::Error,
        };
        let receipt = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 500, 1_000_000);

        let results = verify_receipts(&[&adapter], &[receipt]).await;
        assert_eq!(results.len(), 1);
        match &results[0] {
            Err(ReceiptVerificationError::VerificationFailed { receipt_id, .. }) => {
                assert_eq!(*receipt_id, [0xAA; 32]);
            }
            other => panic!("expected VerificationFailed, got: {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // verify_receipts: valid=false path (F-03)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_valid_false_is_ok_but_not_valid() {
        let adapter = StubAdapter {
            id: "test",
            verify_mode: StubVerifyMode::ValidFalse,
        };
        let receipt = make_receipt_with_id(
            [0x11; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            500,
            1_000_000,
        );

        let results = verify_receipts(&[&adapter], &[receipt]).await;
        assert_eq!(results.len(), 1);
        // Ok does NOT mean valid — callers must check result.valid.
        let v = results[0].as_ref().unwrap();
        assert!(!v.result.valid);
        assert_eq!(v.receipt_id, [0x11; 32]);
    }

    // -------------------------------------------------------------------
    // verify_receipts: batch does not fail-fast (F-06)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_batch_no_fail_fast() {
        // First receipt has no matching verifier, second succeeds.
        let adapter = StubAdapter {
            id: "lightning",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        let receipt_no_match = make_receipt_with_id(
            [0x01; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            100,
            1_000_000,
        );
        let mut receipt_match = make_receipt_with_id(
            [0x02; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            200,
            1_000_001,
        );
        receipt_match.adapter_id = "lightning".to_string();

        let results = verify_receipts(&[&adapter], &[receipt_no_match, receipt_match]).await;
        assert_eq!(results.len(), 2);
        // First receipt: error (no verifier).
        assert!(results[0].is_err());
        // Second receipt: success despite first failing.
        let v = results[1].as_ref().unwrap();
        assert!(v.result.valid);
        assert_eq!(v.receipt_id, [0x02; 32]);
    }

    // -------------------------------------------------------------------
    // all_receipts_valid: convenience check
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn all_receipts_valid_returns_true_when_all_valid() {
        let adapter = StubAdapter {
            id: "test",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        let r1 = make_receipt_with_id(
            [0x01; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            100,
            1_000_000,
        );
        let r2 = make_receipt_with_id(
            [0x02; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            200,
            1_000_001,
        );
        let results = verify_receipts(&[&adapter], &[r1, r2]).await;
        assert!(all_receipts_valid(&results));
    }

    #[tokio::test]
    async fn all_receipts_valid_returns_false_when_one_invalid() {
        let valid_adapter = StubAdapter {
            id: "test",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        let invalid_adapter = StubAdapter {
            id: "bad",
            verify_mode: StubVerifyMode::ValidFalse,
        };

        let r1 = make_receipt_with_id(
            [0x01; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            100,
            1_000_000,
        );
        let mut r2 = make_receipt_with_id(
            [0x02; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            200,
            1_000_001,
        );
        r2.adapter_id = "bad".to_string();

        let verifiers: Vec<&dyn PaymentVerifierDyn> = vec![&valid_adapter, &invalid_adapter];
        let results = verify_receipts_dyn(&verifiers, &[r1, r2]).await;
        assert!(!all_receipts_valid(&results));
    }

    #[test]
    fn all_receipts_valid_returns_false_on_error() {
        let results: Vec<Result<ReceiptVerification, ReceiptVerificationError>> =
            vec![Err(ReceiptVerificationError::NoVerifierForAdapter {
                receipt_id: [0xAA; 32],
                adapter_id: "missing".to_string(),
            })];
        assert!(!all_receipts_valid(&results));
    }

    #[test]
    fn all_receipts_valid_empty_is_vacuously_true() {
        let results: Vec<Result<ReceiptVerification, ReceiptVerificationError>> = vec![];
        assert!(all_receipts_valid(&results));
    }

    // -------------------------------------------------------------------
    // verify_receipts: empty receipts → empty results
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_empty_receipts() {
        let adapter = StubAdapter {
            id: "test",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        let results = verify_receipts(&[&adapter], &[]).await;
        assert!(results.is_empty());
    }

    // -------------------------------------------------------------------
    // verify_receipts_dyn: heterogeneous verifiers with distinct IDs
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_dyn_heterogeneous() {
        let adapter_a = StubAdapter {
            id: "test",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        let adapter_b = StubAdapter {
            id: "lightning",
            verify_mode: StubVerifyMode::ValidTrue,
        };

        let mut receipt_a = make_receipt_with_id(
            [0x01; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            100,
            1_000_000,
        );
        receipt_a.adapter_id = "test".to_string();

        let mut receipt_b = make_receipt_with_id(
            [0x02; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            200,
            1_000_001,
        );
        receipt_b.adapter_id = "lightning".to_string();

        let verifiers: Vec<&dyn PaymentVerifierDyn> = vec![&adapter_a, &adapter_b];
        let results = verify_receipts_dyn(&verifiers, &[receipt_a, receipt_b]).await;
        assert_eq!(results.len(), 2);
        let v0 = results[0].as_ref().unwrap();
        let v1 = results[1].as_ref().unwrap();
        assert!(v0.result.valid);
        assert!(v1.result.valid);
        assert_eq!(v1.result.adapter_id, "lightning");
    }

    // -------------------------------------------------------------------
    // verify_receipts_dyn: no matching verifier → per-receipt error
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_dyn_no_verifier() {
        let adapter = StubAdapter {
            id: "x402",
            verify_mode: StubVerifyMode::ValidTrue,
        };
        let receipt = make_receipt("did:dht:z6MkAlice", "did:dht:z6MkBob", 500, 1_000_000);

        let verifiers: Vec<&dyn PaymentVerifierDyn> = vec![&adapter];
        let results = verify_receipts_dyn(&verifiers, &[receipt]).await;
        assert_eq!(results.len(), 1);
        match &results[0] {
            Err(ReceiptVerificationError::NoVerifierForAdapter { adapter_id, .. }) => {
                assert_eq!(adapter_id, "test");
            }
            other => panic!("expected NoVerifierForAdapter, got: {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // verify_receipts_dyn: valid=false path (F-03)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_receipts_dyn_valid_false() {
        let adapter = StubAdapter {
            id: "test",
            verify_mode: StubVerifyMode::ValidFalse,
        };
        let receipt = make_receipt_with_id(
            [0x22; 32],
            "did:dht:z6MkAlice",
            "did:dht:z6MkBob",
            500,
            1_000_000,
        );

        let verifiers: Vec<&dyn PaymentVerifierDyn> = vec![&adapter];
        let results = verify_receipts_dyn(&verifiers, &[receipt]).await;
        assert_eq!(results.len(), 1);
        let v = results[0].as_ref().unwrap();
        assert!(!v.result.valid);
        assert_eq!(v.receipt_id, [0x22; 32]);
    }

    // -------------------------------------------------------------------
    // ReceiptVerificationError serde roundtrip (F-05)
    // -------------------------------------------------------------------

    #[test]
    fn receipt_verification_error_serde_roundtrip() {
        let err = ReceiptVerificationError::NoVerifierForAdapter {
            receipt_id: [0xAA; 32],
            adapter_id: "x402".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let deserialized: ReceiptVerificationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deserialized);

        let err2 = ReceiptVerificationError::VerificationFailed {
            receipt_id: [0xBB; 32],
            error: PaymentError::InvalidReceipt("bad proof".into()),
        };
        let json2 = serde_json::to_string(&err2).unwrap();
        let deserialized2: ReceiptVerificationError = serde_json::from_str(&json2).unwrap();
        assert_eq!(err2, deserialized2);
    }

    // -------------------------------------------------------------------
    // ReceiptVerificationError Display formatting
    // -------------------------------------------------------------------

    #[test]
    fn receipt_verification_error_display() {
        let err = ReceiptVerificationError::NoVerifierForAdapter {
            receipt_id: [0xAA; 32],
            adapter_id: "x402".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("x402"));
        assert!(msg.contains("no verifier"));

        let err2 = ReceiptVerificationError::VerificationFailed {
            receipt_id: [0xBB; 32],
            error: PaymentError::InvalidReceipt("bad proof".into()),
        };
        let msg2 = err2.to_string();
        assert!(msg2.contains("verification failed"));
    }
}
