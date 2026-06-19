//! Payment adapter trait and supporting types for SCP economic governance.
//!
//! Defines the [`PaymentAdapter`] trait that abstracts over concrete payment
//! rails (x402, Lightning, SPL, Stripe, etc.), following the same pattern as
//! transport adapters (ADR-005, spec section 16.12.1). Also defines the
//! supporting types: [`AdapterCapabilities`], [`PaymentAuthorization`],
//! [`PaymentReceipt`], [`PaymentMetadata`], [`VerificationResult`],
//! [`RefundConfirmation`], and [`PaymentError`].
//!
//! See spec section 19.2.1 (adapter trait) and 19.2.6 (conformance testing).
//! See ADR-033 in `.docs/adrs/phase-3.md`.

use std::fmt;

use serde::{Deserialize, Serialize};

use scp_identity::DID;

use scp_protocol::economy::types::{Amount, CurrencyCode, PaidActionType};

// ---------------------------------------------------------------------------
// ContextId (local alias)
// ---------------------------------------------------------------------------

/// Context identifier. Alias consistent with other economy-adjacent modules.
pub type ContextId = String;

// ---------------------------------------------------------------------------
// PaymentAdapter trait
// ---------------------------------------------------------------------------

/// Abstraction over a concrete payment rail.
///
/// Implementors connect to real payment infrastructure (x402, Lightning, SPL
/// tokens, Stripe, etc.) or provide in-memory test ledgers. The trait follows
/// an authorize/capture two-phase pattern that accommodates both
/// authorize-then-capture rails (x402, Stripe) and invoice-then-preimage
/// rails (Lightning).
///
/// See spec section 19.2.1.
pub trait PaymentAdapter: Send + Sync {
    /// Returns the unique identifier for this adapter (e.g., `"x402"`,
    /// `"lightning"`, `"spl"`, `"stripe"`, `"test"`).
    fn adapter_id(&self) -> &str;

    /// Returns the capabilities of this adapter.
    fn capabilities(&self) -> AdapterCapabilities;

    /// Authorizes (reserves) a payment from `payer` to `payee`.
    ///
    /// Returns a [`PaymentAuthorization`] that can later be captured or
    /// voided. The authorization may have an expiry after which it is
    /// automatically voided by the payment rail.
    fn authorize(
        &self,
        payer: &DID,
        payee: &DID,
        amount: Amount,
        currency: CurrencyCode,
        metadata: PaymentMetadata,
    ) -> impl std::future::Future<Output = Result<PaymentAuthorization, PaymentError>> + Send;

    /// Captures (settles) a previously authorized payment.
    ///
    /// Moves funds from payer to payee. Returns a [`PaymentReceipt`] that
    /// serves as a provenance record in the context event log.
    fn capture(
        &self,
        auth: &PaymentAuthorization,
    ) -> impl std::future::Future<Output = Result<PaymentReceipt, PaymentError>> + Send;

    /// Voids (cancels) a previously authorized payment.
    ///
    /// Releases the reserved funds. Must be called if the associated action
    /// fails after authorization (spec section 19.2.2, step 9).
    fn void(
        &self,
        auth: &PaymentAuthorization,
    ) -> impl std::future::Future<Output = Result<(), PaymentError>> + Send;

    /// Verifies a [`PaymentAuthorization`] is authentic and still valid.
    ///
    /// The receiving side calls this to confirm the authorization was actually
    /// issued by the claimed adapter, has not expired, and has not been
    /// tampered with. This prevents a malicious sender from forging a
    /// `PaymentAuthorization` struct.
    ///
    /// See spec section 19.2.2, step 5.
    fn verify_authorization(
        &self,
        auth: &PaymentAuthorization,
    ) -> impl std::future::Future<Output = Result<(), PaymentError>> + Send;

    /// Verifies a payment receipt against the payment rail.
    ///
    /// Checks the adapter-specific proof (on-chain state, preimage hash,
    /// etc.) to confirm the payment actually occurred.
    fn verify(
        &self,
        receipt: &PaymentReceipt,
    ) -> impl std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send;

    /// Refunds a previously captured payment.
    ///
    /// If `amount` is `None`, refunds the full captured amount. If `Some`,
    /// performs a partial refund of the specified amount.
    fn refund(
        &self,
        receipt: &PaymentReceipt,
        amount: Option<Amount>,
    ) -> impl std::future::Future<Output = Result<RefundConfirmation, PaymentError>> + Send;
}

// ---------------------------------------------------------------------------
// AdapterCapabilities
// ---------------------------------------------------------------------------

/// Describes the capabilities and constraints of a [`PaymentAdapter`].
///
/// Used by the SDK to select compatible adapters during payment negotiation
/// (spec section 19.2.3).
///
/// See spec section 19.2.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Spec-defined fields (section 19.2.1).
pub struct AdapterCapabilities {
    /// Currencies this adapter can handle.
    pub supported_currencies: Vec<CurrencyCode>,
    /// Whether the adapter supports continuous streaming payments
    /// (ILP/STREAM-style).
    pub supports_streaming: bool,
    /// Whether the adapter supports authorizing N units and capturing
    /// incrementally.
    pub supports_batch_auth: bool,
    /// Whether the adapter supports skipping authorize and capturing
    /// directly (low-latency path).
    pub supports_single_step: bool,
    /// Minimum amount the adapter can process, if any.
    pub min_amount: Option<Amount>,
    /// Maximum amount the adapter can process, if any.
    pub max_amount: Option<Amount>,
    /// Expected settlement latency in milliseconds.
    pub typical_settlement_ms: u64,
    /// Whether this adapter requires a facilitator to verify and settle
    /// (e.g., x402).
    pub requires_facilitator: bool,
}

// ---------------------------------------------------------------------------
// PaymentMetadata
// ---------------------------------------------------------------------------

/// Metadata attached to a payment authorization request.
///
/// Provides context for the payment without revealing encrypted content.
///
/// See spec section 19.2.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentMetadata {
    /// The type of action being paid for.
    pub action_type: PaidActionType,
    /// The context in which the action occurs. `None` for relay-level payments.
    pub context_id: Option<ContextId>,
    /// Idempotency key to prevent duplicate authorization.
    pub idempotency_key: [u8; 16],
}

impl Default for PaymentMetadata {
    fn default() -> Self {
        // M20: Use random idempotency key in Default to prevent accidental
        // collisions between two independently-constructed defaults.
        let key: [u8; 16] = rand::random();
        Self {
            action_type: PaidActionType::MessageSend,
            context_id: None,
            idempotency_key: key,
        }
    }
}

// ---------------------------------------------------------------------------
// PaymentAuthorization
// ---------------------------------------------------------------------------

/// A reserved payment that can be captured or voided.
///
/// Returned by [`PaymentAdapter::authorize`], consumed by
/// [`PaymentAdapter::capture`] or [`PaymentAdapter::void`].
///
/// See spec section 19.2.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAuthorization {
    /// Unique identifier for this authorization.
    pub auth_id: [u8; 32],
    /// The DID of the payer.
    pub payer: DID,
    /// The DID of the payee.
    pub payee: DID,
    /// The authorized amount.
    pub amount: Amount,
    /// The currency of the authorized amount.
    pub currency: CurrencyCode,
    /// The adapter that created this authorization.
    pub adapter_id: String,
    /// Unix timestamp (seconds) when the authorization was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the authorization hold expires.
    pub expires_at: u64,
    /// Adapter-specific opaque state needed for capture/void.
    pub adapter_state: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Batch limits
// ---------------------------------------------------------------------------

/// Maximum number of [`PaymentReceipt`]s accepted in a single
/// `verify_payment_receipts` call.
///
/// Verification fans out to one serial `PaymentAdapter::verify_dyn` round-trip
/// per receipt against a live payment rail. An unbounded batch lets a single
/// unauthenticated call drive an arbitrarily large number of outbound
/// adapter-verification I/O operations, which is a denial-of-service vector.
/// This cap bounds the per-call receipt batch — and therefore the outbound
/// adapter I/O — to a fixed ceiling.
///
/// The FFI bridges enforce this at the boundary (returning a validation error)
/// and the supervisor dispatch chokepoint enforces it as defense in depth for
/// non-bridge callers. Mirrors the `MAX_BATCH_ASSETS` precedent used for
/// `commit_deploy`.
pub const MAX_RECEIPT_BATCH: usize = 10_000;

// ---------------------------------------------------------------------------
// PaymentReceipt
// ---------------------------------------------------------------------------

/// Proof that a payment was captured (settled).
///
/// Recorded in the context event log as a provenance record. Any party can
/// call [`PaymentAdapter::verify`] to check the receipt against the payment
/// rail.
///
/// See spec section 19.6.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Unique identifier for this receipt.
    pub receipt_id: [u8; 32],
    /// The DID of the payer.
    pub payer: DID,
    /// The DID of the payee.
    pub payee: DID,
    /// The captured amount.
    pub amount: Amount,
    /// The currency of the captured amount.
    pub currency: CurrencyCode,
    /// The type of action that was paid for.
    pub action_type: PaidActionType,
    /// The context in which the action occurred. `None` for relay-level
    /// payments.
    pub context_id: Option<ContextId>,
    /// The adapter that processed this payment.
    pub adapter_id: String,
    /// Adapter-specific proof of payment:
    /// - x402: on-chain transaction hash
    /// - Lightning: preimage
    /// - SPL: transaction signature
    pub adapter_proof: Vec<u8>,
    /// Unix timestamp (seconds) when the payment was captured.
    pub timestamp: u64,
    /// Whether this receipt is anchored in the canonical Merkle event log.
    ///
    /// `false` until ADR-051 makes per-payee receipts convergent: a
    /// `PaymentReceipt` is per-payee application activity surfaced as a local
    /// `ContextEvent`, not a convergent Merkle leaf (spec §19.6, ADR-011
    /// amendment exclusion taxonomy §2). Consumers requiring Merkle-proven
    /// provenance MUST reject an unanchored receipt. This field is deliberately
    /// EXCLUDED from the signing preimage (§19.6 receipt signature scope ends at
    /// `timestamp`).
    pub anchored: bool,
    /// Ed25519 signature by the payer over the receipt data.
    pub signature: Vec<u8>,
}

impl fmt::Debug for PaymentReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymentReceipt")
            .field("receipt_id", &self.receipt_id)
            .field("payer", &self.payer)
            .field("payee", &self.payee)
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("action_type", &self.action_type)
            .field("context_id", &self.context_id)
            .field("adapter_id", &self.adapter_id)
            .field(
                "adapter_proof",
                &format!("[{} bytes]", self.adapter_proof.len()),
            )
            .field("timestamp", &self.timestamp)
            .field("anchored", &self.anchored)
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// VerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a [`PaymentReceipt`] against the payment rail.
///
/// See spec section 19.2.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the receipt's proof verified successfully.
    pub valid: bool,
    /// The adapter that performed the verification.
    pub adapter_id: String,
    /// The amount confirmed by the payment rail.
    pub verified_amount: Amount,
    /// The currency confirmed by the payment rail.
    pub verified_currency: CurrencyCode,
    /// Unix timestamp (seconds) of the verification.
    pub verification_timestamp: u64,
}

// ---------------------------------------------------------------------------
// RefundConfirmation
// ---------------------------------------------------------------------------

/// Confirmation that a refund was processed by the payment rail.
///
/// See spec section 19.2.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundConfirmation {
    /// Unique identifier for this refund.
    pub refund_id: [u8; 32],
    /// The receipt ID of the original payment that was refunded.
    pub original_receipt_id: [u8; 32],
    /// The amount refunded.
    pub refunded_amount: Amount,
    /// The currency of the refund.
    pub currency: CurrencyCode,
    /// Adapter-specific refund proof.
    pub adapter_proof: Vec<u8>,
}

// ---------------------------------------------------------------------------
// PaymentError
// ---------------------------------------------------------------------------

/// Errors that can occur during payment operations.
///
/// See spec section 19.2.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentError {
    /// The payer does not have sufficient balance for the requested amount.
    InsufficientBalance {
        /// The balance available.
        available: Amount,
        /// The amount requested.
        requested: Amount,
    },
    /// The requested currency is not supported by this adapter.
    UnsupportedCurrency(CurrencyCode),
    /// The authorization has expired.
    AuthorizationExpired {
        /// The expired authorization ID.
        auth_id: [u8; 32],
    },
    /// The authorization has already been captured.
    AlreadyCaptured {
        /// The already-captured authorization ID.
        auth_id: [u8; 32],
    },
    /// The authorization has already been voided.
    AlreadyVoided {
        /// The already-voided authorization ID.
        auth_id: [u8; 32],
    },
    /// The receipt is invalid (e.g., corrupted proof, mismatched fields).
    InvalidReceipt(String),
    /// An adapter-specific error (passthrough).
    AdapterError(String),
    /// No compatible payment adapter found between payer and payee.
    NoCompatiblePaymentAdapter,
}

impl std::fmt::Display for PaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientBalance {
                available,
                requested,
            } => write!(
                f,
                "insufficient balance: available {available}, requested {requested}"
            ),
            Self::UnsupportedCurrency(c) => write!(f, "unsupported currency: {c}"),
            Self::AuthorizationExpired { .. } => write!(f, "authorization expired"),
            Self::AlreadyCaptured { .. } => write!(f, "authorization already captured"),
            Self::AlreadyVoided { .. } => write!(f, "authorization already voided"),
            Self::InvalidReceipt(msg) => write!(f, "invalid receipt: {msg}"),
            Self::AdapterError(msg) => write!(f, "adapter error: {msg}"),
            Self::NoCompatiblePaymentAdapter => write!(f, "no compatible payment adapter"),
        }
    }
}

impl std::error::Error for PaymentError {}

// ---------------------------------------------------------------------------
// PaymentAdapterDyn — object-safe variant
// ---------------------------------------------------------------------------

/// Object-safe variant of [`PaymentAdapter`] for use with trait objects.
///
/// The base [`PaymentAdapter`] trait uses RPITIT (return-position impl trait
/// in trait), which prevents `dyn PaymentAdapter`. This trait uses boxed
/// futures instead, enabling `Arc<dyn PaymentAdapterDyn>` storage on
/// `ContextManager` for the 9-step payment flow (spec §19.2.2).
///
/// See also [`super::receipt::PaymentVerifierDyn`] for the verification-only
/// counterpart.
pub trait PaymentAdapterDyn: Send + Sync {
    /// Returns the unique identifier for this adapter.
    fn adapter_id(&self) -> &str;

    /// Returns the capabilities of this adapter.
    fn capabilities(&self) -> AdapterCapabilities;

    /// Authorizes (reserves) a payment from `payer` to `payee`.
    fn authorize_dyn<'a>(
        &'a self,
        payer: &'a DID,
        payee: &'a DID,
        amount: Amount,
        currency: CurrencyCode,
        metadata: PaymentMetadata,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<PaymentAuthorization, PaymentError>>
                + Send
                + 'a,
        >,
    >;

    /// Captures (settles) a previously authorized payment.
    fn capture_dyn<'a>(
        &'a self,
        auth: &'a PaymentAuthorization,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PaymentReceipt, PaymentError>> + Send + 'a>,
    >;

    /// Voids (cancels) a previously authorized payment.
    fn void_dyn<'a>(
        &'a self,
        auth: &'a PaymentAuthorization,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PaymentError>> + Send + 'a>>;

    /// Verifies a [`PaymentAuthorization`] is authentic and still valid.
    fn verify_authorization_dyn<'a>(
        &'a self,
        auth: &'a PaymentAuthorization,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PaymentError>> + Send + 'a>>;

    /// Verifies a payment receipt against the payment rail.
    fn verify_dyn<'a>(
        &'a self,
        receipt: &'a PaymentReceipt,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send + 'a>,
    >;

    /// Refunds a previously captured payment.
    fn refund_dyn<'a>(
        &'a self,
        receipt: &'a PaymentReceipt,
        amount: Option<Amount>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<RefundConfirmation, PaymentError>> + Send + 'a>,
    >;
}

/// Blanket impl: every [`PaymentAdapter`] is also [`PaymentAdapterDyn`].
#[allow(clippy::similar_names)] // payer/payee is the domain language
impl<T: PaymentAdapter> PaymentAdapterDyn for T {
    fn adapter_id(&self) -> &str {
        PaymentAdapter::adapter_id(self)
    }

    fn capabilities(&self) -> AdapterCapabilities {
        PaymentAdapter::capabilities(self)
    }

    fn authorize_dyn<'a>(
        &'a self,
        payer: &'a DID,
        payee: &'a DID,
        amount: Amount,
        currency: CurrencyCode,
        metadata: PaymentMetadata,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<PaymentAuthorization, PaymentError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(PaymentAdapter::authorize(
            self, payer, payee, amount, currency, metadata,
        ))
    }

    fn capture_dyn<'a>(
        &'a self,
        auth: &'a PaymentAuthorization,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PaymentReceipt, PaymentError>> + Send + 'a>,
    > {
        Box::pin(PaymentAdapter::capture(self, auth))
    }

    fn void_dyn<'a>(
        &'a self,
        auth: &'a PaymentAuthorization,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PaymentError>> + Send + 'a>>
    {
        Box::pin(PaymentAdapter::void(self, auth))
    }

    fn verify_authorization_dyn<'a>(
        &'a self,
        auth: &'a PaymentAuthorization,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PaymentError>> + Send + 'a>>
    {
        Box::pin(PaymentAdapter::verify_authorization(self, auth))
    }

    fn verify_dyn<'a>(
        &'a self,
        receipt: &'a PaymentReceipt,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send + 'a>,
    > {
        Box::pin(PaymentAdapter::verify(self, receipt))
    }

    fn refund_dyn<'a>(
        &'a self,
        receipt: &'a PaymentReceipt,
        amount: Option<Amount>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<RefundConfirmation, PaymentError>> + Send + 'a>,
    > {
        Box::pin(PaymentAdapter::refund(self, receipt, amount))
    }
}

// ---------------------------------------------------------------------------
// NoOpPaymentAdapter — test-only no-op implementation.
// ---------------------------------------------------------------------------

/// A no-op payment adapter that authorizes zero-cost actions and returns
/// dummy receipts for non-zero actions.
///
/// Used in tests and the governance dispatch path to wire the
/// [`prepare_paid_action`](crate::economy::integration::prepare_paid_action) call without requiring real payment
/// infrastructure. Free actions (cost=0) bypass the adapter entirely
/// (handled by `prepare_paid_action`). Non-zero actions will be authorized
/// with a dummy authorization that always succeeds.
///
/// Gated behind `#[cfg(any(test, feature = "testing"))]` to prevent
/// accidental use in production code.
#[cfg(any(test, feature = "testing"))]
pub struct NoOpPaymentAdapter;

#[cfg(any(test, feature = "testing"))]
#[allow(clippy::unnecessary_literal_bound, clippy::similar_names)]
impl PaymentAdapter for NoOpPaymentAdapter {
    fn adapter_id(&self) -> &str {
        "noop"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            supported_currencies: vec![CurrencyCode(*b"USD\0")],
            supports_streaming: false,
            supports_batch_auth: false,
            supports_single_step: true,
            min_amount: None,
            max_amount: None,
            typical_settlement_ms: 0,
            requires_facilitator: false,
        }
    }

    async fn authorize(
        &self,
        payer: &DID,
        payee: &DID,
        amount: Amount,
        currency: CurrencyCode,
        _metadata: PaymentMetadata,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            auth_id: [0u8; 32],
            payer: payer.clone(),
            payee: payee.clone(),
            amount,
            currency,
            adapter_id: "noop".to_owned(),
            created_at: 0,
            expires_at: u64::MAX,
            adapter_state: Vec::new(),
        })
    }

    async fn capture(&self, auth: &PaymentAuthorization) -> Result<PaymentReceipt, PaymentError> {
        Ok(PaymentReceipt {
            receipt_id: [0u8; 32],
            payer: auth.payer.clone(),
            payee: auth.payee.clone(),
            amount: auth.amount,
            currency: auth.currency,
            action_type: PaidActionType::MessageSend,
            context_id: None,
            adapter_id: "noop".to_owned(),
            adapter_proof: Vec::new(),
            timestamp: 0,
            anchored: false,
            signature: Vec::new(),
        })
    }

    async fn void(&self, _auth: &PaymentAuthorization) -> Result<(), PaymentError> {
        Ok(())
    }

    async fn verify_authorization(&self, _auth: &PaymentAuthorization) -> Result<(), PaymentError> {
        Ok(())
    }

    async fn verify(&self, _receipt: &PaymentReceipt) -> Result<VerificationResult, PaymentError> {
        Ok(VerificationResult {
            valid: true,
            adapter_id: "noop".to_owned(),
            verified_amount: Amount(0),
            verified_currency: CurrencyCode(*b"USD\0"),
            verification_timestamp: 0,
        })
    }

    async fn refund(
        &self,
        _receipt: &PaymentReceipt,
        _amount: Option<Amount>,
    ) -> Result<RefundConfirmation, PaymentError> {
        Ok(RefundConfirmation {
            refund_id: [0u8; 32],
            original_receipt_id: [0u8; 32],
            refunded_amount: Amount(0),
            currency: CurrencyCode(*b"USD\0"),
            adapter_proof: Vec::new(),
        })
    }
}
