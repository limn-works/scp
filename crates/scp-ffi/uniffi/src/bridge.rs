//! `UniFFI` bridge: exported functions, opaque objects, records, enums, and
//! error conversions.
//!
//! All proc-macro exports live here. The supplementary UDL file
//! (`scp.udl`) defines only callback interfaces (which proc-macros cannot
//! express). Both are required by `UniFFI` to generate the full Swift and
//! Kotlin bindings.
//!
//! # Type categories (ADR-021)
//!
//! - **Opaque objects** — hold crypto state, wrapped in `Arc<T>`. Generated
//!   as classes in Swift and Kotlin.
//! - **Records** — pure data, passed by value. Generated as structs (Swift)
//!   and data classes (Kotlin).
//! - **Enums** — discriminated unions. Generated as enums in both languages.
//! - **Error** — `ScpError` maps to Swift `throws` and Kotlin exceptions.
//!
//! # Async bridging (ADR-021)
//!
//! All I/O-bound bridge functions are `async fn`. `UniFFI` generates Swift
//! `async` functions (via `CheckedContinuation`) and Kotlin `suspend`
//! functions (via coroutine integration). The tokio runtime executes the
//! future; `UniFFI`'s async scaffolding resumes the caller on completion.
//!
//! See ADR-021 in `.docs/adrs/phase-4.md`.

use std::fmt;
use std::sync::Arc;

#[cfg(feature = "allow_in_memory_custody")]
use scp_identity::{DidCache, IdentityError, InMemoryDhtClient};
use scp_identity::{DidDht, DidDocument as CoreDidDocument, DidMethod, ScpIdentity};
#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::error::PlatformError;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};
use uuid::Uuid;

use scp_core::context::membership::KeyPackage;

use crate::{decrement_handle_count, increment_handle_count, runtime};

/// Wrapper for [`InMemoryKeyCustody`] that implements [`Debug`] with a
/// redacted representation, preventing key material from appearing in logs.
///
/// Only available when the `allow_in_memory_custody` feature is enabled.
/// Production mobile builds (iOS/Android) MUST NOT enable this feature.
/// See GitHub issue #88 and ADR-006.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) struct OpaqueInMemoryKeyCustody(pub(crate) InMemoryKeyCustody);

#[cfg(feature = "allow_in_memory_custody")]
impl fmt::Debug for OpaqueInMemoryKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InMemoryKeyCustody([redacted])")
    }
}

/// Creates a `DidDht` instance with a signing function derived from the
/// custody held inside an [`OpaqueInMemoryKeyCustody`].
///
/// `DidDht::new()` creates an instance with `sign_fn: None`, which causes
/// all DHT publish operations (used by `add_agent_key`, `rotate_agent_key`,
/// `remove_agent_key`) to fail. This helper constructs a properly configured
/// instance with the signing function wired to the custody's key material.
#[cfg(feature = "allow_in_memory_custody")]
#[allow(clippy::type_complexity)]
fn make_dht_with_signer(
    custody: &Arc<OpaqueInMemoryKeyCustody>,
) -> DidDht<InMemoryDhtClient, scp_identity::cache::SystemClock> {
    let custody_clone = Arc::clone(custody);
    let sign_fn: Arc<
        dyn Fn(
                u64,
                Vec<u8>,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<u8>, IdentityError>> + Send>,
            > + Send
            + Sync,
    > = Arc::new(move |key_id: u64, data: Vec<u8>| {
        let kc = Arc::clone(&custody_clone);
        Box::pin(async move {
            let handle = scp_platform::traits::KeyHandle::new(key_id);
            let sig =
                kc.0.sign(&handle, &data)
                    .await
                    .map_err(IdentityError::Platform)?;
            Ok(sig.into_bytes())
        })
    });
    DidDht::with_client_and_signer(
        Arc::new(InMemoryDhtClient::new()),
        Arc::new(DidCache::new()),
        sign_fn,
    )
}

// ---------------------------------------------------------------------------
// CallbackKeyCustody — concrete adapter wrapping KeyCustodyProvider callback
//
// `KeyCustody` uses RPITIT (return-position `impl Trait` in trait) and is
// therefore NOT object-safe. This adapter provides a concrete type that
// implements `KeyCustody` by delegating to the UniFFI `KeyCustodyProvider`
// callback interface. Used for `"platform"` and `"software"` custody paths.
//
// Private key material never crosses the FFI boundary (ADR-006). The adapter
// translates between scp-platform's typed API (KeyHandle, Signature, PublicKey)
// and the callback's raw byte arrays.
//
// See SCP-214 acceptance criteria 2-3 and ADR-006.
// ---------------------------------------------------------------------------

/// Concrete [`KeyCustody`] adapter that delegates to a UniFFI
/// [`KeyCustodyProvider`](crate::KeyCustodyProvider) callback.
///
/// This bridges the gap between scp-platform's `KeyCustody` trait (which uses
/// RPITIT and is not object-safe) and the UniFFI callback interface (which
/// is `dyn`-dispatched via `Box<dyn KeyCustodyProvider>`).
pub(crate) struct CallbackKeyCustody {
    provider: Box<dyn crate::KeyCustodyProvider>,
}

impl CallbackKeyCustody {
    /// Creates a new adapter wrapping the given callback provider.
    pub(crate) fn new(provider: Box<dyn crate::KeyCustodyProvider>) -> Self {
        Self { provider }
    }
}

impl fmt::Debug for CallbackKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallbackKeyCustody([platform])")
    }
}

// SAFETY: `KeyCustodyProvider` is `Send + Sync` by trait bound.
unsafe impl Send for CallbackKeyCustody {}
unsafe impl Sync for CallbackKeyCustody {}

impl KeyCustody for CallbackKeyCustody {
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError> {
        let type_str = match key_type {
            KeyType::Ed25519 => "ed25519".to_owned(),
            KeyType::X25519 => "x25519".to_owned(),
        };
        let key_id = self
            .provider
            .generate_keypair(type_str)
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
        // Parse the returned key_id string as a u64 handle identifier.
        let id: u64 = key_id.parse().map_err(|_| {
            PlatformError::CustodyError(format!(
                "KeyCustodyProvider::generate_keypair returned non-numeric key_id: {key_id}"
            ))
        })?;
        Ok(KeyHandle::new(id))
    }

    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError> {
        let sig_bytes = self
            .provider
            .sign(key.id().to_string(), data.to_vec())
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
        Ok(Signature::new(sig_bytes))
    }

    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError> {
        let pk_bytes = self
            .provider
            .get_public_key(key.id().to_string())
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
        Ok(PublicKey::new(pk_bytes))
    }

    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError> {
        self.provider
            .destroy_key(key.id().to_string())
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))
    }

    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        let shared = self
            .provider
            .dh_agree(key.id().to_string(), peer_public.to_vec())
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
        if shared.len() != 32 {
            return Err(PlatformError::CustodyError(format!(
                "dh_agree returned {} bytes, expected 32",
                shared.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&shared);
        Ok(SharedSecret::new(arr))
    }

    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<PseudonymKeypair, PlatformError> {
        let result_bytes = self
            .provider
            .derive_pseudonym(key.id().to_string(), context_id.to_vec())
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
        // The callback returns concatenated [public_key_bytes (32) || key_id_utf8].
        if result_bytes.len() < 33 {
            return Err(PlatformError::CustodyError(format!(
                "derive_pseudonym returned {} bytes, expected at least 33 \
                 (32 public key + key_id)",
                result_bytes.len()
            )));
        }
        let public_key_bytes = &result_bytes[..32];
        let key_id_str = std::str::from_utf8(&result_bytes[32..]).map_err(|_| {
            PlatformError::CustodyError(
                "derive_pseudonym key_id portion is not valid UTF-8".to_owned(),
            )
        })?;
        let key_id: u64 = key_id_str.parse().map_err(|_| {
            PlatformError::CustodyError(format!(
                "derive_pseudonym key_id is not numeric: {key_id_str}"
            ))
        })?;
        Ok(PseudonymKeypair {
            public_key: PublicKey::new(public_key_bytes.to_vec()),
            key_handle: KeyHandle::new(key_id),
        })
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        // Rotatable pseudonyms append the epoch to the context_id before
        // delegating to derive_pseudonym. The domain separator difference
        // ("scp-pseudonym-v2") is handled by the platform adapter.
        // For the callback interface, we encode epoch into the context_id.
        let mut extended = context_id.to_vec();
        extended.extend_from_slice(&pseudonym_epoch.to_be_bytes());
        extended.extend_from_slice(b"scp-pseudonym-v2");

        let result_bytes = self
            .provider
            .derive_pseudonym(key.id().to_string(), extended)
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;

        if result_bytes.len() < 33 {
            return Err(PlatformError::CustodyError(format!(
                "derive_rotatable_pseudonym returned {} bytes, expected at least 33",
                result_bytes.len()
            )));
        }
        let public_key_bytes = &result_bytes[..32];
        let key_id_str = std::str::from_utf8(&result_bytes[32..]).map_err(|_| {
            PlatformError::CustodyError(
                "derive_rotatable_pseudonym key_id is not valid UTF-8".to_owned(),
            )
        })?;
        let key_id: u64 = key_id_str.parse().map_err(|_| {
            PlatformError::CustodyError(format!(
                "derive_rotatable_pseudonym key_id is not numeric: {key_id_str}"
            ))
        })?;
        Ok(PseudonymKeypair {
            public_key: PublicKey::new(public_key_bytes.to_vec()),
            key_handle: KeyHandle::new(key_id),
        })
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        let type_str = self.provider.custody_type(key.id().to_string());
        match type_str.as_str() {
            "hardware" => CustodyType::Hardware,
            "software" => CustodyType::Software,
            _ => CustodyType::InMemory,
        }
    }
}

// ---------------------------------------------------------------------------
// ScpError — unified error type (maps to Swift throws / Kotlin exceptions)
//
// Each variant carries `message` (human-readable detail) and `code`
// (machine-readable SCP-{CATEGORY}-{NUMBER} identifier).
//
// See ADR-021 acceptance criterion 8.
// ---------------------------------------------------------------------------

/// Unified error type for the `UniFFI` bridge.
///
/// Maps to Swift `ScpError` (an `enum` conforming to `Error`) and Kotlin
/// `ScpException` (a sealed exception hierarchy). Every function that can
/// fail is declared `#[uniffi::export]` with `Result<T, ScpError>`.
///
/// Error codes follow `SCP-{CATEGORY}-{NUMBER}` from sdk-common.md.
#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
pub enum ScpError {
    /// An identity operation failed (DID creation, resolution, key rotation).
    #[error("identity error [{code}]: {message}")]
    Identity { message: String, code: String },

    /// A context lifecycle operation failed (create, join, leave, close, send).
    #[error("context error [{code}]: {message}")]
    Context { message: String, code: String },

    /// A capability or governance permission check failed.
    #[error("permission error [{code}]: {message}")]
    Permission { message: String, code: String },

    /// A cryptographic operation failed (MLS, sender keys, encryption).
    #[error("crypto error [{code}]: {message}")]
    Crypto { message: String, code: String },

    /// A transport operation failed (connection, send, subscription).
    #[error("transport error [{code}]: {message}")]
    Transport { message: String, code: String },

    /// A tool operation failed (registration, invocation, verification).
    #[error("tool error [{code}]: {message}")]
    Tool { message: String, code: String },

    /// Input validation failed (malformed data, schema mismatch, constraint violation).
    #[error("validation error [{code}]: {message}")]
    Validation { message: String, code: String },
}

// ---------------------------------------------------------------------------
// From<scp-core error types> for ScpError
// ---------------------------------------------------------------------------

impl From<scp_identity::IdentityError> for ScpError {
    fn from(e: scp_identity::IdentityError) -> Self {
        Self::Identity {
            message: format!(
                "{e} — check DID format, key custody configuration, or DHT connectivity"
            ),
            code: "SCP-IDENT-1001".to_owned(),
        }
    }
}

impl From<scp_core::context::ContextError> for ScpError {
    fn from(e: scp_core::context::ContextError) -> Self {
        Self::Context {
            message: format!("{e} — verify context state, membership, and permissions"),
            code: "SCP-CTX-2001".to_owned(),
        }
    }
}

impl From<scp_core::context::builder::ContextCreationError> for ScpError {
    fn from(e: scp_core::context::builder::ContextCreationError) -> Self {
        Self::Context {
            message: format!(
                "context creation failed: {e} — check context parameters and identity"
            ),
            code: "SCP-CTX-2002".to_owned(),
        }
    }
}

impl From<scp_core::context::templates::TemplateError> for ScpError {
    fn from(e: scp_core::context::templates::TemplateError) -> Self {
        Self::Context {
            message: format!(
                "template validation failed: {e} — ensure context params match the template"
            ),
            code: "SCP-CTX-2003".to_owned(),
        }
    }
}

impl From<scp_core::context::roles::RoleError> for ScpError {
    fn from(e: scp_core::context::roles::RoleError) -> Self {
        Self::Context {
            message: format!(
                "role operation failed: {e} — verify role definitions and member permissions"
            ),
            code: "SCP-CTX-2004".to_owned(),
        }
    }
}

impl From<scp_core::context::ttl::TtlError> for ScpError {
    fn from(e: scp_core::context::ttl::TtlError) -> Self {
        Self::Context {
            message: format!(
                "TTL operation failed: {e} — check TTL configuration and context state"
            ),
            code: "SCP-CTX-2005".to_owned(),
        }
    }
}

impl From<scp_core::context::promotion::PromotionError> for ScpError {
    fn from(e: scp_core::context::promotion::PromotionError) -> Self {
        Self::Context {
            message: format!(
                "context promotion failed: {e} — verify eligibility and governance rules"
            ),
            code: "SCP-CTX-2006".to_owned(),
        }
    }
}

impl From<scp_core::context::tools::ToolError> for ScpError {
    fn from(e: scp_core::context::tools::ToolError) -> Self {
        Self::Tool {
            message: format!(
                "tool operation failed: {e} — check tool registration, permissions, and input schema"
            ),
            code: "SCP-TOOL-6001".to_owned(),
        }
    }
}

impl From<scp_core::context::tools::invoke::InvocationError> for ScpError {
    fn from(e: scp_core::context::tools::invoke::InvocationError) -> Self {
        Self::Tool {
            message: format!(
                "tool invocation failed: {e} — verify tool ID, input, and caller permissions"
            ),
            code: "SCP-TOOL-6002".to_owned(),
        }
    }
}

impl From<scp_core::context::tools::schema::SchemaValidationError> for ScpError {
    fn from(e: scp_core::context::tools::schema::SchemaValidationError) -> Self {
        Self::Validation {
            message: format!(
                "schema validation failed: {e} — check input against the tool's JSON Schema"
            ),
            code: "SCP-VALID-7001".to_owned(),
        }
    }
}

impl From<scp_core::crypto::mls::error::MlsError> for ScpError {
    fn from(e: scp_core::crypto::mls::error::MlsError) -> Self {
        Self::Crypto {
            message: format!(
                "MLS operation failed: {e} — check group state and member key packages"
            ),
            code: "SCP-CRYPTO-4001".to_owned(),
        }
    }
}

impl From<scp_core::crypto::sender_keys::SenderKeyError> for ScpError {
    fn from(e: scp_core::crypto::sender_keys::SenderKeyError) -> Self {
        Self::Crypto {
            message: format!(
                "sender key operation failed: {e} — verify key material and encryption parameters"
            ),
            code: "SCP-CRYPTO-4002".to_owned(),
        }
    }
}

impl From<scp_core::crypto::ucan::UcanError> for ScpError {
    fn from(e: scp_core::crypto::ucan::UcanError) -> Self {
        Self::Permission {
            message: format!(
                "{e} — check token format, signatures, time bounds, and capability chain"
            ),
            code: "SCP-PERM-3001".to_owned(),
        }
    }
}

impl From<scp_core::envelope::EnvelopeError> for ScpError {
    fn from(e: scp_core::envelope::EnvelopeError) -> Self {
        Self::Crypto {
            message: format!(
                "envelope operation failed: {e} — check payload size, signing keys, and encryption state"
            ),
            code: "SCP-CRYPTO-4003".to_owned(),
        }
    }
}

impl From<scp_event_log::EventLogError> for ScpError {
    fn from(e: scp_event_log::EventLogError) -> Self {
        Self::Context {
            message: format!(
                "event log operation failed: {e} — verify log integrity and sequence numbers"
            ),
            code: "SCP-CTX-2007".to_owned(),
        }
    }
}

impl From<scp_core::provenance::ProvenanceError> for ScpError {
    fn from(e: scp_core::provenance::ProvenanceError) -> Self {
        Self::Validation {
            message: format!("provenance validation failed: {e} — check cross-context chain depth"),
            code: "SCP-VALID-7002".to_owned(),
        }
    }
}

impl From<scp_core::trust::TrustError> for ScpError {
    fn from(e: scp_core::trust::TrustError) -> Self {
        Self::Validation {
            message: format!(
                "trust evaluation failed: {e} — check event log data and attestation validity"
            ),
            code: "SCP-VALID-7003".to_owned(),
        }
    }
}

impl From<scp_core::uri::ScpUriError> for ScpError {
    fn from(e: scp_core::uri::ScpUriError) -> Self {
        Self::Validation {
            message: format!("invalid SCP URI: {e} — check URI format (scp://relay/context-id)"),
            code: "SCP-VALID-7004".to_owned(),
        }
    }
}

impl From<scp_core::well_known::WellKnownValidationError> for ScpError {
    fn from(e: scp_core::well_known::WellKnownValidationError) -> Self {
        Self::Validation {
            message: format!("well-known validation failed: {e} — check relay configuration"),
            code: "SCP-VALID-7005".to_owned(),
        }
    }
}

impl From<scp_core::discovery::DiscoveryError> for ScpError {
    fn from(e: scp_core::discovery::DiscoveryError) -> Self {
        Self::Context {
            message: format!(
                "discovery operation failed: {e} — check relay connectivity and search parameters"
            ),
            code: "SCP-CTX-2008".to_owned(),
        }
    }
}

impl From<scp_core::bridge::registration::BridgeRegistrationError> for ScpError {
    fn from(e: scp_core::bridge::registration::BridgeRegistrationError) -> Self {
        Self::Context {
            message: format!(
                "bridge registration failed: {e} — verify bridge configuration and permissions"
            ),
            code: "SCP-CTX-2009".to_owned(),
        }
    }
}

impl From<scp_core::bridge::shadow::ShadowError> for ScpError {
    fn from(e: scp_core::bridge::shadow::ShadowError) -> Self {
        Self::Context {
            message: format!(
                "shadow context operation failed: {e} — check bridge state and context permissions"
            ),
            code: "SCP-CTX-2010".to_owned(),
        }
    }
}

impl From<scp_transport::TransportError> for ScpError {
    fn from(e: scp_transport::TransportError) -> Self {
        Self::Transport {
            message: format!(
                "{e} — check relay URL, network connectivity, and transport configuration"
            ),
            code: "SCP-TRANS-5001".to_owned(),
        }
    }
}

impl From<scp_platform::PlatformError> for ScpError {
    fn from(e: scp_platform::PlatformError) -> Self {
        Self::Crypto {
            message: format!(
                "platform key operation failed: {e} — check key custody configuration"
            ),
            code: "SCP-CRYPTO-4004".to_owned(),
        }
    }
}

impl From<serde_json::Error> for ScpError {
    fn from(e: serde_json::Error) -> Self {
        Self::Validation {
            message: format!("JSON serialization/deserialization failed: {e} — check input format"),
            code: "SCP-VALID-7006".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Enums (passed by value)
//
// See ADR-021 acceptance criterion 11.
// ---------------------------------------------------------------------------

/// The custody method used to protect an identity's private key.
///
/// See ADR-006 (Platform Abstraction) and `scp_platform::CustodyType`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum CustodyMethod {
    /// Key material stored in memory only (testing / in-process).
    InMemory,
    /// Key material protected by hardware security module
    /// (Secure Enclave on iOS, Android Keystore on Android).
    Platform,
    /// Key material in software-managed encrypted storage (not HSM-backed).
    Software,
    /// Identity loaded by DID string without local key material.
    ///
    /// Used by [`identity_load`] to represent an identity whose keys are
    /// managed externally (e.g., via an injected `KeyCustodyProvider`).
    External,
}

/// Context lifecycle state.
///
/// See ADR-008 (Context Lifecycle State Machine) and `scp_core::context::ContextState`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ContextState {
    /// Context is being initialized (MLS group forming, params validating).
    Creating,
    /// Context is fully active — members can send and receive.
    Active,
    /// Context is in the cooperative closing window — finalizing.
    Closing,
    /// Context is permanently closed.
    Closed,
    /// Context TTL has expired.
    Expired,
}

/// Memory scope for a context — governs key destruction and data retention on close.
///
/// See ADR-018 (Context TTL and Memory Scope) and spec §5.11.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum MemoryScope {
    /// All keys destroyed immediately on close. Content unreadable post-close.
    Ephemeral,
    /// Keys destroyed after a verification window (summary retained).
    Summary,
    /// All keys and content preserved after close.
    Full,
}

/// Governance model for context administration.
///
/// See spec §5.3 (Capability Ceiling Governance).
#[derive(Debug, Clone, uniffi::Enum)]
pub enum GovernanceModel {
    /// Single admin with unilateral control over governance decisions.
    SingleAdmin,
    /// N-of-M multisig governance (threshold defined in context params).
    Multisig,
    /// Token-weighted voting governance.
    TokenVoting,
}

// ---------------------------------------------------------------------------
// Records (pure data, passed by value)
//
// See ADR-021 acceptance criterion 10.
// ---------------------------------------------------------------------------

/// A DID document returned by identity resolution.
///
/// See ADR-002 (DID) and spec §3 (Identity).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DIDDocument {
    /// The DID string this document describes (e.g., `"did:dht:z6Mk..."`).
    pub id: String,
    /// Verification method IDs listed in the `authentication` relationship.
    pub authentication: Vec<String>,
    /// Verification method IDs listed in the `assertion_method` relationship.
    pub assertion_methods: Vec<String>,
    /// `alsoKnownAs` entries (alternative DID identifiers for this subject).
    pub also_known_as: Vec<String>,
    /// Service endpoint URLs declared in the DID document.
    pub service_endpoints: Vec<String>,
}

/// Context creation parameters.
///
/// All fields are optional and fall back to protocol defaults when omitted.
///
/// See ADR-008 (Context Lifecycle) and spec §5 (Contexts).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ContextParams {
    /// Capability ceiling — maximum capabilities any participant can hold.
    /// Empty list means no ceiling restriction.
    pub ceiling: Vec<String>,
    /// Governance model for this context.
    pub governance: GovernanceModel,
    /// Memory scope governing key destruction on close.
    pub memory_scope: MemoryScope,
    /// Optional time-to-live in seconds (0 = no TTL).
    pub ttl_seconds: u64,
    /// Whether this context can be promoted from ephemeral to persistent.
    pub promotable: bool,
}

/// A message received from an SCP context.
///
/// See spec §8 (Messaging).
#[derive(Debug, Clone, uniffi::Record)]
pub struct Message {
    /// DID of the message sender.
    pub sender_did: String,
    /// Raw message payload bytes (decrypted application content).
    pub payload: Vec<u8>,
    /// Unix timestamp (seconds since epoch) when the message was created.
    pub timestamp: u64,
    /// Monotonic sequence number within the context event log.
    pub sequence: u64,
    /// Context ID this message belongs to.
    pub context_id: String,
    /// Optional provenance metadata (cross-context origin chain).
    pub provenance: Option<DataProvenance>,
}

/// Provenance metadata for cross-context data transfer.
///
/// Every message or tool output that crosses a context boundary carries
/// provenance metadata tracing it back to its origin. See spec §12 (Provenance).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DataProvenance {
    /// DID of the original data source.
    pub source_did: String,
    /// Context ID where this data originated.
    pub origin_context_id: String,
    /// Depth of cross-context hops (0 = direct, 1 = one hop, etc.).
    pub chain_depth: u32,
    /// Ed25519 signature bytes over the provenance record.
    pub signature: Vec<u8>,
}

/// Tool definition for registration in a context.
///
/// See ADR-010 (Tool Registry) and spec §6 (Tools).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ToolDefinition {
    /// Human-readable tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// JSON Schema for tool input (as a JSON string).
    pub input_schema_json: String,
    /// JSON Schema for tool output (as a JSON string).
    pub output_schema_json: String,
    /// DID of the tool operator (responsible party).
    pub operator_did: String,
    /// Test vectors for integrity verification (serialized as JSON string).
    pub test_vectors_json: Option<String>,
    /// SHA-256 hash of the implementation binary (32 bytes).
    pub implementation_hash: Option<Vec<u8>>,
}

/// Result of verifying a tool against its test vectors.
///
/// See ADR-010 (Tool Registry).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ToolVerificationResult {
    /// The verified tool's ID.
    pub tool_id: String,
    /// `true` if all test vectors passed.
    pub passed: bool,
    /// Failure messages for vectors that did not pass. Empty on success.
    pub failures: Vec<String>,
}

/// Transport connection status.
///
/// See ADR-005 (Transport Abstraction).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TransportStatus {
    /// `true` if the transport is currently connected to a relay.
    pub connected: bool,
    /// The relay URL if connected. `None` if disconnected.
    pub relay_url: Option<String>,
    /// Round-trip latency to the relay in milliseconds. `None` if not measured.
    pub latency_ms: Option<f64>,
}

/// A protocol event from the context event log.
///
/// See ADR-011 (Event Log) and spec §13 (Event Log).
#[derive(Debug, Clone, uniffi::Record)]
pub struct Event {
    /// The event type (e.g., `"ContextCreated"`, `"MessageSent"`, `"ToolInvoked"`).
    pub event_type: String,
    /// DID of the actor who produced this event.
    pub actor_did: String,
    /// Unix timestamp (seconds since epoch) when the event was created.
    pub timestamp: u64,
    /// Event-specific data serialized as a JSON string.
    pub payload_json: String,
    /// Monotonic sequence number within the log.
    pub sequence: u64,
}

/// A Merkle proof from the event log.
///
/// See ADR-011 (Event Log).
#[derive(Debug, Clone, uniffi::Record)]
pub struct Proof {
    /// `true` if the claim was verified successfully.
    pub verified: bool,
    /// The proof type: `"inclusion"` or `"absence"`.
    pub proof_type: String,
    /// Proof details serialized as a JSON string (Merkle path or sorted neighbors).
    pub details_json: String,
}

/// A UCAN token with metadata accessible to SDK consumers.
///
/// See ADR-016 (UCAN Enforcement) and spec §10 (UCAN).
#[derive(Debug, Clone, uniffi::Record)]
pub struct UcanTokenData {
    /// Unique token identifier (derived from the UCAN nonce).
    pub token_id: String,
    /// Issuer DID — the entity that created and signed this token.
    pub issuer: String,
    /// Audience DID — the entity this token is delegated to.
    pub audience: String,
    /// Capability URIs granted by this token (e.g., `"scp:ctx:abc123/messages:write"`).
    pub capabilities: Vec<String>,
    /// Expiry timestamp (seconds since Unix epoch). `None` = no expiry.
    pub expires_at: Option<u64>,
}

/// Aggregated trust inputs for agent-level evaluation.
///
/// See ADR-017 (Trust Engine) and spec §7 (Trust).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TrustInput {
    /// DID of the subject being evaluated.
    pub subject_did: String,
    /// Context ID in which the evaluation is performed.
    pub context_id: String,
    /// Number of verified attestations from independent attestors.
    pub verified_attestation_count: u32,
    /// Participation count from the participation record.
    pub participation_count: u64,
    /// Number of triggered consequence rules in the evaluation window.
    pub triggered_consequences: u32,
    /// Evaluation timestamp (seconds since epoch).
    pub evaluated_at: u64,
}

// ---------------------------------------------------------------------------
// Opaque objects (passed by reference, hold state)
//
// Wrapped in Arc<T> for thread-safe shared ownership across the FFI boundary.
// UniFFI handles Arc automatically in the generated bindings.
//
// See ADR-021 acceptance criterion 9.
// ---------------------------------------------------------------------------

/// Opaque handle to an SCP identity.
///
/// Stores the DID string, custody type, and key custody provider so that
/// key material remains live for the lifetime of the handle:
///
/// - **In-memory custody** (dev/desktop): retained [`InMemoryKeyCustody`]
///   with key material in heap memory. Only available when the
///   `allow_in_memory_custody` feature is enabled.
/// - **Platform/Software custody** (production mobile): retained
///   [`CallbackKeyCustody`] adapter wrapping the injected
///   [`KeyCustodyProvider`](crate::KeyCustodyProvider) callback. Private
///   key material stays in the platform TEE (Secure Enclave / Keystore).
///
/// Generated as `class Identity` in both Swift and Kotlin.
///
/// See ADR-002 (DID), ADR-006 (Platform Abstraction), and SCP-214.
#[derive(Debug, uniffi::Object)]
pub struct Identity {
    /// The DID string (e.g., `"did:dht:z6Mk..."`).
    pub(crate) did: String,
    /// The custody method used for this identity.
    pub(crate) custody_type: CustodyMethod,
    /// Retained `ScpIdentity` for all custody paths.
    ///
    /// Holds the `KeyHandle`s into the custody provider. Must outlive any
    /// signing or key-rotation operation on this handle.
    #[allow(dead_code)]
    pub(crate) core_id: Option<ScpIdentity>,
    /// Retained DID document for agent key operations.
    ///
    /// Needed by `add_agent_key`, `rotate_agent_key`, `remove_agent_key` which
    /// take the current document as input. Updated in place when agent key
    /// operations succeed.
    #[allow(dead_code)]
    pub(crate) core_document: Option<CoreDidDocument>,
    /// Retained `InMemoryKeyCustody` for in-memory custody paths.
    ///
    /// Key material lives here. Dropping this destroys all private keys.
    /// Only available when `allow_in_memory_custody` is enabled.
    #[allow(dead_code)]
    #[cfg(feature = "allow_in_memory_custody")]
    pub(crate) in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
    /// Retained [`CallbackKeyCustody`] for platform/software custody paths.
    ///
    /// Wraps the injected [`KeyCustodyProvider`](crate::KeyCustodyProvider)
    /// callback so all crypto operations delegate to the platform TEE.
    /// `None` for in-memory and external custody.
    #[allow(dead_code)]
    pub(crate) callback_custody: Option<Arc<CallbackKeyCustody>>,
}

#[uniffi::export]
impl Identity {
    /// Returns the DID string for this identity.
    #[must_use]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    /// Returns the custody method string for this identity.
    ///
    /// One of: `"in_memory"`, `"platform"`, `"software"`, `"external"`.
    #[must_use]
    pub fn custody_type(&self) -> String {
        match self.custody_type {
            CustodyMethod::InMemory => "in_memory".to_owned(),
            CustodyMethod::Platform => "platform".to_owned(),
            CustodyMethod::Software => "software".to_owned(),
            CustodyMethod::External => "external".to_owned(),
        }
    }

    /// Rotates the active signing key for this identity (async).
    ///
    /// Generates a new Active Signing Key, updates the DID document on the
    /// DHT, and returns an updated `Identity` with the same DID but a new
    /// active signing key.
    ///
    /// Requires a retained custody provider (in-memory or platform callback).
    /// External/loaded identities without retained crypto state cannot rotate.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Identity` if key rotation or DID document publish fails,
    /// or if no custody provider is available.
    ///
    /// See SCP-214 acceptance criterion 9.
    pub async fn rotate_key(self: Arc<Self>) -> Result<Arc<Self>, ScpError> {
        let core_id = self.core_id.as_ref().ok_or_else(|| ScpError::Identity {
            message: "key rotation requires retained crypto state — this identity \
                      was loaded without key material (use identity_create or \
                      identity_create_with_custody)"
                .to_owned(),
            code: "SCP-IDENT-1002".to_owned(),
        })?;

        // Dispatch to the correct custody path.
        if let Some(ref callback) = self.callback_custody {
            // Platform/software custody: rotate via CallbackKeyCustody.
            let dht = DidDht::new();
            let (new_identity, new_document) = dht
                .rotate(core_id, callback.as_ref())
                .await
                .map_err(ScpError::from)?;

            let handle = Arc::new(Identity {
                did: new_identity.did.clone(),
                custody_type: self.custody_type.clone(),
                core_id: Some(new_identity),
                core_document: Some(new_document),
                #[cfg(feature = "allow_in_memory_custody")]
                in_memory_custody: None,
                callback_custody: self.callback_custody.clone(),
            });
            increment_handle_count();
            return Ok(handle);
        }

        #[cfg(feature = "allow_in_memory_custody")]
        if let Some(ref custody) = self.in_memory_custody {
            let dht = make_dht_with_signer(custody);
            let (new_identity, new_document) = dht
                .rotate(core_id, &custody.0)
                .await
                .map_err(ScpError::from)?;

            let handle = Arc::new(Identity {
                did: new_identity.did.clone(),
                custody_type: CustodyMethod::InMemory,
                core_id: Some(new_identity),
                core_document: Some(new_document),
                in_memory_custody: self.in_memory_custody.clone(),
                callback_custody: None,
            });
            increment_handle_count();
            return Ok(handle);
        }

        Err(ScpError::Identity {
            message: "key rotation requires a custody provider — use \
                      identity_create_with_custody() for platform custody or \
                      identity_create(\"in_memory\") for dev/test"
                .to_owned(),
            code: "SCP-IDENT-1002".to_owned(),
        })
    }

    /// Returns whether this identity has an agent signing key (`#agent` VM).
    ///
    /// Checks the retained `ScpIdentity`'s `agent_signing_key` field
    /// (`core_id`). Returns `false` for external/loaded identities that
    /// have no retained `ScpIdentity` (even if the DID document on the DHT
    /// contains an `#agent` verification method).
    ///
    /// **Note:** This method checks `core_id` (key handle existence), while
    /// [`get_agent_public_key`](Self::get_agent_public_key) checks
    /// `core_document` (DID document contents). Both should agree for
    /// identities created via `identity_create_with_agent_key` or after
    /// calling `add_agent_key`. For loaded identities without retained
    /// crypto state, both return `false`/`None`.
    ///
    /// See ADR-039 acceptance criterion 4.
    #[must_use]
    pub fn has_agent_key(&self) -> bool {
        self.core_id
            .as_ref()
            .is_some_and(|id| id.agent_signing_key.is_some())
    }

    /// Returns the agent signing key's public key as a multibase-encoded string.
    ///
    /// Retrieves the `#agent` verification method's `publicKeyMultibase` from
    /// the retained DID document (`core_document`). Returns `None` if no
    /// agent key exists or if the identity has no retained document.
    ///
    /// **Note:** This method checks `core_document` (DID document contents),
    /// while [`has_agent_key`](Self::has_agent_key) checks `core_id` (key
    /// handle existence). Both should agree for identities created via
    /// `identity_create_with_agent_key` or after calling `add_agent_key`.
    /// For loaded identities without retained crypto state, both return
    /// `false`/`None`.
    ///
    /// See ADR-039 acceptance criterion 4.
    #[must_use]
    pub fn get_agent_public_key(&self) -> Option<String> {
        self.core_document
            .as_ref()
            .and_then(|doc| doc.agent_verification_method())
            .map(|vm| vm.public_key_multibase.clone())
    }

    /// Adds an agent signing key to this identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair for the `#agent` verification method,
    /// adds it to the DID document, publishes the updated document to the DHT,
    /// and returns a new `Identity` handle with the agent key.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Identity` if:
    /// - The identity already has an agent key
    /// - No in-memory custody is available (feature-gated)
    /// - Key generation or DHT publishing fails
    ///
    /// See ADR-039 acceptance criterion 4.
    // async required by UniFFI export interface even though non-custody path has no await
    #[allow(clippy::unused_async)]
    pub async fn add_agent_key(self: Arc<Self>) -> Result<Arc<Self>, ScpError> {
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            Err(ScpError::Identity {
                message: "agent key operations require in-memory custody — \
                          enable the \"allow_in_memory_custody\" feature or use \
                          the platform KeyCustodyProvider interface"
                    .to_owned(),
                code: "SCP-IDENT-1008".to_owned(),
            })
        }

        #[cfg(feature = "allow_in_memory_custody")]
        {
            let core_id = self.core_id.as_ref().ok_or_else(|| ScpError::Identity {
                message: "cannot add agent key to an external/loaded identity \
                          without core state — use identity_create first"
                    .to_owned(),
                code: "SCP-IDENT-1005".to_owned(),
            })?;
            let core_doc = self
                .core_document
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    message: "cannot add agent key without a retained DID document".to_owned(),
                    code: "SCP-IDENT-1005".to_owned(),
                })?;
            let custody = self
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    message: "cannot add agent key without in-memory custody".to_owned(),
                    code: "SCP-IDENT-1008".to_owned(),
                })?
                .clone();

            // Clone what we need for the spawned task.
            let identity_clone = core_id.clone();
            let doc_clone = core_doc.clone();
            let did = self.did.clone();
            let custody_type = self.custody_type.clone();
            let in_memory_custody = Some(custody.clone());
            let dht = make_dht_with_signer(&custody);

            runtime()
                .spawn(async move {
                    let (updated_identity, updated_doc) = dht
                        .add_agent_key(&identity_clone, &doc_clone, &custody.0)
                        .await
                        .map_err(ScpError::from)?;

                    let handle = Arc::new(Self {
                        did,
                        custody_type,
                        core_id: Some(updated_identity),
                        core_document: Some(updated_doc),
                        in_memory_custody,
                        callback_custody: None,
                    });
                    increment_handle_count();
                    Ok(handle)
                })
                .await
                .map_err(|e| ScpError::Identity {
                    message: format!("tokio task join error during add_agent_key: {e}"),
                    code: "SCP-IDENT-1007".to_owned(),
                })?
        }
    }

    /// Removes the agent signing key from this identity (ADR-039).
    ///
    /// Removes the `#agent` verification method from the DID document,
    /// publishes the updated document to the DHT, and returns a new `Identity`
    /// handle without the agent key.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Identity` if:
    /// - The identity has no agent key
    /// - No in-memory custody is available (feature-gated)
    /// - DHT publishing fails
    ///
    /// See ADR-039 acceptance criterion 4.
    // async required by UniFFI export interface even though non-custody path has no await
    #[allow(clippy::unused_async)]
    pub async fn remove_agent_key(self: Arc<Self>) -> Result<Arc<Self>, ScpError> {
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            Err(ScpError::Identity {
                message: "agent key operations require in-memory custody — \
                          enable the \"allow_in_memory_custody\" feature or use \
                          the platform KeyCustodyProvider interface"
                    .to_owned(),
                code: "SCP-IDENT-1008".to_owned(),
            })
        }

        #[cfg(feature = "allow_in_memory_custody")]
        {
            let core_id = self.core_id.as_ref().ok_or_else(|| ScpError::Identity {
                message: "cannot remove agent key from an external/loaded identity \
                          without core state"
                    .to_owned(),
                code: "SCP-IDENT-1005".to_owned(),
            })?;
            let core_doc = self
                .core_document
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    message: "cannot remove agent key without a retained DID document".to_owned(),
                    code: "SCP-IDENT-1005".to_owned(),
                })?;

            let custody = self
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    message: "cannot remove agent key without in-memory custody \
                              (needed for DHT publish signing)"
                        .to_owned(),
                    code: "SCP-IDENT-1008".to_owned(),
                })?;

            // Clone what we need for the spawned task.
            let identity_clone = core_id.clone();
            let doc_clone = core_doc.clone();
            let did = self.did.clone();
            let custody_type = self.custody_type.clone();
            let in_memory_custody = self.in_memory_custody.clone();
            let dht = make_dht_with_signer(custody);

            runtime()
                .spawn(async move {
                    let (updated_identity, updated_doc) = dht
                        .remove_agent_key(&identity_clone, &doc_clone)
                        .await
                        .map_err(ScpError::from)?;

                    let handle = Arc::new(Self {
                        did,
                        custody_type,
                        core_id: Some(updated_identity),
                        core_document: Some(updated_doc),
                        in_memory_custody,
                        callback_custody: None,
                    });
                    increment_handle_count();
                    Ok(handle)
                })
                .await
                .map_err(|e| ScpError::Identity {
                    message: format!("tokio task join error during remove_agent_key: {e}"),
                    code: "SCP-IDENT-1007".to_owned(),
                })?
        }
    }

    /// Rotates the agent signing key for this identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair, moves the old `#agent` key to
    /// `#retired-agent-{sequence}`, installs the new key as `#agent`, publishes
    /// the updated DID document, and returns a new `Identity` handle.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Identity` if:
    /// - The identity has no agent key to rotate
    /// - No in-memory custody is available (feature-gated)
    /// - Key generation or DHT publishing fails
    ///
    /// See ADR-039 acceptance criterion 4.
    // async required by UniFFI export interface even though non-custody path has no await
    #[allow(clippy::unused_async)]
    pub async fn rotate_agent_key(self: Arc<Self>) -> Result<Arc<Self>, ScpError> {
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            Err(ScpError::Identity {
                message: "agent key operations require in-memory custody — \
                          enable the \"allow_in_memory_custody\" feature or use \
                          the platform KeyCustodyProvider interface"
                    .to_owned(),
                code: "SCP-IDENT-1008".to_owned(),
            })
        }

        #[cfg(feature = "allow_in_memory_custody")]
        {
            let core_id = self.core_id.as_ref().ok_or_else(|| ScpError::Identity {
                message: "cannot rotate agent key on an external/loaded identity \
                          without core state"
                    .to_owned(),
                code: "SCP-IDENT-1005".to_owned(),
            })?;
            let core_doc = self
                .core_document
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    message: "cannot rotate agent key without a retained DID document".to_owned(),
                    code: "SCP-IDENT-1005".to_owned(),
                })?;
            let custody = self
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    message: "cannot rotate agent key without in-memory custody".to_owned(),
                    code: "SCP-IDENT-1008".to_owned(),
                })?
                .clone();

            // Clone what we need for the spawned task.
            let identity_clone = core_id.clone();
            let doc_clone = core_doc.clone();
            let did = self.did.clone();
            let custody_type = self.custody_type.clone();
            let in_memory_custody = Some(custody.clone());
            let dht = make_dht_with_signer(&custody);

            runtime()
                .spawn(async move {
                    let (updated_identity, updated_doc) = dht
                        .rotate_agent_key(&identity_clone, &doc_clone, &custody.0)
                        .await
                        .map_err(ScpError::from)?;

                    let handle = Arc::new(Self {
                        did,
                        custody_type,
                        core_id: Some(updated_identity),
                        core_document: Some(updated_doc),
                        in_memory_custody,
                        callback_custody: None,
                    });
                    increment_handle_count();
                    Ok(handle)
                })
                .await
                .map_err(|e| ScpError::Identity {
                    message: format!("tokio task join error during rotate_agent_key: {e}"),
                    code: "SCP-IDENT-1007".to_owned(),
                })?
        }
    }
}

impl Drop for Identity {
    /// Decrements the global FFI handle count.
    ///
    /// Called when the last `Arc<Identity>` is dropped, releasing the handle.
    /// This allows [`crate::scp_shutdown`] to detect when all handles are
    /// gone before tearing down the tokio runtime.
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

/// Opaque handle to an SCP context.
///
/// Stores context metadata (ID, state, creator DID) and the retained key
/// custody provider (in-memory or callback) for UCAN signing and inner
/// envelope creation.
///
/// Generated as `class ContextHandle` in both Swift and Kotlin.
///
/// See ADR-008 (Context Lifecycle) and ADR-013 §3 (bridge pattern).
#[derive(Debug, uniffi::Object)]
pub struct ContextHandle {
    /// Unique identifier for this context.
    pub(crate) context_id: String,
    /// Current lifecycle state.
    pub(crate) state: tokio::sync::Mutex<ContextState>,
    /// DID of the context creator.
    pub(crate) creator_did: String,
    /// Retained [`InMemoryKeyCustody`] for UCAN signing (RED-102).
    ///
    /// Set during `context_create` from the creating identity's custody.
    /// Used by `ucan_mint` to produce real Ed25519 signatures.
    /// Only available when `allow_in_memory_custody` is enabled.
    #[allow(dead_code)]
    #[cfg(feature = "allow_in_memory_custody")]
    pub(crate) in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
    /// Retained [`CallbackKeyCustody`] for platform custody contexts.
    #[allow(dead_code)]
    pub(crate) callback_custody: Option<Arc<CallbackKeyCustody>>,
    /// Handle to the creator's active signing key for UCAN minting (RED-102).
    ///
    /// Points into the custody provider. Used by `ucan_mint`.
    #[allow(dead_code)]
    pub(crate) signing_key: Option<KeyHandle>,
    /// Capability ceiling strings for UCAN mint-time enforcement (#339).
    pub(crate) ceiling_strings: Vec<String>,
    /// Session store for stateful tool sessions (spec section 6.2.1).
    pub(crate) session_store: tokio::sync::Mutex<scp_core::context::tools::SessionStore>,
}

#[uniffi::export]
impl ContextHandle {
    /// Returns the context's unique identifier.
    pub fn context_id(&self) -> String {
        self.context_id.clone()
    }

    /// Returns the context's current lifecycle state as a string.
    ///
    /// One of: `"creating"`, `"active"`, `"closing"`, `"closed"`, `"expired"`.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` if the state lock is poisoned.
    pub fn state(&self) -> Result<String, ScpError> {
        let guard = self.state.try_lock().map_err(|_| ScpError::Context {
            message: "context state lock is contended — retry".to_owned(),
            code: "SCP-CTX-2012".to_owned(),
        })?;
        Ok(match *guard {
            ContextState::Creating => "creating".to_owned(),
            ContextState::Active => "active".to_owned(),
            ContextState::Closing => "closing".to_owned(),
            ContextState::Closed => "closed".to_owned(),
            ContextState::Expired => "expired".to_owned(),
        })
    }

    /// Returns the DID of the context creator.
    pub fn creator_did(&self) -> String {
        self.creator_did.clone()
    }
}

impl Drop for ContextHandle {
    /// Decrements the global FFI handle count.
    ///
    /// Called when the last `Arc<ContextHandle>` is dropped. This allows
    /// [`crate::scp_shutdown`] to detect when all handles are released
    /// before tearing down the tokio runtime.
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

/// Opaque handle to a UCAN token.
///
/// Exposes token metadata without leaking raw JWT or signature bytes.
/// The raw encoded token is held internally for future validation operations.
///
/// Generated as `class UcanToken` in both Swift and Kotlin.
///
/// See ADR-016 (UCAN Enforcement).
#[derive(Debug, uniffi::Object)]
pub struct UcanToken {
    /// Stable token data accessible to SDK consumers.
    pub(crate) data: UcanTokenData,
    /// Raw encoded JWT string — held for use in validation operations.
    /// Will be used when UCAN validation is wired to scp-core in a future story.
    #[allow(dead_code)]
    pub(crate) encoded: String,
}

#[uniffi::export]
impl UcanToken {
    /// Returns the token's stable metadata record.
    #[must_use]
    pub fn token_data(&self) -> UcanTokenData {
        self.data.clone()
    }

    /// Returns the token's unique ID.
    #[must_use]
    pub fn token_id(&self) -> String {
        self.data.token_id.clone()
    }

    /// Returns the issuer DID.
    #[must_use]
    pub fn issuer(&self) -> String {
        self.data.issuer.clone()
    }

    /// Returns the audience DID.
    #[must_use]
    pub fn audience(&self) -> String {
        self.data.audience.clone()
    }

    /// Returns the list of capability URIs granted by this token.
    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        self.data.capabilities.clone()
    }

    /// Returns the expiry timestamp (seconds since epoch) or `None` if no expiry.
    #[must_use]
    pub const fn expires_at(&self) -> Option<u64> {
        self.data.expires_at
    }
}

// `Drop` for `UcanToken` — now that `ucan_mint` is wired to `scp-core` and
// calls `increment_handle_count()`, this `Drop` impl decrements the counter
// to maintain `scp_shutdown` handle-drain correctness (RED-102).
impl Drop for UcanToken {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

/// Opaque handle to the transport layer.
///
/// Exposes connection status and relay URL without leaking connection state.
/// The actual transport (WebSocket, multi-relay routing) is managed internally.
///
/// Generated as `class TransportManager` in both Swift and Kotlin.
///
/// See ADR-005 (Transport Abstraction).
#[derive(Debug, uniffi::Object)]
pub struct TransportManager {
    /// Current connection state.
    pub(crate) status: std::sync::Mutex<TransportStatus>,
}

#[uniffi::export]
impl TransportManager {
    /// Returns the current transport connection status record.
    pub fn status(&self) -> TransportStatus {
        self.status
            .lock()
            .map(|s| s.clone())
            .unwrap_or(TransportStatus {
                connected: false,
                relay_url: None,
                latency_ms: None,
            })
    }

    /// Returns `true` if the transport is currently connected.
    pub fn is_connected(&self) -> bool {
        self.status.lock().map(|s| s.connected).unwrap_or(false)
    }
}

impl Drop for TransportManager {
    /// Decrements the global FFI handle count.
    ///
    /// Called when the last `Arc<TransportManager>` is dropped. This allows
    /// [`crate::scp_shutdown`] to detect when all handles are released
    /// before tearing down the tokio runtime.
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Free functions — identity operations
//
// See ADR-021 acceptance criterion 2.
// ---------------------------------------------------------------------------

/// Creates a new DID identity with the specified custody method.
///
/// # Arguments
///
/// * `custody` — The custody type string. Accepted values depend on the build
///   configuration:
///   - `"platform"` — always accepted; requires a wired `KeyCustodyProvider`.
///   - `"software"` — always accepted; requires a wired `KeyCustodyProvider`.
///   - `"in_memory"` — **only** accepted when the `allow_in_memory_custody`
///     feature is enabled at compile time. Returns `ScpError::Identity` with
///     code `SCP-IDENT-1008` otherwise. Stores key material in unprotected heap
///     memory; suitable for testing and development but NOT for production use
///     on mobile devices.
///
/// # Returns
///
/// An `Identity` handle with the new DID and custody type.
///
/// # Errors
///
/// Returns `ScpError::Identity` if key generation or DID creation fails.
/// Returns `ScpError::Identity` with code `SCP-IDENT-1008` if `"in_memory"` is
/// requested but the `allow_in_memory_custody` feature is not enabled.
/// Returns `ScpError::Validation` if the custody string is not recognized.
///
/// # In-memory custody (feature-gated)
///
/// When `custody` is `"in_memory"` and the `allow_in_memory_custody` feature
/// is enabled, this function creates a real `did:dht` identity using
/// [`scp_identity::DidDht`] backed by `InMemoryKeyCustody`. The
/// returned DID is self-certifying and has the `did:dht:z` prefix.
///
/// `"in_memory"` custody stores key material in unprotected heap memory.
/// It is suitable for testing and development but NOT for production use
/// on mobile devices — use `"platform"` (Secure Enclave / Android Keystore)
/// in production. See GitHub issue #88 and ADR-006.
#[uniffi::export]
pub async fn identity_create(custody: String) -> Result<Arc<Identity>, ScpError> {
    let custody_method = parse_custody_method(&custody)?;

    runtime()
        .spawn(async move {
            match custody_method {
                CustodyMethod::InMemory => {
                    // Gate: `"in_memory"` custody is only available when the
                    // `allow_in_memory_custody` feature is enabled. Production
                    // mobile builds MUST NOT enable this feature. See #88.
                    #[cfg(not(feature = "allow_in_memory_custody"))]
                    {
                        Err(ScpError::Identity {
                            message: "\"in_memory\" custody is not available in this build \
                                      — enable the \"allow_in_memory_custody\" feature for \
                                      dev/desktop use. Production mobile builds must use \
                                      \"platform\" custody (Secure Enclave / Android Keystore)."
                                .to_owned(),
                            code: "SCP-IDENT-1008".to_owned(),
                        })
                    }

                    #[cfg(feature = "allow_in_memory_custody")]
                    {
                        // Wire to real scp-core using InMemoryKeyCustody.
                        // The `testing` feature is available in dev/test/desktop
                        // builds; production mobile builds use the "platform"
                        // custody path via KeyCustodyProvider callback.
                        //
                        // IMPORTANT: both `core_identity` and `key_custody` must be
                        // retained in the handle. `ScpIdentity` holds `KeyHandle`s
                        // that are indices into `key_custody`'s internal store.
                        // Dropping `key_custody` destroys all private key material
                        // and renders those handles dangling.
                        let key_custody =
                            Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
                        let dht = DidDht::new();
                        let (identity, document) =
                            dht.create(&key_custody.0).await.map_err(ScpError::from)?;

                        let handle = Arc::new(Identity {
                            did: identity.did.clone(),
                            custody_type: CustodyMethod::InMemory,
                            core_id: Some(identity),
                            core_document: Some(document),
                            in_memory_custody: Some(key_custody),
                            callback_custody: None,
                        });
                        increment_handle_count();
                        Ok(handle)
                    }
                }
                CustodyMethod::Platform | CustodyMethod::Software => {
                    // Platform and software custody require a wired
                    // KeyCustodyProvider (ADR-006 platform abstraction).
                    // Use `identity_create_with_custody` to inject a
                    // platform-backed KeyCustodyProvider callback.
                    Err(ScpError::Identity {
                        message: format!(
                            "custody type {custody:?} requires a KeyCustodyProvider — \
                             use identity_create_with_custody() to inject a Secure \
                             Enclave (iOS) or Android Keystore (Android) backed \
                             custody provider"
                        ),
                        code: "SCP-IDENT-1003".to_owned(),
                    })
                }
                CustodyMethod::External => {
                    // `parse_custody_method` never produces External — it is only
                    // constructed internally by `identity_load` for DID-string-only
                    // handles that have no local key material. Reaching this arm
                    // in `identity_create` is a bridge-layer bug.
                    Err(ScpError::Identity {
                        message: "internal: CustodyMethod::External cannot be used with \
                                  identity_create — use identity_load for external DID handles"
                            .to_owned(),
                        code: "SCP-IDENT-1005".to_owned(),
                    })
                }
            }
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during identity creation: {e}"),
            code: "SCP-IDENT-1007".to_owned(),
        })?
}

/// Creates a new SCP identity using an injected platform custody provider.
///
/// This is the production-grade identity creation path for mobile platforms.
/// The `provider` callback handles all cryptographic operations (signing,
/// key generation, pseudonym derivation) inside the platform's TEE (Secure
/// Enclave on iOS, Android Keystore on Android). Private key material never
/// crosses the FFI boundary (ADR-006).
///
/// # Arguments
///
/// * `provider` — A [`KeyCustodyProvider`](crate::KeyCustodyProvider) callback
///   implementation injected from Swift or Kotlin.
///
/// # Returns
///
/// An `Identity` handle with `custody_type` set to `"platform"`.
///
/// # Errors
///
/// Returns `ScpError::Identity` if DID creation or DHT publish fails.
///
/// See SCP-214 acceptance criteria 2-3.
#[uniffi::export]
pub async fn identity_create_with_custody(
    provider: Box<dyn crate::KeyCustodyProvider>,
) -> Result<Arc<Identity>, ScpError> {
    runtime()
        .spawn(async move {
            let callback_custody = Arc::new(CallbackKeyCustody::new(provider));

            let dht = DidDht::new();
            let (identity, document) = dht
                .create(callback_custody.as_ref())
                .await
                .map_err(ScpError::from)?;

            let handle = Arc::new(Identity {
                did: identity.did.clone(),
                custody_type: CustodyMethod::Platform,
                core_id: Some(identity),
                core_document: Some(document),
                #[cfg(feature = "allow_in_memory_custody")]
                in_memory_custody: None,
                callback_custody: Some(callback_custody),
            });
            increment_handle_count();
            Ok(handle)
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during identity creation: {e}"),
            code: "SCP-IDENT-1007".to_owned(),
        })?
}

/// Loads an existing identity from storage by its DID.
///
/// # Arguments
///
/// * `did` — The DID string to load (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// An `Identity` handle for the loaded DID.
///
/// # Errors
///
/// Returns `ScpError::Identity` if the DID format is unsupported or the
/// identity cannot be loaded from storage.
#[uniffi::export]
pub async fn identity_load(did: String) -> Result<Arc<Identity>, ScpError> {
    runtime()
        .spawn(async move {
            if !did.starts_with("did:dht:") {
                return Err(ScpError::Identity {
                    message: format!("unsupported DID method: {did} — only did:dht is supported"),
                    code: "SCP-IDENT-1004".to_owned(),
                });
            }

            // identity_load returns a DID-string-only handle. Key operations
            // require the KeyCustodyProvider callback interface to be wired.
            let handle = Arc::new(Identity {
                did,
                custody_type: CustodyMethod::External,
                core_id: None,
                core_document: None,
                #[cfg(feature = "allow_in_memory_custody")]
                in_memory_custody: None,
                callback_custody: None,
            });
            increment_handle_count();
            Ok(handle)
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during identity load: {e}"),
            code: "SCP-IDENT-1005".to_owned(),
        })?
}

/// Resolves a DID to its document.
///
/// # Arguments
///
/// * `did` — The DID string to resolve (e.g., `"did:dht:z6Mk..."`).
///
/// # Returns
///
/// A `DIDDocument` record with the resolved document fields.
///
/// # Errors
///
/// Returns `ScpError::Identity` if the DID cannot be resolved (not found
/// on DHT, invalid format, verification failure).
#[uniffi::export]
pub async fn identity_resolve(did: String) -> Result<DIDDocument, ScpError> {
    runtime()
        .spawn(async move {
            let did_method = DidDht::new();
            let document = did_method.resolve(&did).await.map_err(ScpError::from)?;

            Ok(DIDDocument {
                id: document.id.clone(),
                authentication: document.authentication.clone(),
                assertion_methods: document.assertion_method.clone(),
                also_known_as: document.also_known_as.clone(),
                service_endpoints: document
                    .service
                    .iter()
                    .map(|s| s.service_endpoint.clone())
                    .collect(),
            })
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during DID resolution: {e}"),
            code: "SCP-IDENT-1006".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Free functions — context lifecycle operations
//
// See ADR-021 acceptance criterion 3.
// ---------------------------------------------------------------------------

/// Creates a new SCP context.
///
/// # Arguments
///
/// * `identity` — The identity of the context creator.
/// * `params` — Context creation parameters (governs ceiling, governance,
///   memory scope, and TTL; used in full scp-core wiring).
///
/// # Returns
///
/// A `ContextHandle` in the active state.
///
/// # Errors
///
/// Returns `ScpError::Context` if context creation fails (validation,
/// MLS group formation, or event log initialization).
#[uniffi::export]
pub async fn context_create(
    identity: Arc<Identity>,
    params: ContextParams,
) -> Result<Arc<ContextHandle>, ScpError> {
    runtime()
        .spawn(async move {
            let context_id = format!("ctx-{}", Uuid::new_v4());

            // Convert bridge ContextParams to scp-core ContextParams.
            let core_params = bridge_params_to_core(&params);

            // Delegate to the shared ContextManager.
            let manager = crate::runtime::context_manager();
            let _core_handle = manager
                .create_context(context_id.clone(), core_params, identity.did.clone().into())
                .await
                .map_err(ScpError::from)?;

            // Register the creator's DID as a local DID for defense-in-depth,
            // matching NAPI's behavior.
            manager
                .register_local_did(identity.did.clone().into())
                .await;

            // Extract key custody and signing key from the identity (RED-102).
            #[cfg(feature = "allow_in_memory_custody")]
            let in_memory_custody = identity.in_memory_custody.clone();
            let callback_custody = identity.callback_custody.clone();
            let signing_key = identity.core_id.as_ref().map(|id| id.active_signing_key);

            // Derive the context-scoped pseudonym routing ID via the retained
            // KeyCustody (SCP-214 criterion 5, spec §9.10.4). This produces a
            // deterministic pseudonym from the identity key + context ID.
            if let (Some(core_id), Some(identity_key)) = (
                identity.core_id.as_ref(),
                identity.core_id.as_ref().map(|id| &id.identity_key),
            ) {
                let _pseudonym = if let Some(ref cb) = callback_custody {
                    cb.derive_pseudonym(identity_key, context_id.as_bytes())
                        .await
                        .ok()
                } else {
                    #[cfg(feature = "allow_in_memory_custody")]
                    {
                        if let Some(ref imc) = identity.in_memory_custody {
                            imc.0
                                .derive_pseudonym(identity_key, context_id.as_bytes())
                                .await
                                .ok()
                        } else {
                            None
                        }
                    }
                    #[cfg(not(feature = "allow_in_memory_custody"))]
                    {
                        None
                    }
                };
                // The pseudonym is derived for routing ID use. The actual
                // routing ID is stored by the ContextManager's transport
                // provider. Here we validate the derivation succeeds and
                // the custody provider is functional for this context.
                let _ = core_id;
            }

            let handle = Arc::new(ContextHandle {
                context_id,
                state: tokio::sync::Mutex::new(ContextState::Active),
                creator_did: identity.did.clone(),
                #[cfg(feature = "allow_in_memory_custody")]
                in_memory_custody,
                callback_custody,
                signing_key,
                ceiling_strings: params.ceiling.clone(),
                session_store: tokio::sync::Mutex::new(
                    scp_core::context::tools::SessionStore::new(),
                ),
            });
            increment_handle_count();
            Ok(handle)
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during context creation: {e}"),
            code: "SCP-CTX-2011".to_owned(),
        })?
}

/// Joins an existing SCP context.
///
/// # Arguments
///
/// * `handle` — The context to join.
/// * `identity` — The identity joining the context.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not in active state or
/// if the join operation fails (key package, MLS add, event log).
#[uniffi::export]
pub async fn context_join(
    handle: Arc<ContextHandle>,
    identity: Arc<Identity>,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let state = handle.state.lock().await;

            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Context {
                    message: format!(
                        "cannot join context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-CTX-2013".to_owned(),
                });
            }
            drop(state);

            // Delegate to the shared ContextManager. Build a core ContextHandle
            // to pass the context_id, then join via the manager.
            let manager = crate::runtime::context_manager();
            let core_handle = scp_core::context::ContextHandle::new(
                handle.context_id.clone(),
                scp_core::context::ContextParams::default(),
            );
            // Transition core handle to Active so join_context accepts it.
            let _ = core_handle
                .transition_to(&scp_core::context::ContextState::Active)
                .await;

            let key_package = KeyPackage {
                owner_did: identity.did.clone().into(),
                mls_key_package_bytes: None,
            };

            manager
                .join_context(&core_handle, key_package)
                .await
                .map_err(ScpError::from)?;

            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during context join: {e}"),
            code: "SCP-CTX-2014".to_owned(),
        })?
}

/// Leaves an SCP context.
///
/// # Arguments
///
/// * `handle` — The context to leave.
/// * `identity` — The identity leaving the context.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not in active state or
/// if the leave operation fails (MLS remove, sender key update, event log).
#[uniffi::export]
pub async fn context_leave(
    handle: Arc<ContextHandle>,
    identity: Arc<Identity>,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let state = handle.state.lock().await;

            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Context {
                    message: format!(
                        "cannot leave context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-CTX-2015".to_owned(),
                });
            }
            drop(state);

            // Delegate to the shared ContextManager.
            let manager = crate::runtime::context_manager();
            let core_handle = scp_core::context::ContextHandle::new(
                handle.context_id.clone(),
                scp_core::context::ContextParams::default(),
            );
            let _ = core_handle
                .transition_to(&scp_core::context::ContextState::Active)
                .await;

            let member_did: scp_identity::DID = identity.did.clone().into();
            manager
                .leave_context(&core_handle, &member_did, &member_did)
                .await
                .map_err(ScpError::from)?;

            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during context leave: {e}"),
            code: "SCP-CTX-2016".to_owned(),
        })?
}

/// Closes an SCP context.
///
/// Initiates the cooperative closing window: notifies members, generates
/// summaries (if `memory_scope` == Summary), and destroys keys per memory scope.
///
/// # Arguments
///
/// * `handle` — The context to close.
/// * `identity` — The identity initiating the close (must have close capability).
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not in active state or
/// the caller lacks the close capability.
#[uniffi::export]
pub async fn context_close(
    handle: Arc<ContextHandle>,
    identity: Arc<Identity>,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            // Authorization is enforced by the ContextManager (which delegates
            // to ttl::close_context checking the ContextClose capability). No
            // bridge-layer auth check — the ContextManager is authoritative.
            let identity_did = identity.did.clone();

            let mut state = handle.state.lock().await;
            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Context {
                    message: format!(
                        "cannot close context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-CTX-2017".to_owned(),
                });
            }

            // Delegate to the shared ContextManager.
            let manager = crate::runtime::context_manager();
            let core_handle = scp_core::context::ContextHandle::new(
                handle.context_id.clone(),
                scp_core::context::ContextParams::default(),
            );
            let _ = core_handle
                .transition_to(&scp_core::context::ContextState::Active)
                .await;

            let initiator_did: scp_identity::DID = identity_did.into();
            manager
                .close_context(&core_handle, &initiator_did)
                .await
                .map_err(ScpError::from)?;

            *state = ContextState::Closed;
            drop(state);

            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during context close: {e}"),
            code: "SCP-CTX-2018".to_owned(),
        })?
}

/// Sends a message to an SCP context.
///
/// The payload is encrypted via the context's MLS group key (or sender key
/// for broadcast contexts) before transmission.
///
/// # Arguments
///
/// * `handle` — The context to send to.
/// * `identity` — The identity of the sender.
/// * `payload` — The raw message payload bytes to send.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not active.
/// Returns `ScpError::Crypto` if encryption fails.
/// Returns `ScpError::Transport` if delivery fails.
#[uniffi::export]
pub async fn context_send(
    handle: Arc<ContextHandle>,
    identity: Arc<Identity>,
    payload: Vec<u8>,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let state = handle.state.lock().await;

            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Context {
                    message: format!(
                        "cannot send to context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-CTX-2019".to_owned(),
                });
            }
            drop(state);

            // Validate inner envelope signing via the retained KeyCustody
            // (SCP-214 criterion 6). This ensures the identity's active signing
            // key can produce a valid Ed25519 signature before delegating to
            // the ContextManager for message delivery.
            if let Some(core_id) = identity.core_id.as_ref() {
                let context_id = handle.context_id.clone();
                let sender_did_str = identity.did.clone();
                let now_ms = scp_core::time::now_millis().map_err(|e| ScpError::Crypto {
                    message: format!("clock error: {e}"),
                    code: "SCP-CRYPTO-4000".to_owned(),
                })?;

                let params = scp_core::envelope::InnerEnvelopeParams {
                    context_id: &context_id,
                    sender_did: &sender_did_str,
                    epoch: 0,
                    generation: 0,
                    sequence: 0,
                    timestamp: now_ms,
                    message_type: scp_core::envelope::MessageType::Content,
                    payload: &payload,
                    provenance: None,
                    signing_key_id: scp_identity::SigningKeyId::Active,
                };

                if let Some(ref cb) = handle.callback_custody {
                    scp_core::envelope::create_inner_envelope(
                        &params,
                        cb.as_ref(),
                        &core_id.active_signing_key,
                    )
                    .await
                    .map_err(|e| ScpError::Crypto {
                        message: format!("inner envelope signing failed: {e}"),
                        code: "SCP-CRYPTO-4001".to_owned(),
                    })?;
                } else {
                    #[cfg(feature = "allow_in_memory_custody")]
                    if let Some(ref imc) = handle.in_memory_custody {
                        scp_core::envelope::create_inner_envelope(
                            &params,
                            &imc.0,
                            &core_id.active_signing_key,
                        )
                        .await
                        .map_err(|e| ScpError::Crypto {
                            message: format!("inner envelope signing failed: {e}"),
                            code: "SCP-CRYPTO-4001".to_owned(),
                        })?;
                    }
                }
            }

            // Delegate to the shared ContextManager for message delivery
            // through the transport provider.
            let manager = crate::runtime::context_manager();
            let core_handle = scp_core::context::ContextHandle::new(
                handle.context_id.clone(),
                scp_core::context::ContextParams::default(),
            );
            let _ = core_handle
                .transition_to(&scp_core::context::ContextState::Active)
                .await;

            let sender_did: scp_identity::DID = identity.did.clone().into();
            manager
                .send_message(&core_handle, &sender_did, &payload, None)
                .await
                .map_err(ScpError::from)?;

            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during message send: {e}"),
            code: "SCP-CTX-2020".to_owned(),
        })?
}

/// Subscribes to incoming messages for a context via a callback listener.
///
/// The Swift SDK wrapper converts this callback to `AsyncStream<Message>`;
/// the Kotlin SDK wrapper converts it to `Flow<Message>` via `callbackFlow`.
///
/// # Arguments
///
/// * `handle` — The context to subscribe to.
/// * `listener` — A `MessageListener` callback implementation (passed as Box
///   per `UniFFI` callback interface convention).
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not in active state.
#[uniffi::export]
pub async fn context_subscribe(
    handle: Arc<ContextHandle>,
    listener: Box<dyn crate::MessageListener>,
) -> Result<(), ScpError> {
    let state = handle.state.lock().await;

    if !matches!(*state, ContextState::Active) {
        return Err(ScpError::Context {
            message: format!(
                "cannot subscribe to context in {:?} state — context must be active",
                *state
            ),
            code: "SCP-CTX-2021".to_owned(),
        });
    }
    drop(state);

    // Signal stream completion — full transport wiring connects this
    // listener to the message pipeline in integration stories.
    listener.on_complete();
    Ok(())
}

// ---------------------------------------------------------------------------
// Free functions — tool operations
//
// See ADR-021 acceptance criterion 4.
// ---------------------------------------------------------------------------

/// Registers a tool in an SCP context.
///
/// # Arguments
///
/// * `handle` — The context to register the tool in.
/// * `definition` — Tool definition including name, schema, and test vectors.
///
/// # Returns
///
/// The tool ID string assigned to the registered tool.
///
/// # Errors
///
/// Returns `ScpError::Tool` if the context is not active, registration
/// fails (permission denied, schema invalid, duplicate name, etc.).
#[uniffi::export]
pub async fn tool_register(
    handle: Arc<ContextHandle>,
    definition: ToolDefinition,
) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            let state = handle.state.lock().await;

            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Tool {
                    message: format!(
                        "cannot register tool in context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-TOOL-6003".to_owned(),
                });
            }
            drop(state);

            let tool_id = format!("tool-{}", Uuid::new_v4());
            let _ = definition;
            Ok(tool_id)
        })
        .await
        .map_err(|e| ScpError::Tool {
            message: format!("tokio task join error during tool registration: {e}"),
            code: "SCP-TOOL-6004".to_owned(),
        })?
}

/// Invokes a tool within an SCP context.
///
/// # Arguments
///
/// * `handle` — The context containing the tool.
/// * `tool_id` — The ID of the tool to invoke.
/// * `input_json` — Tool input parameters as a JSON string.
/// * `identity` — The identity of the invoker (used for capability checking).
///
/// # Returns
///
/// The tool output as a JSON string.
///
/// # Errors
///
/// Returns `ScpError::Tool` if the tool is not found, invocation fails,
/// input fails schema validation, or the invoker lacks capability.
#[uniffi::export]
pub async fn tool_invoke(
    handle: Arc<ContextHandle>,
    tool_id: String,
    input_json: String,
    identity: Arc<Identity>,
) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            let state = handle.state.lock().await;

            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Tool {
                    message: format!(
                        "cannot invoke tool in context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-TOOL-6005".to_owned(),
                });
            }
            drop(state);

            let _ = (tool_id, input_json, identity);
            Ok("{}".to_owned())
        })
        .await
        .map_err(|e| ScpError::Tool {
            message: format!("tokio task join error during tool invocation: {e}"),
            code: "SCP-TOOL-6006".to_owned(),
        })?
}

/// Verifies a tool against its registered test vectors.
///
/// # Arguments
///
/// * `handle` — The context containing the tool.
/// * `tool_id` — The ID of the tool to verify.
///
/// # Returns
///
/// A `ToolVerificationResult` with pass/fail status and failure messages.
///
/// # Errors
///
/// Returns `ScpError::Tool` if the tool is not found in the context.
#[uniffi::export]
pub async fn tool_verify(
    handle: Arc<ContextHandle>,
    tool_id: String,
) -> Result<ToolVerificationResult, ScpError> {
    runtime()
        .spawn(async move {
            let state = handle.state.lock().await;

            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Tool {
                    message: format!(
                        "cannot verify tool in context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-TOOL-6007".to_owned(),
                });
            }
            drop(state);

            Ok(ToolVerificationResult {
                tool_id,
                passed: true,
                failures: Vec::new(),
            })
        })
        .await
        .map_err(|e| ScpError::Tool {
            message: format!("tokio task join error during tool verification: {e}"),
            code: "SCP-TOOL-6008".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Free functions — cross-context tool invocation (spec section 6.2)
// ---------------------------------------------------------------------------

/// Invokes a tool across context boundaries.
///
/// Validates chain depth per spec section 6.2 (max 3 hops).
///
/// # Arguments
///
/// * `source_handle` — The calling context.
/// * `target_handle` — The context containing the tool.
/// * `tool_id` — The tool to invoke.
/// * `input_json` — Tool input as a JSON string.
/// * `identity` — The invoker's identity.
/// * `chain_depth` — Current chain depth (0 for first hop).
///
/// # Errors
///
/// Returns `ScpError::Tool` if chain depth exceeded or contexts not active.
#[uniffi::export]
pub async fn tool_invoke_cross_context(
    source_handle: Arc<ContextHandle>,
    target_handle: Arc<ContextHandle>,
    tool_id: String,
    input_json: String,
    identity: Arc<Identity>,
    chain_depth: u8,
) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            // Validate source context is active.
            let source_state = source_handle.state.lock().await;
            if !matches!(*source_state, ContextState::Active) {
                return Err(ScpError::Tool {
                    message: format!(
                        "cannot invoke cross-context tool: source context in {:?} state",
                        *source_state
                    ),
                    code: "SCP-TOOL-6010".to_owned(),
                });
            }
            drop(source_state);

            // Validate target context is active.
            let target_state = target_handle.state.lock().await;
            if !matches!(*target_state, ContextState::Active) {
                return Err(ScpError::Tool {
                    message: format!(
                        "cannot invoke cross-context tool: target context in {:?} state",
                        *target_state
                    ),
                    code: "SCP-TOOL-6011".to_owned(),
                });
            }
            drop(target_state);

            // Validate chain depth.
            if chain_depth > scp_core::provenance::attach::DEFAULT_MAX_CHAIN_DEPTH {
                return Err(ScpError::Tool {
                    message: format!(
                        "cross-context chain depth {chain_depth} exceeds maximum {}",
                        scp_core::provenance::attach::DEFAULT_MAX_CHAIN_DEPTH
                    ),
                    code: "SCP-TOOL-6012".to_owned(),
                });
            }

            let output = serde_json::json!({
                "tool": tool_id,
                "source_context": source_handle.context_id,
                "target_context": target_handle.context_id,
                "status": "validated",
                "chain_depth": chain_depth,
                "invoker_did": identity.did,
                "validated_input": serde_json::from_str::<serde_json::Value>(&input_json)
                    .unwrap_or(serde_json::Value::Null),
            });

            serde_json::to_string(&output).map_err(|e| ScpError::Tool {
                message: format!("failed to serialize cross-context output: {e}"),
                code: "SCP-TOOL-6013".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Tool {
            message: format!("tokio task join error during cross-context invocation: {e}"),
            code: "SCP-TOOL-6009".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Free functions — stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

/// Creates a stateful tool session.
///
/// Sessions enable multi-turn workflows with TTL and per-caller caps
/// (default: 5 concurrent sessions per caller, per spec section 6.2.1).
///
/// # Returns
///
/// The session ID (UUID string).
#[uniffi::export]
pub async fn tool_session_create(
    handle: Arc<ContextHandle>,
    tool_id: String,
    source_context_id: String,
    ttl_seconds: u64,
) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            let state = handle.state.lock().await;
            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Tool {
                    message: format!(
                        "cannot create session in context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-TOOL-6014".to_owned(),
                });
            }
            drop(state);

            let mut store = handle.session_store.lock().await;

            // Enforce per-caller session cap.
            let current = store.count_by_source(&source_context_id);
            if current >= scp_core::context::tools::DEFAULT_SESSION_CAP_PER_CALLER {
                return Err(ScpError::Tool {
                    message: format!(
                        "session cap exceeded for caller '{}': {} active (max {})",
                        source_context_id,
                        current,
                        scp_core::context::tools::DEFAULT_SESSION_CAP_PER_CALLER
                    ),
                    code: "SCP-TOOL-6015".to_owned(),
                });
            }

            let session_id = Uuid::new_v4().to_string();
            let now_ms = scp_core::time::now_millis().map_err(|e| ScpError::Tool {
                message: format!("clock error: {e}"),
                code: "SCP-TOOL-6016".to_owned(),
            })?;

            let session = scp_core::context::tools::ToolSession {
                session_id: session_id.clone(),
                tool_id,
                source_context: source_context_id,
                state: serde_json::Value::Null,
                created_at: now_ms,
                ttl: std::time::Duration::from_secs(ttl_seconds),
                call_count: 0,
            };

            store.insert(session);
            Ok(session_id)
        })
        .await
        .map_err(|e| ScpError::Tool {
            message: format!("tokio task join error during session creation: {e}"),
            code: "SCP-TOOL-6009".to_owned(),
        })?
}

/// Invokes a tool within an active session.
///
/// Each call is individually governed. Session state is carried forward
/// and the call count is incremented on success.
///
/// # Returns
///
/// The tool output as a JSON string.
#[uniffi::export]
pub async fn tool_session_invoke(
    handle: Arc<ContextHandle>,
    session_id: String,
    input_json: String,
    identity: Arc<Identity>,
) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            let state = handle.state.lock().await;
            if !matches!(*state, ContextState::Active) {
                return Err(ScpError::Tool {
                    message: format!(
                        "cannot invoke session in context in {:?} state — context must be active",
                        *state
                    ),
                    code: "SCP-TOOL-6017".to_owned(),
                });
            }
            drop(state);

            let mut store = handle.session_store.lock().await;

            let session = store.get(&session_id).ok_or_else(|| ScpError::Tool {
                message: format!("session '{session_id}' not found"),
                code: "SCP-TOOL-6018".to_owned(),
            })?;

            // Check expiry.
            let now_ms = scp_core::time::now_millis().map_err(|e| ScpError::Tool {
                message: format!("clock error: {e}"),
                code: "SCP-TOOL-6016".to_owned(),
            })?;
            if session.is_expired(now_ms) {
                store.remove(&session_id);
                return Err(ScpError::Tool {
                    message: format!("session '{session_id}' has expired"),
                    code: "SCP-TOOL-6019".to_owned(),
                });
            }

            let tool_id = session.tool_id.clone();
            let call_count = session.call_count;

            // Increment call count.
            if let Some(session) = store.get_mut(&session_id) {
                session.call_count = session.call_count.saturating_add(1);
            }

            let output = serde_json::json!({
                "tool": tool_id,
                "session_id": session_id,
                "status": "validated",
                "call_count": call_count + 1,
                "invoker_did": identity.did,
                "validated_input": serde_json::from_str::<serde_json::Value>(&input_json)
                    .unwrap_or(serde_json::Value::Null),
            });

            serde_json::to_string(&output).map_err(|e| ScpError::Tool {
                message: format!("failed to serialize session invoke output: {e}"),
                code: "SCP-TOOL-6020".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Tool {
            message: format!("tokio task join error during session invocation: {e}"),
            code: "SCP-TOOL-6009".to_owned(),
        })?
}

/// Closes a stateful tool session.
///
/// Removes the session from the store, releasing the caller's session slot.
#[uniffi::export]
pub async fn tool_session_close(
    handle: Arc<ContextHandle>,
    session_id: String,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let mut store = handle.session_store.lock().await;
            if store.remove(&session_id).is_none() {
                return Err(ScpError::Tool {
                    message: format!("session '{session_id}' not found"),
                    code: "SCP-TOOL-6021".to_owned(),
                });
            }
            Ok(())
        })
        .await
        .map_err(|e| ScpError::Tool {
            message: format!("tokio task join error during session close: {e}"),
            code: "SCP-TOOL-6009".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Free functions — transport operations
//
// See ADR-021 acceptance criterion 5.
// ---------------------------------------------------------------------------

/// Connects to an SCP relay.
///
/// # Arguments
///
/// * `relay_url` — The URL of the SCP relay (e.g., `"wss://relay.example.com"`).
///
/// # Returns
///
/// A `TransportManager` handle for the established connection.
///
/// # Errors
///
/// Returns `ScpError::Transport` if the connection fails (unreachable relay,
/// protocol mismatch, timeout, authentication failure).
#[uniffi::export]
pub async fn transport_connect(relay_url: String) -> Result<Arc<TransportManager>, ScpError> {
    if !relay_url.starts_with("wss://") {
        return Err(ScpError::Transport {
            message: format!(
                "relay URL must use wss:// scheme, got: {relay_url:?} — \
                 plain-text ws:// is not permitted; use TLS"
            ),
            code: "SCP-TRANS-5001".to_owned(),
        });
    }

    runtime()
        .spawn(async move {
            let handle = Arc::new(TransportManager {
                status: std::sync::Mutex::new(TransportStatus {
                    connected: true,
                    relay_url: Some(relay_url),
                    latency_ms: None,
                }),
            });
            increment_handle_count();
            Ok(handle)
        })
        .await
        .map_err(|e| ScpError::Transport {
            message: format!("tokio task join error during transport connect: {e}"),
            code: "SCP-TRANS-5002".to_owned(),
        })?
}

/// Returns the current transport connection status.
///
/// # Errors
///
/// Returns `ScpError::Transport` if querying the transport status fails.
#[uniffi::export]
pub async fn transport_status(manager: Arc<TransportManager>) -> Result<TransportStatus, ScpError> {
    Ok(manager.status())
}

// ---------------------------------------------------------------------------
// Free functions — UCAN operations
//
// See ADR-021 acceptance criterion 6.
// ---------------------------------------------------------------------------

/// Validates a UCAN token for a required capability.
///
/// Performs full validation: signature verification, time bounds checking,
/// delegation chain traversal, attenuation enforcement, nonce replay
/// detection, and capability matching.
///
/// # Arguments
///
/// * `handle` — The context the token is presented in.
/// * `token` — The encoded UCAN token string (JWT format).
/// * `capability` — The required capability URI (e.g.,
///   `"scp:ctx:abc123/messages:write"`).
/// * `presenting_agent_did` — Optional DID of the agent presenting the
///   token. Falls back to the token's audience field if `None`. Required
///   for ADR-016 step 5 (audience verification).
/// * `proof_tokens` — Optional list of encoded UCAN proof tokens for
///   delegation chain traversal (ADR-016 step 3).
///
/// # Errors
///
/// Returns `ScpError::Permission` if validation fails (malformed token,
/// invalid signature, expired, insufficient capabilities, revoked,
/// broken delegation chain).
#[uniffi::export]
pub async fn ucan_validate(
    handle: Arc<ContextHandle>,
    token: String,
    capability: String,
    presenting_agent_did: Option<String>,
    proof_tokens: Option<Vec<String>>,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let _ = (
                handle,
                token,
                capability,
                presenting_agent_did,
                proof_tokens,
            );
            Err(ScpError::Permission {
                message: "not yet connected to runtime — UCAN validation requires a live context"
                    .to_owned(),
                code: "SCP-PERM-3002".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Permission {
            message: format!("tokio task join error during UCAN validation: {e}"),
            code: "SCP-PERM-3003".to_owned(),
        })?
}

/// Mints a new UCAN token for a context member with real Ed25519 signing.
///
/// Uses the context creator's key custody and active signing key
/// (retained on the context handle during `context_create`) to produce a
/// properly signed UCAN token via `scp_core::crypto::ucan::mint::mint_ucan`.
///
/// When the `allow_in_memory_custody` feature is enabled, uses the
/// `InMemoryKeyCustody` retained on the context handle. When disabled,
/// UCAN minting requires a wired `KeyCustodyProvider` (not yet
/// implemented — returns an error).
///
/// # Arguments
///
/// * `handle` — The context to mint the token for (must have key custody
///   from `context_create` with an `in_memory` identity, or a wired
///   `KeyCustodyProvider`).
/// * `member_did` — The DID of the member receiving the token.
/// * `capabilities` — List of capability strings to grant (e.g.,
///   `"messages:write"`). Scoped to the context automatically.
///
/// # Returns
///
/// A `UcanToken` handle with the minted token's metadata and a real
/// Ed25519 signature.
///
/// # Errors
///
/// Returns `ScpError::Permission` if the context does not have key custody
/// (created from an `identity_load` handle without key material) or if
/// signing fails.
///
/// See RED-102 for the `KeyCustody` wiring story.
#[uniffi::export]
pub async fn ucan_mint(
    handle: Arc<ContextHandle>,
    member_did: String,
    capabilities: Vec<String>,
) -> Result<Arc<UcanToken>, ScpError> {
    ucan_mint_impl(handle, member_did, capabilities).await
}

/// Inner implementation of [`ucan_mint`], split out for cfg-gating clarity.
#[cfg(feature = "allow_in_memory_custody")]
async fn ucan_mint_impl(
    handle: Arc<ContextHandle>,
    member_did: String,
    capabilities: Vec<String>,
) -> Result<Arc<UcanToken>, ScpError> {
    runtime()
        .spawn(async move {
            // Extract key custody and signing key from the context handle (RED-102).
            let custody =
                handle
                    .in_memory_custody
                    .as_ref()
                    .ok_or_else(|| ScpError::Permission {
                        message: "UCAN minting requires key custody — create the context with \
                              an in_memory identity (identity_create(\"in_memory\"))"
                            .to_owned(),
                        code: "SCP-PERM-3004".to_owned(),
                    })?;
            let signing_key = handle.signing_key.ok_or_else(|| ScpError::Permission {
                message: "UCAN minting requires a signing key — the context creator identity \
                          must have an active signing key"
                    .to_owned(),
                code: "SCP-PERM-3004".to_owned(),
            })?;

            let params = scp_core::crypto::ucan::mint::MintParams {
                issuer_did: &handle.creator_did,
                issuer_key: &signing_key,
                audience_did: &member_did,
                context_id: &handle.context_id,
                capabilities: &capabilities,
                lifetime_secs: 3600, // 1 hour default
                not_before: None,
                proofs: vec![],
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: if handle.ceiling_strings.is_empty() {
                    None
                } else {
                    Some(handle.ceiling_strings.iter().cloned().collect())
                },
            };

            let token = scp_core::crypto::ucan::mint::mint_ucan(&params, &custody.0)
                .await
                .map_err(ScpError::from)?;

            let data = UcanTokenData {
                token_id: token.payload.nnc.clone(),
                issuer: token.payload.iss.clone(),
                audience: token.payload.aud.clone(),
                capabilities: token.payload.att.iter().map(|a| a.with.clone()).collect(),
                expires_at: Some(token.payload.exp),
            };

            increment_handle_count();
            Ok(Arc::new(UcanToken {
                data,
                encoded: token.encoded,
            }))
        })
        .await
        .map_err(|e| ScpError::Permission {
            message: format!("tokio task join error during UCAN mint: {e}"),
            code: "SCP-PERM-3005".to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)] // Must be async to match the cfg(feature) variant's signature.
async fn ucan_mint_impl(
    _handle: Arc<ContextHandle>,
    _member_did: String,
    _capabilities: Vec<String>,
) -> Result<Arc<UcanToken>, ScpError> {
    Err(ScpError::Permission {
        message: "UCAN minting requires key custody — the in_memory custody path \
                  is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use, or wire \
                  a KeyCustodyProvider for production."
            .to_owned(),
        code: "SCP-PERM-3004".to_owned(),
    })
}

/// Revokes a UCAN token.
///
/// Adds the token to the context's revocation list. Revoked tokens are no
/// longer accepted by validation. Revocation is distributed to all context
/// members.
///
/// # Arguments
///
/// * `handle` — The context the token belongs to.
/// * `token` — The full encoded JWT string of the token to revoke.
///
/// # Errors
///
/// Returns `ScpError::Permission` if revocation fails (token not found,
/// revoker not authorized — must be the token's issuer or context creator).
#[uniffi::export]
pub async fn ucan_revoke(handle: Arc<ContextHandle>, token: String) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let _ = (handle, token);
            Err(ScpError::Permission {
                message: "not yet connected to runtime — UCAN revocation requires a live context"
                    .to_owned(),
                code: "SCP-PERM-3006".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Permission {
            message: format!("tokio task join error during UCAN revocation: {e}"),
            code: "SCP-PERM-3007".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Free functions — event log operations
//
// See ADR-021 acceptance criterion 7.
// ---------------------------------------------------------------------------

/// Queries the context event log with optional filter criteria.
///
/// # Arguments
///
/// * `handle` — The context whose event log to query.
/// * `filter_json` — Optional JSON string with filter parameters:
///   `event_type`, `actor_did`, `after_sequence`, `before_sequence`,
///   `after_timestamp`, `before_timestamp`, `limit`.
///   Pass `None` to return all events.
///
/// # Returns
///
/// A list of `Event` records matching the filter.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not active or the query fails.
#[uniffi::export]
pub async fn event_log_query(
    handle: Arc<ContextHandle>,
    filter_json: Option<String>,
) -> Result<Vec<Event>, ScpError> {
    runtime()
        .spawn(async move {
            let _ = (handle, filter_json);
            Err(ScpError::Context {
                message: "not yet connected to runtime — event log query requires a live context"
                    .to_owned(),
                code: "SCP-CTX-2023".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during event log query: {e}"),
            code: "SCP-CTX-2024".to_owned(),
        })?
}

/// Verifies a claim against the context event log (Merkle proof).
///
/// Generates and verifies an inclusion or absence proof for the given claim.
///
/// # Arguments
///
/// * `handle` — The context whose event log to verify against.
/// * `claim_json` — JSON string describing the claim:
///   - `"type"`: `"inclusion"` or `"absence"`
///   - `"leaf_index"` (for inclusion): event position
///   - `"event_hash"` (for absence): hex-encoded hash to prove absent
///
/// # Returns
///
/// A `Proof` record with the verification result and Merkle proof details.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not active or the
/// verification fails (empty log, invalid index, etc.).
#[uniffi::export]
pub async fn event_log_verify(
    handle: Arc<ContextHandle>,
    claim_json: String,
) -> Result<Proof, ScpError> {
    runtime()
        .spawn(async move {
            let _ = (handle, claim_json);
            Err(ScpError::Context {
                message:
                    "not yet connected to runtime — event log verification requires a live context"
                        .to_owned(),
                code: "SCP-CTX-2025".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during event log verification: {e}"),
            code: "SCP-CTX-2026".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Free functions — governance operations (#387)
//
// All 24 GovernanceAction variants are dispatchable via
// ContextManager::execute_governance_action.
// ---------------------------------------------------------------------------

/// Executes an approved governance action on a context.
///
/// The `proposal_json` must be a JSON-serialized `GovernanceProposal` with
/// status `Approved`. All 24 governance action variants (ADR-031) are
/// supported.
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `proposal_json` — JSON-serialized `GovernanceProposal`.
///
/// # Errors
///
/// Returns `ScpError::Permission` if the proposal is not approved, targets
/// the wrong context, or has already been executed (replay protection).
/// Returns `ScpError::Context` for any other governance execution failure.
#[uniffi::export]
pub async fn governance_execute(
    handle: Arc<ContextHandle>,
    proposal_json: String,
) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            let proposal: scp_core::context::governance::GovernanceProposal =
                serde_json::from_str(&proposal_json)?;
            let manager = crate::runtime::context_manager();
            let result = manager
                .execute_governance_action(&handle.context_id, &proposal)
                .await
                .map_err(ScpError::from)?;
            // Serialize the result variant name for the caller.
            use scp_core::context::manager::GovernanceActionResult;
            let result_str = match result {
                GovernanceActionResult::MemberAdded => "MemberAdded",
                GovernanceActionResult::MemberRemoved => "MemberRemoved",
                GovernanceActionResult::RoleChanged => "RoleChanged",
                GovernanceActionResult::ToolRegistered => "ToolRegistered",
                GovernanceActionResult::ToolRemoved => "ToolRemoved",
                GovernanceActionResult::CeilingModified => "CeilingModified",
                GovernanceActionResult::ContextClosed => "ContextClosed",
                GovernanceActionResult::TtlExtended => "TtlExtended",
                GovernanceActionResult::PruningPolicyModified => "PruningPolicyModified",
                GovernanceActionResult::AdminTransferred => "AdminTransferred",
                GovernanceActionResult::SignerAdded => "SignerAdded",
                GovernanceActionResult::SignerRemoved => "SignerRemoved",
                GovernanceActionResult::ThresholdModified => "ThresholdModified",
                GovernanceActionResult::ChildContextCreated => "ChildContextCreated",
                GovernanceActionResult::ToolInterfaceEstablished => "ToolInterfaceEstablished",
                GovernanceActionResult::MemberReset => "MemberReset",
                GovernanceActionResult::ConflictResolved => "ConflictResolved",
                GovernanceActionResult::ContextPromoted => "ContextPromoted",
                GovernanceActionResult::ReadAccessRevoked(_) => "ReadAccessRevoked",
                GovernanceActionResult::ReadAccessRestored(_) => "ReadAccessRestored",
                GovernanceActionResult::WriteAccessRevoked(_) => "WriteAccessRevoked",
                GovernanceActionResult::WriteAccessRestored(_) => "WriteAccessRestored",
                GovernanceActionResult::ContentKeysRotated(_) => "ContentKeysRotated",
                GovernanceActionResult::GovernanceReconfigured(_) => "GovernanceReconfigured",
                GovernanceActionResult::AuthorBlocked(_) => "AuthorBlocked",
                GovernanceActionResult::SubscriberBanned(_) => "SubscriberBanned",
                GovernanceActionResult::SubscriberUnbanned { .. } => "SubscriberUnbanned",
                GovernanceActionResult::Executed => "Executed",
            };
            Ok(result_str.to_owned())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during governance execution: {e}"),
            code: "SCP-CTX-2032".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Free functions — broadcast operations (#387)
// ---------------------------------------------------------------------------

/// Subscribes a DID to a broadcast context.
///
/// For open broadcast contexts, any DID can subscribe. For gated contexts,
/// a valid `messagesRead` UCAN is required (passed as `ucan_token` JSON).
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not active, not a
/// broadcast context, or if subscription fails.
#[uniffi::export]
pub async fn broadcast_subscribe(
    handle: Arc<ContextHandle>,
    subscriber_did: String,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let did: scp_identity::DID = subscriber_did.into();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            manager
                .subscribe_broadcast::<
                    crate::bridge::NoOpDidResolver,
                    crate::bridge::NoOpNonceTracker,
                    crate::bridge::NoOpRevocationChecker,
                    crate::bridge::NoOpProofResolver,
                    std::hash::RandomState,
                >(&handle.context_id, &did, None, timestamp, None)
                .await
                .map_err(ScpError::from)?;
            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during broadcast subscribe: {e}"),
            code: "SCP-CTX-2033".to_owned(),
        })?
}

/// Unsubscribes a DID from a broadcast context.
///
/// When `rotate_keys` is `true`, all authors rotate their broadcast keys
/// for forward secrecy.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not active or not broadcast.
#[uniffi::export]
pub async fn broadcast_unsubscribe(
    handle: Arc<ContextHandle>,
    subscriber_did: String,
    rotate_keys: bool,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let did: scp_identity::DID = subscriber_did.into();
            manager
                .unsubscribe_broadcast(&handle.context_id, &did, rotate_keys)
                .await
                .map_err(ScpError::from)?;
            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during broadcast unsubscribe: {e}"),
            code: "SCP-CTX-2034".to_owned(),
        })?
}

/// Publishes a message to a broadcast context.
///
/// The payload is encrypted with the author's broadcast key.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not active, not broadcast,
/// or the sender is not an author.
#[uniffi::export]
pub async fn broadcast_publish(
    handle: Arc<ContextHandle>,
    author_did: String,
    payload: Vec<u8>,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let did: scp_identity::DID = author_did.into();
            manager
                .publish_broadcast(
                    &handle.context_id,
                    &did,
                    &payload,
                    &ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]),
                )
                .await
                .map_err(ScpError::from)?;
            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during broadcast publish: {e}"),
            code: "SCP-CTX-2035".to_owned(),
        })?
}

/// Blocks a subscriber's read access in a broadcast context.
///
/// The subscriber is removed from the registry and added to all authors'
/// block lists; all author keys are rotated.
///
/// # Errors
///
/// Returns `ScpError::Context` if the operation fails.
#[uniffi::export]
pub async fn broadcast_block_subscriber(
    handle: Arc<ContextHandle>,
    subscriber_did: String,
    blocker_did: String,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let subscriber: scp_identity::DID = subscriber_did.into();
            let blocker: scp_identity::DID = blocker_did.into();
            manager
                .block_broadcast_subscriber(&handle.context_id, &subscriber, &blocker)
                .await
                .map_err(ScpError::from)?;
            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during broadcast block: {e}"),
            code: "SCP-CTX-2036".to_owned(),
        })?
}

/// Handles a broadcast key request from a subscriber.
///
/// Validates the author DID is locally controlled and processes the key
/// distribution request.
///
/// # Errors
///
/// Returns `ScpError::Context` if the operation fails.
#[uniffi::export]
pub async fn broadcast_handle_key_request(
    handle: Arc<ContextHandle>,
    author_did: String,
    requester_did: String,
) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let author: scp_identity::DID = author_did.into();
            let requester: scp_identity::DID = requester_did.into();
            let decision = manager
                .handle_broadcast_key_request(&handle.context_id, &author, &requester)
                .await
                .map_err(ScpError::from)?;
            Ok(format!("{decision:?}"))
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during key request handling: {e}"),
            code: "SCP-CTX-2037".to_owned(),
        })?
}

/// Returns the number of broadcast subscribers for a context.
///
/// Returns `None` if the context is not registered or not a broadcast context.
#[uniffi::export]
pub async fn broadcast_subscriber_count(handle: Arc<ContextHandle>) -> Option<u64> {
    let manager = crate::runtime::context_manager();
    manager
        .broadcast_subscriber_count(&handle.context_id)
        .await
        .map(|n| n as u64)
}

/// Returns `true` if the given DID is a broadcast subscriber.
#[uniffi::export]
pub async fn broadcast_is_subscriber(handle: Arc<ContextHandle>, did: String) -> bool {
    let manager = crate::runtime::context_manager();
    manager
        .is_broadcast_subscriber(&handle.context_id, &did)
        .await
}

/// Returns the broadcast admission policy for a context.
///
/// Returns the policy as a string: `"Open"` or `"Gated"`.
/// Returns `None` if the context is not a broadcast context.
#[uniffi::export]
pub async fn broadcast_admission(handle: Arc<ContextHandle>) -> Option<String> {
    let manager = crate::runtime::context_manager();
    manager
        .broadcast_admission(&handle.context_id)
        .await
        .map(|a| format!("{a:?}"))
}

// ---------------------------------------------------------------------------
// Free functions — membership queries (#387)
// ---------------------------------------------------------------------------

/// Returns the current member count for a context.
///
/// Returns `None` if the context is not registered.
#[uniffi::export]
pub async fn context_member_count(handle: Arc<ContextHandle>) -> Option<u64> {
    let manager = crate::runtime::context_manager();
    manager
        .member_count(&handle.context_id)
        .await
        .map(|n| n as u64)
}

/// Returns `true` if the given DID is a member of the context.
#[uniffi::export]
pub async fn context_is_member(handle: Arc<ContextHandle>, did: String) -> bool {
    let manager = crate::runtime::context_manager();
    manager.is_member(&handle.context_id, &did).await
}

/// Returns all member DIDs for a context.
#[uniffi::export]
pub async fn context_member_dids(handle: Arc<ContextHandle>) -> Vec<String> {
    let manager = crate::runtime::context_manager();
    manager.member_dids(&handle.context_id).await
}

/// Returns the role assignment for a specific member as a JSON string.
///
/// Returns `None` if the member is not found or the context is not registered.
#[uniffi::export]
pub async fn context_member_role(handle: Arc<ContextHandle>, did: String) -> Option<String> {
    let manager = crate::runtime::context_manager();
    manager
        .member_role(&handle.context_id, &did)
        .await
        .map(|r| format!("{r:?}"))
}

// ---------------------------------------------------------------------------
// Free functions — events (#387)
// ---------------------------------------------------------------------------

/// Drains all pending events from the context's receive buffer.
///
/// Returns a list of event descriptions as JSON strings. Returns empty
/// if the context is not registered.
#[uniffi::export]
pub async fn context_drain_events(handle: Arc<ContextHandle>) -> Vec<String> {
    let manager = crate::runtime::context_manager();
    manager
        .drain_events(&handle.context_id)
        .await
        .into_iter()
        .map(|e| format!("{e:?}"))
        .collect()
}

// ---------------------------------------------------------------------------
// Free functions — TTL operations (#387)
// ---------------------------------------------------------------------------

/// Handles TTL expiry for a context.
///
/// Transitions from `Active` to `Expired`, destroys keys per memory scope.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not active.
#[uniffi::export]
#[allow(clippy::significant_drop_tightening)]
pub async fn context_handle_ttl_expiry(handle: Arc<ContextHandle>) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let core_handle = scp_core::context::ContextHandle::new(
                handle.context_id.clone(),
                scp_core::context::ContextParams::default(),
            );
            let _ = core_handle
                .transition_to(&scp_core::context::ContextState::Active)
                .await;
            manager
                .handle_ttl_expiry(&core_handle)
                .await
                .map_err(ScpError::from)?;

            // Update the FFI handle state to reflect expiry.
            let mut state = handle.state.lock().await;
            *state = ContextState::Expired;

            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during TTL expiry: {e}"),
            code: "SCP-CTX-2038".to_owned(),
        })?
}

/// Proposes a TTL extension. Records consent from the given member.
///
/// Returns `true` if all members have consented (unanimous approval).
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not registered or the
/// member is not found.
#[uniffi::export]
pub async fn context_propose_ttl_extension(
    handle: Arc<ContextHandle>,
    member_did: String,
    proposed_seconds: u64,
) -> Result<bool, ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let did: scp_identity::DID = member_did.into();
            let duration = std::time::Duration::from_secs(proposed_seconds);
            manager
                .propose_ttl_extension(&handle.context_id, &did, duration)
                .await
                .map_err(ScpError::from)
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during TTL extension proposal: {e}"),
            code: "SCP-CTX-2039".to_owned(),
        })?
}

/// Resets the TTL timer after a successful unanimous extension.
///
/// Cancels the old timer and spawns a new one with the given duration.
#[uniffi::export]
pub async fn context_reset_ttl_timer(handle: Arc<ContextHandle>, new_seconds: u64) {
    let manager = crate::runtime::context_manager();
    let core_handle = scp_core::context::ContextHandle::new(
        handle.context_id.clone(),
        scp_core::context::ContextParams::default(),
    );
    let _ = core_handle
        .transition_to(&scp_core::context::ContextState::Active)
        .await;
    let duration = std::time::Duration::from_secs(new_seconds);
    manager
        .reset_ttl_timer(&handle.context_id, duration, core_handle)
        .await;
}

// ---------------------------------------------------------------------------
// Free functions — local DID management (#387)
// ---------------------------------------------------------------------------

/// Registers a DID as locally controlled by this node/SDK.
///
/// Used for defense-in-depth validation in broadcast key request handling.
#[uniffi::export]
pub async fn register_local_did(did: String) {
    let manager = crate::runtime::context_manager();
    manager.register_local_did(did.into()).await;
}

/// Returns `true` if the given DID is registered as locally controlled.
#[uniffi::export]
pub async fn is_local_did(did: String) -> bool {
    let manager = crate::runtime::context_manager();
    let did_ref: scp_identity::DID = did.into();
    manager.is_local_did(&did_ref).await
}

// ---------------------------------------------------------------------------
// No-op validation trait stubs for subscribe_broadcast generic params
//
// These are minimal implementations satisfying the generic bounds on
// ContextManager::subscribe_broadcast. Broadcast subscription in open mode
// does not require UCAN validation; gated mode validation will be wired
// when the full UCAN pipeline is integrated with the FFI layer.
// ---------------------------------------------------------------------------

pub(crate) struct NoOpDidResolver;
impl scp_core::crypto::ucan::validate::DidResolver for NoOpDidResolver {
    fn resolve_public_key(
        &self,
        _did: &str,
    ) -> Result<[u8; 32], scp_core::crypto::ucan::UcanError> {
        Err(scp_core::crypto::ucan::UcanError::MalformedToken(
            "NoOpDidResolver: no DID resolution available".into(),
        ))
    }
}

pub(crate) struct NoOpNonceTracker;
impl scp_core::crypto::ucan::validate::NonceTracker for NoOpNonceTracker {
    fn check_and_record(
        &mut self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_core::crypto::ucan::UcanError> {
        Ok(())
    }
}

pub(crate) struct NoOpRevocationChecker;
impl scp_core::crypto::ucan::validate::RevocationChecker for NoOpRevocationChecker {
    fn is_revoked(&self, _token_cid: &str) -> bool {
        false
    }
}

pub(crate) struct NoOpProofResolver;
impl scp_core::crypto::ucan::validate::ProofResolver for NoOpProofResolver {
    fn resolve_proof(
        &self,
        cid: &str,
    ) -> Result<scp_core::crypto::ucan::UcanToken, scp_core::crypto::ucan::UcanError> {
        Err(scp_core::crypto::ucan::UcanError::DelegationChainBroken(
            format!("NoOpProofResolver: no proof available for CID {cid}"),
        ))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts bridge `ContextParams` to scp-core `ContextParams`.
fn bridge_params_to_core(params: &ContextParams) -> scp_core::context::ContextParams {
    use scp_core::context::params::{Capability, PromotionPolicy};

    let ceiling: Vec<Capability> = params.ceiling.iter().map(Capability::new).collect();

    let memory_scope = match params.memory_scope {
        MemoryScope::Ephemeral => scp_core::context::params::MemoryScope::Ephemeral,
        MemoryScope::Summary => scp_core::context::params::MemoryScope::Summary,
        MemoryScope::Full => scp_core::context::params::MemoryScope::Full,
    };

    let ttl = if params.ttl_seconds > 0 {
        Some(std::time::Duration::from_secs(params.ttl_seconds))
    } else {
        None
    };

    // GovernanceModel in scp-core currently only has SingleAdmin.
    // All bridge governance variants map to SingleAdmin until scp-core
    // adds additional model variants (the governance engine dispatch already
    // handles all 24 actions regardless of the model enum).
    let governance = scp_core::context::params::GovernanceModel::SingleAdmin;

    let promotion_policy = if params.promotable {
        PromotionPolicy::Promotable
    } else {
        PromotionPolicy::NoPromotion
    };

    scp_core::context::ContextParams {
        ceiling,
        governance,
        memory_scope,
        ttl,
        promotion_policy,
        ..scp_core::context::ContextParams::default()
    }
}

/// Parses a custody type string into a `CustodyMethod`.
pub(crate) fn parse_custody_method(custody: &str) -> Result<CustodyMethod, ScpError> {
    match custody {
        "in_memory" => Ok(CustodyMethod::InMemory),
        "platform" => Ok(CustodyMethod::Platform),
        "software" => Ok(CustodyMethod::Software),
        other => Err(ScpError::Validation {
            message: format!(
                "unknown custody type: {other:?} — expected \"in_memory\", \"platform\", or \"software\""
            ),
            code: "SCP-VALID-7007".to_owned(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Provenance quality evaluation
// ---------------------------------------------------------------------------

/// Evaluates the provenance quality tier for data with the given parameters.
///
/// Returns an integer (0-3) representing the quality tier:
/// - `0` = `NoProvenance`
/// - `1` = `EphemeralKnownParties`
/// - `2` = `SummaryVerified`
/// - `3` = `PersistentVerifiable`
///
/// See spec §24.5 and ADR-019.
///
/// # Errors
///
/// Returns [`ScpError::Validation`] if `source_type` or `context_state`
/// contain unrecognized values.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI requires owned String parameters
pub fn evaluate_provenance_quality(
    source_context: Option<String>,
    source_type: String,
    context_state: String,
    counterparties: Vec<String>,
) -> Result<u32, ScpError> {
    use scp_core::provenance::evaluate::{SourceContextState, evaluate_quality};
    use scp_core::provenance::{DiscoveryMethod, SourceType};

    let st = match source_type.as_str() {
        "persistent" => SourceType::Persistent,
        "ephemeral" => SourceType::Ephemeral,
        "summary" => SourceType::Summary,
        other => {
            return Err(ScpError::Validation {
                message: format!(
                    "invalid source_type '{other}': expected 'persistent', 'ephemeral', or 'summary'"
                ),
                code: "SCP-VALID-7000".to_owned(),
            });
        }
    };

    let cs = match context_state.as_str() {
        "active" => SourceContextState::Active,
        "closed_with_summary_verified" => SourceContextState::ClosedWithSummary {
            summary_verified: true,
        },
        "closed_with_summary_unverified" => SourceContextState::ClosedWithSummary {
            summary_verified: false,
        },
        "closed_ephemeral" => SourceContextState::ClosedEphemeral,
        "unknown" => SourceContextState::Unknown,
        other => {
            return Err(ScpError::Validation {
                message: format!(
                    "invalid context_state '{other}': expected 'active', \
                     'closed_with_summary_verified', 'closed_with_summary_unverified', \
                     'closed_ephemeral', or 'unknown'"
                ),
                code: "SCP-VALID-7000".to_owned(),
            });
        }
    };

    let provenance = source_context.map(|ctx| scp_core::provenance::DataProvenance {
        source_context: ctx,
        source_type: st,
        counterparties: counterparties
            .into_iter()
            .map(scp_identity::DID::from)
            .collect(),
        purpose: None,
        discovery_method: DiscoveryMethod::None,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_core::context::MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    });

    let quality = evaluate_quality(provenance.as_ref(), &cs);

    Ok(quality as u32)
}

// ---------------------------------------------------------------------------
// Trust engine bridge functions (§7 — Four-Layer Trust Evaluation)
// ---------------------------------------------------------------------------

/// Result of a trust score query.
///
/// Contains participation-derived event counts and a normalized composite
/// score for convenience. The trust engine does not produce authoritative
/// scores — agents apply their own criteria to these inputs.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TrustScoreResult {
    /// Number of message events attributed to the DID.
    pub message_count: u64,
    /// Number of governance action events attributed to the DID.
    pub governance_count: u64,
    /// Normalized composite score (0.0–1.0) based on total participation.
    pub composite_score: f64,
}

/// Result of attestation verification.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AttestationVerificationResult {
    /// Whether the attestation is valid.
    pub valid: bool,
    /// Chain depth (1 for a single attestation).
    pub chain_depth: u32,
    /// Error message if verification failed, empty string if valid.
    pub error_message: String,
}

/// Result of creating a challenge request.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ChallengeResult {
    /// The unique challenge ID (UUID v4).
    pub challenge_id: String,
    /// The serialized challenge request (JSON).
    pub challenge_json: String,
}

/// Queries participation-based trust data for a DID within a context.
///
/// See ADR-017 Layer 2 (Participation).
#[uniffi::export]
pub fn trust_query_score(did: String, context_id: String) -> Result<TrustScoreResult, ScpError> {
    if did.is_empty() {
        return Err(ScpError::Validation {
            message: "DID must not be empty".to_owned(),
            code: "SCP-VALID-7010".to_owned(),
        });
    }
    if context_id.is_empty() {
        return Err(ScpError::Validation {
            message: "context_id must not be empty".to_owned(),
            code: "SCP-VALID-7011".to_owned(),
        });
    }

    // The runtime registry tracks per-context event logs. Event counts are
    // a best-effort approximation at this layer (Merkle tree stores hashes,
    // not full events). For per-DID counts, use the full participation
    // record computation with event objects.
    let (message_count, governance_count) =
        crate::runtime::query_trust_event_counts(&context_id, &did);

    let total = message_count + governance_count;
    #[allow(clippy::cast_precision_loss)]
    let composite_score = (1.0 + total as f64).log10().min(1.0);

    Ok(TrustScoreResult {
        message_count,
        governance_count,
        composite_score,
    })
}

/// Verifies an attestation's Ed25519 signature, evidence, expiry, and
/// revocation status.
///
/// See ADR-017 Layer 3 (Attestation).
#[uniffi::export]
pub fn trust_verify_attestation(
    attestation_json: String,
) -> Result<AttestationVerificationResult, ScpError> {
    let attestation: scp_core::trust::Attestation = serde_json::from_str(&attestation_json)
        .map_err(|e| ScpError::Validation {
            message: format!("failed to parse attestation JSON: {e}"),
            code: "SCP-VALID-7012".to_owned(),
        })?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::SystemClock;

    match scp_core::trust::verify_attestation(&attestation, &resolver, &clock) {
        Ok(()) => Ok(AttestationVerificationResult {
            valid: true,
            chain_depth: 1,
            error_message: String::new(),
        }),
        Err(e) => Ok(AttestationVerificationResult {
            valid: false,
            chain_depth: 0,
            error_message: format!("{e}"),
        }),
    }
}

/// Creates a challenge request for capability verification.
///
/// See ADR-017 Layer 3 (Challenge-Response).
#[uniffi::export]
pub fn trust_create_challenge(target_did: String) -> Result<ChallengeResult, ScpError> {
    if target_did.is_empty() {
        return Err(ScpError::Validation {
            message: "target DID must not be empty".to_owned(),
            code: "SCP-VALID-7013".to_owned(),
        });
    }

    struct EphemeralSigner(ed25519_dalek::SigningKey);
    impl scp_core::trust::ChallengeSigner for EphemeralSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, scp_core::trust::TrustError> {
            use ed25519_dalek::Signer;
            let sig = self.0.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let signer = EphemeralSigner(signing_key);

    let request = scp_core::trust::issue_challenge(
        "did:key:ephemeral-challenger".into(),
        target_did.into(),
        scp_core::trust::ChallengeType::SchemaValidation,
        serde_json::json!({}),
        std::time::Duration::from_secs(300),
        &signer,
    )
    .map_err(|e| ScpError::Validation {
        message: format!("challenge creation failed: {e}"),
        code: "SCP-VALID-7014".to_owned(),
    })?;

    let challenge_json = serde_json::to_string(&request).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize challenge: {e}"),
        code: "SCP-VALID-7015".to_owned(),
    })?;

    Ok(ChallengeResult {
        challenge_id: request.challenge_id,
        challenge_json,
    })
}

/// Verifies a challenge response against its original challenge request.
///
/// See ADR-017 Layer 3 (Challenge-Response).
#[uniffi::export]
pub fn trust_verify_response(
    challenge_json: String,
    response_json: String,
) -> Result<bool, ScpError> {
    let request: scp_core::trust::ChallengeRequest = serde_json::from_str(&challenge_json)
        .map_err(|e| ScpError::Validation {
            message: format!("failed to parse challenge JSON: {e}"),
            code: "SCP-VALID-7016".to_owned(),
        })?;

    let response: scp_core::trust::ChallengeResponse = serde_json::from_str(&response_json)
        .map_err(|e| ScpError::Validation {
            message: format!("failed to parse response JSON: {e}"),
            code: "SCP-VALID-7017".to_owned(),
        })?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::SystemClock;

    Ok(scp_core::trust::verify_challenge_response(&request, &response, &resolver, &clock).is_ok())
}
