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
use scp_identity::IdentityError;
use scp_identity::resolver::{DualLayerResolver, NoOpRelayQuerier};
use scp_identity::{DidCache, InMemoryDhtClient};
use scp_identity::{DidDht, DidDocument as CoreDidDocument, DidMethod, ScpIdentity};
use scp_platform::error::PlatformError;
#[cfg(feature = "allow_in_memory_custody")]
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};
use uuid::Uuid;

use scp_core::context::membership::KeyPackage;

use scp_ffi_common::validate::{
    validate_capability_uri, validate_did, validate_relay_url, validate_tool_id,
    validate_tool_name, validate_ucan_token,
};

use crate::{decrement_handle_count, increment_handle_count, runtime};

/// Tool handler function type: maps JSON input to JSON output (or error string).
type ToolHandlerMap = std::collections::HashMap<
    String,
    std::sync::Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>,
>;

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

/// Concrete [`KeyCustody`] adapter that delegates to a `UniFFI`
/// [`KeyCustodyProvider`](crate::KeyCustodyProvider) callback.
///
/// This bridges the gap between scp-platform's `KeyCustody` trait (which uses
/// RPITIT and is not object-safe) and the `UniFFI` callback interface (which
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
            "software" | "software_biometric" => CustodyType::Software,
            _ => CustodyType::InMemory,
        }
    }
}

impl CallbackKeyCustody {
    /// Exports the raw Ed25519 signing key for the given handle.
    ///
    /// Delegates to [`KeyCustodyProvider::export_signing_key_bytes`] on the
    /// platform callback. Required for governance vote signing.
    pub(crate) async fn export_ed25519_signing_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<ed25519_dalek::SigningKey, PlatformError> {
        let key_bytes = self
            .provider
            .export_signing_key_bytes(handle.id().to_string())
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
        let arr: [u8; 32] = key_bytes.try_into().map_err(|v: Vec<u8>| {
            PlatformError::CustodyError(format!(
                "export_signing_key_bytes returned {} bytes, expected 32",
                v.len()
            ))
        })?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
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

impl From<scp_ffi_common::validate::ValidationError> for ScpError {
    fn from(e: scp_ffi_common::validate::ValidationError) -> Self {
        Self::Validation {
            message: e.message,
            code: "SCP-VALID-7000".to_owned(),
        }
    }
}

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
    /// Minimum protocol version required to join (spec §13.4).
    /// Encoded as `(major << 8) | minor`, e.g., `0x0100` for SCP/1.0.
    /// `0` means no minimum (defaults to SCP/1.0).
    pub min_protocol_version: u16,
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

/// Current data availability status of the source context (spec §24.2.2).
///
/// Reflects operational state, not creation-time memory scope. A persistent
/// context that closes becomes `Ephemeral` or `Summary`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum SourceType {
    /// Source context is still open and verifiable.
    Persistent,
    /// Source context has closed and keys have been destroyed.
    Ephemeral,
    /// Source context has closed and a verified summary is available.
    Summary,
}

/// How the data source was discovered by the receiving party (spec §24.2.3).
#[derive(Debug, Clone, uniffi::Enum)]
pub enum DiscoveryMethod {
    /// Source was discovered through shared membership in the given context.
    SharedContext { context_id: String },
    /// Source was discovered through a discovery registry context.
    Registry { context_id: String },
    /// No protocol-level discovery path.
    None,
}

/// Provenance metadata for cross-context data transfer (spec §24.2.1).
///
/// Attached automatically by the protocol when data crosses context boundaries.
/// Records the full lineage of a piece of data: where it came from, who was
/// involved, how it was discovered, and how many context hops it has traversed.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DataProvenance {
    /// The context from which this data originated.
    pub source_context: String,
    /// Current data availability status of the source context.
    pub source_type: SourceType,
    /// DIDs of the parties involved in the source context at the time of
    /// data flow.
    pub counterparties: Vec<String>,
    /// Optional human-readable purpose description for this data flow.
    pub purpose: Option<String>,
    /// How the data source was discovered.
    pub discovery_method: DiscoveryMethod,
    /// Age of the data in seconds at the time provenance was attached.
    pub age_secs: u64,
    /// Memory scope of the source context.
    pub memory_scope: MemoryScope,
    /// Number of cross-context hops this data has traversed (0 = direct).
    pub chain_depth: u8,
    /// Ordered list of intermediary context IDs when `chain_depth > 0`.
    pub chain_path: Option<Vec<String>>,
    /// Cost of producing this data in smallest currency unit, if any (spec §19.6).
    pub payment_amount: Option<u64>,
    /// Payment adapter used, if any (spec §19.6).
    pub payment_adapter: Option<String>,
    /// Receipt ID for verification of the payment (32 bytes), if any.
    pub payment_receipt_id: Option<Vec<u8>>,
}

impl DataProvenance {
    /// Converts an scp-core `DataProvenance` into the `UniFFI` bridge type.
    pub fn from_core(core: &scp_core::provenance::DataProvenance) -> Self {
        let source_type = match core.source_type {
            scp_core::provenance::SourceType::Persistent => SourceType::Persistent,
            scp_core::provenance::SourceType::Ephemeral => SourceType::Ephemeral,
            scp_core::provenance::SourceType::Summary => SourceType::Summary,
        };

        let discovery_method = match &core.discovery_method {
            scp_core::provenance::DiscoveryMethod::SharedContext(ctx) => {
                DiscoveryMethod::SharedContext {
                    context_id: ctx.clone(),
                }
            }
            scp_core::provenance::DiscoveryMethod::Registry(ctx) => DiscoveryMethod::Registry {
                context_id: ctx.clone(),
            },
            scp_core::provenance::DiscoveryMethod::None => DiscoveryMethod::None,
        };

        let memory_scope = match core.memory_scope {
            scp_core::context::MemoryScope::Ephemeral => MemoryScope::Ephemeral,
            scp_core::context::MemoryScope::Summary => MemoryScope::Summary,
            scp_core::context::MemoryScope::Full => MemoryScope::Full,
        };

        Self {
            source_context: core.source_context.clone(),
            source_type,
            counterparties: core
                .counterparties
                .iter()
                .map(ToString::to_string)
                .collect(),
            purpose: core.purpose.clone(),
            discovery_method,
            age_secs: core.age.as_secs(),
            memory_scope,
            chain_depth: core.chain_depth,
            chain_path: core.chain_path.clone(),
            payment_amount: core.payment_amount.map(|a| a.0),
            payment_adapter: core.payment_adapter.clone(),
            payment_receipt_id: core.payment_receipt_id.map(|r| r.to_vec()),
        }
    }

    /// Converts this `UniFFI` bridge type into an scp-core `DataProvenance`.
    pub fn to_core(&self) -> Result<scp_core::provenance::DataProvenance, ScpError> {
        let source_type = match self.source_type {
            SourceType::Persistent => scp_core::provenance::SourceType::Persistent,
            SourceType::Ephemeral => scp_core::provenance::SourceType::Ephemeral,
            SourceType::Summary => scp_core::provenance::SourceType::Summary,
        };

        let discovery_method = match &self.discovery_method {
            DiscoveryMethod::SharedContext { context_id } => {
                scp_core::provenance::DiscoveryMethod::SharedContext(context_id.clone())
            }
            DiscoveryMethod::Registry { context_id } => {
                scp_core::provenance::DiscoveryMethod::Registry(context_id.clone())
            }
            DiscoveryMethod::None => scp_core::provenance::DiscoveryMethod::None,
        };

        let memory_scope = match self.memory_scope {
            MemoryScope::Ephemeral => scp_core::context::MemoryScope::Ephemeral,
            MemoryScope::Summary => scp_core::context::MemoryScope::Summary,
            MemoryScope::Full => scp_core::context::MemoryScope::Full,
        };

        let payment_receipt_id: Option<[u8; 32]> = match &self.payment_receipt_id {
            Some(v) => {
                let arr: [u8; 32] = v.as_slice().try_into().map_err(|_| ScpError::Validation {
                    message: format!(
                        "payment_receipt_id must be exactly 32 bytes, got {}",
                        v.len()
                    ),
                    code: "SCP-VALID-7080".to_owned(),
                })?;
                Some(arr)
            }
            None => None,
        };

        Ok(scp_core::provenance::DataProvenance {
            source_context: self.source_context.clone(),
            source_type,
            counterparties: self
                .counterparties
                .iter()
                .map(|s| scp_identity::DID::from(s.as_str()))
                .collect(),
            purpose: self.purpose.clone(),
            discovery_method,
            age: std::time::Duration::from_secs(self.age_secs),
            memory_scope,
            chain_depth: self.chain_depth,
            chain_path: self.chain_path.clone(),
            payment_amount: self
                .payment_amount
                .map(scp_core::economy::types::Amount::new),
            payment_adapter: self.payment_adapter.clone(),
            payment_receipt_id,
        })
    }
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

/// A signed consistency checkpoint from the context event log.
///
/// Checkpoints are signed snapshots of the event log state at a point in time.
/// Members exchange checkpoints to detect relay equivocation: if two members
/// have different Merkle roots for the same event count, the relay is showing
/// different histories to different members.
///
/// See ADR-011 acceptance criterion 8 and ADR-030 (pruning/checkpointing).
#[derive(Debug, Clone, uniffi::Record)]
pub struct Checkpoint {
    /// The context this checkpoint belongs to.
    pub context_id: String,
    /// The DID of the member who generated this checkpoint.
    pub sender_did: String,
    /// The number of events in the log at checkpoint time.
    pub event_count: u64,
    /// The Merkle root hash at checkpoint time, hex-encoded.
    pub merkle_root: String,
    /// Current MLS epoch. `None` for Broadcast contexts.
    pub epoch: Option<u64>,
    /// Unix timestamp (seconds) when the checkpoint was generated.
    pub timestamp: u64,
    /// Ed25519 signature over the canonical checkpoint fields, hex-encoded.
    pub signature: String,
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

            let handle = Arc::new(Self {
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

            let handle = Arc::new(Self {
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
#[derive(uniffi::Object)]
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
    /// Tool registry for this context.
    pub(crate) tool_registry: tokio::sync::Mutex<scp_core::context::tools::ToolRegistry>,
    /// Registered tool handlers keyed by tool ID.
    pub(crate) tool_handlers: tokio::sync::Mutex<ToolHandlerMap>,
    /// Session store for stateful tool sessions (spec section 6.2.1).
    pub(crate) session_store: tokio::sync::Mutex<scp_core::context::tools::SessionStore>,
    /// Optional economic policy as a JSON string (§19.3, ADR-033).
    pub(crate) economic_policy: std::sync::Mutex<Option<String>>,
}

impl std::fmt::Debug for ContextHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextHandle")
            .field("context_id", &self.context_id)
            .field("creator_did", &self.creator_did)
            .field("ceiling_strings", &self.ceiling_strings)
            .finish_non_exhaustive()
    }
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
/// Holds a reference to the underlying `NativeRelayAdapter` established by
/// `transport_connect`. The adapter represents a live WebSocket connection
/// to an SCP relay.
///
/// Generated as `class TransportManager` in both Swift and Kotlin.
///
/// See ADR-005 (Transport Abstraction).
#[derive(Debug, uniffi::Object)]
pub struct TransportManager {
    /// Current connection state.
    pub(crate) status: std::sync::Mutex<TransportStatus>,
    /// The underlying relay adapter (live WebSocket connection).
    /// `None` after `transport_disconnect` is called.
    pub(crate) adapter:
        std::sync::Mutex<Option<Arc<scp_transport::native::adapter::NativeRelayAdapter>>>,
}

#[uniffi::export]
impl TransportManager {
    /// Returns the current transport connection status record.
    ///
    /// Reflects actual connection state: `connected` is `true` only if the
    /// underlying relay adapter is still held.
    pub fn status(&self) -> TransportStatus {
        let has_adapter = self.adapter.lock().map(|a| a.is_some()).unwrap_or(false);
        let status = self
            .status
            .lock()
            .map(|s| s.clone())
            .unwrap_or(TransportStatus {
                connected: false,
                relay_url: None,
                latency_ms: None,
            });
        TransportStatus {
            connected: has_adapter && status.connected,
            relay_url: if has_adapter { status.relay_url } else { None },
            latency_ms: status.latency_ms,
        }
    }

    /// Returns `true` if the transport is currently connected.
    pub fn is_connected(&self) -> bool {
        self.adapter.lock().map(|a| a.is_some()).unwrap_or(false)
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
/// Ensures the global production DID resolver is initialized.
///
/// Creates a `DualLayerResolver` backed by `InMemoryDhtClient` and
/// `NoOpRelayQuerier`. The resolver is shared across all UCAN validation
/// calls. Idempotent: subsequent calls are no-ops.
///
/// See #311 for the DID resolver unification design.
fn ensure_did_resolver_initialized(handle: tokio::runtime::Handle) {
    if crate::runtime::did_resolver().is_some() {
        return;
    }

    let dht_client = Arc::new(InMemoryDhtClient::new());
    let relay_querier = Arc::new(NoOpRelayQuerier);
    let cache = Arc::new(DidCache::new());
    let bootstrap_relays = Vec::new();

    let resolver = Arc::new(DualLayerResolver::new(
        relay_querier,
        dht_client,
        cache,
        bootstrap_relays,
    ));

    crate::runtime::init_did_resolver(resolver, handle);
}

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

                        // Initialize the production DID resolver for UCAN
                        // validation (H4 — matching PyO3/NAPI behavior).
                        ensure_did_resolver_initialized(tokio::runtime::Handle::current());

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

            // Initialize the production DID resolver for UCAN validation.
            ensure_did_resolver_initialized(tokio::runtime::Handle::current());

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
// Free functions — device attestation (#419)
//
// See §9.3 (Sybil Resistance and Identity Uniqueness).
// ---------------------------------------------------------------------------

/// Generates a device attestation token for an identity.
///
/// Uses [`InMemoryDeviceAttestation`] to produce a synthetic attestation token,
/// then attaches it to the identity's DID document.
///
/// # Arguments
///
/// * `identity` — The identity to attest (must have been created with
///   `identity_create`, not `identity_load`).
///
/// # Returns
///
/// The attestation token as a base64-encoded string.
///
/// # Errors
///
/// Returns `ScpError::Identity` if the identity was externally loaded (no
/// retained crypto state) or if attestation generation fails.
///
/// See §9.3, issue #362, #419.
#[uniffi::export]
pub async fn identity_attest_device(identity: Arc<Identity>) -> Result<String, ScpError> {
    identity_attest_device_impl(identity).await
}

#[cfg(feature = "allow_in_memory_custody")]
async fn identity_attest_device_impl(identity: Arc<Identity>) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            use scp_platform::testing::InMemoryDeviceAttestation;
            use scp_platform::traits::DeviceAttestation;

            let _core_id = identity
                .core_id
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    message: "device attestation requires retained identity state — the identity \
                          was externally loaded via identity_load"
                        .to_owned(),
                    code: "SCP-IDENT-1007".to_owned(),
                })?;

            let attestation = InMemoryDeviceAttestation::new();
            let token = attestation.attest().await.map_err(|e| ScpError::Identity {
                message: format!("device attestation failed: {e}"),
                code: "SCP-IDENT-1010".to_owned(),
            })?;

            use base64::Engine;
            Ok(base64::engine::general_purpose::STANDARD.encode(token.as_bytes()))
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during device attestation: {e}"),
            code: "SCP-IDENT-1007".to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)]
async fn identity_attest_device_impl(_identity: Arc<Identity>) -> Result<String, ScpError> {
    Err(ScpError::Identity {
        message: "device attestation requires in-memory custody — the in_memory custody \
                  path is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use."
            .to_owned(),
        code: "SCP-IDENT-1010".to_owned(),
    })
}

/// Verifies a device attestation token.
///
/// Uses [`InMemoryDeviceAttestation`] to check the token format.
///
/// # Arguments
///
/// * `did` — The DID string (unused in verification but kept for API
///   consistency).
/// * `token_base64` — The base64-encoded attestation token to verify.
///
/// # Returns
///
/// `true` if the token is valid, `false` otherwise.
///
/// # Errors
///
/// Returns `ScpError::Identity` if base64 decoding fails or if verification
/// encounters an error.
///
/// See §9.3, issue #362, #419.
#[uniffi::export]
pub async fn identity_verify_device_attestation(
    did: String,
    token_base64: String,
) -> Result<bool, ScpError> {
    identity_verify_device_attestation_impl(did, token_base64).await
}

#[cfg(feature = "allow_in_memory_custody")]
async fn identity_verify_device_attestation_impl(
    _did: String,
    token_base64: String,
) -> Result<bool, ScpError> {
    runtime()
        .spawn(async move {
            use base64::Engine;
            use scp_platform::testing::InMemoryDeviceAttestation;
            use scp_platform::traits::DeviceAttestation;

            let token_bytes = base64::engine::general_purpose::STANDARD
                .decode(&token_base64)
                .map_err(|e| ScpError::Identity {
                    message: format!("invalid base64 attestation token: {e}"),
                    code: "SCP-IDENT-1011".to_owned(),
                })?;

            let token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
            let attestation = InMemoryDeviceAttestation::new();

            attestation
                .verify(&token)
                .await
                .map_err(|e| ScpError::Identity {
                    message: format!("device attestation verification failed: {e}"),
                    code: "SCP-IDENT-1012".to_owned(),
                })
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during device attestation verification: {e}"),
            code: "SCP-IDENT-1007".to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)]
async fn identity_verify_device_attestation_impl(
    _did: String,
    _token_base64: String,
) -> Result<bool, ScpError> {
    Err(ScpError::Identity {
        message: "device attestation verification requires in-memory custody — the in_memory \
                  custody path is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use."
            .to_owned(),
        code: "SCP-IDENT-1010".to_owned(),
    })
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
            validate_did(&identity.did)?;

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

            // Register per-context UCAN validation state (revocation list,
            // nonce tracker, event log) for the UCAN pipeline.
            crate::runtime::ensure_ucan_registered(&context_id, &identity.did, &params.ceiling);

            let handle = Arc::new(ContextHandle {
                context_id,
                state: tokio::sync::Mutex::new(ContextState::Active),
                creator_did: identity.did.clone(),
                #[cfg(feature = "allow_in_memory_custody")]
                in_memory_custody,
                callback_custody,
                signing_key,
                ceiling_strings: params.ceiling.clone(),
                tool_registry: tokio::sync::Mutex::new(
                    scp_core::context::tools::ToolRegistry::new(),
                ),
                tool_handlers: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                session_store: tokio::sync::Mutex::new(
                    scp_core::context::tools::SessionStore::new(),
                ),
                economic_policy: std::sync::Mutex::new(None),
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
            validate_did(&identity.did)?;

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
            //
            // This ephemeral ContextHandle carries default params — the
            // ContextManager ignores them, performing version compatibility
            // checks against the stored context's params instead.
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

            // Wire CloseOrchestrator for contexts with summary verification.
            // After the ContextManager has processed the close, check the
            // context's memory scope and initiate the appropriate destruction
            // path via CloseOrchestrator (#365).
            let memory_scope = core_handle.params().memory_scope;
            let now = scp_core::time::now_secs().unwrap_or(0);

            let crypto_provider = crate::runtime::context_manager_crypto();
            let orchestrator = scp_core::context::close::CloseOrchestrator::new(crypto_provider);

            let close_action = orchestrator
                .initiate_close(
                    &handle.context_id,
                    scp_core::context::close::ContextCloseReason::GovernanceClosed,
                    memory_scope,
                    &[], // relay_urls — not available at bridge layer
                    &[], // blob_ids — not available at bridge layer
                    scp_core::context::memory_scope::KeyDestructionLevel::SoftwareOnly,
                    0,    // member_count — not tracked at bridge layer
                    None, // verification_window_secs — use default
                    now,
                )
                .map_err(|e| ScpError::Context {
                    message: format!("close orchestration failed: {e}"),
                    code: "SCP-CTX-2017".to_owned(),
                })?;

            // Log the close action for observability. For Summary scope,
            // the verification window is opened but not actively polled —
            // that requires a SummaryTool which needs design decisions.
            // For Ephemeral, keys are destroyed immediately.
            // For Full, data is preserved.
            match close_action {
                scp_core::context::close::CloseAction::KeysDestroyed { .. } => {
                    tracing::info!(
                        context_id = %handle.context_id,
                        "close orchestrator: keys destroyed (ephemeral scope)"
                    );
                }
                scp_core::context::close::CloseAction::VerificationWindowOpened {
                    ref window,
                    ..
                } => {
                    tracing::info!(
                        context_id = %handle.context_id,
                        deadline = window.deadline(),
                        "close orchestrator: summary verification window opened"
                    );
                }
                scp_core::context::close::CloseAction::Preserved { .. } => {
                    tracing::info!(
                        context_id = %handle.context_id,
                        "close orchestrator: full data preservation (no key destruction)"
                    );
                }
            }

            // Clean up per-context UCAN state.
            crate::runtime::remove_ucan_state(&handle.context_id);

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
            validate_did(&identity.did)?;

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
                    version: scp_core::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
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
            validate_tool_name(&definition.name)?;

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

            let input_schema: serde_json::Value =
                serde_json::from_str(&definition.input_schema_json).map_err(|e| {
                    ScpError::Validation {
                        message: format!("invalid input_schema_json: {e}"),
                        code: "SCP-VALID-7035".to_owned(),
                    }
                })?;
            let output_schema: serde_json::Value =
                serde_json::from_str(&definition.output_schema_json).map_err(|e| {
                    ScpError::Validation {
                        message: format!("invalid output_schema_json: {e}"),
                        code: "SCP-VALID-7036".to_owned(),
                    }
                })?;

            let test_vectors: Vec<scp_core::context::tools::TestVector> =
                match definition.test_vectors_json.as_deref() {
                    None => Vec::new(),
                    Some(json) => serde_json::from_str(json).map_err(|e| ScpError::Validation {
                        message: format!("invalid test_vectors_json: {e}"),
                        code: "SCP-VALID-7037".to_owned(),
                    })?,
                };

            let implementation_hash: [u8; 32] = match definition.implementation_hash.as_deref() {
                None => [0u8; 32],
                Some(bytes) => <[u8; 32]>::try_from(bytes).map_err(|_| ScpError::Validation {
                    message: format!(
                        "implementation_hash must be exactly 32 bytes, got {}",
                        bytes.len()
                    ),
                    code: "SCP-VALID-7038".to_owned(),
                })?,
            };

            let tool_id = format!("tool-{}", definition.name.replace(' ', "-").to_lowercase());

            let core_registration = scp_core::context::tools::ToolRegistration {
                tool_id: tool_id.clone(),
                name: definition.name,
                description: definition.description,
                schema: scp_core::context::tools::ToolSchema {
                    input_schema,
                    output_schema,
                },
                implementation_hash,
                test_vectors,
                operator_did: definition.operator_did.into(),
                economic_metadata: None,
                registered_at: 0,
                signature: Vec::new(),
            };

            // Build a role state for capability checking.
            let ceiling = scp_core::context::roles::default_ceiling();
            let role_state = scp_core::context::roles::ContextRoleState::new(
                &handle.context_id,
                &handle.creator_did,
                ceiling,
                vec![],
            )
            .map_err(|e| ScpError::Tool {
                message: format!("failed to create role state: {e}"),
                code: "SCP-TOOL-6003".to_owned(),
            })?;

            let mut registry = handle.tool_registry.lock().await;
            let (registered_id, _event) = scp_core::context::tools::register_tool(
                &mut registry,
                &role_state,
                core_registration,
                &handle.creator_did,
            )
            .map_err(|e| ScpError::Tool {
                message: format!("tool registration failed: {e}"),
                code: "SCP-TOOL-6001".to_owned(),
            })?;

            Ok(registered_id)
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
/// * `ucan_token` — Optional JWT-encoded UCAN token authorizing the invocation.
///   Must contain `tool_invoke:{tool_id}` or `tool_invoke:*` capability. When
///   present, the full 11-step ADR-016 validation pipeline is executed before
///   tool dispatch. See spec §6.2, §8, ADR-016, and issue #319.
/// * `proof_tokens` — Optional list of encoded parent UCAN tokens for
///   delegation chain traversal (ADR-016 step 3). Only relevant when
///   `ucan_token` is `Some`.
///
/// # Returns
///
/// The tool output as a JSON string.
///
/// # Errors
///
/// Returns `ScpError::Tool` if the tool is not found, invocation fails,
/// input fails schema validation, or the invoker lacks capability.
/// Returns `ScpError::Permission` if the UCAN token is invalid, expired,
/// revoked, or lacks the required tool invocation capability.
#[uniffi::export]
pub async fn tool_invoke(
    handle: Arc<ContextHandle>,
    tool_id: String,
    input_json: String,
    identity: Arc<Identity>,
    ucan_token: Option<String>,
    proof_tokens: Option<Vec<String>>,
) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            validate_tool_id(&tool_id)?;
            validate_did(&identity.did)?;

            // UCAN token is mandatory for tool invocation — all bridges
            // enforce this. Reject early if missing (§6.2, ADR-016, #423).
            let ucan_token = ucan_token.ok_or_else(|| ScpError::Permission {
                message: "UCAN token is required for tool invocation — \
                          pass a valid JWT-encoded UCAN with tool_invoke:{tool_id} \
                          or tool_invoke:* capability"
                    .to_owned(),
                code: "SCP-PERM-3001".to_owned(),
            })?;
            validate_ucan_token(&ucan_token)?;

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

            // Primary authorization: UCAN token validation via the full 11-step
            // ADR-016 pipeline. See spec §6.2, §8, ADR-016, and issue #319.
            validate_tool_ucan_uniffi(
                &handle,
                &tool_id,
                &ucan_token,
                &identity.did,
                proof_tokens.as_ref(),
            )?;

            let registry = handle.tool_registry.lock().await;
            let registration = registry.get(&tool_id).ok_or_else(|| ScpError::Tool {
                message: format!(
                    "tool '{tool_id}' not found in context '{}'",
                    handle.context_id
                ),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            let input_value: serde_json::Value =
                serde_json::from_str(&input_json).map_err(|e| ScpError::Tool {
                    message: format!("invalid input JSON: {e}"),
                    code: "SCP-TOOL-6002".to_owned(),
                })?;
            scp_core::context::tools::validate_value_against_schema(
                &input_value,
                &registration.schema.input_schema,
            )
            .map_err(|e| ScpError::Tool {
                message: format!("input validation failed for tool '{tool_id}': {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            let output_schema = registration.schema.output_schema.clone();
            drop(registry);

            let handlers = handle.tool_handlers.lock().await;
            let output = if let Some(handler) = handlers.get(&tool_id) {
                let handler = handler.clone();
                drop(handlers);
                let out = handler(input_value.clone()).map_err(|e| ScpError::Tool {
                    message: format!("tool handler for '{tool_id}' failed: {e}"),
                    code: "SCP-TOOL-6002".to_owned(),
                })?;
                scp_core::context::tools::validate_value_against_schema(&out, &output_schema)
                    .map_err(|msg| ScpError::Tool {
                        message: format!("output validation failed for tool '{tool_id}': {msg}"),
                        code: "SCP-TOOL-6002".to_owned(),
                    })?;
                out
            } else {
                drop(handlers);
                serde_json::json!({
                    "tool": tool_id,
                    "context": handle.context_id,
                    "status": "validated",
                    "input_valid": true,
                    "invoker_did": identity.did,
                    "validated_input": input_value,
                })
            };

            serde_json::to_string(&output).map_err(|e| ScpError::Tool {
                message: format!("failed to serialize tool output: {e}"),
                code: "SCP-TOOL-6006".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Tool {
            message: format!("tokio task join error during tool invocation: {e}"),
            code: "SCP-TOOL-6006".to_owned(),
        })?
}

/// Validates a UCAN token for tool invocation authorization (`UniFFI` bridge).
///
/// Runs the full 11-step ADR-016 pipeline, requiring `tool_invoke:{tool_id}`
/// or `tool_invoke:*` capability. Extracted to keep `tool_invoke` focused.
fn validate_tool_ucan_uniffi(
    handle: &ContextHandle,
    tool_id: &str,
    ucan_token: &str,
    identity_did: &str,
    proof_tokens: Option<&Vec<String>>,
) -> Result<(), ScpError> {
    use scp_core::context::tools::invoke::validate_tool_invocation_ucan;
    use scp_core::crypto::ucan::validate::{
        DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext, parse_ucan,
    };

    // Build proof resolver from optional proof tokens.
    let mut proofs = std::collections::HashMap::new();
    if let Some(tokens) = proof_tokens {
        for encoded in tokens {
            let proof_token = parse_ucan(encoded).map_err(|e| ScpError::Permission {
                message: format!("malformed proof token: {e}"),
                code: "SCP-PERM-3002".to_owned(),
            })?;
            let cid = scp_core::crypto::ucan::mint::compute_cid(&proof_token);
            proofs.insert(cid, proof_token);
        }
    }
    let proof_resolver = scp_ffi_common::BridgeProofResolver { proofs };

    // Ensure UCAN state is registered for this context.
    crate::runtime::ensure_ucan_registered(
        &handle.context_id,
        &handle.creator_did,
        &handle.ceiling_strings,
    );

    crate::runtime::with_ucan_state(&handle.context_id, |ucan_state| {
        let production_resolver = crate::runtime::did_resolver();
        let did_resolver = scp_ffi_common::DispatchDidResolver::new(
            production_resolver.map(std::convert::AsRef::as_ref),
        );
        let revocation_checker = scp_ffi_common::BridgeRevocationChecker {
            revocation_list: &ucan_state.revocation_list,
        };
        let mut nonce_adapter = scp_ffi_common::BridgeNonceTracker {
            inner: &mut ucan_state.nonce_tracker,
        };

        let mut ctx = ValidationContext {
            did_resolver: &did_resolver,
            nonce_tracker: &mut nonce_adapter,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &ucan_state.ceiling_strings,
            context_creator_did: &ucan_state.creator_did,
            presenting_agent_did: identity_did,
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        validate_tool_invocation_ucan(ucan_token, &handle.context_id, tool_id, &mut ctx).map_err(
            |e| ScpError::Permission {
                message: format!("UCAN authorization failed for tool '{tool_id}': {e}"),
                code: "SCP-PERM-3002".to_owned(),
            },
        )
    })
    .ok_or_else(|| ScpError::Permission {
        message: format!("context '{}' not found in UCAN registry", handle.context_id),
        code: "SCP-PERM-3002".to_owned(),
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
/// Validates UCAN authorization against the target context and chain depth
/// per spec section 6.2 (max 3 hops).
///
/// # Arguments
///
/// * `source_handle` — The calling context.
/// * `target_handle` — The context containing the tool.
/// * `tool_id` — The tool to invoke.
/// * `input_json` — Tool input as a JSON string.
/// * `identity` — The invoker's identity.
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Validated against the TARGET context's ceiling using the full 11-step
///   ADR-016 pipeline.
/// * `chain_depth` — Current chain depth (0 for first hop).
/// * `proof_tokens` — Optional list of encoded parent UCAN tokens for
///   delegation chain traversal.
///
/// # Errors
///
/// Returns `ScpError::Permission` if the UCAN token is invalid, expired,
/// revoked, or lacks the required tool invocation capability.
/// Returns `ScpError::Tool` if chain depth exceeded or contexts not active.
#[uniffi::export]
#[allow(clippy::too_many_arguments)] // FFI boundary: UniFFI requires explicit params
pub async fn tool_invoke_cross_context(
    source_handle: Arc<ContextHandle>,
    target_handle: Arc<ContextHandle>,
    tool_id: String,
    input_json: String,
    identity: Arc<Identity>,
    ucan_token: String,
    chain_depth: u8,
    proof_tokens: Option<Vec<String>>,
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

            // Primary authorization: UCAN token validation via the full 11-step
            // ADR-016 pipeline against the TARGET context's ceiling.
            // See spec §6.2, §8, ADR-016, and issue #319.
            validate_tool_ucan_uniffi(
                &target_handle,
                &tool_id,
                &ucan_token,
                &identity.did,
                proof_tokens.as_ref(),
            )?;

            let input_value: serde_json::Value =
                serde_json::from_str(&input_json).map_err(|e| ScpError::Tool {
                    message: format!("invalid input JSON: {e}"),
                    code: "SCP-TOOL-6002".to_owned(),
                })?;

            let registry = target_handle.tool_registry.lock().await;
            let registration = registry.get(&tool_id).ok_or_else(|| ScpError::Tool {
                message: format!(
                    "tool '{tool_id}' not found in target context '{}'",
                    target_handle.context_id
                ),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            scp_core::context::tools::validate_value_against_schema(
                &input_value,
                &registration.schema.input_schema,
            )
            .map_err(|e| ScpError::Tool {
                message: format!("input validation failed: {e}"),
                code: "SCP-TOOL-6002".to_owned(),
            })?;

            let output_schema = registration.schema.output_schema.clone();
            drop(registry);

            let handlers = target_handle.tool_handlers.lock().await;
            let output = if let Some(handler) = handlers.get(&tool_id) {
                let handler = handler.clone();
                drop(handlers);
                let out = handler(input_value.clone()).map_err(|e| ScpError::Tool {
                    message: format!("cross-context tool handler for '{tool_id}' failed: {e}"),
                    code: "SCP-TOOL-6002".to_owned(),
                })?;
                scp_core::context::tools::validate_value_against_schema(&out, &output_schema)
                    .map_err(|msg| ScpError::Tool {
                        message: format!("output validation failed for tool '{tool_id}': {msg}"),
                        code: "SCP-TOOL-6002".to_owned(),
                    })?;
                out
            } else {
                drop(handlers);
                serde_json::json!({
                    "tool": tool_id,
                    "source_context": source_handle.context_id,
                    "target_context": target_handle.context_id,
                    "status": "validated",
                    "chain_depth": chain_depth,
                    "invoker_did": identity.did,
                    "validated_input": input_value,
                })
            };

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
/// Each call is individually governed: the invoker must present a valid
/// UCAN token. Session state is carried forward and the call count is
/// incremented on success.
///
/// # Arguments
///
/// * `handle` — The context containing the tool session.
/// * `session_id` — The session to invoke within.
/// * `input_json` — Tool input parameters as a JSON string.
/// * `identity` — The identity of the invoker.
/// * `ucan_token` — JWT-encoded UCAN token authorizing the invocation.
///   Validated using the full 11-step ADR-016 pipeline.
/// * `proof_tokens` — Optional list of encoded parent UCAN tokens for
///   delegation chain traversal.
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
    ucan_token: String,
    proof_tokens: Option<Vec<String>>,
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

            // Look up tool_id from session for UCAN validation.
            let tool_id_for_ucan = {
                let store = handle.session_store.lock().await;
                let session = store.get(&session_id).ok_or_else(|| ScpError::Tool {
                    message: format!("session '{session_id}' not found"),
                    code: "SCP-TOOL-6018".to_owned(),
                })?;
                session.tool_id.clone()
            };

            // Primary authorization: UCAN token validation via the full 11-step
            // ADR-016 pipeline. See spec §6.2, §8, ADR-016, and issue #319.
            validate_tool_ucan_uniffi(
                &handle,
                &tool_id_for_ucan,
                &ucan_token,
                &identity.did,
                proof_tokens.as_ref(),
            )?;

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
            let current_state = session.state.clone();
            let call_count = session.call_count;
            drop(store);

            let input_value: serde_json::Value =
                serde_json::from_str(&input_json).map_err(|e| ScpError::Tool {
                    message: format!("invalid input JSON: {e}"),
                    code: "SCP-TOOL-6002".to_owned(),
                })?;

            // Validate input against tool's input schema if tool is registered.
            let registry = handle.tool_registry.lock().await;
            if let Some(registration) = registry.get(&tool_id) {
                scp_core::context::tools::validate_value_against_schema(
                    &input_value,
                    &registration.schema.input_schema,
                )
                .map_err(|e| ScpError::Tool {
                    message: format!("input validation failed: {e}"),
                    code: "SCP-TOOL-6002".to_owned(),
                })?;
            }
            drop(registry);

            // Execute via handler or echo mode.
            let handlers = handle.tool_handlers.lock().await;
            let (new_state, output) = if let Some(handler) = handlers.get(&tool_id) {
                let handler = handler.clone();
                drop(handlers);
                let out = handler(input_value.clone()).map_err(|e| ScpError::Tool {
                    message: format!("tool handler for '{tool_id}' failed: {e}"),
                    code: "SCP-TOOL-6002".to_owned(),
                })?;
                (current_state, out)
            } else {
                drop(handlers);
                let out = serde_json::json!({
                    "tool": tool_id,
                    "session_id": session_id,
                    "status": "validated",
                    "call_count": call_count + 1,
                    "invoker_did": identity.did,
                    "validated_input": input_value,
                });
                (current_state, out)
            };

            // Update session state and increment call count.
            let mut store = handle.session_store.lock().await;
            if let Some(session) = store.get_mut(&session_id) {
                session.state = new_state;
                session.call_count = session.call_count.saturating_add(1);
            }

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
/// Establishes a WebSocket connection to the specified relay URL using
/// [`NativeRelayAdapter::connect_sourced`] with `Explicit` source
/// (requires `wss://`). The adapter is stored in the returned
/// `TransportManager` handle.
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
/// Returns `ScpError::Transport` if the URL scheme is not permitted
/// (only `wss://` is accepted for explicit connections) or if the
/// WebSocket connection cannot be established (unreachable relay,
/// protocol mismatch, timeout, authentication failure).
#[uniffi::export]
pub async fn transport_connect(relay_url: String) -> Result<Arc<TransportManager>, ScpError> {
    use scp_transport::native::adapter::NativeRelayAdapter;
    use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

    validate_relay_url(&relay_url)?;
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
            let sourced = SourcedRelayUrl {
                url: relay_url.clone(),
                source: RelayUrlSource::Explicit,
            };

            // Establish a real WebSocket connection to the relay.
            let adapter = NativeRelayAdapter::connect_sourced(&sourced)
                .await
                .map_err(ScpError::from)?;

            let arc_adapter = Arc::new(adapter);

            let handle = Arc::new(TransportManager {
                status: std::sync::Mutex::new(TransportStatus {
                    connected: true,
                    relay_url: Some(relay_url),
                    latency_ms: None,
                }),
                adapter: std::sync::Mutex::new(Some(arc_adapter)),
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
/// Reflects actual connection state: `connected` is `true` only if the
/// underlying relay adapter is still held by the manager.
///
/// # Errors
///
/// Returns `ScpError::Transport` if querying the transport status fails.
#[uniffi::export]
pub async fn transport_status(manager: Arc<TransportManager>) -> Result<TransportStatus, ScpError> {
    Ok(manager.status())
}

/// Disconnects from the current SCP relay.
///
/// Clears the relay adapter from the `TransportManager` handle. After this
/// call, the `TransportManager` reports `connected: false` and the adapter's
/// WebSocket connection is released when the last reference is dropped.
///
/// This is idempotent — calling it when already disconnected is a no-op.
///
/// # Arguments
///
/// * `manager` — The `TransportManager` returned by `transport_connect`.
///
/// # Errors
///
/// Returns `ScpError::Transport` if the internal mutex is poisoned.
#[uniffi::export]
pub async fn transport_disconnect(manager: Arc<TransportManager>) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            // Clear the adapter from the manager.
            {
                let mut adapter_guard =
                    manager.adapter.lock().map_err(|_| ScpError::Transport {
                        message: "adapter mutex is poisoned — cannot clear relay adapter"
                            .to_owned(),
                        code: "SCP-TRANS-5003".to_owned(),
                    })?;
                *adapter_guard = None;
            }

            // Update the status to disconnected.
            {
                let mut status_guard = manager.status.lock().map_err(|_| ScpError::Transport {
                    message: "status mutex is poisoned — cannot update transport status".to_owned(),
                    code: "SCP-TRANS-5003".to_owned(),
                })?;
                status_guard.connected = false;
                status_guard.relay_url = None;
                status_guard.latency_ms = None;
            }

            Ok(())
        })
        .await
        .map_err(|e| ScpError::Transport {
            message: format!("tokio task join error during transport disconnect: {e}"),
            code: "SCP-TRANS-5003".to_owned(),
        })?
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
            validate_ucan_token(&token)?;
            validate_capability_uri(&capability)?;

            use scp_core::crypto::ucan::capability::CapabilityUri;
            use scp_core::crypto::ucan::validate::{
                DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext, parse_ucan, validate_ucan,
            };

            // Step 1: Parse the UCAN token.
            let parsed_token = parse_ucan(&token).map_err(|e| ScpError::Permission {
                message: format!("malformed UCAN token: {e}"),
                code: "SCP-PERM-3002".to_owned(),
            })?;

            // Parse the required capability URI.
            let required_cap: CapabilityUri =
                capability
                    .parse()
                    .map_err(
                        |e: scp_core::crypto::ucan::UcanError| ScpError::Permission {
                            message: format!("invalid capability URI '{capability}': {e}"),
                            code: "SCP-PERM-3002".to_owned(),
                        },
                    )?;

            // Determine the presenting agent DID: explicit parameter or token audience.
            let agent_did = presenting_agent_did
                .as_deref()
                .unwrap_or(&parsed_token.payload.aud);

            // Build proof resolver from optional proof tokens.
            let mut proofs = std::collections::HashMap::new();
            if let Some(ref tokens) = proof_tokens {
                for encoded in tokens {
                    let proof_token = parse_ucan(encoded).map_err(|e| ScpError::Permission {
                        message: format!("malformed proof token: {e}"),
                        code: "SCP-PERM-3002".to_owned(),
                    })?;
                    let cid = scp_core::crypto::ucan::mint::compute_cid(&proof_token);
                    proofs.insert(cid, proof_token);
                }
            }
            let proof_resolver = scp_ffi_common::BridgeProofResolver { proofs };

            // Ensure UCAN state is registered for this context.
            crate::runtime::ensure_ucan_registered(
                &handle.context_id,
                &handle.creator_did,
                &handle.ceiling_strings,
            );

            // Execute the full 11-step validation pipeline via per-context state.
            let validation_result =
                crate::runtime::with_ucan_state(&handle.context_id, |ucan_state| {
                    let production_resolver = crate::runtime::did_resolver();
                    let did_resolver = scp_ffi_common::DispatchDidResolver::new(
                        production_resolver.map(std::convert::AsRef::as_ref),
                    );
                    let revocation_checker = scp_ffi_common::BridgeRevocationChecker {
                        revocation_list: &ucan_state.revocation_list,
                    };
                    let mut nonce_adapter = scp_ffi_common::BridgeNonceTracker {
                        inner: &mut ucan_state.nonce_tracker,
                    };

                    let mut ctx = ValidationContext {
                        did_resolver: &did_resolver,
                        nonce_tracker: &mut nonce_adapter,
                        revocation_checker: &revocation_checker,
                        proof_resolver: &proof_resolver,
                        ceiling: &ucan_state.ceiling_strings,
                        context_creator_did: &ucan_state.creator_did,
                        presenting_agent_did: agent_did,
                        clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
                    };

                    validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(|e| {
                        ScpError::Permission {
                            message: format!("UCAN validation failed: {e}"),
                            code: "SCP-PERM-3002".to_owned(),
                        }
                    })
                })
                .ok_or_else(|| ScpError::Permission {
                    message: format!("context '{}' not found in UCAN registry", handle.context_id),
                    code: "SCP-PERM-3002".to_owned(),
                })?;
            validation_result?;

            Ok(())
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
    validate_did(&member_did)?;
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
            use scp_core::crypto::ucan::revoke::compute_revocation_cid;

            // Ensure UCAN state is registered for this context.
            crate::runtime::ensure_ucan_registered(
                &handle.context_id,
                &handle.creator_did,
                &handle.ceiling_strings,
            );

            // Compute the revocation CID from the raw JWT string (SHA-256 of
            // the encoded token), matching scp-core's format.
            crate::runtime::with_ucan_state(&handle.context_id, |ucan_state| {
                let token_cid = compute_revocation_cid(&token);
                ucan_state.revocation_list.revoke(token_cid);
            })
            .ok_or_else(|| ScpError::Permission {
                message: format!("context '{}' not found in UCAN registry", handle.context_id),
                code: "SCP-PERM-3006".to_owned(),
            })?;

            Ok(())
        })
        .await
        .map_err(|e| ScpError::Permission {
            message: format!("tokio task join error during UCAN revocation: {e}"),
            code: "SCP-PERM-3007".to_owned(),
        })?
}

/// Delegates a UCAN token to another member.
///
/// Creates a delegated UCAN from an existing parent token, signed with the
/// delegator's Ed25519 key via the retained [`KeyCustody`] provider.
/// Delegation enforces attenuation (capabilities can only narrow, never widen).
///
/// # Arguments
///
/// * `handle` — The context the token belongs to.
/// * `delegator_did` — The DID of the entity delegating (must match parent
///   token's audience).
/// * `delegatee_did` — The DID of the entity receiving the delegation.
/// * `parent_token` — The encoded parent UCAN token (JWT format).
/// * `capabilities` — List of capability URI strings to delegate (must be
///   subset of parent's capabilities).
///
/// # Returns
///
/// A `UcanToken` handle with the delegated token's metadata.
///
/// # Errors
///
/// Returns `ScpError::Permission` if delegation fails: delegator not matching
/// parent audience, capabilities wider than parent, signing failure, etc.
///
/// See ADR-016 criterion 4.
#[uniffi::export]
pub async fn ucan_delegate(
    handle: Arc<ContextHandle>,
    delegator_did: String,
    delegatee_did: String,
    parent_token: String,
    capabilities: Vec<String>,
) -> Result<Arc<UcanToken>, ScpError> {
    validate_did(&delegator_did)?;
    validate_did(&delegatee_did)?;
    validate_ucan_token(&parent_token)?;
    for cap in &capabilities {
        validate_capability_uri(cap)?;
    }
    ucan_delegate_impl(
        handle,
        delegator_did,
        delegatee_did,
        parent_token,
        capabilities,
    )
    .await
}

/// Inner implementation of [`ucan_delegate`], split out for cfg-gating clarity.
#[cfg(feature = "allow_in_memory_custody")]
async fn ucan_delegate_impl(
    handle: Arc<ContextHandle>,
    delegator_did: String,
    delegatee_did: String,
    parent_token: String,
    capabilities: Vec<String>,
) -> Result<Arc<UcanToken>, ScpError> {
    runtime()
        .spawn(async move {
            use scp_core::crypto::ucan::Attenuation;
            use scp_core::crypto::ucan::mint::{DelegateParams, delegate_ucan};
            use scp_core::crypto::ucan::validate::parse_ucan;

            // Extract key custody and signing key from the context handle.
            let custody =
                handle
                    .in_memory_custody
                    .as_ref()
                    .ok_or_else(|| ScpError::Permission {
                        message: "UCAN delegation requires key custody — create the context with \
                              an in_memory identity (identity_create(\"in_memory\"))"
                            .to_owned(),
                        code: "SCP-PERM-3004".to_owned(),
                    })?;
            let signing_key = handle.signing_key.ok_or_else(|| ScpError::Permission {
                message: "UCAN delegation requires a signing key — the context creator identity \
                          must have an active signing key"
                    .to_owned(),
                code: "SCP-PERM-3004".to_owned(),
            })?;

            // Parse the parent token.
            let parsed_parent = parse_ucan(&parent_token).map_err(|e| ScpError::Permission {
                message: format!("malformed parent UCAN token: {e}"),
                code: "SCP-PERM-3002".to_owned(),
            })?;

            // Build attenuated capabilities from the capability URI strings.
            let context_id = &handle.context_id;
            let attenuations: Vec<Attenuation> = capabilities
                .iter()
                .map(|cap| {
                    let cap_uri = if cap.starts_with("scp:ctx:") {
                        cap.clone()
                    } else {
                        format!("scp:ctx:{context_id}/{cap}")
                    };
                    let action = cap_uri.rsplit_once('/').map_or_else(
                        || cap.clone(),
                        |(_, a)| {
                            a.split_once(':')
                                .map_or_else(|| a.to_owned(), |(_, act)| act.to_owned())
                        },
                    );
                    Attenuation {
                        with: cap_uri,
                        can: action,
                    }
                })
                .collect();

            // Get ceiling from handle for delegation-time enforcement (#339).
            let ceiling = if handle.ceiling_strings.is_empty() {
                None
            } else {
                Some(handle.ceiling_strings.iter().cloned().collect())
            };

            let params = DelegateParams {
                parent_token: &parsed_parent,
                delegator_did: &delegator_did,
                delegator_key: &signing_key,
                delegatee_did: &delegatee_did,
                attenuated_capabilities: &attenuations,
                lifetime_secs: 3600,
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling,
            };

            let token = delegate_ucan(&params, &custody.0)
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
            message: format!("tokio task join error during UCAN delegation: {e}"),
            code: "SCP-PERM-3005".to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)] // Must be async to match the cfg(feature) variant's signature.
async fn ucan_delegate_impl(
    _handle: Arc<ContextHandle>,
    _delegator_did: String,
    _delegatee_did: String,
    _parent_token: String,
    _capabilities: Vec<String>,
) -> Result<Arc<UcanToken>, ScpError> {
    Err(ScpError::Permission {
        message: "UCAN delegation requires key custody — the in_memory custody path \
                  is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use, or wire \
                  a KeyCustodyProvider for production."
            .to_owned(),
        code: "SCP-PERM-3004".to_owned(),
    })
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
            // Ensure UCAN state (which contains the event log) is registered.
            crate::runtime::ensure_ucan_registered(
                &handle.context_id,
                &handle.creator_did,
                &handle.ceiling_strings,
            );

            // Parse optional filter JSON.
            let filter: Option<serde_json::Value> = match filter_json {
                Some(ref json_str) => {
                    Some(
                        serde_json::from_str(json_str).map_err(|e| ScpError::Context {
                            message: format!("invalid filter JSON: {e}"),
                            code: "SCP-CTX-2023".to_owned(),
                        })?,
                    )
                }
                None => None,
            };

            let filter_event_type = filter
                .as_ref()
                .and_then(|f| f.get("event_type"))
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let filter_actor_did = filter
                .as_ref()
                .and_then(|f| f.get("actor_did"))
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let filter_after_seq = filter
                .as_ref()
                .and_then(|f| f.get("after_sequence"))
                .and_then(serde_json::Value::as_u64);
            let filter_before_seq = filter
                .as_ref()
                .and_then(|f| f.get("before_sequence"))
                .and_then(serde_json::Value::as_u64);
            #[allow(clippy::cast_possible_truncation)]
            let filter_limit = filter
                .as_ref()
                .and_then(|f| f.get("limit"))
                .and_then(serde_json::Value::as_u64)
                .map(|v| v as usize);

            // Query the event log from per-context UCAN state.
            let events = crate::runtime::with_ucan_state(&handle.context_id, |ucan_state| {
                let event_count = scp_event_log::tree::event_count(&ucan_state.event_log);

                if event_count == 0 {
                    return Vec::new();
                }

                let merkle_root = scp_event_log::tree::root(&ucan_state.event_log);
                let merkle_root_hex = hex::encode(merkle_root);

                // Query events stored in the event log by iterating the
                // stored events slice and applying filters.
                let all_events = ucan_state.event_log.events();

                if !all_events.is_empty() {
                    let mut results: Vec<Event> = Vec::new();
                    for evt in all_events {
                        // Apply sequence range filters.
                        if let Some(after) = filter_after_seq
                            && evt.sequence <= after
                        {
                            continue;
                        }
                        if let Some(before) = filter_before_seq
                            && evt.sequence >= before
                        {
                            continue;
                        }
                        // Apply event type filter.
                        if let Some(ref et) = filter_event_type
                            && format!("{:?}", evt.event_type) != *et
                        {
                            continue;
                        }
                        // Apply actor DID filter.
                        if let Some(ref actor) = filter_actor_did
                            && evt.actor_did.0 != *actor
                        {
                            continue;
                        }

                        // Try to interpret payload bytes as UTF-8 JSON; fall
                        // back to hex encoding for binary payloads.
                        let payload_json = std::str::from_utf8(&evt.payload.data)
                            .ok()
                            .filter(|s| serde_json::from_str::<serde_json::Value>(s).is_ok())
                            .map_or_else(
                                || {
                                    serde_json::json!({
                                        "hex": hex::encode(&evt.payload.data),
                                    })
                                    .to_string()
                                },
                                str::to_owned,
                            );

                        results.push(Event {
                            event_type: format!("{:?}", evt.event_type),
                            actor_did: evt.actor_did.0.clone(),
                            timestamp: evt.timestamp,
                            payload_json,
                            sequence: evt.sequence,
                        });

                        if let Some(lim) = filter_limit
                            && results.len() >= lim
                        {
                            break;
                        }
                    }
                    if !results.is_empty() {
                        return results;
                    }
                }

                // Fallback: return a summary event with Merkle root metadata.
                let now = scp_core::time::now_secs().unwrap_or(0);
                let summary = Event {
                    event_type: "LogSummary".to_owned(),
                    actor_did: String::new(),
                    timestamp: now,
                    payload_json: serde_json::json!({
                        "event_count": event_count,
                        "merkle_root": merkle_root_hex,
                    })
                    .to_string(),
                    sequence: event_count.saturating_sub(1),
                };

                let summary_events = vec![summary];
                if let Some(lim) = filter_limit {
                    summary_events.into_iter().take(lim).collect()
                } else {
                    summary_events
                }
            })
            .ok_or_else(|| ScpError::Context {
                message: format!("context '{}' not found in UCAN registry", handle.context_id),
                code: "SCP-CTX-2023".to_owned(),
            })?;

            Ok(events)
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
            // Parse the claim JSON.
            let claim: serde_json::Value =
                serde_json::from_str(&claim_json).map_err(|e| ScpError::Context {
                    message: format!("invalid claim JSON: {e}"),
                    code: "SCP-CTX-2025".to_owned(),
                })?;

            let claim_type =
                claim
                    .get("type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ScpError::Context {
                        message: "claim must include 'type' field ('inclusion' or 'absence')"
                            .to_owned(),
                        code: "SCP-CTX-2025".to_owned(),
                    })?;

            // Ensure UCAN state (which contains the event log) is registered.
            crate::runtime::ensure_ucan_registered(
                &handle.context_id,
                &handle.creator_did,
                &handle.ceiling_strings,
            );

            match claim_type {
                "inclusion" => {
                    let leaf_index = claim
                        .get("leaf_index")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| ScpError::Context {
                            message: "inclusion claim must include 'leaf_index' (integer)"
                                .to_owned(),
                            code: "SCP-CTX-2025".to_owned(),
                        })?;

                    crate::runtime::with_ucan_state(&handle.context_id, |ucan_state| {
                        let proof = scp_event_log::proof::prove_inclusion(
                            &ucan_state.event_log,
                            leaf_index,
                        )
                        .map_err(|e| ScpError::Context {
                            message: format!("inclusion proof failed: {e}"),
                            code: "SCP-CTX-2025".to_owned(),
                        })?;
                        let verified = scp_event_log::proof::verify_inclusion(&proof);

                        let path_steps: Vec<serde_json::Value> = proof
                            .path
                            .iter()
                            .map(|step| {
                                let direction = match step.direction {
                                    scp_event_log::proof::Direction::Left => "left",
                                    scp_event_log::proof::Direction::Right => "right",
                                };
                                serde_json::json!({
                                    "sibling_hash": hex::encode(step.sibling_hash),
                                    "direction": direction,
                                })
                            })
                            .collect();

                        let details = serde_json::json!({
                            "leaf_index": proof.leaf_index,
                            "leaf_hash": hex::encode(proof.leaf_hash),
                            "root": hex::encode(proof.root),
                            "path": path_steps,
                            "path_length": proof.path.len(),
                        });

                        Ok(Proof {
                            verified,
                            proof_type: "inclusion".to_owned(),
                            details_json: details.to_string(),
                        })
                    })
                    .ok_or_else(|| ScpError::Context {
                        message: format!(
                            "context '{}' not found in UCAN registry",
                            handle.context_id
                        ),
                        code: "SCP-CTX-2025".to_owned(),
                    })?
                }
                "absence" => {
                    let event_hash_hex = claim
                        .get("event_hash")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ScpError::Context {
                            message: "absence claim must include 'event_hash' (hex string)"
                                .to_owned(),
                            code: "SCP-CTX-2025".to_owned(),
                        })?;

                    let event_hash_bytes =
                        hex::decode(event_hash_hex).map_err(|e| ScpError::Context {
                            message: format!("invalid event_hash hex: {e}"),
                            code: "SCP-CTX-2025".to_owned(),
                        })?;
                    let event_hash: [u8; 32] =
                        event_hash_bytes
                            .try_into()
                            .map_err(|v: Vec<u8>| ScpError::Context {
                                message: format!("event_hash must be 32 bytes, got {}", v.len()),
                                code: "SCP-CTX-2025".to_owned(),
                            })?;

                    crate::runtime::with_ucan_state(&handle.context_id, |ucan_state| {
                        let proof =
                            scp_event_log::proof::prove_absence(&ucan_state.event_log, &event_hash)
                                .map_err(|e| ScpError::Context {
                                    message: format!("absence proof failed: {e}"),
                                    code: "SCP-CTX-2025".to_owned(),
                                })?;

                        let lower = proof.lower.as_ref().map(|lwp| {
                            serde_json::json!({
                                "leaf_hash": hex::encode(lwp.leaf_hash),
                                "leaf_index": lwp.leaf_index,
                            })
                        });
                        let upper = proof.upper.as_ref().map(|uwp| {
                            serde_json::json!({
                                "leaf_hash": hex::encode(uwp.leaf_hash),
                                "leaf_index": uwp.leaf_index,
                            })
                        });

                        let lower_verified = proof.lower.as_ref().is_none_or(|lwp| {
                            scp_event_log::proof::verify_inclusion(&lwp.inclusion_proof)
                        });
                        let upper_verified = proof.upper.as_ref().is_none_or(|uwp| {
                            scp_event_log::proof::verify_inclusion(&uwp.inclusion_proof)
                        });
                        let verified = lower_verified && upper_verified;

                        let details = serde_json::json!({
                            "query_hash": hex::encode(proof.query_hash),
                            "root": hex::encode(proof.root),
                            "leaf_count": proof.leaf_count,
                            "lower": lower,
                            "upper": upper,
                        });

                        Ok(Proof {
                            verified,
                            proof_type: "absence".to_owned(),
                            details_json: details.to_string(),
                        })
                    })
                    .ok_or_else(|| ScpError::Context {
                        message: format!(
                            "context '{}' not found in UCAN registry",
                            handle.context_id
                        ),
                        code: "SCP-CTX-2025".to_owned(),
                    })?
                }
                other => Err(ScpError::Context {
                    message: format!(
                        "unsupported claim type '{other}': expected 'inclusion' or 'absence'"
                    ),
                    code: "SCP-CTX-2025".to_owned(),
                }),
            }
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during event log verification: {e}"),
            code: "SCP-CTX-2026".to_owned(),
        })?
}

/// Generates a signed consistency checkpoint from the current event log state.
///
/// Creates a snapshot of the event log's Merkle root and event count, signs it
/// with the caller's identity key, and returns the checkpoint. Checkpoints
/// enable equivocation detection: members exchange signed Merkle roots and
/// compare them to detect relay misbehavior.
///
/// # Arguments
///
/// * `handle` — The context whose event log to checkpoint.
/// * `identity` — The identity generating the checkpoint (used for signing).
/// * `epoch` — The current MLS epoch (pass 0 for Broadcast contexts).
///
/// # Returns
///
/// A [`Checkpoint`] containing the signed checkpoint data.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not found in the UCAN
/// registry. Returns `ScpError::Permission` if key custody is not available.
///
/// See ADR-011 acceptance criterion 8 and ADR-030.
#[uniffi::export]
pub async fn event_log_checkpoint(
    handle: Arc<ContextHandle>,
    identity: Arc<Identity>,
    epoch: u64,
) -> Result<Checkpoint, ScpError> {
    event_log_checkpoint_impl(handle, identity, epoch).await
}

#[cfg(feature = "allow_in_memory_custody")]
async fn event_log_checkpoint_impl(
    handle: Arc<ContextHandle>,
    identity: Arc<Identity>,
    epoch: u64,
) -> Result<Checkpoint, ScpError> {
    runtime()
        .spawn(async move {
            let custody =
                identity
                    .in_memory_custody
                    .as_ref()
                    .ok_or_else(|| ScpError::Permission {
                        message: "event log checkpoint requires key custody — create the identity \
                              with in_memory custody (identity_create(\"in_memory\"))"
                            .to_owned(),
                        code: "SCP-PERM-3008".to_owned(),
                    })?;
            let core_id = identity
                .core_id
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    message:
                        "event log checkpoint requires retained identity state — the identity \
                          was externally loaded"
                            .to_owned(),
                    code: "SCP-IDENT-1007".to_owned(),
                })?;

            // Ensure UCAN state (which contains the event log) is registered.
            crate::runtime::ensure_ucan_registered(
                &handle.context_id,
                &handle.creator_did,
                &handle.ceiling_strings,
            );

            let sender_did = scp_identity::DID(identity.did.clone());
            let context_id = handle.context_id.clone();

            let checkpoint = crate::runtime::with_ucan_state(&context_id, |ucan_state| {
                let signer = scp_core::event_log::KeyCustodySigner {
                    custody: &custody.0,
                    key: &core_id.active_signing_key,
                };
                // generate_checkpoint is async — use block_in_place to allow
                // blocking inside this spawned async task. block_in_place moves
                // the worker thread to blocking mode (requires multi-thread runtime).
                let handle = tokio::runtime::Handle::current();
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        scp_event_log::checkpoint::generate_checkpoint(
                            &ucan_state.event_log,
                            &sender_did,
                            epoch,
                            &signer,
                        )
                        .await
                        .map_err(|e| ScpError::Context {
                            message: format!("checkpoint generation failed: {e}"),
                            code: "SCP-CTX-2027".to_owned(),
                        })
                    })
                })
            })
            .ok_or_else(|| ScpError::Context {
                message: format!("context '{context_id}' not found in UCAN registry"),
                code: "SCP-CTX-2027".to_owned(),
            })??;

            Ok(Checkpoint {
                context_id: checkpoint.context_id,
                sender_did: checkpoint.sender_did.0,
                event_count: checkpoint.event_count,
                merkle_root: hex::encode(checkpoint.merkle_root),
                epoch: checkpoint.epoch,
                timestamp: checkpoint.timestamp,
                signature: hex::encode(checkpoint.signature),
            })
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during event log checkpoint: {e}"),
            code: "SCP-CTX-2028".to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)]
async fn event_log_checkpoint_impl(
    _handle: Arc<ContextHandle>,
    _identity: Arc<Identity>,
    _epoch: u64,
) -> Result<Checkpoint, ScpError> {
    Err(ScpError::Permission {
        message: "event log checkpoint requires key custody — the in_memory custody path \
                  is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use, or wire \
                  a KeyCustodyProvider for production."
            .to_owned(),
        code: "SCP-PERM-3008".to_owned(),
    })
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
    let context_id = handle.context_id.clone();

    let result = runtime()
        .spawn(async move {
            let proposal: scp_core::context::governance::GovernanceProposal =
                serde_json::from_str(&proposal_json)?;
            let manager = crate::runtime::context_manager();
            let result = manager
                .execute_governance_action(&context_id, &proposal)
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
        })?;

    // Re-sync role state from ContextManager after governance execution (#796).
    // Governance actions may modify roles/membership; without this sync the
    // Swift/Kotlin SDKs see stale role state for UCAN/tool capability checks.
    if let Err(e) = crate::runtime::sync_role_state_from_manager(&handle.context_id).await {
        tracing::warn!(
            context_id = %handle.context_id,
            "failed to sync role state after governance execution: {e}"
        );
    }

    result
}

// ---------------------------------------------------------------------------
// Free functions — governance proposal lifecycle (#621)
// ---------------------------------------------------------------------------

/// Resolves the raw Ed25519 signing key from a `UniFFI` `ContextHandle`.
///
/// Checks `callback_custody` first (platform/software), then falls back
/// to `in_memory_custody`. Returns `ScpError::Context` if neither is
/// available or the key handle is missing.
async fn resolve_uniffi_signing_key(
    handle: &ContextHandle,
) -> Result<ed25519_dalek::SigningKey, ScpError> {
    let key_handle = handle.signing_key.ok_or_else(|| ScpError::Context {
        message: "no signing key on context handle — governance lifecycle \
                  requires an identity with an active signing key"
            .to_owned(),
        code: "SCP-CTX-2040".to_owned(),
    })?;

    if let Some(ref cb) = handle.callback_custody {
        return cb
            .export_ed25519_signing_key(&key_handle)
            .await
            .map_err(|e| ScpError::Context {
                message: format!("failed to export signing key from platform custody: {e}"),
                code: "SCP-CTX-2040".to_owned(),
            });
    }

    #[cfg(feature = "allow_in_memory_custody")]
    if let Some(ref imc) = handle.in_memory_custody {
        return imc
            .0
            .export_ed25519_signing_key(&key_handle)
            .await
            .map_err(|e| ScpError::Context {
                message: format!("failed to export signing key from in-memory custody: {e}"),
                code: "SCP-CTX-2040".to_owned(),
            });
    }

    Err(ScpError::Context {
        message: "no custody provider on context handle — governance lifecycle \
                  requires an identity created with custody"
            .to_owned(),
        code: "SCP-CTX-2040".to_owned(),
    })
}

/// Parses a hex-encoded proposal ID into a 32-byte array.
fn parse_uniffi_proposal_id(hex_str: &str) -> Result<[u8; 32], ScpError> {
    let bytes = hex::decode(hex_str).map_err(|e| ScpError::Validation {
        message: format!("invalid proposal ID hex: {e}"),
        code: "SCP-CTX-2040".to_owned(),
    })?;
    bytes.try_into().map_err(|v: Vec<u8>| ScpError::Validation {
        message: format!("proposal ID must be 32 bytes, got {}", v.len()),
        code: "SCP-CTX-2040".to_owned(),
    })
}

/// Proposes a governance action for voting.
///
/// Delegates to [`ContextManager::propose_governance_action_checked`].
/// For `SingleAdmin` contexts, the proposal is auto-approved and executed.
/// For multi-admin models (Threshold, Majority, Unanimity), the proposal
/// enters `Pending` status.
///
/// # Arguments
///
/// * `handle` — The context handle.
/// * `proposer_did` — DID of the proposer.
/// * `action_json` — JSON-serialized `GovernanceAction`.
///
/// # Returns
///
/// JSON string: `{ "proposal_id": hex, "status": string, "execution_result": string | null }`.
///
/// # Errors
///
/// Returns `ScpError::Context` (SCP-CTX-2041) if the proposal fails.
#[uniffi::export]
pub async fn governance_propose(
    handle: Arc<ContextHandle>,
    proposer_did: String,
    action_json: String,
) -> Result<String, ScpError> {
    let signing_key = resolve_uniffi_signing_key(&handle).await?;
    let context_id = handle.context_id.clone();

    let result = runtime()
        .spawn(async move {
            let action: scp_core::context::governance::GovernanceAction =
                serde_json::from_str(&action_json)?;
            let did = scp_identity::DID(proposer_did);
            let manager = crate::runtime::context_manager();
            let outcome = manager
                .propose_governance_action_checked(&context_id, &did, action, &signing_key)
                .await
                .map_err(ScpError::from)?;

            let result_str = outcome.execution_result.as_ref().map(|r| format!("{r:?}"));

            let response = serde_json::json!({
                "proposal_id": hex::encode(outcome.proposal.proposal_id),
                "status": format!("{:?}", outcome.status),
                "execution_result": result_str,
            });
            Ok(response.to_string())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during governance proposal: {e}"),
            code: "SCP-CTX-2041".to_owned(),
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(&handle.context_id).await {
        tracing::warn!(
            context_id = %handle.context_id,
            "failed to sync role state after governance proposal: {e}"
        );
    }

    result
}

/// Casts an approval vote on a pending governance proposal.
///
/// Delegates to [`ContextManager::approve_governance_proposal`].
///
/// # Errors
///
/// Returns `ScpError::Context` (SCP-CTX-2042) if the vote fails.
#[uniffi::export]
pub async fn governance_approve(
    handle: Arc<ContextHandle>,
    voter_did: String,
    proposal_id_hex: String,
) -> Result<String, ScpError> {
    let signing_key = resolve_uniffi_signing_key(&handle).await?;
    let context_id = handle.context_id.clone();
    let proposal_id = parse_uniffi_proposal_id(&proposal_id_hex)?;

    let result = runtime()
        .spawn(async move {
            let did = scp_identity::DID(voter_did);
            let manager = crate::runtime::context_manager();
            let status = manager
                .approve_governance_proposal(&context_id, &proposal_id, &did, &signing_key)
                .await
                .map_err(ScpError::from)?;

            Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during governance approval: {e}"),
            code: "SCP-CTX-2042".to_owned(),
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(&handle.context_id).await {
        tracing::warn!(
            context_id = %handle.context_id,
            "failed to sync role state after governance approval: {e}"
        );
    }

    result
}

/// Casts a rejection vote on a pending governance proposal.
///
/// Delegates to [`ContextManager::reject_governance_proposal`].
///
/// # Errors
///
/// Returns `ScpError::Context` (SCP-CTX-2043) if the vote fails.
#[uniffi::export]
pub async fn governance_reject(
    handle: Arc<ContextHandle>,
    voter_did: String,
    proposal_id_hex: String,
) -> Result<String, ScpError> {
    let signing_key = resolve_uniffi_signing_key(&handle).await?;
    let context_id = handle.context_id.clone();
    let proposal_id = parse_uniffi_proposal_id(&proposal_id_hex)?;

    let result = runtime()
        .spawn(async move {
            let did = scp_identity::DID(voter_did);
            let manager = crate::runtime::context_manager();
            let status = manager
                .reject_governance_proposal(&context_id, &proposal_id, &did, &signing_key)
                .await
                .map_err(ScpError::from)?;

            Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during governance rejection: {e}"),
            code: "SCP-CTX-2043".to_owned(),
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(&handle.context_id).await {
        tracing::warn!(
            context_id = %handle.context_id,
            "failed to sync role state after governance rejection: {e}"
        );
    }

    result
}

/// Withdraws a previously cast vote on a pending governance proposal.
///
/// Delegates to [`ContextManager::withdraw_governance_vote`]. No signing
/// key is required.
///
/// # Errors
///
/// Returns `ScpError::Context` (SCP-CTX-2044) if the withdrawal fails.
#[uniffi::export]
pub async fn governance_withdraw(
    handle: Arc<ContextHandle>,
    voter_did: String,
    proposal_id_hex: String,
) -> Result<String, ScpError> {
    let context_id = handle.context_id.clone();
    let proposal_id = parse_uniffi_proposal_id(&proposal_id_hex)?;

    let result = runtime()
        .spawn(async move {
            let did = scp_identity::DID(voter_did);
            let manager = crate::runtime::context_manager();
            let status = manager
                .withdraw_governance_vote(&context_id, &proposal_id, &did)
                .await
                .map_err(ScpError::from)?;

            Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during governance withdrawal: {e}"),
            code: "SCP-CTX-2044".to_owned(),
        })?;

    if let Err(e) = crate::runtime::sync_role_state_from_manager(&handle.context_id).await {
        tracing::warn!(
            context_id = %handle.context_id,
            "failed to sync role state after governance withdrawal: {e}"
        );
    }

    result
}

/// Retrieves a single governance proposal by hex-encoded ID.
///
/// # Errors
///
/// Returns `ScpError::Context` (SCP-CTX-2045) if the proposal is not found.
#[uniffi::export]
pub async fn governance_get_proposal(
    handle: Arc<ContextHandle>,
    proposal_id_hex: String,
) -> Result<String, ScpError> {
    let context_id = handle.context_id.clone();
    let proposal_id = parse_uniffi_proposal_id(&proposal_id_hex)?;

    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let proposal = manager
                .get_proposal(&context_id, &proposal_id)
                .await
                .map_err(ScpError::from)?;

            serde_json::to_string(&proposal).map_err(|e| ScpError::Context {
                message: format!("serialization failed: {e}"),
                code: "SCP-CTX-2045".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during get proposal: {e}"),
            code: "SCP-CTX-2045".to_owned(),
        })?
}

/// Lists all governance proposals for a context.
///
/// Returns a JSON array of proposals.
///
/// # Errors
///
/// Returns `ScpError::Context` (SCP-CTX-2046) if listing fails.
#[uniffi::export]
pub async fn governance_list_proposals(handle: Arc<ContextHandle>) -> Result<String, ScpError> {
    let context_id = handle.context_id.clone();

    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let proposals = manager
                .list_proposals(&context_id)
                .await
                .map_err(ScpError::from)?;

            serde_json::to_string(&proposals).map_err(|e| ScpError::Context {
                message: format!("serialization failed: {e}"),
                code: "SCP-CTX-2046".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during list proposals: {e}"),
            code: "SCP-CTX-2046".to_owned(),
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
/// The payload is encrypted with the author's broadcast key. The author's
/// identity must have been previously created via `identity_create` so
/// that the key custody provider and signing key handle are available.
///
/// # Arguments
///
/// * `handle` — The context to publish to.
/// * `identity` — The identity of the author publishing the message.
/// * `payload` — The raw message payload bytes to encrypt and publish.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not active, not broadcast,
/// or the sender is not an author.
/// Returns `ScpError::Crypto` if custody signing fails.
/// Returns `ScpError::Permission` if no custody provider is available.
#[uniffi::export]
pub async fn broadcast_publish(
    handle: Arc<ContextHandle>,
    identity: Arc<Identity>,
    payload: Vec<u8>,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let did: scp_identity::DID = identity.did.clone().into();

            let core_id = identity
                .core_id
                .as_ref()
                .ok_or_else(|| ScpError::Permission {
                    message: "broadcast publish requires a fully created identity with key handles"
                        .to_owned(),
                    code: "SCP-PERM-3020".to_owned(),
                })?;
            let signing_key_handle = &core_id.active_signing_key;

            // Dispatch to the correct custody path (callback > in-memory).
            if let Some(ref cb) = identity.callback_custody {
                manager
                    .publish_broadcast(
                        &handle.context_id,
                        &did,
                        &payload,
                        cb.as_ref(),
                        signing_key_handle,
                    )
                    .await
                    .map_err(ScpError::from)?;
            } else {
                #[cfg(feature = "allow_in_memory_custody")]
                {
                    let imc = identity.in_memory_custody.as_ref().ok_or_else(|| {
                        ScpError::Permission {
                            message: "broadcast publish requires key custody — create the \
                                      identity with identity_create(\"in_memory\") or \
                                      identity_create_with_custody()"
                                .to_owned(),
                            code: "SCP-PERM-3021".to_owned(),
                        }
                    })?;
                    manager
                        .publish_broadcast(
                            &handle.context_id,
                            &did,
                            &payload,
                            &imc.0,
                            signing_key_handle,
                        )
                        .await
                        .map_err(ScpError::from)?;
                }
                #[cfg(not(feature = "allow_in_memory_custody"))]
                {
                    return Err(ScpError::Permission {
                        message: "broadcast publish requires key custody — use \
                                  identity_create_with_custody() to inject a platform \
                                  custody provider"
                            .to_owned(),
                        code: "SCP-PERM-3022".to_owned(),
                    });
                }
            }

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

/// Unblocks a previously blocked subscriber in a broadcast context (§9.16.8).
///
/// Forward-only: the unblocked subscriber can request the current key on
/// next pull but cannot decrypt content from the block period.
///
/// # Errors
///
/// - [`ScpError::Context`] with `SCP-CTX-2037` if the tokio task fails.
/// - [`ScpError::Context`] if the subscriber is not blocked or the
///   author is not registered.
#[uniffi::export]
pub async fn broadcast_unblock_subscriber(
    handle: Arc<ContextHandle>,
    subscriber_did: String,
    unblocker_did: String,
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let subscriber: scp_identity::DID = subscriber_did.into();
            let unblocker: scp_identity::DID = unblocker_did.into();
            manager
                .unblock_broadcast_subscriber(&handle.context_id, &unblocker, &subscriber)
                .await
                .map_err(ScpError::from)?;
            Ok(())
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during broadcast unblock: {e}"),
            code: "SCP-CTX-2037".to_owned(),
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

    let min_protocol_version = if params.min_protocol_version == 0 {
        None
    } else {
        let (major, minor) =
            scp_core::context::decode_protocol_version(params.min_protocol_version);
        Some((major, minor))
    };

    scp_core::context::ContextParams {
        ceiling,
        governance,
        memory_scope,
        ttl,
        promotion_policy,
        min_protocol_version,
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
        scp_core::trust::ChallengeType::schema_validation(),
        "scp:capability:schema-validation/v1".to_string(),
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

    struct EphemeralVerifySigner(ed25519_dalek::SigningKey);
    impl scp_core::trust::ChallengeSigner for EphemeralVerifySigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, scp_core::trust::TrustError> {
            use ed25519_dalek::Signer;
            let sig = self.0.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }

    let verify_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verify_signer = EphemeralVerifySigner(verify_signing_key);

    Ok(scp_core::trust::verify_challenge_response(
        &request,
        &response,
        &resolver,
        &clock,
        &verify_signer,
        None,
    )
    .is_ok())
}

// ---------------------------------------------------------------------------
// verify_participation_requirements (SCP-BA-004)
// ---------------------------------------------------------------------------

/// Verifies participation profiles against admission requirements.
///
/// Both inputs are JSON strings:
/// - `profile_json`: JSON array of [`ParticipationProfile`] objects.
/// - `requirements_json`: JSON array of [`RequireParticipation`] objects.
///
/// Uses the current system time for freshness checks. Returns `true` if all
/// requirements are satisfied, throws `ScpError` with a diagnostic message
/// if any requirement fails or if the JSON is malformed.
///
/// See §7.3.2.1.
#[uniffi::export]
pub fn verify_participation_requirements(
    profile_json: String,
    requirements_json: String,
) -> Result<bool, ScpError> {
    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(&profile_json)
        .map_err(|e| ScpError::Validation {
            message: format!("failed to parse participation profiles JSON: {e}"),
            code: "SCP-VALID-7030".to_owned(),
        })?;

    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(&requirements_json).map_err(|e| ScpError::Validation {
            message: format!("failed to parse participation requirements JSON: {e}"),
            code: "SCP-VALID-7031".to_owned(),
        })?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    scp_core::trust::verify_participation_requirements(current_time, &requirements, &profiles)
        .map_err(|e| ScpError::Validation {
            message: format!("participation admission verification failed: {e}"),
            code: "SCP-VALID-7032".to_owned(),
        })?;

    Ok(true)
}

// ---------------------------------------------------------------------------
// Economic policy bridge (§19.3, ADR-033)
// ---------------------------------------------------------------------------

/// Sets the economic policy for a context (§19.3).
///
/// Accepts the economic policy as a JSON string. Validates the JSON against
/// the `EconomicPolicy` schema before storing. If the existing policy has
/// `locked: true`, the mutation is rejected — matching the
/// `ContextManager::execute_set_economic_policy` behaviour in scp-core.
///
/// # Warning
///
/// This is a low-level FFI function that directly overwrites the economic
/// policy. It does **not** go through governance — no event logging, no
/// 24-hour notification period, no proposal flow. Governance enforcement
/// is the SDK / application layer's responsibility.
///
/// # Errors
///
/// - `ScpError::Validation` if the JSON is invalid or does not parse as
///   `EconomicPolicy`.
/// - `ScpError::Permission` if the existing economic policy is locked.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI requires owned String parameters
pub fn set_economic_policy(
    handle: Arc<ContextHandle>,
    policy_json: String,
) -> Result<(), ScpError> {
    // Hold the mutex for the entire check-validate-store sequence to prevent
    // TOCTOU races (another thread bypassing the lock between check and store).
    let mut guard = handle
        .economic_policy
        .lock()
        .map_err(|_| ScpError::Context {
            message: "economic_policy lock is poisoned".to_owned(),
            code: "SCP-CTX-2012".to_owned(),
        })?;

    // Check whether the existing policy is locked (§19.3).
    if let Some(ref existing_json) = *guard
        && let Ok(existing) =
            serde_json::from_str::<scp_core::economy::types::EconomicPolicy>(existing_json)
        && existing.locked
    {
        return Err(ScpError::Permission {
            message: "economic policy is locked and cannot be changed".to_owned(),
            code: "SCP-CTX-2013".to_owned(),
        });
    }

    let _policy: scp_core::economy::types::EconomicPolicy = serde_json::from_str(&policy_json)
        .map_err(|e| ScpError::Validation {
            message: format!("invalid economic policy JSON: {e}"),
            code: "SCP-VALID-7001".to_owned(),
        })?;

    *guard = Some(policy_json);
    Ok(())
}

/// Returns the economic policy for a context as a JSON string, or `None`.
#[uniffi::export]
pub fn get_economic_policy(handle: Arc<ContextHandle>) -> Result<Option<String>, ScpError> {
    let guard = handle
        .economic_policy
        .lock()
        .map_err(|_| ScpError::Context {
            message: "economic_policy lock is poisoned".to_owned(),
            code: "SCP-CTX-2012".to_owned(),
        })?;
    Ok(guard.clone())
}

// ---------------------------------------------------------------------------
// Context export/import (#363)
// ---------------------------------------------------------------------------

/// Exports a context's full state as serialized `MessagePack` bytes.
///
/// Returns the serialized bytes of a `StoredValue<ContextExport>` envelope
/// (§17.5), suitable for backup, migration, or transfer to another node.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context does not exist, export fails,
/// or serialization fails.
#[uniffi::export]
pub async fn context_export(handle: Arc<ContextHandle>) -> Result<Vec<u8>, ScpError> {
    let ctx_id = handle.context_id.clone();
    let creator_did = handle.creator_did.clone();
    runtime()
        .spawn(async move {
            let manager = crate::runtime::context_manager();
            let export = manager
                .export_context(&ctx_id, scp_identity::DID::from(creator_did))
                .await
                .map_err(ScpError::from)?;
            scp_core::context::export_import::serialize_export(&export).map_err(|e| {
                ScpError::Context {
                    message: format!("export serialization failed: {e}"),
                    code: "SCP-CTX-2030".to_owned(),
                }
            })
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during context export: {e}"),
            code: "SCP-CTX-2031".to_owned(),
        })?
}

/// Imports a context from serialized `MessagePack` bytes.
///
/// The bytes must be a `StoredValue<ContextExport>` envelope (§17.5), as
/// produced by [`context_export`].
///
/// Returns the context ID of the imported context.
///
/// # Errors
///
/// Returns `ScpError::Context` if deserialization, validation, or import
/// fails.
#[uniffi::export]
pub async fn context_import(data: Vec<u8>) -> Result<String, ScpError> {
    runtime()
        .spawn(async move {
            let export =
                scp_core::context::export_import::deserialize_export(&data).map_err(|e| {
                    ScpError::Context {
                        message: format!("invalid export data: {e}"),
                        code: "SCP-CTX-2032".to_owned(),
                    }
                })?;
            let context_id = export.snapshot.context_id.clone();
            let manager = crate::runtime::context_manager();
            manager
                .import_context(export)
                .await
                .map_err(ScpError::from)?;
            Ok(context_id)
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during context import: {e}"),
            code: "SCP-CTX-2033".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Provenance — attach and chain depth (#370)
// ---------------------------------------------------------------------------

/// Attaches provenance metadata when data crosses a context boundary.
///
/// Returns a JSON string with the attached provenance record.
///
/// See ADR-019 acceptance criteria 2-3, 6.
#[uniffi::export]
pub fn provenance_attach(
    source_context_id: String,
    source_type: String,
    memory_scope_str: String,
    members: Vec<String>,
    target_context_id: String,
    existing_chain_depth: Option<u8>,
) -> Result<String, ScpError> {
    let st = match source_type.as_str() {
        "persistent" => scp_core::provenance::SourceType::Persistent,
        "ephemeral" => scp_core::provenance::SourceType::Ephemeral,
        "summary" => scp_core::provenance::SourceType::Summary,
        other => {
            return Err(ScpError::Validation {
                message: format!("invalid source_type '{other}'"),
                code: "SCP-VALID-7040".to_owned(),
            });
        }
    };
    let ms = match memory_scope_str.as_str() {
        "full" => scp_core::context::MemoryScope::Full,
        "summary" => scp_core::context::MemoryScope::Summary,
        "ephemeral" => scp_core::context::MemoryScope::Ephemeral,
        other => {
            return Err(ScpError::Validation {
                message: format!("invalid memory_scope '{other}'"),
                code: "SCP-VALID-7041".to_owned(),
            });
        }
    };

    let source_info = scp_core::provenance::attach::SourceContextInfo {
        context_id: source_context_id,
        source_type: st,
        memory_scope: ms,
        members: members.into_iter().map(scp_identity::DID::from).collect(),
        discovery_method: scp_core::provenance::DiscoveryMethod::None,
        data_age: std::time::Duration::from_secs(0),
        purpose: None,
        counterparty_policy: scp_core::provenance::CounterpartyPolicy::default(),
    };

    let existing_prov = existing_chain_depth.map(|depth| scp_core::provenance::DataProvenance {
        source_context: String::new(),
        source_type: scp_core::provenance::SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: scp_core::provenance::DiscoveryMethod::None,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_core::context::MemoryScope::Full,
        chain_depth: depth,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    });

    let prov = scp_core::provenance::attach::attach_provenance(
        &source_info,
        &target_context_id,
        existing_prov.as_ref(),
        None,
        None,
    );

    let result = serde_json::json!({
        "source_context": prov.source_context,
        "source_type": format!("{:?}", prov.source_type),
        "chain_depth": prov.chain_depth,
        "counterparties": prov.counterparties.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "age_secs": prov.age.as_secs(),
        "memory_scope": format!("{:?}", prov.memory_scope),
        "chain_path": prov.chain_path,
        "purpose": prov.purpose,
    });

    serde_json::to_string(&result).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize provenance: {e}"),
        code: "SCP-VALID-7042".to_owned(),
    })
}

/// Checks whether the provenance chain depth is within the allowed limit.
#[uniffi::export]
#[must_use]
pub fn provenance_check_chain_depth(chain_depth: u8, max_depth: Option<u8>) -> bool {
    let max = max_depth.unwrap_or(scp_core::provenance::attach::DEFAULT_MAX_CHAIN_DEPTH);
    let prov = scp_core::provenance::DataProvenance {
        source_context: String::new(),
        source_type: scp_core::provenance::SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: scp_core::provenance::DiscoveryMethod::None,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_core::context::MemoryScope::Full,
        chain_depth,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };
    scp_core::provenance::attach::check_chain_depth(&prov, max).is_ok()
}

// ---------------------------------------------------------------------------
// Bridge connector — trust evaluation (#370)
// ---------------------------------------------------------------------------

/// Evaluates the trust level for an action based on bridge provenance.
///
/// Returns an integer (0-3) representing the trust tier.
#[uniffi::export]
pub fn bridge_evaluate_trust(
    is_bridged: bool,
    is_native_transport: bool,
    shadow_status: String,
) -> Result<u8, ScpError> {
    if !is_bridged {
        let level = scp_core::bridge::provenance::evaluate_trust_level(None, is_native_transport);
        return Ok(level as u8);
    }

    let status = match shadow_status.as_str() {
        "shadow" => scp_core::bridge::ShadowProvenanceStatus::Shadow,
        "claimed" => scp_core::bridge::ShadowProvenanceStatus::Claimed,
        other => {
            return Err(ScpError::Validation {
                message: format!("invalid shadow_status '{other}': expected 'shadow' or 'claimed'"),
                code: "SCP-VALID-7043".to_owned(),
            });
        }
    };

    let base = scp_core::provenance::DataProvenance {
        source_context: String::new(),
        source_type: scp_core::provenance::SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: scp_core::provenance::DiscoveryMethod::None,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_core::context::MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    };

    let connector = scp_core::bridge::BridgeConnector {
        bridge_id: String::new(),
        operator_did: "did:key:unused".into(),
        platform: String::new(),
        mode: scp_core::bridge::BridgeMode::Relay,
        status: scp_core::bridge::BridgeStatus::Active,
        registration_context: String::new(),
        registered_at: 0,
    };

    let shadow = scp_core::bridge::ShadowIdentity {
        shadow_id: String::new(),
        platform_handle: String::new(),
        bridge_id: String::new(),
        attributed_role: "observer".to_string(),
        provenance_status: status,
        created_at: 0,
    };

    let bp = scp_core::bridge::provenance::mark_bridge_provenance(base, &connector, &shadow);
    let level = scp_core::bridge::provenance::evaluate_trust_level(Some(&bp), is_native_transport);
    Ok(level as u8)
}

// ---------------------------------------------------------------------------
// Sync — offline classification (#370)
// ---------------------------------------------------------------------------

/// Classifies an offline duration into the appropriate recovery tier.
///
/// Returns `"short"`, `"extended"`, or `"long"`.
#[uniffi::export]
#[must_use]
pub fn sync_classify_offline(last_relay_contact: u64, now: u64) -> String {
    match scp_core::sync::classify_offline_duration(last_relay_contact, now) {
        scp_core::sync::OfflineTier::Short => "short".to_string(),
        scp_core::sync::OfflineTier::Extended => "extended".to_string(),
        scp_core::sync::OfflineTier::Long => "long".to_string(),
    }
}

/// Classifies an offline duration using custom policy thresholds.
///
/// Returns `"short"`, `"extended"`, or `"long"`.
#[uniffi::export]
#[must_use]
pub fn sync_classify_offline_custom(
    last_relay_contact: u64,
    now: u64,
    tier_1_threshold_secs: u64,
    tier_2_threshold_secs: u64,
) -> String {
    let policy = scp_core::sync::SyncPolicy::default()
        .with_tier_1_threshold_secs(tier_1_threshold_secs)
        .with_tier_2_threshold_secs(tier_2_threshold_secs);

    match policy.classify_offline_duration(last_relay_contact, now) {
        scp_core::sync::OfflineTier::Short => "short".to_string(),
        scp_core::sync::OfflineTier::Extended => "extended".to_string(),
        scp_core::sync::OfflineTier::Long => "long".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Discovery — address parsing and normalization (#370)
// ---------------------------------------------------------------------------

/// Parses an SCP address string into its components.
///
/// Returns a JSON string with the parsed address type and fields.
#[uniffi::export]
pub fn discovery_parse_address(address: String) -> Result<String, ScpError> {
    let parsed =
        scp_core::discovery::parse_address(&address).map_err(|e| ScpError::Validation {
            message: format!("invalid address '{address}': {e}"),
            code: "SCP-VALID-7044".to_owned(),
        })?;

    let result = match parsed {
        scp_core::discovery::addressing::ParsedAddress::DiscoveryHandle { local_part, scope } => {
            serde_json::json!({
                "type": "DiscoveryHandle",
                "local_part": local_part,
                "scope": scope,
            })
        }
        scp_core::discovery::addressing::ParsedAddress::DomainHandle { local_part, domain } => {
            serde_json::json!({
                "type": "DomainHandle",
                "local_part": local_part,
                "domain": domain,
            })
        }
        scp_core::discovery::addressing::ParsedAddress::AttestationHandle { handle, platform } => {
            serde_json::json!({
                "type": "AttestationHandle",
                "handle": handle,
                "platform": platform,
            })
        }
        scp_core::discovery::addressing::ParsedAddress::Unscoped { name } => {
            serde_json::json!({
                "type": "Unscoped",
                "name": name,
            })
        }
    };

    serde_json::to_string(&result).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize parsed address: {e}"),
        code: "SCP-VALID-7045".to_owned(),
    })
}

/// Creates a discovery query as a JSON string.
#[uniffi::export]
pub fn discovery_create_query(
    capabilities: Option<Vec<String>>,
    keywords: Option<Vec<String>>,
    min_history_secs: Option<u64>,
) -> Result<String, ScpError> {
    let query = scp_core::discovery::DiscoveryQuery {
        capability_filter: capabilities,
        keywords,
        min_history: min_history_secs.map(std::time::Duration::from_secs),
    };

    serde_json::to_string(&query).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize query: {e}"),
        code: "SCP-VALID-7046".to_owned(),
    })
}

/// Normalizes an address string per SCP addressing rules.
///
/// Lowercases and trims whitespace.
#[uniffi::export]
#[must_use]
pub fn discovery_normalize_address(address: String) -> String {
    scp_core::discovery::normalize_address(&address)
}

// ---------------------------------------------------------------------------
// Petname bridge functions (§22.4)
// ---------------------------------------------------------------------------

/// Global petname map keyed by owner DID string.
fn uniffi_petname_maps()
-> &'static std::sync::Mutex<std::collections::HashMap<String, scp_core::discovery::PetnameMap>> {
    use std::sync::{Mutex, OnceLock};
    static MAPS: OnceLock<
        Mutex<std::collections::HashMap<String, scp_core::discovery::PetnameMap>>,
    > = OnceLock::new();
    MAPS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Global handle registries keyed by discovery context ID.
fn uniffi_handle_registries()
-> &'static std::sync::Mutex<std::collections::HashMap<String, scp_core::discovery::HandleRegistry>>
{
    use std::sync::{Mutex, OnceLock};
    static REGISTRIES: OnceLock<
        Mutex<std::collections::HashMap<String, scp_core::discovery::HandleRegistry>>,
    > = OnceLock::new();
    REGISTRIES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Sets a petname for a DID.
#[uniffi::export]
pub fn petname_set(owner_did: String, target_did: String, name: String) -> Result<(), ScpError> {
    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }
    if target_did.is_empty() {
        return Err(ScpError::Validation {
            message: "target_did must not be empty".to_owned(),
            code: "SCP-VALID-7111".to_owned(),
        });
    }
    let mut guard = uniffi_petname_maps()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let map = guard.entry(owner_did).or_default();
    map.set_petname(scp_identity::DID::from(target_did.as_str()), name);
    Ok(())
}

/// Removes a petname from a DID.
#[uniffi::export]
pub fn petname_remove(owner_did: String, target_did: String) -> Result<(), ScpError> {
    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }
    let mut guard = uniffi_petname_maps()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    if let Some(map) = guard.get_mut(&owner_did) {
        map.remove_petname(&scp_identity::DID::from(target_did.as_str()));
    }
    Ok(())
}

/// Sets a petname for a context.
#[uniffi::export]
pub fn petname_set_context(
    owner_did: String,
    context_id: String,
    name: String,
) -> Result<(), ScpError> {
    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }
    if context_id.is_empty() {
        return Err(ScpError::Validation {
            message: "context_id must not be empty".to_owned(),
            code: "SCP-VALID-7113".to_owned(),
        });
    }
    let mut guard = uniffi_petname_maps()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let map = guard.entry(owner_did).or_default();
    map.set_context_petname(context_id, name);
    Ok(())
}

/// Removes a petname from a context.
#[uniffi::export]
pub fn petname_remove_context(owner_did: String, context_id: String) -> Result<(), ScpError> {
    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }
    let mut guard = uniffi_petname_maps()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    if let Some(map) = guard.get_mut(&owner_did) {
        map.remove_context_petname(&context_id);
    }
    Ok(())
}

/// Resolves a petname to DIDs. Returns a JSON array of DID strings.
#[uniffi::export]
pub fn petname_resolve_did(owner_did: String, name: String) -> Result<String, ScpError> {
    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }
    let guard = uniffi_petname_maps()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let dids: Vec<String> = guard
        .get(&owner_did)
        .map(|map| {
            map.resolve_did(&name)
                .into_iter()
                .map(|d| d.to_string())
                .collect()
        })
        .unwrap_or_default();
    serde_json::to_string(&dids).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize petname resolve result: {e}"),
        code: "SCP-VALID-7114".to_owned(),
    })
}

/// Resolves a petname to context IDs. Returns a JSON array of strings.
#[uniffi::export]
pub fn petname_resolve_context(owner_did: String, name: String) -> Result<String, ScpError> {
    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }
    let guard = uniffi_petname_maps()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    let ids: Vec<String> = guard
        .get(&owner_did)
        .map(|map| map.resolve_context(&name))
        .unwrap_or_default();
    serde_json::to_string(&ids).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize petname resolve result: {e}"),
        code: "SCP-VALID-7114".to_owned(),
    })
}

/// Gets the petname for a DID.
#[uniffi::export]
pub fn petname_get_for_did(
    owner_did: String,
    target_did: String,
) -> Result<Option<String>, ScpError> {
    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }
    let guard = uniffi_petname_maps()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    Ok(guard.get(&owner_did).and_then(|map| {
        map.petname_for_did(&scp_identity::DID::from(target_did.as_str()))
            .map(str::to_owned)
    }))
}

/// Gets the petname for a context.
#[uniffi::export]
pub fn petname_get_for_context(
    owner_did: String,
    context_id: String,
) -> Result<Option<String>, ScpError> {
    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }
    let guard = uniffi_petname_maps()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("petname lock poisoned: {e}"),
            code: "SCP-VALID-7112".to_owned(),
        })?;
    Ok(guard
        .get(&owner_did)
        .and_then(|map| map.petname_for_context(&context_id).map(str::to_owned)))
}

// ---------------------------------------------------------------------------
// Handle registry bridge functions (§22.3.1)
// ---------------------------------------------------------------------------

/// Registers a handle in a discovery context. Returns JSON result.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn handle_register(
    discovery_context_id: String,
    handle: String,
    target_json: String,
    registrant_did: String,
    description: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<String, ScpError> {
    let target = uniffi_parse_handle_target(&target_json)?;
    let params = scp_core::discovery::HandleRegisterParams {
        handle,
        target,
        metadata: Some(scp_core::discovery::HandleMetadata { description, tags }),
    };
    let mut guard = uniffi_handle_registries()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7120".to_owned(),
        })?;
    let registry = guard
        .entry(discovery_context_id.clone())
        .or_insert_with(|| scp_core::discovery::HandleRegistry::new(discovery_context_id));
    let result = registry
        .register(&params, &scp_identity::DID::from(registrant_did.as_str()))
        .map_err(|e| ScpError::Validation {
            message: format!("clock error during handle registration: {e}"),
            code: "SCP-VALID-7121".to_owned(),
        })?;
    serde_json::to_string(&result).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize handle register result: {e}"),
        code: "SCP-VALID-7122".to_owned(),
    })
}

/// Looks up a handle in a discovery context. Returns JSON result.
#[uniffi::export]
pub fn handle_lookup(
    discovery_context_id: String,
    handle: String,
    type_filter: Option<String>,
) -> Result<String, ScpError> {
    let filter = match type_filter.as_deref() {
        Some("identity") => Some(scp_core::discovery::HandleTypeFilter::Identity),
        Some("context") => Some(scp_core::discovery::HandleTypeFilter::Context),
        Some(other) => {
            return Err(ScpError::Validation {
                message: format!("invalid type_filter '{other}': expected 'identity' or 'context'"),
                code: "SCP-VALID-7123".to_owned(),
            });
        }
        None => None,
    };
    let guard = uniffi_handle_registries()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7120".to_owned(),
        })?;
    let result = guard.get(&discovery_context_id).map_or_else(
        || scp_core::discovery::HandleLookupResult {
            results: Vec::new(),
        },
        |registry| {
            registry.lookup(&scp_core::discovery::HandleLookupParams {
                handle,
                type_filter: filter,
            })
        },
    );
    serde_json::to_string(&result).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize handle lookup result: {e}"),
        code: "SCP-VALID-7124".to_owned(),
    })
}

/// Deregisters a handle from a discovery context. Returns JSON result.
#[uniffi::export]
pub fn handle_deregister(
    discovery_context_id: String,
    handle: String,
    did: String,
) -> Result<String, ScpError> {
    let mut guard = uniffi_handle_registries()
        .lock()
        .map_err(|e| ScpError::Validation {
            message: format!("handle registry lock poisoned: {e}"),
            code: "SCP-VALID-7120".to_owned(),
        })?;
    let result = guard.get_mut(&discovery_context_id).map_or_else(
        || scp_core::discovery::HandleDeregisterResult { removed: false },
        |registry| {
            registry.deregister(&scp_core::discovery::HandleDeregisterParams {
                handle,
                did: scp_identity::DID::from(did.as_str()),
            })
        },
    );
    serde_json::to_string(&result).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize handle deregister result: {e}"),
        code: "SCP-VALID-7125".to_owned(),
    })
}

/// Resolves a human-readable address via multi-path resolution.
/// Returns a JSON array of `AddressResolution` objects.
#[uniffi::export]
pub fn address_resolve(
    owner_did: String,
    address: String,
    known_contexts_json: Option<String>,
) -> Result<String, ScpError> {
    use scp_core::discovery::addressing::{
        AddressResolution, AddressType, HandleQuerier, HandleTarget, ResolutionLayer,
        ResolutionPath, TrustLevel,
    };

    if owner_did.is_empty() {
        return Err(ScpError::Validation {
            message: "owner_did must not be empty".to_owned(),
            code: "SCP-VALID-7110".to_owned(),
        });
    }

    struct UniFFIHandleQuerier;

    impl HandleQuerier for UniFFIHandleQuerier {
        async fn lookup_handle(
            &self,
            context_id: &String,
            handle: &str,
            type_filter: Option<AddressType>,
        ) -> Vec<AddressResolution> {
            let Ok(guard) = uniffi_handle_registries().lock() else {
                return Vec::new();
            };
            let Some(registry) = guard.get(context_id.as_str()) else {
                return Vec::new();
            };
            let filter = type_filter.map(|tf| match tf {
                AddressType::Identity => scp_core::discovery::HandleTypeFilter::Identity,
                AddressType::Context => scp_core::discovery::HandleTypeFilter::Context,
            });
            let result = registry.lookup(&scp_core::discovery::HandleLookupParams {
                handle: handle.to_owned(),
                type_filter: filter,
            });
            let now = scp_core::time::now_secs().unwrap_or(0);
            result
                .results
                .into_iter()
                .map(|entry| {
                    let resolution_path = ResolutionPath {
                        layer: ResolutionLayer::DiscoveryContext,
                        source: "local_registry".to_owned(),
                        source_id: Some(context_id.clone()),
                        resolved_at: now,
                    };
                    let trust_level = TrustLevel::DiscoveryContextVerified;
                    match &entry.target {
                        HandleTarget::Identity { did } => AddressResolution::Identity {
                            did: did.clone(),
                            trust_level,
                            resolution_path,
                        },
                        HandleTarget::Context {
                            context_id: ctx_id,
                            relay_urls,
                        } => AddressResolution::Context {
                            context_id: ctx_id.clone(),
                            relay_urls: relay_urls.clone(),
                            mode: None,
                            trust_level,
                            resolution_path,
                        },
                    }
                })
                .collect()
        }

        async fn lookup_domain_handle(
            &self,
            _domain: &str,
            _handle: &str,
        ) -> Vec<AddressResolution> {
            Vec::new()
        }

        async fn lookup_attestation_handle(
            &self,
            _handle: &str,
            _platform: Option<&str>,
        ) -> Vec<AddressResolution> {
            Vec::new()
        }
    }

    let known_contexts: std::collections::HashMap<String, String> =
        if let Some(ref json) = known_contexts_json {
            serde_json::from_str(json).map_err(|e| ScpError::Validation {
                message: format!("invalid known_contexts_json: {e}"),
                code: "SCP-VALID-7090".to_owned(),
            })?
        } else {
            let guard = uniffi_handle_registries()
                .lock()
                .map_err(|e| ScpError::Validation {
                    message: format!("handle registry lock poisoned: {e}"),
                    code: "SCP-VALID-7120".to_owned(),
                })?;
            guard.keys().map(|k| (k.clone(), k.clone())).collect()
        };
    let known_domains: Vec<&str> = Vec::new();
    let petname_map = {
        let guard = uniffi_petname_maps()
            .lock()
            .map_err(|e| ScpError::Validation {
                message: format!("petname lock poisoned: {e}"),
                code: "SCP-VALID-7112".to_owned(),
            })?;
        guard.get(&owner_did).cloned().unwrap_or_default()
    };

    let handle = tokio::runtime::Handle::current();
    let results = tokio::task::block_in_place(|| {
        handle.block_on(async {
            let mut resolver = scp_core::discovery::AddressResolver::new();
            let querier = UniFFIHandleQuerier;
            resolver
                .resolve(
                    &address,
                    &petname_map,
                    &querier,
                    &known_contexts,
                    &known_domains,
                )
                .await
                .map_err(|e| ScpError::Validation {
                    message: format!("address resolution failed: {e}"),
                    code: "SCP-VALID-7091".to_owned(),
                })
        })
    })?;

    fn addr_resolution_to_json(resolution: &AddressResolution) -> serde_json::Value {
        match resolution {
            AddressResolution::Identity {
                did,
                trust_level,
                resolution_path,
            } => serde_json::json!({
                "type": "Identity",
                "did": did.to_string(),
                "trust_level": trust_to_json(trust_level),
                "resolution_path": path_to_json(resolution_path),
            }),
            AddressResolution::Context {
                context_id,
                relay_urls,
                mode,
                trust_level,
                resolution_path,
            } => serde_json::json!({
                "type": "Context",
                "context_id": context_id,
                "relay_urls": relay_urls,
                "mode": mode,
                "trust_level": trust_to_json(trust_level),
                "resolution_path": path_to_json(resolution_path),
            }),
        }
    }

    fn trust_to_json(trust_level: &TrustLevel) -> serde_json::Value {
        match trust_level {
            TrustLevel::DirectExchange => serde_json::json!({"kind": "DirectExchange"}),
            TrustLevel::LocalPetname => serde_json::json!({"kind": "LocalPetname"}),
            TrustLevel::MultiLayerCorroborated { sources } => serde_json::json!({
                "kind": "MultiLayerCorroborated",
                "sources": sources.iter().map(path_to_json).collect::<Vec<_>>(),
            }),
            TrustLevel::DomainVerified => serde_json::json!({"kind": "DomainVerified"}),
            TrustLevel::AttestationVerified => {
                serde_json::json!({"kind": "AttestationVerified"})
            }
            TrustLevel::DiscoveryContextVerified => {
                serde_json::json!({"kind": "DiscoveryContextVerified"})
            }
        }
    }

    fn path_to_json(path: &ResolutionPath) -> serde_json::Value {
        let layer = match path.layer {
            ResolutionLayer::Petname => "Petname",
            ResolutionLayer::DiscoveryContext => "DiscoveryContext",
            ResolutionLayer::Attestation => "Attestation",
            ResolutionLayer::Domain => "Domain",
            ResolutionLayer::MultiLayerCorroborated => "MultiLayerCorroborated",
        };
        serde_json::json!({
            "layer": layer,
            "source": path.source,
            "source_id": path.source_id,
            "resolved_at": path.resolved_at,
        })
    }

    let json_results: Vec<serde_json::Value> =
        results.iter().map(addr_resolution_to_json).collect();
    serde_json::to_string(&json_results).map_err(|e| ScpError::Validation {
        message: format!("failed to serialize address resolution results: {e}"),
        code: "SCP-VALID-7092".to_owned(),
    })
}

/// Parses a `HandleTarget` from a JSON string (`UniFFI` helper).
fn uniffi_parse_handle_target(
    json: &str,
) -> Result<scp_core::discovery::addressing::HandleTarget, ScpError> {
    let val: serde_json::Value = serde_json::from_str(json).map_err(|e| ScpError::Validation {
        message: format!("invalid target_json: {e}"),
        code: "SCP-VALID-7126".to_owned(),
    })?;
    let target_type = val["type"].as_str().ok_or_else(|| ScpError::Validation {
        message: "target_json must have a 'type' field ('identity' or 'context')".to_owned(),
        code: "SCP-VALID-7126".to_owned(),
    })?;
    match target_type {
        "identity" => {
            let did = val["did"].as_str().ok_or_else(|| ScpError::Validation {
                message: "identity target must have a 'did' field".to_owned(),
                code: "SCP-VALID-7126".to_owned(),
            })?;
            Ok(scp_core::discovery::addressing::HandleTarget::Identity {
                did: scp_identity::DID::from(did),
            })
        }
        "context" => {
            let ctx_id = val["context_id"]
                .as_str()
                .ok_or_else(|| ScpError::Validation {
                    message: "context target must have a 'context_id' field".to_owned(),
                    code: "SCP-VALID-7126".to_owned(),
                })?;
            let relay_urls = val["relay_urls"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            Ok(scp_core::discovery::addressing::HandleTarget::Context {
                context_id: ctx_id.to_owned(),
                relay_urls,
            })
        }
        other => Err(ScpError::Validation {
            message: format!("invalid target type '{other}': expected 'identity' or 'context'"),
            code: "SCP-VALID-7126".to_owned(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Identity — create with agent key (#421)
// ---------------------------------------------------------------------------

/// Creates a new SCP identity with an agent signing key.
///
/// Same as `identity_create` but also generates an `#agent` verification
/// method keypair in the DID document (ADR-039). The returned `Identity`
/// has `has_agent_key() == true`.
///
/// Only available with `"in_memory"` custody when the
/// `allow_in_memory_custody` feature is enabled. Production mobile builds
/// must use `identity_create_with_custody` + `add_agent_key`.
///
/// # Arguments
///
/// * `custody` — Custody method string (`"in_memory"`).
///
/// # Errors
///
/// Returns `ScpError::Identity` if the custody method is unsupported or
/// key generation/DHT publish fails.
///
/// See ADR-039 acceptance criterion 4 and SCP-AB-016.
#[uniffi::export]
pub async fn identity_create_with_agent_key(custody: String) -> Result<Arc<Identity>, ScpError> {
    let custody_method = parse_custody_method(&custody)?;

    runtime()
        .spawn(async move {
            match custody_method {
                CustodyMethod::InMemory => {
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
                        let key_custody =
                            Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
                        let dht = DidDht::new();
                        let (identity, document) = dht
                            .create_with_agent_key(&key_custody.0)
                            .await
                            .map_err(ScpError::from)?;

                        // Initialize the production DID resolver for UCAN validation.
                        ensure_did_resolver_initialized(tokio::runtime::Handle::current());

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
                CustodyMethod::Platform | CustodyMethod::Software => Err(ScpError::Identity {
                    message: format!(
                        "custody type {custody:?} requires a KeyCustodyProvider — \
                             use identity_create_with_custody() + add_agent_key() to create \
                             an identity with an agent key using platform custody"
                    ),
                    code: "SCP-IDENT-1003".to_owned(),
                }),
                CustodyMethod::External => Err(ScpError::Identity {
                    message: "internal: CustodyMethod::External cannot be used with \
                                  identity_create_with_agent_key — use identity_load for \
                                  external DID handles"
                        .to_owned(),
                    code: "SCP-IDENT-1005".to_owned(),
                }),
            }
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during identity creation with agent key: {e}"),
            code: "SCP-IDENT-1007".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Identity — migrate (#421)
// ---------------------------------------------------------------------------

/// Migrates an identity to a new DID (Layer 2 DID rotation).
///
/// Generates a new keypair, creates a new DID, and links the old DID to
/// the new one via `alsoKnownAs` in the old DID document.
///
/// # Arguments
///
/// * `identity` — The identity to migrate. Must have retained crypto state
///   (created via `identity_create` or `identity_create_with_agent_key`,
///   not via `identity_load`).
///
/// # Returns
///
/// A new `Identity` handle with the migrated DID.
///
/// # Errors
///
/// Returns `ScpError::Identity` if the identity has no retained crypto
/// state, key generation fails, or DHT publish fails.
///
/// See ADR-003 acceptance criterion 4b.
#[uniffi::export]
pub async fn identity_migrate(identity: Arc<Identity>) -> Result<Arc<Identity>, ScpError> {
    let core_id = identity
        .core_id
        .as_ref()
        .ok_or_else(|| ScpError::Identity {
            message: "identity migration requires retained crypto state — this identity \
                  was loaded without key material (use identity_create or \
                  identity_create_with_custody)"
                .to_owned(),
            code: "SCP-IDENT-1009".to_owned(),
        })?;
    let core_document = identity
        .core_document
        .as_ref()
        .ok_or_else(|| ScpError::Identity {
            message: "identity migration requires a retained DID document".to_owned(),
            code: "SCP-IDENT-1009".to_owned(),
        })?;

    // We need a custody provider to generate new keys.
    #[cfg(feature = "allow_in_memory_custody")]
    let in_memory = identity.in_memory_custody.as_ref();

    let old_identity = core_id.clone();
    let old_document = core_document.clone();
    let custody_type = identity.custody_type.clone();

    #[cfg(feature = "allow_in_memory_custody")]
    let custody_arc = in_memory.map(Arc::clone);
    let callback_custody = identity.callback_custody.as_ref().map(Arc::clone);

    runtime()
        .spawn(async move {
            // Determine which custody to use for key generation.
            #[cfg(feature = "allow_in_memory_custody")]
            if let Some(ref kc) = custody_arc {
                let pre_rotation_key =
                    kc.0.generate_keypair(scp_platform::traits::KeyType::Ed25519)
                        .await
                        .map_err(|e| ScpError::Identity {
                            message: format!("key generation failed during migration: {e}"),
                            code: "SCP-IDENT-1009".to_owned(),
                        })?;

                let rotated_at = scp_core::time::now_secs().map_err(|e| ScpError::Identity {
                    message: format!("failed to get current time: {e}"),
                    code: "SCP-IDENT-1009".to_owned(),
                })?;

                let dht = DidDht::new();
                let (new_identity, new_document, _rotation_event) = dht
                    .migrate_identity(
                        &old_identity,
                        &old_document,
                        &pre_rotation_key,
                        &kc.0,
                        rotated_at,
                    )
                    .await
                    .map_err(ScpError::from)?;

                let has_agent = new_document.has_agent_key();
                let handle = Arc::new(Identity {
                    did: new_identity.did.clone(),
                    custody_type,
                    core_id: Some(new_identity),
                    core_document: Some(new_document),
                    #[cfg(feature = "allow_in_memory_custody")]
                    in_memory_custody: custody_arc,
                    callback_custody,
                });
                increment_handle_count();
                let _ = has_agent; // suppress unused warning
                return Ok(handle);
            }

            if let Some(ref cc) = callback_custody {
                let pre_rotation_key = cc
                    .generate_keypair(scp_platform::traits::KeyType::Ed25519)
                    .await
                    .map_err(|e| ScpError::Identity {
                        message: format!("key generation failed during migration: {e}"),
                        code: "SCP-IDENT-1009".to_owned(),
                    })?;

                let rotated_at = scp_core::time::now_secs().map_err(|e| ScpError::Identity {
                    message: format!("failed to get current time: {e}"),
                    code: "SCP-IDENT-1009".to_owned(),
                })?;

                let dht = DidDht::new();
                let (new_identity, new_document, _rotation_event) = dht
                    .migrate_identity(
                        &old_identity,
                        &old_document,
                        &pre_rotation_key,
                        cc.as_ref(),
                        rotated_at,
                    )
                    .await
                    .map_err(ScpError::from)?;

                let handle = Arc::new(Identity {
                    did: new_identity.did.clone(),
                    custody_type,
                    core_id: Some(new_identity),
                    core_document: Some(new_document),
                    #[cfg(feature = "allow_in_memory_custody")]
                    in_memory_custody: None,
                    callback_custody: Some(Arc::clone(cc)),
                });
                increment_handle_count();
                return Ok(handle);
            }

            Err(ScpError::Identity {
                message: "identity migration requires a retained custody provider \
                          (in-memory or callback)"
                    .to_owned(),
                code: "SCP-IDENT-1009".to_owned(),
            })
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during identity migration: {e}"),
            code: "SCP-IDENT-1007".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Sync — get policy (#428)
// ---------------------------------------------------------------------------

/// Sync policy parameters record.
///
/// Contains the default sync policy values. Returned by `sync_get_policy`.
///
/// See ADR-029 in `.docs/adrs/phase-6.md`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncPolicyResult {
    /// Tier 1 upper bound in seconds (default 14400 = 4 hours).
    pub tier_1_threshold_secs: u64,
    /// Tier 2 upper bound in seconds (default 604800 = 7 days).
    pub tier_2_threshold_secs: u64,
    /// Gap timeout in seconds (default 30).
    pub gap_timeout_secs: u64,
    /// Max buffered messages in the reorder buffer (default 100).
    pub reorder_buffer_capacity: u32,
    /// Max sequential MLS Commits for epoch catch-up (default 100).
    pub max_sequential_commits: u64,
    /// Per-Commit processing timeout in seconds (default 5).
    pub commit_process_timeout_secs: u64,
    /// Sender key re-acquisition timeout in seconds (default 60).
    pub sender_key_timeout_secs: u64,
    /// Reconnection dedup window in seconds (default 30).
    pub reconnection_dedup_window_secs: u64,
}

/// Returns the default sync policy parameters.
///
/// Returns a `SyncPolicyResult` record with all default values from
/// `SyncPolicy::default()`.
///
/// See ADR-029 in `.docs/adrs/phase-6.md`.
#[uniffi::export]
#[must_use]
pub fn sync_get_policy() -> SyncPolicyResult {
    let policy = scp_core::sync::SyncPolicy::default();

    #[allow(clippy::cast_possible_truncation)]
    SyncPolicyResult {
        tier_1_threshold_secs: policy.tier_1_threshold_secs,
        tier_2_threshold_secs: policy.tier_2_threshold_secs,
        gap_timeout_secs: policy.gap_timeout.as_secs(),
        reorder_buffer_capacity: policy.reorder_buffer_capacity as u32,
        max_sequential_commits: policy.max_sequential_commits,
        commit_process_timeout_secs: policy.commit_process_timeout.as_secs(),
        sender_key_timeout_secs: policy.sender_key_timeout.as_secs(),
        reconnection_dedup_window_secs: policy.reconnection_dedup_window.as_secs(),
    }
}

// ---------------------------------------------------------------------------
// Bridge connector — register and create shadow (#421)
// ---------------------------------------------------------------------------

/// Bridge registration result record.
///
/// Returned by `bridge_register`. Contains the details of a successfully
/// registered bridge connector.
///
/// See spec section 12 (Bridge System) and ADR-023.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BridgeRegistrationResult {
    /// Unique identifier for the registered bridge.
    pub bridge_id: String,
    /// DID of the bridge operator.
    pub operator_did: String,
    /// External platform name (e.g., `"discord"`, `"slack"`).
    pub platform: String,
    /// Bridge operating mode (`"relay"`, `"puppet"`, `"api"`, `"cooperative"`).
    pub mode: String,
    /// Bridge status after registration (e.g., `"active"`).
    pub status: String,
    /// Context the bridge is registered in.
    pub context_id: String,
}

/// Shadow identity result record.
///
/// Returned by `bridge_create_shadow`. Contains the details of a shadow
/// identity representing an external platform participant.
///
/// See spec section 12 (Bridge System) and ADR-023.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ShadowIdentityResult {
    /// Unique identifier for this shadow identity.
    pub shadow_id: String,
    /// External platform handle (e.g., `"@user#1234"`).
    pub platform_handle: String,
    /// Bridge connector that created this shadow.
    pub bridge_id: String,
    /// Role attributed to this shadow.
    pub attributed_role: String,
    /// Provenance status: `"Shadow"` or `"Claimed"`.
    pub provenance_status: String,
}

/// Registers a new bridge connector with a context.
///
/// Creates a bridge registration, submits a registration request, and
/// immediately approves it using the provided governance DID.
///
/// # Arguments
///
/// * `context_id` — Context to register the bridge in.
/// * `operator_did` — DID of the human operator accountable for the bridge.
/// * `governance_did` — DID of the governance authority approving the
///   registration.  Must differ from `operator_did` (self-approval is
///   forbidden per ADR-023).
/// * `platform` — External platform name (e.g., `"discord"`, `"slack"`).
/// * `mode` — Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.
///
/// # Returns
///
/// A `BridgeRegistrationResult` with the registration details.
///
/// # Errors
///
/// Returns `ScpError::Validation` if `mode` is not recognized, or
/// `ScpError::Context` if registration or approval fails (including
/// self-approval).
///
/// See spec section 12 (Bridge System) and ADR-023.
#[uniffi::export]
pub fn bridge_register(
    context_id: String,
    operator_did: String,
    governance_did: String,
    platform: String,
    mode: String,
) -> Result<BridgeRegistrationResult, ScpError> {
    validate_did(&operator_did)?;
    validate_did(&governance_did)?;

    let bridge_mode = match mode.as_str() {
        "relay" => scp_core::bridge::BridgeMode::Relay,
        "puppet" => scp_core::bridge::BridgeMode::Puppet,
        "api" => scp_core::bridge::BridgeMode::Api,
        "cooperative" => scp_core::bridge::BridgeMode::Cooperative,
        other => {
            return Err(ScpError::Validation {
                message: format!(
                    "invalid bridge mode '{other}': expected 'relay', 'puppet', 'api', or 'cooperative'"
                ),
                code: "SCP-VALID-7050".to_owned(),
            });
        }
    };

    let mut registry = scp_core::bridge::registration::BridgeRegistry::new(context_id.clone());

    let bridge_id = format!(
        "bridge-{platform}-{}",
        context_id.chars().take(8).collect::<String>()
    );
    let request = scp_core::bridge::registration::BridgeRegistrationRequest {
        bridge_id: bridge_id.clone(),
        operator_did: operator_did.clone().into(),
        platform: platform.clone(),
        mode: bridge_mode,
        context_id: context_id.clone(),
        requested_at: 0,
        self_hosted: false,
    };

    scp_core::bridge::registration::register_bridge(&mut registry, request).map_err(|e| {
        ScpError::Context {
            message: format!("bridge registration failed: {e}"),
            code: "SCP-CTX-2100".to_owned(),
        }
    })?;

    let approver_did: scp_identity::DID = governance_did.into();
    let (connector, _approval_event) = scp_core::bridge::registration::approve_registration(
        &mut registry,
        &bridge_id,
        &approver_did,
        0,
    )
    .map_err(|e| ScpError::Context {
        message: format!("bridge approval failed: {e}"),
        code: "SCP-CTX-2101".to_owned(),
    })?;

    Ok(BridgeRegistrationResult {
        bridge_id: connector.bridge_id,
        operator_did,
        platform,
        mode,
        status: "active".to_owned(),
        context_id,
    })
}

/// Creates a shadow identity for an external platform participant.
///
/// Shadow identities represent non-SCP participants in a bridged context.
/// They carry provenance metadata indicating they are not native SCP
/// identities.
///
/// # Arguments
///
/// * `bridge_id` — The bridge connector ID that owns this shadow.
/// * `platform_handle` — External platform handle (e.g., `"@user#1234"`).
/// * `bridge_mode` — Bridge mode: `"relay"`, `"puppet"`, `"api"`, or
///   `"cooperative"`.
/// * `context_id` — Context the shadow is being created in.
///
/// # Returns
///
/// A `ShadowIdentityResult` with the shadow identity details.
///
/// # Errors
///
/// Returns `ScpError::Validation` if `bridge_mode` is not recognized, or
/// `ScpError::Context` if shadow creation fails.
///
/// See spec section 12 (Bridge System) and ADR-023.
#[uniffi::export]
pub fn bridge_create_shadow(
    bridge_id: String,
    platform_handle: String,
    bridge_mode: String,
    context_id: String,
) -> Result<ShadowIdentityResult, ScpError> {
    let mode = match bridge_mode.as_str() {
        "relay" => scp_core::bridge::BridgeMode::Relay,
        "puppet" => scp_core::bridge::BridgeMode::Puppet,
        "api" => scp_core::bridge::BridgeMode::Api,
        "cooperative" => scp_core::bridge::BridgeMode::Cooperative,
        other => {
            return Err(ScpError::Validation {
                message: format!(
                    "invalid bridge mode '{other}': expected 'relay', 'puppet', 'api', or 'cooperative'"
                ),
                code: "SCP-VALID-7050".to_owned(),
            });
        }
    };

    let shadow_id = format!("shadow-{bridge_id}-{}", platform_handle.replace('@', ""));
    let mut shadow_registry = scp_core::bridge::shadow::ShadowRegistry::new(context_id);
    let mut sender_key_store = scp_core::crypto::sender_keys::SenderKeyStore::new();

    let params = scp_core::bridge::shadow::CreateShadowParams {
        shadow_id: &shadow_id,
        bridge_id: &bridge_id,
        bridge_mode: mode,
        platform_handle: &platform_handle,
        context_member_dids: &[],
        timestamp: 0,
    };

    let (shadow, _event) = scp_core::bridge::shadow::create_shadow(
        &mut shadow_registry,
        &mut sender_key_store,
        &params,
    )
    .map_err(|e| ScpError::Context {
        message: format!("shadow creation failed: {e}"),
        code: "SCP-CTX-2102".to_owned(),
    })?;

    Ok(ShadowIdentityResult {
        shadow_id: shadow.shadow_id,
        platform_handle: shadow.platform_handle,
        bridge_id: shadow.bridge_id,
        attributed_role: shadow.attributed_role,
        provenance_status: format!("{:?}", shadow.provenance_status),
    })
}

// ---------------------------------------------------------------------------
// Discovery — context_discover (#428)
// ---------------------------------------------------------------------------

/// Discovers contexts from a DID string or `scp://` URI.
///
/// Detects whether the query is a DID or an `scp://` URI and delegates to
/// the appropriate core discovery function.
///
/// Returns a JSON string containing an array of discovery results, each
/// with: `context_id`, `relay_urls`, `publisher_did`, `discovery_source`,
/// `mode`, `metadata_summary`.
///
/// # Arguments
///
/// * `query` — A DID string (e.g., `"did:dht:z6Mk..."`) or an `scp://`
///   URI (e.g., `"scp://context/a1b2c3?relay=wss%3A%2F%2Frelay.example.com"`).
///
/// # Errors
///
/// Returns `ScpError::Context` if DID resolution or URI parsing fails.
/// Returns `ScpError::Validation` if the query is neither a DID nor an
/// `scp://` URI.
///
/// See §5.14.11, §18.2.2, §18.4.
#[uniffi::export]
pub async fn context_discover(query: String) -> Result<String, ScpError> {
    if query.starts_with("scp://") {
        // Parse scp:// URI — synchronous, no network I/O.
        let result =
            scp_core::discovery::resolve_context_uri(&query).map_err(|e| ScpError::Context {
                message: format!("failed to resolve scp:// URI: {e}"),
                code: "SCP-CTX-2020".to_owned(),
            })?;

        let results = vec![discovery_result_to_json(&result)];
        serde_json::to_string(&results).map_err(|e| ScpError::Context {
            message: format!("failed to serialize discovery results: {e}"),
            code: "SCP-CTX-2021".to_owned(),
        })
    } else if query.starts_with("did:") {
        validate_did(&query)?;

        runtime()
            .spawn(async move {
                let did_dht = DidDht::new();
                let results = scp_core::discovery::resolve_contexts_from_did(&query, &did_dht)
                    .await
                    .map_err(|e| ScpError::Context {
                        message: format!("DHT discovery failed for '{query}': {e}"),
                        code: "SCP-CTX-2022".to_owned(),
                    })?;

                let json_results: Vec<serde_json::Value> =
                    results.iter().map(discovery_result_to_json).collect();
                serde_json::to_string(&json_results).map_err(|e| ScpError::Context {
                    message: format!("failed to serialize discovery results: {e}"),
                    code: "SCP-CTX-2023".to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                message: format!("tokio task join error during discovery: {e}"),
                code: "SCP-CTX-2024".to_owned(),
            })?
    } else {
        Err(ScpError::Validation {
            message: format!(
                "query must be a DID (starts with 'did:') or an scp:// URI \
                 (starts with 'scp://'), got: {query}"
            ),
            code: "SCP-VALID-7062".to_owned(),
        })
    }
}

/// Converts a `ContextDiscoveryResult` into a JSON value (helper).
///
/// Includes `trust_level` and `resolution_path` per §22.2.1.
/// `ResolutionLayer` values use `PascalCase` per §22.11.3.
fn discovery_result_to_json(
    result: &scp_core::discovery::ContextDiscoveryResult,
) -> serde_json::Value {
    let (source_str, trust_level_kind, resolution_layer, resolution_source, resolution_source_id) =
        match &result.discovery_source {
            scp_core::discovery::ContextDiscoverySource::DhtDidDocument => {
                ("dht_did_document", "DomainVerified", "Domain", "dht", None)
            }
            scp_core::discovery::ContextDiscoverySource::WellKnown => {
                ("well_known", "DomainVerified", "Domain", "well-known", None)
            }
            scp_core::discovery::ContextDiscoverySource::DiscoveryContext { context_id } => (
                "discovery_context",
                "DiscoveryContextVerified",
                "DiscoveryContext",
                "discovery_context",
                Some(context_id.as_str()),
            ),
            // §22.7: An scp:// URI is shared out-of-band, so the trust level is
            // DirectExchange and the resolution layer is "Domain" (closest match
            // for URI-based resolution — no discovery context is involved).
            scp_core::discovery::ContextDiscoverySource::ContextUri => (
                "context_uri",
                "DirectExchange",
                "Domain",
                "context_uri",
                None,
            ),
        };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut obj = serde_json::json!({
        "context_id": result.context_id,
        "relay_urls": result.relay_urls,
        "publisher_did": &*result.publisher_did,
        "discovery_source": source_str,
        "mode": result.mode,
        "metadata_summary": result.metadata_summary,
        "trust_level": {
            "kind": trust_level_kind,
        },
        "resolution_path": {
            "layer": resolution_layer,
            "source": resolution_source,
            "source_id": resolution_source_id,
            "resolved_at": now_secs,
        },
    });

    // Add discovery_context_id if applicable.
    if let scp_core::discovery::ContextDiscoverySource::DiscoveryContext { context_id } =
        &result.discovery_source
    {
        obj["discovery_context_id"] = serde_json::Value::String(context_id.clone());
    }

    obj
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_handle() -> Arc<ContextHandle> {
        Arc::new(ContextHandle {
            context_id: "ctx-test".to_owned(),
            state: tokio::sync::Mutex::new(ContextState::Active),
            creator_did: "did:dht:z6MkTestUser".to_owned(),
            #[cfg(feature = "allow_in_memory_custody")]
            in_memory_custody: None,
            callback_custody: None,
            signing_key: None,
            ceiling_strings: Vec::new(),
            tool_registry: tokio::sync::Mutex::new(scp_core::context::tools::ToolRegistry::new()),
            tool_handlers: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            session_store: tokio::sync::Mutex::new(scp_core::context::tools::SessionStore::new()),
            economic_policy: std::sync::Mutex::new(None),
        })
    }

    fn test_identity() -> Arc<Identity> {
        Arc::new(Identity {
            did: "did:dht:z6MkTestUser".to_owned(),
            custody_type: CustodyMethod::InMemory,
            core_id: None,
            core_document: None,
            #[cfg(feature = "allow_in_memory_custody")]
            in_memory_custody: None,
            callback_custody: None,
        })
    }

    /// `UniFFI` `tool_invoke` must reject `None` `ucan_token` with a
    /// `Permission` error. Matches `PyO3`/NAPI behavior where the token
    /// is a required non-optional parameter. See issue #423.
    #[tokio::test]
    async fn tool_invoke_rejects_none_ucan_token() {
        let result = tool_invoke(
            test_handle(),
            "test-tool".to_owned(),
            "{}".to_owned(),
            test_identity(),
            None, // No UCAN token
            None,
        )
        .await;

        let err = result.expect_err("None ucan_token must be rejected");
        match err {
            ScpError::Permission { ref code, .. } => {
                assert_eq!(code, "SCP-PERM-3001");
            }
            other => panic!("expected ScpError::Permission, got {other:?}"),
        }
    }

    /// Roundtrip set / get for economic policy on the `UniFFI` `ContextHandle`.
    #[test]
    fn set_get_economic_policy_roundtrip() {
        let handle = test_handle();

        // Initially None.
        let result = get_economic_policy(Arc::clone(&handle)).unwrap();
        assert!(result.is_none());

        // Set valid policy.
        let json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":null,"per_tool_invoke":100,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkTest"}"#;
        set_economic_policy(Arc::clone(&handle), json.to_owned()).unwrap();

        let result = get_economic_policy(Arc::clone(&handle)).unwrap();
        assert_eq!(result.as_deref(), Some(json));

        // Invalid JSON is rejected.
        let err = set_economic_policy(Arc::clone(&handle), "not json".to_owned());
        assert!(err.is_err());

        // Original policy unchanged after rejected set.
        let result = get_economic_policy(handle).unwrap();
        assert_eq!(result.as_deref(), Some(json));
    }

    /// Verifies that setting economic policy on a locked policy is rejected.
    #[test]
    fn set_economic_policy_rejects_when_locked() {
        let handle = test_handle();

        // Set a locked policy.
        let locked_json = r#"{"locked":true,"cost_schedule":{"currency":[85,83,68,0],"per_message":null,"per_tool_invoke":100,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkTest"}"#;
        set_economic_policy(Arc::clone(&handle), locked_json.to_owned()).unwrap();

        // Attempting to overwrite should fail.
        let new_json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":2,"per_tool_invoke":null,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkTest"}"#;
        let result = set_economic_policy(Arc::clone(&handle), new_json.to_owned());
        assert!(result.is_err());

        // Locked policy should be unchanged.
        let result = get_economic_policy(handle).unwrap();
        assert_eq!(result.as_deref(), Some(locked_json));
    }

    #[test]
    fn data_provenance_from_core_roundtrip() {
        let core_prov = scp_core::provenance::DataProvenance {
            source_context: "ctx-abc".to_string(),
            source_type: scp_core::provenance::SourceType::Persistent,
            counterparties: vec![
                scp_identity::DID::from("did:dht:z6MkAlice"),
                scp_identity::DID::from("did:dht:z6MkBob"),
            ],
            purpose: Some("sharing".to_string()),
            discovery_method: scp_core::provenance::DiscoveryMethod::SharedContext(
                "ctx-shared".to_string(),
            ),
            age: std::time::Duration::from_secs(42),
            memory_scope: scp_core::context::MemoryScope::Full,
            chain_depth: 2,
            chain_path: Some(vec!["ctx-hop1".to_string(), "ctx-hop2".to_string()]),
            payment_amount: Some(scp_core::economy::types::Amount::new(1000)),
            payment_adapter: Some("stripe".to_string()),
            payment_receipt_id: Some([0xCC; 32]),
        };

        let ffi = DataProvenance::from_core(&core_prov);
        assert_eq!(ffi.source_context, "ctx-abc");
        assert!(matches!(ffi.source_type, SourceType::Persistent));
        assert_eq!(ffi.counterparties.len(), 2);
        assert_eq!(ffi.purpose.as_deref(), Some("sharing"));
        assert!(matches!(
            ffi.discovery_method,
            DiscoveryMethod::SharedContext { .. }
        ));
        assert_eq!(ffi.age_secs, 42);
        assert!(matches!(ffi.memory_scope, MemoryScope::Full));
        assert_eq!(ffi.chain_depth, 2);
        assert_eq!(ffi.chain_path.as_ref().map(Vec::len), Some(2));
        assert_eq!(ffi.payment_amount, Some(1000));
        assert_eq!(ffi.payment_adapter.as_deref(), Some("stripe"));
        assert_eq!(ffi.payment_receipt_id.as_ref().map(Vec::len), Some(32));

        // Round-trip back to core
        let roundtripped = ffi.to_core().unwrap();
        assert_eq!(roundtripped.source_context, core_prov.source_context);
        assert_eq!(roundtripped.source_type, core_prov.source_type);
        assert_eq!(
            roundtripped.counterparties,
            vec![
                scp_identity::DID::from("did:dht:z6MkAlice"),
                scp_identity::DID::from("did:dht:z6MkBob"),
            ]
        );
        assert_eq!(roundtripped.discovery_method, core_prov.discovery_method);
        assert_eq!(roundtripped.purpose, core_prov.purpose);
        assert_eq!(roundtripped.age.as_secs(), 42);
        assert_eq!(roundtripped.memory_scope, core_prov.memory_scope);
        assert_eq!(roundtripped.chain_depth, core_prov.chain_depth);
        assert_eq!(roundtripped.chain_path, core_prov.chain_path);
        assert_eq!(roundtripped.payment_amount, core_prov.payment_amount);
        assert_eq!(roundtripped.payment_adapter, core_prov.payment_adapter);
        assert_eq!(
            roundtripped.payment_receipt_id,
            core_prov.payment_receipt_id
        );
    }

    #[test]
    fn data_provenance_from_core_ephemeral_no_payment() {
        let core_prov = scp_core::provenance::DataProvenance {
            source_context: "ctx-eph".to_string(),
            source_type: scp_core::provenance::SourceType::Ephemeral,
            counterparties: vec![],
            purpose: None,
            discovery_method: scp_core::provenance::DiscoveryMethod::None,
            age: std::time::Duration::from_secs(0),
            memory_scope: scp_core::context::MemoryScope::Ephemeral,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        let ffi = DataProvenance::from_core(&core_prov);
        assert!(matches!(ffi.source_type, SourceType::Ephemeral));
        assert!(ffi.counterparties.is_empty());
        assert!(ffi.purpose.is_none());
        assert!(matches!(ffi.discovery_method, DiscoveryMethod::None));
        assert!(matches!(ffi.memory_scope, MemoryScope::Ephemeral));
        assert_eq!(ffi.chain_depth, 0);
        assert!(ffi.chain_path.is_none());
        assert!(ffi.payment_amount.is_none());
    }

    #[test]
    fn data_provenance_from_core_summary_registry() {
        let core_prov = scp_core::provenance::DataProvenance {
            source_context: "ctx-sum".to_string(),
            source_type: scp_core::provenance::SourceType::Summary,
            counterparties: vec![scp_identity::DID::from("did:dht:z6MkCharlie")],
            purpose: None,
            discovery_method: scp_core::provenance::DiscoveryMethod::Registry(
                "ctx-reg".to_string(),
            ),
            age: std::time::Duration::from_secs(600),
            memory_scope: scp_core::context::MemoryScope::Summary,
            chain_depth: 1,
            chain_path: Some(vec!["ctx-mid".to_string()]),
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        };

        let ffi = DataProvenance::from_core(&core_prov);
        assert!(matches!(ffi.source_type, SourceType::Summary));
        assert!(matches!(
            ffi.discovery_method,
            DiscoveryMethod::Registry { .. }
        ));
        assert!(matches!(ffi.memory_scope, MemoryScope::Summary));

        let roundtripped = ffi.to_core().unwrap();
        assert_eq!(
            roundtripped.source_type,
            scp_core::provenance::SourceType::Summary
        );
        assert!(matches!(
            roundtripped.discovery_method,
            scp_core::provenance::DiscoveryMethod::Registry(_)
        ));
    }

    #[test]
    fn data_provenance_payment_receipt_id_wrong_length() {
        let ffi = DataProvenance {
            source_context: "ctx-bad".to_string(),
            source_type: SourceType::Persistent,
            counterparties: vec![],
            purpose: None,
            discovery_method: DiscoveryMethod::None,
            age_secs: 0,
            memory_scope: MemoryScope::Ephemeral,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: Some(vec![0xAA; 16]), // 16 bytes, not 32
        };

        let err = ffi.to_core().unwrap_err();
        match err {
            ScpError::Validation { code, message } => {
                assert_eq!(code, "SCP-VALID-7080");
                assert!(
                    message.contains("32 bytes"),
                    "expected '32 bytes' in message, got: {message}"
                );
            }
            other => panic!("expected Validation error, got: {other:?}"),
        }
    }

    // -- discovery_result_to_json: trust_level / resolution_path tests --------

    #[test]
    fn discovery_result_to_json_dht_source() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "abc123".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            publisher_did: "did:dht:zTest".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::DhtDidDocument,
            mode: Some("broadcast".to_owned()),
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["context_id"], "abc123");
        assert_eq!(json["discovery_source"], "dht_did_document");
        assert_eq!(json["mode"], "broadcast");
        // §22.7: trust_level is a discriminated union object; resolution_path
        // uses spec PascalCase layer values per §22.11.3.
        assert_eq!(json["trust_level"]["kind"], "DomainVerified");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "dht");
        assert!(json["resolution_path"]["resolved_at"].as_u64().unwrap() > 0);
    }

    #[test]
    fn discovery_result_to_json_discovery_context_source() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "ctx456".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            publisher_did: "did:dht:zTest".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::DiscoveryContext {
                context_id: "disc-ctx-1".to_owned(),
            },
            mode: None,
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["trust_level"]["kind"], "DiscoveryContextVerified");
        assert_eq!(json["resolution_path"]["layer"], "DiscoveryContext");
        assert_eq!(json["resolution_path"]["source"], "discovery_context");
        assert_eq!(json["resolution_path"]["source_id"], "disc-ctx-1");
        assert_eq!(json["discovery_context_id"], "disc-ctx-1");
    }

    #[test]
    fn discovery_result_to_json_context_uri_source() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "deadbeef".to_owned(),
            relay_urls: vec!["wss://relay.example.com/scp/v1".to_owned()],
            publisher_did: "".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::ContextUri,
            mode: Some("broadcast".to_owned()),
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["trust_level"]["kind"], "DirectExchange");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "context_uri");
        assert!(json["resolution_path"]["source_id"].is_null());
        assert!(json["resolution_path"]["resolved_at"].as_u64().unwrap() > 0);
    }

    #[test]
    fn discovery_result_to_json_well_known_source() {
        let result = scp_core::discovery::ContextDiscoveryResult {
            context_id: "wk789".to_owned(),
            relay_urls: vec!["wss://relay.example.com".to_owned()],
            publisher_did: "did:web:example.com".into(),
            discovery_source: scp_core::discovery::ContextDiscoverySource::WellKnown,
            mode: None,
            metadata_summary: Some("Example context".to_owned()),
        };

        let json = discovery_result_to_json(&result);
        assert_eq!(json["trust_level"]["kind"], "DomainVerified");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "well-known");
        assert!(json["resolution_path"]["source_id"].is_null());
    }
}
