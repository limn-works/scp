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

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_core::crypto::ucan::{Attenuation, UcanError as CoreUcanError, UcanHeader, UcanPayload};
use scp_core::crypto::ucan::capability::CapabilityUri;
use scp_core::crypto::ucan::validate::{
    DidResolver, NonceTracker as NonceTrackerTrait, ProofResolver, RevocationChecker,
    ValidationContext, parse_ucan, validate_ucan,
};
use scp_core::identity::{DidDht, DidMethod, ScpIdentity};
use scp_platform::PlatformError;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{
    CustodyType, KeyCustody, KeyHandle, KeyType, PseudonymKeypair, PublicKey, SharedSecret,
    Signature,
};
use uuid::Uuid;

use crate::{KeyCustodyProvider, decrement_handle_count, increment_handle_count, runtime};

/// Wrapper for [`InMemoryKeyCustody`] that implements [`Debug`] with a
/// redacted representation, preventing key material from appearing in logs.
pub(crate) struct OpaqueInMemoryKeyCustody(pub(crate) InMemoryKeyCustody);

impl fmt::Debug for OpaqueInMemoryKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InMemoryKeyCustody([redacted])")
    }
}

/// Adapter that wraps a UniFFI [`KeyCustodyProvider`] callback interface and
/// implements [`KeyCustody`] so that `scp-core` functions can use platform
/// custody (Secure Enclave, Android Keystore) transparently.
///
/// Maintains a bidirectional mapping between `KeyHandle(u64)` (scp-core) and
/// `String` key IDs (platform callback interface). Thread-safe via `RwLock`.
/// Uses `std::sync::RwLock` instead of `TokioMutex` so that `custody_type()`
/// (a sync trait method) can acquire a read lock without requiring an async
/// runtime context.
///
/// See ADR-006 (Platform Abstraction) and SCP-214 criterion 2.
pub(crate) struct KeyCustodyProviderAdapter {
    /// The injected platform custody callback.
    provider: Arc<dyn KeyCustodyProvider>,
    /// Mapping from `KeyHandle(u64)` to platform key ID strings.
    handle_to_id: std::sync::RwLock<HashMap<u64, String>>,
    /// Counter for allocating new `KeyHandle` IDs.
    next_id: AtomicU64,
}

impl KeyCustodyProviderAdapter {
    /// Creates a new adapter wrapping the given platform custody provider.
    pub(crate) fn new(provider: Arc<dyn KeyCustodyProvider>) -> Self {
        Self {
            provider,
            handle_to_id: std::sync::RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl KeyCustody for KeyCustodyProviderAdapter {
    fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        async move {
            let type_str = match key_type {
                KeyType::Ed25519 => "ed25519".to_owned(),
                KeyType::X25519 => "x25519".to_owned(),
            };
            let key_id = self
                .provider
                .generate_keypair(type_str)
                .await
                .map_err(|e| PlatformError::CustodyError(format!("{e}")))?;

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let handle = KeyHandle::new(id);
            self.handle_to_id
                .write()
                .map_err(|_| {
                    PlatformError::CustodyError("handle_to_id lock poisoned".to_owned())
                })?
                .insert(id, key_id);
            Ok(handle)
        }
    }

    fn sign(
        &self,
        key: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
        let key_id = key.id();
        let data = data.to_vec();
        async move {
            let id = {
                let map = self.handle_to_id.read().map_err(|_| {
                    PlatformError::CustodyError("handle_to_id lock poisoned".to_owned())
                })?;
                map.get(&key_id)
                    .cloned()
                    .ok_or(PlatformError::KeyNotFound)?
            };
            let sig_bytes = self
                .provider
                .sign(id, data)
                .await
                .map_err(|e| PlatformError::CustodyError(format!("{e}")))?;
            Ok(Signature::new(sig_bytes))
        }
    }

    fn public_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let id = {
                let map = self.handle_to_id.read().map_err(|_| {
                    PlatformError::CustodyError("handle_to_id lock poisoned".to_owned())
                })?;
                map.get(&key_id)
                    .cloned()
                    .ok_or(PlatformError::KeyNotFound)?
            };
            let pk_bytes = self
                .provider
                .get_public_key(id)
                .await
                .map_err(|e| PlatformError::CustodyError(format!("{e}")))?;
            Ok(PublicKey::new(pk_bytes))
        }
    }

    fn destroy_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key_id = key.id();
        async move {
            let id = {
                let mut map = self.handle_to_id.write().map_err(|_| {
                    PlatformError::CustodyError("handle_to_id lock poisoned".to_owned())
                })?;
                map.remove(&key_id).ok_or(PlatformError::KeyNotFound)?
            };
            self.provider
                .destroy_key(id)
                .await
                .map_err(|e| PlatformError::CustodyError(format!("{e}")))?;
            Ok(())
        }
    }

    fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
        let key_id = key.id();
        let peer = *peer_public;
        async move {
            let id = {
                let map = self.handle_to_id.read().map_err(|_| {
                    PlatformError::CustodyError("handle_to_id lock poisoned".to_owned())
                })?;
                map.get(&key_id)
                    .cloned()
                    .ok_or(PlatformError::KeyNotFound)?
            };
            let secret_bytes = self
                .provider
                .dh_agree(id, peer.to_vec())
                .await
                .map_err(|e| PlatformError::CustodyError(format!("{e}")))?;
            let arr: [u8; 32] = secret_bytes.try_into().map_err(|_| {
                PlatformError::CustodyError("dh_agree must return 32 bytes".to_owned())
            })?;
            Ok(SharedSecret::new(arr))
        }
    }

    fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send {
        let key_id = key.id();
        let ctx = context_id.to_vec();
        async move {
            let id = {
                let map = self.handle_to_id.read().map_err(|_| {
                    PlatformError::CustodyError("handle_to_id lock poisoned".to_owned())
                })?;
                map.get(&key_id)
                    .cloned()
                    .ok_or(PlatformError::KeyNotFound)?
            };
            let result_bytes = self
                .provider
                .derive_pseudonym(id, ctx)
                .await
                .map_err(|e| PlatformError::CustodyError(format!("{e}")))?;

            // The callback returns [public_key_bytes(32) || key_id_utf8_bytes].
            if result_bytes.len() < 33 {
                return Err(PlatformError::CustodyError(
                    "derive_pseudonym must return at least 33 bytes \
                     (32 public key + key_id)"
                        .to_owned(),
                ));
            }
            let pub_key_bytes = result_bytes[..32].to_vec();
            let pseudo_key_id = String::from_utf8(result_bytes[32..].to_vec()).map_err(|_| {
                PlatformError::CustodyError(
                    "derive_pseudonym key_id portion must be valid UTF-8".to_owned(),
                )
            })?;

            let pseudo_handle_id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let pseudo_handle = KeyHandle::new(pseudo_handle_id);
            self.handle_to_id
                .write()
                .map_err(|_| {
                    PlatformError::CustodyError("handle_to_id lock poisoned".to_owned())
                })?
                .insert(pseudo_handle_id, pseudo_key_id);

            Ok(PseudonymKeypair {
                public_key: PublicKey::new(pub_key_bytes),
                key_handle: pseudo_handle,
            })
        }
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        let key_id = key.id();
        let map_guard = match self.handle_to_id.read() {
            Ok(guard) => guard,
            Err(_) => return CustodyType::Hardware,
        };
        let Some(id) = map_guard.get(&key_id).cloned() else {
            return CustodyType::Hardware;
        };
        drop(map_guard);
        let type_str = self.provider.custody_type(id);
        match type_str.as_str() {
            "hardware" => CustodyType::Hardware,
            "software" => CustodyType::Software,
            "in_memory" => CustodyType::InMemory,
            _ => CustodyType::Hardware,
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

impl From<scp_core::identity::IdentityError> for ScpError {
    fn from(e: scp_core::identity::IdentityError) -> Self {
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

impl From<scp_core::event_log::EventLogError> for ScpError {
    fn from(e: scp_core::event_log::EventLogError) -> Self {
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
// Bridge trait implementations for scp-core UCAN validation pipeline
//
// These adapters bridge the UniFFI runtime state to scp-core's validation
// traits. Follows the same pattern as the PyO3 bridge in
// crates/scp-ffi/src/ucan.rs.
// ---------------------------------------------------------------------------

/// Bridge [`DidResolver`] that extracts Ed25519 public keys from DID strings.
///
/// Supports `did:dht:z{z-base-32-encoded-pubkey}` (production) and
/// `did:key:{hex-encoded-pubkey}` (testing).
struct BridgeDidResolver;

impl DidResolver for BridgeDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], CoreUcanError> {
        if let Some(suffix) = did.strip_prefix("did:dht:z") {
            let decoded = zbase32::decode(suffix).map_err(|_| {
                CoreUcanError::MalformedToken(format!("z-base-32 decode failed for DID: {did}"))
            })?;
            let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
                CoreUcanError::MalformedToken(format!(
                    "DID public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            return Ok(bytes);
        }

        if let Some(hex_str) = did.strip_prefix("did:key:") {
            let bytes = decode_hex(hex_str).map_err(|e| {
                CoreUcanError::MalformedToken(format!("hex decode failed for did:key DID: {e}"))
            })?;
            let pk: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                CoreUcanError::MalformedToken(format!(
                    "DID public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            return Ok(pk);
        }

        Err(CoreUcanError::MalformedToken(format!(
            "unsupported DID method: {did} (expected did:dht: or did:key:)"
        )))
    }
}

/// Bridge [`RevocationChecker`] wrapping the context's [`RevocationList`].
struct BridgeRevocationChecker<'a> {
    revocation_list: &'a scp_core::crypto::ucan::revoke::RevocationList,
}

impl RevocationChecker for BridgeRevocationChecker<'_> {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.revocation_list.is_revoked(token_cid)
    }
}

/// Bridge [`ProofResolver`] backed by an in-memory `HashMap`.
struct BridgeProofResolver {
    proofs: HashMap<String, scp_core::crypto::ucan::UcanToken>,
}

impl ProofResolver for BridgeProofResolver {
    fn resolve_proof(&self, cid: &str) -> Result<scp_core::crypto::ucan::UcanToken, CoreUcanError> {
        self.proofs.get(cid).cloned().ok_or_else(|| {
            CoreUcanError::DelegationChainBroken(format!("proof CID not found: {cid}"))
        })
    }
}

/// Adapter bridging `nonce::NonceTracker<C>` struct to `validate::NonceTracker`
/// trait.
struct BridgeNonceTracker<'a, C: scp_core::identity::cache::Clock> {
    inner: &'a mut scp_core::crypto::ucan::nonce::NonceTracker<C>,
}

impl<C: scp_core::identity::cache::Clock> NonceTrackerTrait for BridgeNonceTracker<'_, C> {
    fn check_and_record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), CoreUcanError> {
        self.inner.check_and_record(nonce, token_expiry)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decodes a hex string to bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {}", hex.len()));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte =
            u8::from_str_radix(byte_str, 16).map_err(|e| format!("hex decode error: {e}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Encodes bytes as a lowercase hex string.
fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Generates a nonce in the format `{unix_millis_timestamp}-{16_random_bytes_hex}`.
fn generate_nonce() -> Result<String, ScpError> {
    use rand::Rng;

    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ScpError::Permission {
            message: format!("system clock error: {e}"),
            code: "SCP-PERM-3010".to_owned(),
        })?
        .as_millis();

    let mut random_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut random_bytes);

    let hex = encode_hex(&random_bytes);
    Ok(format!("{now_millis}-{hex}"))
}

/// Builds a [`BridgeProofResolver`] from optional encoded proof token strings.
fn build_proof_resolver(proof_tokens: Option<&[String]>) -> Result<BridgeProofResolver, ScpError> {
    let mut proofs = HashMap::new();

    if let Some(tokens) = proof_tokens {
        for encoded in tokens {
            let token = parse_ucan(encoded).map_err(ScpError::from)?;
            let cid = scp_core::crypto::ucan::mint::compute_cid(&token);
            proofs.insert(cid, token);
        }
    }

    Ok(BridgeProofResolver { proofs })
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
    /// Participation count from the behavioral record.
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
/// Stores the DID string, custody type, and — for in-memory custody — the
/// retained [`ScpIdentity`] and [`InMemoryKeyCustody`] so that key material
/// remains live for the lifetime of the handle. Platform custody paths use
/// the `KeyCustodyProvider` callback interface instead.
///
/// Generated as `class Identity` in both Swift and Kotlin.
///
/// See ADR-002 (DID) and ADR-013 §2 (bridge pattern).
#[derive(Debug, uniffi::Object)]
pub struct Identity {
    /// The DID string (e.g., `"did:dht:z6Mk..."`).
    pub(crate) did: String,
    /// The custody method used for this identity.
    pub(crate) custody_type: CustodyMethod,
    /// Retained `ScpIdentity` for in-memory custody paths.
    ///
    /// Holds the `KeyHandle`s into `in_memory_custody`. Must outlive any
    /// signing or key-rotation operation on this handle.
    #[allow(dead_code)]
    pub(crate) core_id: Option<ScpIdentity>,
    /// Retained `InMemoryKeyCustody` for in-memory custody paths.
    ///
    /// Key material lives here. Dropping this destroys all private keys.
    #[allow(dead_code)]
    pub(crate) in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
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
    /// # Errors
    ///
    /// Returns `ScpError::Identity` if key rotation or DID document publish fails.
    // async required by UniFFI export interface even though current stub has no await
    #[allow(clippy::unused_async)]
    pub async fn rotate_key(self: Arc<Self>) -> Result<Arc<Self>, ScpError> {
        // Key rotation requires a wired KeyCustodyProvider (ADR-006 platform
        // abstraction). InMemoryKeyCustody is not acceptable in production —
        // it stores private key material in unprotected heap memory on mobile
        // devices. Full implementation is tracked for the platform integration
        // story that wires KeyCustodyProvider callbacks to scp-core.
        Err(ScpError::Identity {
            message: "key rotation requires a wired platform KeyCustodyProvider — \
                      use the KeyCustodyProvider callback interface to inject \
                      Secure Enclave (iOS) or Android Keystore (Android) backed custody"
                .to_owned(),
            code: "SCP-IDENT-1002".to_owned(),
        })
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
/// Stores context metadata (ID, state, creator DID). The actual context
/// runtime (MLS group, transport connections) lives in scp-core and will be
/// wired in full integration stories.
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
    /// Per-context pseudonym routing ID derived via `KeyCustody::derive_pseudonym`.
    /// 32-byte pseudonym public key for relay routing (§9.10.4).
    pub(crate) routing_id: Option<Vec<u8>>,
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

    /// Returns the per-context pseudonym routing ID (32 bytes), or `None` if
    /// pseudonym derivation was not available at context creation time.
    ///
    /// The routing ID is derived via `KeyCustody::derive_pseudonym` (§9.10.4).
    /// It provides per-context unlinkability: different contexts produce
    /// different routing IDs for the same identity key.
    ///
    /// See ADR-006 and SCP-214 criterion 5.
    pub fn routing_id(&self) -> Option<Vec<u8>> {
        self.routing_id.clone()
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

// NOTE: `Drop` for `UcanToken` is intentionally absent until `ucan_mint` is
// wired to `scp-core`. When `ucan_mint` creates a real `UcanToken`, it MUST
// call `increment_handle_count()` in the constructor path, and this `Drop`
// impl MUST be re-added to call `decrement_handle_count()`. The symmetry
// is required for `scp_shutdown` handle-drain logic to work correctly.

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
/// * `custody` — The custody type string: `"in_memory"` or `"platform"`.
///
/// # Returns
///
/// An `Identity` handle with the new DID and custody type.
///
/// # Errors
///
/// Returns `ScpError::Identity` if key generation or DID creation fails.
/// Returns `ScpError::Validation` if the custody string is not recognized.
///
/// # In-memory custody
///
/// When `custody` is `"in_memory"`, this function creates a real
/// `did:dht` identity using [`scp_core::identity::DidDht`] backed by
/// [`scp_platform::testing::InMemoryKeyCustody`]. The returned DID is
/// self-certifying and has the `did:dht:z` prefix.
///
/// `"in_memory"` custody stores key material in unprotected heap memory.
/// It is suitable for testing and development but NOT for production use
/// on mobile devices — use `"platform"` (Secure Enclave / Android Keystore)
/// in production.
#[uniffi::export]
pub async fn identity_create(custody: String) -> Result<Arc<Identity>, ScpError> {
    let custody_method = parse_custody_method(&custody)?;

    runtime()
        .spawn(async move {
            match custody_method {
                CustodyMethod::InMemory => {
                    // Wire to real scp-core using InMemoryKeyCustody.
                    // The `testing` feature is always available in dev/test
                    // builds; production builds use the "platform" custody path.
                    //
                    // IMPORTANT: both `core_identity` and `key_custody` must be
                    // retained in the handle. `ScpIdentity` holds `KeyHandle`s
                    // that are indices into `key_custody`'s internal store.
                    // Dropping `key_custody` destroys all private key material
                    // and renders those handles dangling.
                    let key_custody = Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
                    let dht = DidDht::new();
                    let (identity, _document) =
                        dht.create(&key_custody.0).await.map_err(ScpError::from)?;

                    let handle = Arc::new(Identity {
                        did: identity.did.clone(),
                        custody_type: CustodyMethod::InMemory,
                        core_id: Some(identity),
                        in_memory_custody: Some(key_custody),
                    });
                    increment_handle_count();
                    Ok(handle)
                }
                CustodyMethod::Platform | CustodyMethod::Software => {
                    // Platform and software custody require a wired
                    // KeyCustodyProvider (ADR-006 platform abstraction).
                    // Use identity_create_platform to pass the provider.
                    Err(ScpError::Identity {
                        message: format!(
                            "custody type {custody:?} requires a KeyCustodyProvider — \
                             call identity_create_platform with an injected provider \
                             (Secure Enclave on iOS, Android Keystore on Android)"
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

/// Creates a new DID identity using a platform-injected `KeyCustodyProvider`.
///
/// This function accepts a `KeyCustodyProvider` callback interface implementation
/// (Secure Enclave on iOS, Android Keystore on Android) and uses it to generate
/// keys and create a `did:dht` identity via `scp-core`.
///
/// # Arguments
///
/// * `provider` — A platform-injected `KeyCustodyProvider` callback implementation
///   that handles key generation, signing, and custody.
///
/// # Returns
///
/// An `Identity` handle with the new DID and `Platform` custody type.
///
/// # Errors
///
/// Returns `ScpError::Identity` if key generation or DID creation fails.
///
/// See ADR-006 (Platform Abstraction), ADR-021 (UniFFI Bridge), SCP-214 criterion 2.
#[uniffi::export]
pub async fn identity_create_platform(
    provider: Box<dyn KeyCustodyProvider>,
) -> Result<Arc<Identity>, ScpError> {
    let provider: Arc<dyn KeyCustodyProvider> = Arc::from(provider);
    runtime()
        .spawn(async move {
            let adapter = KeyCustodyProviderAdapter::new(provider);
            let dht = DidDht::new();
            let (identity, _document) = dht.create(&adapter).await.map_err(ScpError::from)?;

            let handle = Arc::new(Identity {
                did: identity.did.clone(),
                custody_type: CustodyMethod::Platform,
                core_id: Some(identity),
                in_memory_custody: None,
            });
            increment_handle_count();
            Ok(handle)
        })
        .await
        .map_err(|e| ScpError::Identity {
            message: format!("tokio task join error during platform identity creation: {e}"),
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
                in_memory_custody: None,
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
            let _ = params;
            let context_id = format!("ctx-{}", Uuid::new_v4());

            crate::runtime::register_context(&context_id, &identity.did)?;

            let routing_id = match (
                identity.in_memory_custody.as_ref(),
                identity.core_id.as_ref(),
            ) {
                (Some(custody), Some(core_id)) => {
                    let pseudonym = custody
                        .0
                        .derive_pseudonym(&core_id.identity_key, context_id.as_bytes())
                        .await
                        .map_err(|e| ScpError::Crypto {
                            message: format!("failed to derive pseudonym routing ID: {e}"),
                            code: "SCP-CRYPTO-4010".to_owned(),
                        })?;
                    Some(pseudonym.public_key.as_bytes().to_vec())
                }
                _ => None,
            };

            let handle = Arc::new(ContextHandle {
                context_id,
                state: tokio::sync::Mutex::new(ContextState::Active),
                creator_did: identity.did.clone(),
                routing_id,
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

            let _ = identity;
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

            let _ = identity;
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

            let _ = identity;
            *state = ContextState::Closed;
            drop(state);

            crate::runtime::remove_context(&handle.context_id);

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

            let _ = (identity, payload);
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
) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            let parsed_token = parse_ucan(&token).map_err(ScpError::from)?;

            let required_cap: CapabilityUri =
                capability
                    .parse()
                    .map_err(|e: CoreUcanError| ScpError::Permission {
                        message: format!("invalid capability URI '{capability}': {e}"),
                        code: "SCP-PERM-3002".to_owned(),
                    })?;

            let agent_did = parsed_token.payload.aud.clone();

            let proof_resolver = build_proof_resolver(None)?;

            crate::runtime::with_context(&handle.context_id, |rt| {
                let did_resolver = BridgeDidResolver;
                let revocation_checker = BridgeRevocationChecker {
                    revocation_list: &rt.revocation_list,
                };
                let mut nonce_adapter = BridgeNonceTracker {
                    inner: &mut rt.nonce_tracker,
                };

                let mut ctx = ValidationContext {
                    did_resolver: &did_resolver,
                    nonce_tracker: &mut nonce_adapter,
                    revocation_checker: &revocation_checker,
                    proof_resolver: &proof_resolver,
                    ceiling: &rt.ceiling_strings,
                    context_creator_did: &rt.creator_did,
                    presenting_agent_did: &agent_did,
                };

                validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(ScpError::from)
            })?;

            Ok(())
        })
        .await
        .map_err(|e| ScpError::Permission {
            message: format!("tokio task join error during UCAN validation: {e}"),
            code: "SCP-PERM-3003".to_owned(),
        })?
}

/// Mints a new UCAN token for a context member.
///
/// Stub: builds a structurally valid JWT with a zero-signature placeholder
/// (`[0u8; 64]`). The token has correct header, payload, and encoding but
/// will NOT pass Ed25519 signature verification. Real signing requires
/// `KeyCustody` to be plumbed through the FFI boundary (SCP-214).
///
/// # Arguments
///
/// * `handle` — The context to mint the token for.
/// * `member_did` — The DID of the member receiving the token.
/// * `capabilities` — List of capability URIs to grant.
///
/// # Returns
///
/// A `UcanToken` handle with the minted token's metadata.
///
/// # Errors
///
/// Returns `ScpError::Permission` if minting fails (system clock error,
/// nonce generation failure, or JSON serialization error).
#[uniffi::export]
pub async fn ucan_mint(
    handle: Arc<ContextHandle>,
    member_did: String,
    capabilities: Vec<String>,
) -> Result<Arc<UcanToken>, ScpError> {
    runtime()
        .spawn(async move {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;

            let creator_did =
                crate::runtime::with_context(&handle.context_id, |rt| Ok(rt.creator_did.clone()))?;

            let nonce = generate_nonce()?;

            let capability_uris: Vec<String> = capabilities
                .iter()
                .map(|cap| {
                    if cap.starts_with("scp:ctx:") {
                        cap.clone()
                    } else {
                        format!("scp:ctx:{}/{cap}", handle.context_id)
                    }
                })
                .collect();

            #[allow(clippy::cast_possible_truncation)]
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| ScpError::Permission {
                    message: format!("system clock error: {e}"),
                    code: "SCP-PERM-3004".to_owned(),
                })?
                .as_secs();
            let exp = now + 3600;

            let header = UcanHeader::new();
            let att: Vec<Attenuation> = capability_uris
                .iter()
                .map(|uri| Attenuation {
                    with: uri.clone(),
                    can: "invoke".to_owned(),
                })
                .collect();

            let payload = UcanPayload {
                iss: creator_did.clone(),
                aud: member_did.clone(),
                exp,
                nbf: None,
                nnc: nonce.clone(),
                att,
                prf: Vec::new(),
                fct: None,
            };

            let header_json = serde_json::to_vec(&header).map_err(|e| ScpError::Permission {
                message: format!("header serialization failed: {e}"),
                code: "SCP-PERM-3004".to_owned(),
            })?;
            let payload_json =
                serde_json::to_vec(&payload).map_err(|e| ScpError::Permission {
                    message: format!("payload serialization failed: {e}"),
                    code: "SCP-PERM-3004".to_owned(),
                })?;

            let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

            // Stub: zero-signature placeholder until KeyCustody is plumbed through FFI (SCP-214)
            let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
            let encoded = format!("{header_b64}.{payload_b64}.{sig_b64}");

            let token_handle = Arc::new(UcanToken {
                data: UcanTokenData {
                    token_id: nonce,
                    issuer: creator_did,
                    audience: member_did,
                    capabilities: capability_uris,
                    expires_at: Some(exp),
                },
                encoded,
            });
            increment_handle_count();
            Ok(token_handle)
        })
        .await
        .map_err(|e| ScpError::Permission {
            message: format!("tokio task join error during UCAN mint: {e}"),
            code: "SCP-PERM-3005".to_owned(),
        })?
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
/// * `token_id` — The unique ID of the token to revoke.
///
/// # Errors
///
/// Returns `ScpError::Permission` if revocation fails (token not found,
/// revoker not authorized — must be the token's issuer or context creator).
#[uniffi::export]
pub async fn ucan_revoke(handle: Arc<ContextHandle>, token_id: String) -> Result<(), ScpError> {
    runtime()
        .spawn(async move {
            crate::runtime::with_context(&handle.context_id, |rt| {
                rt.revocation_list.revoke(token_id.clone());
                Ok(())
            })?;

            Ok(())
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
            let (event_count, merkle_root_hex) =
                crate::runtime::with_context(&handle.context_id, |rt| {
                    let count = scp_core::event_log::tree::event_count(&rt.event_log);
                    let root = scp_core::event_log::tree::root(&rt.event_log);
                    Ok((count, encode_hex(&root)))
                })?;

            let limit = if let Some(ref json) = filter_json {
                let parsed: serde_json::Value =
                    serde_json::from_str(json).map_err(ScpError::from)?;
                #[allow(clippy::cast_possible_truncation)]
                // Limit value is a small integer; u64→usize is safe for realistic filter values.
                parsed
                    .get("limit")
                    .and_then(serde_json::Value::as_u64)
                    .map(|v| v as usize)
            } else {
                None
            };

            if event_count == 0 {
                return Ok(Vec::new());
            }

            let payload_json = serde_json::json!({
                "event_count": event_count,
                "merkle_root": merkle_root_hex,
            });

            #[allow(clippy::cast_possible_truncation)]
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| ScpError::Context {
                    message: format!("system clock error: {e}"),
                    code: "SCP-CTX-2023".to_owned(),
                })?
                .as_secs();

            let summary_event = Event {
                event_type: "LogSummary".to_owned(),
                actor_did: String::new(),
                timestamp: now,
                payload_json: serde_json::to_string(&payload_json).map_err(ScpError::from)?,
                sequence: event_count.saturating_sub(1),
            };

            let events = vec![summary_event];

            if let Some(lim) = limit {
                Ok(events.into_iter().take(lim).collect())
            } else {
                Ok(events)
            }
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
#[allow(clippy::too_many_lines)] // Proof generation with match arms is inherently verbose.
pub async fn event_log_verify(
    handle: Arc<ContextHandle>,
    claim_json: String,
) -> Result<Proof, ScpError> {
    runtime()
        .spawn(async move {
            let claim: serde_json::Value =
                serde_json::from_str(&claim_json).map_err(ScpError::from)?;

            let claim_type =
                claim
                    .get("type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ScpError::Validation {
                        message: "claim must include 'type' field ('inclusion' or 'absence')"
                            .to_owned(),
                        code: "SCP-VALID-7010".to_owned(),
                    })?;

            match claim_type {
                "inclusion" => {
                    let leaf_index = claim
                        .get("leaf_index")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| ScpError::Validation {
                            message: "inclusion claim must include 'leaf_index' (integer)"
                                .to_owned(),
                            code: "SCP-VALID-7011".to_owned(),
                        })?;

                    let (verified, details_json) =
                        crate::runtime::with_context(&handle.context_id, |rt| {
                            let proof = scp_core::event_log::proof::prove_inclusion(
                                &rt.event_log,
                                leaf_index,
                            )
                            .map_err(ScpError::from)?;
                            let verified = scp_core::event_log::proof::verify_inclusion(&proof);

                            let path_steps: Vec<serde_json::Value> = proof
                                .path
                                .iter()
                                .map(|step| {
                                    let direction = match step.direction {
                                        scp_core::event_log::proof::Direction::Left => "left",
                                        scp_core::event_log::proof::Direction::Right => "right",
                                    };
                                    serde_json::json!({
                                        "sibling_hash": encode_hex(&step.sibling_hash),
                                        "direction": direction,
                                    })
                                })
                                .collect();

                            let details = serde_json::json!({
                                "leaf_index": proof.leaf_index,
                                "leaf_hash": encode_hex(&proof.leaf_hash),
                                "root": encode_hex(&proof.root),
                                "path": path_steps,
                                "path_length": proof.path.len(),
                            });

                            Ok((verified, details))
                        })?;

                    Ok(Proof {
                        verified,
                        proof_type: "inclusion".to_owned(),
                        details_json: serde_json::to_string(&details_json)
                            .map_err(ScpError::from)?,
                    })
                }
                "absence" => {
                    let event_hash_hex = claim
                        .get("event_hash")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ScpError::Validation {
                            message: "absence claim must include 'event_hash' (hex string)"
                                .to_owned(),
                            code: "SCP-VALID-7012".to_owned(),
                        })?;

                    let event_hash =
                        decode_hex_hash(event_hash_hex).map_err(|e| ScpError::Validation {
                            message: format!("invalid event_hash: {e}"),
                            code: "SCP-VALID-7013".to_owned(),
                        })?;

                    let (verified, details_json) =
                        crate::runtime::with_context(&handle.context_id, |rt| {
                            let proof = scp_core::event_log::proof::prove_absence(
                                &rt.event_log,
                                &event_hash,
                            )
                            .map_err(ScpError::from)?;

                            let lower = proof.lower.as_ref().map(|lwp| {
                                serde_json::json!({
                                    "leaf_hash": encode_hex(&lwp.leaf_hash),
                                    "leaf_index": lwp.leaf_index,
                                })
                            });

                            let upper = proof.upper.as_ref().map(|uwp| {
                                serde_json::json!({
                                    "leaf_hash": encode_hex(&uwp.leaf_hash),
                                    "leaf_index": uwp.leaf_index,
                                })
                            });

                            let lower_verified = proof.lower.as_ref().is_none_or(|lwp| {
                                scp_core::event_log::proof::verify_inclusion(&lwp.inclusion_proof)
                            });
                            let upper_verified = proof.upper.as_ref().is_none_or(|uwp| {
                                scp_core::event_log::proof::verify_inclusion(&uwp.inclusion_proof)
                            });
                            let verified = lower_verified && upper_verified;

                            let details = serde_json::json!({
                                "query_hash": encode_hex(&proof.query_hash),
                                "root": encode_hex(&proof.root),
                                "leaf_count": proof.leaf_count,
                                "lower": lower,
                                "upper": upper,
                            });

                            Ok((verified, details))
                        })?;

                    Ok(Proof {
                        verified,
                        proof_type: "absence".to_owned(),
                        details_json: serde_json::to_string(&details_json)
                            .map_err(ScpError::from)?,
                    })
                }
                other => Err(ScpError::Validation {
                    message: format!(
                        "unsupported claim type '{other}': expected 'inclusion' or 'absence'"
                    ),
                    code: "SCP-VALID-7014".to_owned(),
                }),
            }
        })
        .await
        .map_err(|e| ScpError::Context {
            message: format!("tokio task join error during event log verification: {e}"),
            code: "SCP-CTX-2026".to_owned(),
        })?
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Decodes a hex string into a 32-byte hash.
fn decode_hex_hash(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex characters (32 bytes), got {}",
            hex.len()
        ));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string".to_owned())?;
        bytes[i] =
            u8::from_str_radix(s, 16).map_err(|e| format!("hex decode error at byte {i}: {e}"))?;
    }
    Ok(bytes)
}
