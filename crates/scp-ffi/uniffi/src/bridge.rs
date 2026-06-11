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

use scp_ffi_common::error_codes as codes;
use std::fmt;
use std::sync::Arc;

use sha2::Digest;
use zeroize::Zeroizing;

use scp_identity::DidCache;
use scp_identity::IdentityError;
#[cfg(any(test, feature = "allow_in_memory_custody"))]
use scp_identity::InMemoryDhtClient;
#[cfg(not(any(test, feature = "allow_in_memory_custody")))]
use scp_identity::PkarrDhtClient;
use scp_identity::resolver::{DualLayerResolver, NoOpRelayQuerier};
use scp_primitives::Clock;

/// DHT client type alias: production builds use [`PkarrDhtClient`] for real
/// Mainline DHT resolution; test and `allow_in_memory_custody` builds use
/// [`InMemoryDhtClient`] to avoid network I/O and enable deterministic
/// identity roundtrips.
///
/// `#[cfg(test)]` alone is insufficient: integration tests (`tests/` directory)
/// compile the crate as a dependency where `cfg(test)` is false. The
/// `allow_in_memory_custody` feature (already required by CI for integration
/// tests) provides the correct gate for both unit and integration test builds.
#[cfg(not(any(test, feature = "allow_in_memory_custody")))]
type FfiDhtClient = PkarrDhtClient;
#[cfg(any(test, feature = "allow_in_memory_custody"))]
type FfiDhtClient = InMemoryDhtClient;

/// Constructs a new [`FfiDhtClient`].
///
/// Production builds create a [`PkarrDhtClient`] (fallible — Mainline DHT
/// socket binding can fail). Test builds create an [`InMemoryDhtClient`]
/// (infallible).
macro_rules! new_ffi_dht_client {
    () => {{
        let result: Result<FfiDhtClient, IdentityError> = {
            #[cfg(not(any(test, feature = "allow_in_memory_custody")))]
            {
                FfiDhtClient::new()
            }
            #[cfg(any(test, feature = "allow_in_memory_custody"))]
            {
                Ok(FfiDhtClient::new())
            }
        };
        result
    }};
}
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
    json_value_type_name, validate_capability_uri, validate_context_id, validate_did,
    validate_mcp_handle, validate_relay_url, validate_tool_id, validate_tool_name,
    validate_transport_mode, validate_ucan_token,
};

use crate::{decrement_handle_count, increment_handle_count, runtime};

/// Generates a real MLS key package for a joining member.
///
/// Mirrors the NAPI bridge's `generate_mls_key_package_bytes`: builds an
/// [`ScpCredential`] from the joiner's DID and TLS-serializes a fresh
/// `KeyPackage` bundle produced by `generate_key_package`. The output bytes
/// are what `MlsCryptoProvider::validate_key_package` and
/// `MlsCryptoProvider::add_member` require — the old `FfiBridgeCrypto` stub
/// used to accept `None`, but real MLS rejects it.
///
/// # Errors
///
/// Returns `ScpError::Crypto` if the DID format is invalid (must be
/// `did:dht:z…`), key package generation fails, or TLS serialization fails.
fn generate_mls_key_package_bytes(did: &str) -> Result<Vec<u8>, ScpError> {
    use scp_core::crypto::mls::credential::ScpCredential;
    use scp_core::crypto::mls::group::generate_key_package;
    use tls_codec::Serialize as TlsSerializeTrait;

    let cred = ScpCredential::new(did.to_owned(), None, scp_identity::SigningKeyId::Active)
        .map_err(|e| ScpError::Crypto {
            msg: format!("failed to create SCP credential for MLS key package: {e}"),
            code: codes::CRYPTO_4010.to_owned(),
        })?;

    let (kp_bundle, _signer, _provider) =
        generate_key_package(&cred).map_err(|e| ScpError::Crypto {
            msg: format!("MLS key package generation failed: {e}"),
            code: codes::CRYPTO_4011.to_owned(),
        })?;

    kp_bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| ScpError::Crypto {
            msg: format!("MLS key package TLS serialization failed: {e}"),
            code: codes::CRYPTO_4012.to_owned(),
        })
}

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

/// Snapshots the hex-encoded Ed25519 verifying-key bytes for the identity's
/// `#0` (DID-deriving) signing key. Used by every `Identity` constructor to
/// populate the ADR-046 parity-testing field — two bridges generating an
/// identity under the same deterministic `seed` produce byte-identical
/// hex output here.
///
/// Intentionally swallows errors (`.ok()`) because a missing verifying-key
/// only disables the parity-harness assertion; the rest of the identity
/// remains usable. Nine call-sites across identity construction
/// (`create`, `rotate_active_key`, `add_agent_key`, `rotate_agent_key`,
/// `remove_agent_key`, `identity_migrate` in-memory arm,
/// `identity_migrate` callback arm, `identity_create_with_custody`,
/// `identity_create_with_agent_key`) delegate here.
async fn snapshot_verifying_key_hex<C: KeyCustody>(custody: &C, key: &KeyHandle) -> Option<String> {
    custody
        .public_key(key)
        .await
        .ok()
        .map(|pk| hex::encode(pk.as_bytes()))
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
) -> Result<DidDht<FfiDhtClient, scp_identity::cache::SystemClock>, IdentityError> {
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
    Ok(DidDht::with_client_and_signer(
        Arc::new(new_ffi_dht_client!()?),
        Arc::new(DidCache::new()),
        sign_fn,
    ))
}

/// Derives this member's per-context pseudonymous routing ID (§9.10.4).
///
/// Single source of truth for the `UniFFI` bridge's pseudonym derivation,
/// shared verbatim by `context_create`, `context_join`, and `context_import`
/// (matching the `PyO3` `derive_member_pseudonym` and `NAPI`
/// `derive_member_pseudonym_required` reference helpers). Encrypted contexts
/// MUST carry a real pseudonym: a zero/sentinel value silently maps to the
/// reserved `[0u8; 32]` routing ID, making the member permanently
/// unaddressable with no surfaced error.
///
/// Custody resolution order: platform/software callback custody first, then
/// (only in `allow_in_memory_custody` builds) the retained in-memory custody.
/// Failures carry the cross-bridge contract codes: missing key material →
/// `IDENT_1054`, derivation failure → `IDENT_1055`, custody unavailable in
/// this build → `IDENT_1056`, wrong public-key length → `IDENT_1057`.
///
/// Callers gate this themselves: `context_create`/`context_join` skip it for
/// broadcast contexts (soft `None`, spec §5.14), while `context_import` calls
/// it unconditionally (the runtime import path is encrypted-only).
async fn derive_member_pseudonym_required(
    identity: &Identity,
    context_id: &str,
) -> Result<[u8; 32], ScpError> {
    let identity_key = identity
        .core_id
        .as_ref()
        .map(|id| id.identity_key)
        .ok_or_else(|| ScpError::Identity {
            msg: "cannot derive pseudonym without retained key material — \
                  encrypted contexts require a real per-member routing ID"
                .to_owned(),
            code: codes::IDENT_1054.to_owned(),
        })?;
    let pseudonym = if let Some(ref cb) = identity.callback_custody {
        cb.derive_pseudonym(&identity_key, context_id.as_bytes())
            .await
            .map_err(|e| ScpError::Identity {
                msg: format!("pseudonym derivation failed: {e}"),
                code: codes::IDENT_1055.to_owned(),
            })?
    } else {
        #[cfg(feature = "allow_in_memory_custody")]
        {
            let imc = identity
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "cannot derive pseudonym without retained key material — \
                          encrypted contexts require a real per-member routing ID"
                        .to_owned(),
                    code: codes::IDENT_1054.to_owned(),
                })?;
            imc.0
                .derive_pseudonym(&identity_key, context_id.as_bytes())
                .await
                .map_err(|e| ScpError::Identity {
                    msg: format!("pseudonym derivation failed: {e}"),
                    code: codes::IDENT_1055.to_owned(),
                })?
        }
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            return Err(ScpError::Identity {
                msg: "pseudonym derivation requires custody — not available in \
                      this build"
                    .to_owned(),
                code: codes::IDENT_1056.to_owned(),
            });
        }
    };
    pseudonym
        .public_key
        .as_bytes()
        .try_into()
        .map_err(|_| ScpError::Identity {
            msg: "pseudonym public key must be 32 bytes".to_owned(),
            code: codes::IDENT_1057.to_owned(),
        })
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
        // Parse the returned key_id string as a u64 handle identifier via the
        // shared helper (unifies the error text with the PyO3/napi bridges).
        scp_ffi_common::custody_parse::parse_handle("generate_keypair", &key_id)
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
        Ok(SharedSecret::new(scp_ffi_common::custody_parse::expect_32(
            "dh_agree", &shared,
        )?))
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
        // Unpack via the shared helper (unifies error text with PyO3/napi).
        scp_ffi_common::custody_parse::unpack_pseudonym("derive_pseudonym", &result_bytes)
    }

    async fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> Result<PseudonymKeypair, PlatformError> {
        // Canonical v2 recipe (spec §9.10.4.A / §9.10.4.1): the provider performs
        // the rotatable derivation itself — seed = HMAC-SHA256(pseudonym_secret,
        // context_id || BE64(pseudonym_epoch) || "scp-pseudonym-v2"); keypair =
        // Ed25519_keygen(seed[0..32]). The epoch is threaded through to the
        // provider rather than synthesized into the context_id bridge-side, so
        // the v1 platform adapter does not re-append its own "scp-pseudonym"
        // domain separator (which would corrupt the v2 domain).
        let result_bytes = self
            .provider
            .derive_rotatable_pseudonym(key.id().to_string(), context_id.to_vec(), pseudonym_epoch)
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;

        // Unpack via the shared helper (unifies error text with PyO3/napi).
        scp_ffi_common::custody_parse::unpack_pseudonym("derive_rotatable_pseudonym", &result_bytes)
    }

    async fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError> {
        // The callback protocol does not expose ed25519→x25519 conversion.
        // Delegates to dh_agree since the callback provider manages key types internally.
        let shared = self
            .provider
            .dh_agree(ed25519_handle.id().to_string(), peer_x25519_public.to_vec())
            .await
            .map_err(|e| PlatformError::CustodyError(e.to_string()))?;
        Ok(SharedSecret::new(scp_ffi_common::custody_parse::expect_32(
            "ed25519_to_x25519_agree",
            &shared,
        )?))
    }

    fn custody_type(&self, key: &KeyHandle) -> CustodyType {
        let type_str = self.provider.custody_type(key.id().to_string());
        match type_str.as_str() {
            "hardware" => CustodyType::Hardware,
            "software" | "software_biometric" => CustodyType::Software,
            _ => CustodyType::InMemory,
        }
    }

    async fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, PlatformError> {
        // Generates the pre-rotation seed locally via OsRng. The bytes
        // never traverse the SDK consumer's `KeyCustodyProvider`
        // callback — the bridge hands them directly to a
        // `PreRotationCustody` instance.
        //
        // # Storage isolation status (spec §9.7.4.1 §3)
        //
        // **Type-level isolation is satisfied** (the bytes never enter
        // the operational `KeyCustody` provider). **Substrate isolation
        // is NOT yet satisfied**: the bridge process and the
        // currently-shipped `InMemoryPreRotationCustody` co-reside in
        // the same Rust process memory as the operational
        // `KeyHandle` ID space. A process-memory dump compromises
        // both.
        //
        // Full §9.7.4.1 §3 substrate isolation requires a non-in-memory
        // `PreRotationCustody` backend (FIDO2, passkey-PRF, Apple
        // Keychain entry under a separate access-control class,
        // Android Keystore alias with separate authentication flow,
        // encrypted offline backup, Shamir, BIP39). Production
        // backends are a separate workstream — see the
        // `PreRotationCustodyKind::InMemory` doc-comment.
        //
        // For HSM-bound platforms where `OsRng` is not the appropriate
        // CSPRNG source, the SDK MUST instead generate pre-rotation
        // key bytes via the platform CSPRNG (`SecRandomCopyBytes` on
        // Apple, `KeyStore.getRandom` on Android) and route them
        // directly into a `PreRotationCustody` impl, bypassing
        // `KeyCustody` entirely.
        use rand::RngCore;
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Ok(seed)
    }

    async fn import_ed25519_signing_key(
        &self,
        _seed: &zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<KeyHandle, PlatformError> {
        // Migrating an identity via callback custody requires the SDK
        // consumer to install the pre-rotation private bytes (revealed
        // at migration time) as the NEW operational `#0` key. The
        // `KeyCustodyProvider` callback interface today has no method
        // for "import a known seed and return a handle" — only
        // `generate_keypair`, which mints a fresh random key.
        //
        // Identity CREATION via callback custody works
        // (`generate_ephemeral_ed25519_seed` above generates locally
        // and routes through `PreRotationCustody`, never touching the
        // SDK callback). MIGRATION is the constrained path.
        //
        // The unblock is to extend `KeyCustodyProvider` with an
        // `import_ed25519_seed_bytes(seed) -> handle` method that
        // SDK consumers (Swift / Kotlin) implement. Until then, this
        // method MUST surface a clear error rather than silently
        // failing later in the migration flow.
        Err(PlatformError::Unsupported(
            "callback custody cannot import pre-rotation seed bytes; \
             KeyCustodyProvider has no import_ed25519_seed_bytes method. \
             Identity creation via callback custody is unaffected.",
        ))
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
        // Private seed material: wrap the parsed 32-byte array in `Zeroizing`
        // so the intermediate seed buffer is wiped on drop, matching the PyO3
        // and NAPI callback custody paths (ADR-006).
        let arr = zeroize::Zeroizing::new(scp_ffi_common::custody_parse::expect_32(
            "export_signing_key_bytes",
            &key_bytes,
        )?);
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
    }
}

// ---------------------------------------------------------------------------
// ScpError — unified error type (maps to Swift throws / Kotlin exceptions)
//
// Each variant carries `msg` (human-readable detail) and `code`
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
    #[error("identity error [{code}]: {msg}")]
    Identity { msg: String, code: String },

    /// A context lifecycle operation failed (create, join, leave, close, send).
    #[error("context error [{code}]: {msg}")]
    Context { msg: String, code: String },

    /// A capability or governance permission check failed.
    #[error("permission error [{code}]: {msg}")]
    Permission { msg: String, code: String },

    /// A cryptographic operation failed (MLS, sender keys, encryption).
    #[error("crypto error [{code}]: {msg}")]
    Crypto { msg: String, code: String },

    /// A transport operation failed (connection, send, subscription).
    #[error("transport error [{code}]: {msg}")]
    Transport { msg: String, code: String },

    /// A tool operation failed (registration, invocation, verification).
    #[error("tool error [{code}]: {msg}")]
    Tool { msg: String, code: String },

    /// Input validation failed (malformed data, schema mismatch, constraint violation).
    #[error("validation error [{code}]: {msg}")]
    Validation { msg: String, code: String },
}

// ---------------------------------------------------------------------------
// From<scp-core error types> for ScpError
// ---------------------------------------------------------------------------

impl From<scp_ffi_common::validate::ValidationError> for ScpError {
    fn from(e: scp_ffi_common::validate::ValidationError) -> Self {
        Self::Validation {
            msg: e.message,
            code: codes::VALID_7000.to_owned(),
        }
    }
}

impl From<scp_ffi_common::bridge_instance::HandleAffinityError> for ScpError {
    fn from(e: scp_ffi_common::bridge_instance::HandleAffinityError) -> Self {
        // Sanitized message — never exposes the raw ids. PERM_3030 lets
        // callers programmatically distinguish this from other permission
        // errors.
        Self::Permission {
            msg: format!("{e}"),
            code: codes::PERM_3030.to_owned(),
        }
    }
}

impl From<scp_identity::IdentityError> for ScpError {
    fn from(e: scp_identity::IdentityError) -> Self {
        use scp_identity::IdentityError as IE;
        use scp_platform::PreRotationCustodyError as PE;

        if let IE::PreRotation(pre_err) = &e {
            let code = match pre_err {
                PE::HandleNotFound => codes::IDENT_1047,
                PE::Unavailable(_) => codes::IDENT_1048,
                PE::UserDeclined => codes::IDENT_1049,
                PE::Storage(_) => codes::IDENT_1050,
                PE::InvalidCallbackResponse(_) => codes::IDENT_1051,
                PE::CommitmentMismatch => codes::IDENT_1052,
            };
            return Self::Identity {
                msg: format!("{e}"),
                code: code.to_owned(),
            };
        }

        // `MigrationPublishFailed` is the typed recovery handle from
        // `DidDht::migrate_identity` (phase-1 surface). Structured
        // partial-state plumbing lands in subsequent PRs — this arm only
        // surfaces the code + message body.
        if matches!(&e, IE::MigrationPublishFailed { .. }) {
            return Self::Identity {
                msg: format!("{e}"),
                code: codes::IDENT_1053.to_owned(),
            };
        }

        Self::Identity {
            msg: format!("{e} — check DID format, key custody configuration, or DHT connectivity"),
            code: codes::IDENT_1001.to_owned(),
        }
    }
}

/// Extracts a leading `SCP-XXX-NNNN` error code from a message body, if any.
///
/// Mirrors the `PyO3` / NAPI bridge helpers. Used to recover
/// economy (12xxx), tool-invocation (6xxx), and permission (3xxx) codes
/// embedded inside `ContextError::PermissionDenied(String)` so Swift /
/// Kotlin callers can detect specific failures without string-matching
/// the message body.
pub(crate) fn extract_scp_code(message: &str) -> Option<String> {
    let trimmed = message.trim_start();
    let rest = trimmed.strip_prefix("SCP-")?;
    let end = rest.find(|c: char| c == ':' || c.is_whitespace())?;
    let suffix = &rest[..end];
    let (category, number) = suffix.split_once('-')?;
    if category.is_empty()
        || !category.chars().all(|c| c.is_ascii_alphabetic())
        || number.is_empty()
        || !number.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some(format!("SCP-{category}-{number}"))
}

impl From<scp_core::context::ContextError> for ScpError {
    fn from(e: scp_core::context::ContextError) -> Self {
        use scp_core::context::ContextError as CE;
        match &e {
            // Surface the canonical rate-limit code on the typed
            // envelope so Swift / Kotlin callers can detect
            // rate-limit rejection without string-matching on the
            // message body.
            CE::RateLimited { .. } => Self::Context {
                msg: format!("{e}"),
                code: codes::ECON_12090.to_owned(),
            },
            // §23.17 snapshot import regression.
            CE::SnapshotFloorRegression { .. } => Self::Context {
                msg: format!("{e}"),
                code: codes::CTX_2091.to_owned(),
            },
            // C3: snapshot import structural/semantic rejection.
            CE::ImportRejected { .. } => Self::Context {
                msg: format!("{e}"),
                code: codes::CTX_2092.to_owned(),
            },
            // §23.16.8 / ADR-050: signed-context-export signature verification
            // failure (forged/tampered snapshot, exporter_did != creator_did,
            // or unresolvable creator key). Surface the dedicated SCP-CTX-2093
            // contract instead of falling through to the catch-all CTX_2001 so
            // Swift / Kotlin callers can distinguish a forged export from a
            // generic context error. The version gate is reported separately
            // (a distinct version error, not this arm), per §23.16.8 / §17.5.
            CE::SnapshotSignatureInvalid { .. } => Self::Context {
                msg: format!("{e}"),
                code: codes::CTX_2093.to_owned(),
            },
            // §23.16.8 / §17.5: signed-context-export format-version gate.
            // The snapshot carries an export-format version this build does not
            // support. This is a distinct contract from CTX_2093 (signature
            // verification failure) so a caller can tell "old/unsupported
            // export format" apart from "forged/tampered snapshot".
            CE::ExportVersionUnsupported { .. } => Self::Context {
                msg: format!("{e}"),
                code: codes::CTX_2094.to_owned(),
            },
            // §9.10.4: pseudonym registry empty on a multi-member encrypted send.
            CE::PseudonymRegistryEmpty { .. } => Self::Context {
                msg: format!("{e}"),
                code: codes::CTX_2095.to_owned(),
            },
            // §9.10.4 / §5.14: per-member pseudonym requested for a broadcast context.
            CE::NotPseudonymousContext { .. } => Self::Context {
                msg: format!("{e}"),
                code: codes::CTX_2096.to_owned(),
            },
            // Recover embedded SCP-ECON-/SCP-TOOL-/SCP-PERM- codes from
            // the runtime's `PermissionDenied(String)` catch-all so the
            // typed-envelope contract holds for tool-economy failures.
            CE::PermissionDenied(msg) => {
                let code = extract_scp_code(msg).unwrap_or_else(|| codes::PERM_3001.to_owned());
                if code.starts_with("SCP-PERM-") {
                    Self::Permission {
                        msg: format!("{e}"),
                        code,
                    }
                } else if code.starts_with("SCP-TOOL-") {
                    Self::Tool {
                        msg: format!("{e}"),
                        code,
                    }
                } else {
                    Self::Context {
                        msg: format!("{e}"),
                        code,
                    }
                }
            }
            _ => Self::Context {
                msg: format!("{e} — verify context state, membership, and permissions"),
                code: codes::CTX_2001.to_owned(),
            },
        }
    }
}

impl From<scp_core::context::builder::ContextCreationError> for ScpError {
    fn from(e: scp_core::context::builder::ContextCreationError) -> Self {
        Self::Context {
            msg: format!("context creation failed: {e} — check context parameters and identity"),
            code: codes::CTX_2002.to_owned(),
        }
    }
}

impl From<scp_core::context::templates::TemplateError> for ScpError {
    fn from(e: scp_core::context::templates::TemplateError) -> Self {
        Self::Context {
            msg: format!(
                "template validation failed: {e} — ensure context params match the template"
            ),
            code: codes::CTX_2003.to_owned(),
        }
    }
}

impl From<scp_core::context::roles::RoleError> for ScpError {
    fn from(e: scp_core::context::roles::RoleError) -> Self {
        Self::Context {
            msg: format!(
                "role operation failed: {e} — verify role definitions and member permissions"
            ),
            code: codes::CTX_2004.to_owned(),
        }
    }
}

impl From<scp_core::context::ttl::TtlError> for ScpError {
    fn from(e: scp_core::context::ttl::TtlError) -> Self {
        Self::Context {
            msg: format!("TTL operation failed: {e} — check TTL configuration and context state"),
            code: codes::CTX_2005.to_owned(),
        }
    }
}

impl From<scp_core::context::promotion::PromotionError> for ScpError {
    fn from(e: scp_core::context::promotion::PromotionError) -> Self {
        Self::Context {
            msg: format!("context promotion failed: {e} — verify eligibility and governance rules"),
            code: codes::CTX_2006.to_owned(),
        }
    }
}

impl From<scp_core::context::tools::ToolError> for ScpError {
    fn from(e: scp_core::context::tools::ToolError) -> Self {
        Self::Tool {
            msg: format!(
                "tool operation failed: {e} — check tool registration, permissions, and input schema"
            ),
            code: codes::TOOL_6001.to_owned(),
        }
    }
}

impl From<scp_core::context::tools::invoke::InvocationError> for ScpError {
    fn from(e: scp_core::context::tools::invoke::InvocationError) -> Self {
        Self::Tool {
            msg: format!(
                "tool invocation failed: {e} — verify tool ID, input, and caller permissions"
            ),
            code: codes::TOOL_6002.to_owned(),
        }
    }
}

impl From<scp_core::context::tools::schema::SchemaValidationError> for ScpError {
    fn from(e: scp_core::context::tools::schema::SchemaValidationError) -> Self {
        Self::Validation {
            msg: format!(
                "schema validation failed: {e} — check input against the tool's JSON Schema"
            ),
            code: codes::VALID_7001.to_owned(),
        }
    }
}

impl From<scp_core::crypto::mls::error::MlsError> for ScpError {
    fn from(e: scp_core::crypto::mls::error::MlsError) -> Self {
        Self::Crypto {
            msg: format!("MLS operation failed: {e} — check group state and member key packages"),
            code: codes::CRYPTO_4001.to_owned(),
        }
    }
}

impl From<scp_core::crypto::sender_keys::SenderKeyError> for ScpError {
    fn from(e: scp_core::crypto::sender_keys::SenderKeyError) -> Self {
        Self::Crypto {
            msg: format!(
                "sender key operation failed: {e} — verify key material and encryption parameters"
            ),
            code: codes::CRYPTO_4002.to_owned(),
        }
    }
}

impl From<scp_core::crypto::ucan::UcanError> for ScpError {
    fn from(e: scp_core::crypto::ucan::UcanError) -> Self {
        // Canonical UCAN→error-code mapping — see `scp-ffi/src/error.rs`
        // for the full rationale. All bridges route through the shared
        // `scp_ffi_common::ucan_errors` module.
        let code = scp_ffi_common::ucan_errors::ucan_error_code(&e).to_owned();
        Self::Permission {
            msg: format!("{e} — check token format, signatures, time bounds, and capability chain"),
            code,
        }
    }
}

impl From<scp_core::envelope::EnvelopeError> for ScpError {
    fn from(e: scp_core::envelope::EnvelopeError) -> Self {
        Self::Crypto {
            msg: format!(
                "envelope operation failed: {e} — check payload size, signing keys, and encryption state"
            ),
            code: codes::CRYPTO_4003.to_owned(),
        }
    }
}

impl From<scp_event_log::EventLogError> for ScpError {
    fn from(e: scp_event_log::EventLogError) -> Self {
        Self::Context {
            msg: format!(
                "event log operation failed: {e} — verify log integrity and sequence numbers"
            ),
            code: codes::CTX_2007.to_owned(),
        }
    }
}

impl From<scp_core::provenance::ProvenanceError> for ScpError {
    fn from(e: scp_core::provenance::ProvenanceError) -> Self {
        Self::Validation {
            msg: format!("provenance validation failed: {e} — check cross-context chain depth"),
            code: codes::VALID_7002.to_owned(),
        }
    }
}

impl From<scp_core::trust::TrustError> for ScpError {
    fn from(e: scp_core::trust::TrustError) -> Self {
        Self::Validation {
            msg: format!(
                "trust evaluation failed: {e} — check event log data and attestation validity"
            ),
            code: codes::VALID_7003.to_owned(),
        }
    }
}

impl From<scp_core::uri::ScpUriError> for ScpError {
    fn from(e: scp_core::uri::ScpUriError) -> Self {
        Self::Validation {
            msg: format!("invalid SCP URI: {e} — check URI format (scp://relay/context-id)"),
            code: codes::VALID_7004.to_owned(),
        }
    }
}

impl From<scp_core::well_known::WellKnownValidationError> for ScpError {
    fn from(e: scp_core::well_known::WellKnownValidationError) -> Self {
        Self::Validation {
            msg: format!("well-known validation failed: {e} — check relay configuration"),
            code: codes::VALID_7005.to_owned(),
        }
    }
}

impl From<scp_core::discovery::DiscoveryError> for ScpError {
    fn from(e: scp_core::discovery::DiscoveryError) -> Self {
        Self::Context {
            msg: format!(
                "discovery operation failed: {e} — check relay connectivity and search parameters"
            ),
            code: codes::CTX_2008.to_owned(),
        }
    }
}

impl From<scp_core::bridge::registration::BridgeRegistrationError> for ScpError {
    fn from(e: scp_core::bridge::registration::BridgeRegistrationError) -> Self {
        Self::Context {
            msg: format!(
                "bridge registration failed: {e} — verify bridge configuration and permissions"
            ),
            code: codes::CTX_2009.to_owned(),
        }
    }
}

impl From<scp_core::bridge::shadow::ShadowError> for ScpError {
    fn from(e: scp_core::bridge::shadow::ShadowError) -> Self {
        Self::Context {
            msg: format!(
                "shadow context operation failed: {e} — check bridge state and context permissions"
            ),
            code: codes::CTX_2010.to_owned(),
        }
    }
}

impl From<scp_transport::TransportError> for ScpError {
    fn from(e: scp_transport::TransportError) -> Self {
        Self::Transport {
            msg: format!(
                "{e} — check relay URL, network connectivity, and transport configuration"
            ),
            code: codes::TRANS_5001.to_owned(),
        }
    }
}

impl From<scp_platform::PlatformError> for ScpError {
    fn from(e: scp_platform::PlatformError) -> Self {
        Self::Crypto {
            msg: format!("platform key operation failed: {e} — check key custody configuration"),
            code: codes::CRYPTO_4004.to_owned(),
        }
    }
}

impl From<serde_json::Error> for ScpError {
    fn from(e: serde_json::Error) -> Self {
        Self::Validation {
            msg: format!("JSON serialization/deserialization failed: {e} — check input format"),
            code: codes::VALID_7006.to_owned(),
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
    /// Used by `identity_load` to represent an identity whose keys are
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
    /// Context migration approved — source is in read-only grace period (§5.11A.4).
    MigratingOut,
    /// Context permanently tombstoned after migration (§5.11A.5). Terminal state.
    Tombstoned,
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

/// Context processing mode. Immutable after creation.
///
/// Determines the encryption strategy for the context.
/// See spec §5.14.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ContextMode {
    /// MLS-backed encryption with sender-side keys and full forward secrecy.
    /// This is the default mode.
    Encrypted,
    /// Per-author AES-256-GCM broadcast keys. No MLS group is created.
    /// Subscriber count is unlimited. See spec section 5.14.
    Broadcast,
}

/// Ceiling mutability policy. Declared at creation, immutable thereafter.
///
/// See ADR-008 and spec §5.3.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum CeilingPolicy {
    /// Ceiling is fixed at creation. Any attempt to modify returns an error.
    /// This is the default and the security-conservative choice.
    Immutable,
    /// Ceiling can be modified through the context's governance model.
    Governed,
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
    /// Context processing mode — `Encrypted` (default) or `Broadcast`.
    /// See spec §5.14.
    pub mode: ContextMode,
    /// Capability ceiling — maximum capabilities any participant can hold.
    /// Empty list means no ceiling restriction.
    pub ceiling: Vec<String>,
    /// Ceiling mutability policy — `Immutable` (default) or `Governed`.
    /// See spec §5.3.
    pub ceiling_policy: CeilingPolicy,
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
    /// Maximum cross-context chain depth (spec §24.4, ADR-043).
    /// `None` uses the protocol default (8).
    pub max_chain_depth: Option<u8>,
    /// Maximum nesting depth for sub-contexts (spec §5.6, ADR-043).
    /// `None` means unbounded.
    pub max_nesting_depth: Option<u32>,
    /// Per-caller session cap (spec §6.2.1, ADR-043).
    /// `None` uses the protocol default (1000).
    pub session_cap: Option<u32>,
    /// Optional economic policy as a JSON string (spec §19, ADR-033).
    /// `None` means no economic policy (free context).
    pub economic_policy: Option<String>,
    /// Optional consequence rules as a JSON-encoded array (ADR-017, #1531).
    /// `None` means no consequence rules.
    ///
    /// Stored as a JSON string rather than a typed Record to avoid extending
    /// the UDL surface with the full `ConsequenceRule` type tree (mirrors the
    /// `aggregate_trust_input` JSON-string pattern). The string is parsed
    /// inside `bridge_params_to_core` and validated against
    /// `consequence_config_json` before the manager is called.
    pub consequence_rules_json: Option<String>,
    /// Optional consequence config as a JSON-encoded object (ADR-017, #1531).
    /// `None` means the default config (severe enforcement tiers gated to
    /// governance only).
    pub consequence_config_json: Option<String>,
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
    /// No protocol-level discovery path (out-of-band introduction).
    OutOfBand,
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
            scp_core::provenance::DiscoveryMethod::OutOfBand => DiscoveryMethod::OutOfBand,
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
            DiscoveryMethod::OutOfBand => scp_core::provenance::DiscoveryMethod::OutOfBand,
        };

        let memory_scope = match self.memory_scope {
            MemoryScope::Ephemeral => scp_core::context::MemoryScope::Ephemeral,
            MemoryScope::Summary => scp_core::context::MemoryScope::Summary,
            MemoryScope::Full => scp_core::context::MemoryScope::Full,
        };

        let payment_receipt_id: Option<[u8; 32]> = match &self.payment_receipt_id {
            Some(v) => {
                let arr: [u8; 32] = v.as_slice().try_into().map_err(|_| ScpError::Validation {
                    msg: format!(
                        "payment_receipt_id must be exactly 32 bytes, got {}",
                        v.len()
                    ),
                    code: codes::VALID_7080.to_owned(),
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
/// See ADR-010 (Tool Registry) and spec §5.4.1 (Tools).
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
    /// Optional per-invocation cost metadata (spec §5.4.1).
    pub cost: Option<ToolCostDefinition>,
}

/// Per-invocation cost metadata for a tool (spec §5.4.1).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ToolCostDefinition {
    /// Cost per invocation in the smallest currency unit.
    pub amount: u64,
    /// ISO 4217 or protocol-defined currency code.
    pub currency: String,
    /// DID of the payment recipient. May differ from `operator_did`.
    pub payee: String,
    /// Optional pricing formula identifier for dynamic pricing (§19.4).
    pub cost_formula: Option<String>,
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
/// - **In-memory custody** (dev/desktop): retained `InMemoryKeyCustody`
///   with key material in heap memory. Only available when the
///   `allow_in_memory_custody` feature is enabled.
/// - **Platform/Software custody** (production mobile): retained
///   `CallbackKeyCustody` adapter wrapping the injected
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
    /// Hex-encoded Ed25519 verifying-key bytes for the identity key
    /// (VM `#0`, the key that derives the DID). 64 hex chars = 32 raw
    /// bytes. `None` for externally loaded identities without live key
    /// material.
    ///
    /// Uses `identity_key` (not `#active`) because the WASM bridge has a
    /// simplified single-key model; exposing the identity key gives
    /// byte-exact cross-bridge parity under a deterministic `seed`
    /// (ADR-046).
    pub(crate) verifying_key_hex: Option<String>,
    /// Monotonic identifier of the bridge instance that minted this handle.
    ///
    /// Consumed by [`uniffi_check_handle!`](crate::uniffi_check_handle) at
    /// every `#[uniffi::export]` entry that accepts an `Identity`. Mismatches
    /// map to `ScpError::Permission` with code `SCP-PERM-3030`.
    pub(crate) instance_id: u64,
    /// JSON-serialized `scp_identity::DidRotationEvent` produced when this
    /// handle was minted by [`Scp::identity_migrate`]. SDK callers MUST
    /// distribute the event to active context members per spec §3.2.1
    /// step 4b. `None` for handles produced by `identity_create`,
    /// `rotate_key`, agent-key ops, or external load — those do not
    /// change the DID, so no `DidRotationEvent` is constructed.
    pub(crate) rotation_event_json: Option<String>,
    /// Opaque handle into [`pre_rotation_custody`](Self::pre_rotation_custody)
    /// for the pre-rotation key whose SHA-256 hash equals the
    /// `pre_rotation_commitment` retained on `core_id`.
    ///
    /// Spec §9.7.4.1 §6 / ADR-003 §4b: the pre-rotation key lives in a
    /// substrate distinct from operational `KeyCustody` so a compromise of
    /// operational keys cannot reveal the pre-rotation key. The handle is
    /// minted at identity creation and consumed by
    /// [`Scp::identity_migrate`], which mints a fresh one for the next
    /// migration. Active-key rotation, agent-key operations, and load
    /// preserve the handle verbatim.
    ///
    /// Rust-internal field — NOT exposed through `#[uniffi::export]`.
    #[allow(dead_code)]
    pub(crate) pre_rotation_handle: scp_platform::PreRotationKeyHandle,
    /// Cold-storage custody for the pre-rotation key referenced by
    /// [`pre_rotation_handle`](Self::pre_rotation_handle).
    ///
    /// The same `Arc` is preserved across all migrations of this identity
    /// (per ADR-003 §4b). Production custody migration is a follow-up
    /// workstream; the in-memory testing backend is sufficient for the
    /// dev/desktop and parity-test paths exercised today.
    ///
    /// Rust-internal field — NOT exposed through `#[uniffi::export]`.
    #[allow(dead_code)]
    pub(crate) pre_rotation_custody: Arc<scp_platform::testing::InMemoryPreRotationCustody>,
}

impl Identity {
    /// Returns the monotonic identifier of the bridge instance that minted
    /// this handle.
    ///
    /// Rust-internal only: consumed by `CoreFields::check_handle` for
    /// per-instance handle affinity. NOT exposed through `#[uniffi::export]`
    /// (see ADR-048 — per-handle `instanceId` is not host-visible).
    #[must_use]
    pub(crate) const fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

#[uniffi::export]
impl Identity {
    /// Returns the DID string for this identity.
    #[must_use]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    /// Returns the JSON-serialized `DidRotationEvent` if this handle
    /// was produced by [`Scp::identity_migrate`]; `None` otherwise.
    /// SDK callers MUST distribute the event to active context members
    /// per spec §3.2.1 step 4b.
    #[must_use]
    pub fn rotation_event_json(&self) -> Option<String> {
        self.rotation_event_json.clone()
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

    /// Returns the hex-encoded Ed25519 verifying-key bytes for the
    /// identity key (VM `#0`, the DID-deriving key), or `null` if this
    /// handle was loaded without live key material.
    ///
    /// Under a deterministic `seed`, this value is byte-identical across
    /// every bridge (ADR-046). See the `verifying_key_hex` field docs
    /// for why `#0` rather than `#active`.
    #[must_use]
    pub fn verifying_key(&self) -> Option<String> {
        self.verifying_key_hex.clone()
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
        // Phase D (#1695): lifecycle gate deleted along with
        // `DEFAULT_BRIDGE_INSTANCE`. The handle's own custody `Arc` keeps
        // the signing key material alive; DID resolver state is now owned
        // per-`Scp` (via `UniffiBridgeInstance`) and no longer process-wide.
        let core_id = self.core_id.as_ref().ok_or_else(|| ScpError::Identity {
            msg: "key rotation requires retained crypto state — this identity \
                      was loaded without key material (use identity_create or \
                      identity_create_with_custody)"
                .to_owned(),
            code: codes::IDENT_1002.to_owned(),
        })?;

        // Dispatch to the correct custody path.
        if let Some(ref callback) = self.callback_custody {
            // Platform/software custody: rotate via CallbackKeyCustody.
            let dht = DidDht::new();
            let (new_identity, new_document) = dht
                .rotate(core_id, callback.as_ref())
                .await
                .map_err(ScpError::from)?;

            let verifying_key_hex =
                snapshot_verifying_key_hex(callback.as_ref(), &new_identity.identity_key).await;

            let handle = Arc::new(Self {
                did: new_identity.did.clone(),
                custody_type: self.custody_type.clone(),
                core_id: Some(new_identity),
                core_document: Some(new_document),
                #[cfg(feature = "allow_in_memory_custody")]
                in_memory_custody: None,
                callback_custody: self.callback_custody.clone(),
                verifying_key_hex,
                instance_id: self.instance_id,
                rotation_event_json: None,
                // `rotate` (active-signing-key rotation) does NOT mint a new
                // pre-rotation commitment, so the per-identity pre-rotation
                // custody and handle are preserved verbatim. Only
                // `migrate_identity` (DID rotation) consumes the existing
                // pre-rotation handle and produces a fresh one.
                pre_rotation_handle: self.pre_rotation_handle,
                pre_rotation_custody: Arc::clone(&self.pre_rotation_custody),
            });
            increment_handle_count();
            return Ok(handle);
        }

        #[cfg(feature = "allow_in_memory_custody")]
        if let Some(ref custody) = self.in_memory_custody {
            let dht = make_dht_with_signer(custody)?;
            let (new_identity, new_document) = dht
                .rotate(core_id, &custody.0)
                .await
                .map_err(ScpError::from)?;

            let verifying_key_hex =
                snapshot_verifying_key_hex(&custody.0, &new_identity.identity_key).await;

            let handle = Arc::new(Self {
                did: new_identity.did.clone(),
                custody_type: CustodyMethod::InMemory,
                core_id: Some(new_identity),
                core_document: Some(new_document),
                in_memory_custody: self.in_memory_custody.clone(),
                callback_custody: None,
                verifying_key_hex,
                instance_id: self.instance_id,
                rotation_event_json: None,
                // See note above: active-key rotation preserves the
                // pre-rotation custody and handle.
                pre_rotation_handle: self.pre_rotation_handle,
                pre_rotation_custody: Arc::clone(&self.pre_rotation_custody),
            });
            increment_handle_count();
            return Ok(handle);
        }

        Err(ScpError::Identity {
            msg: "key rotation requires a custody provider — use \
                      identity_create_with_custody() for platform custody or \
                      identity_create(\"in_memory\") for dev/test"
                .to_owned(),
            code: codes::IDENT_1002.to_owned(),
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
        // Phase D (#1695): lifecycle gate deleted — handle's own custody
        // `Arc` keeps state alive; DID resolver is per-`Scp` now.
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            Err(ScpError::Identity {
                msg: "agent key operations require in-memory custody — \
                          enable the \"allow_in_memory_custody\" feature or use \
                          the platform KeyCustodyProvider interface"
                    .to_owned(),
                code: codes::IDENT_1008.to_owned(),
            })
        }

        #[cfg(feature = "allow_in_memory_custody")]
        {
            let core_id = self.core_id.as_ref().ok_or_else(|| ScpError::Identity {
                msg: "cannot add agent key to an external/loaded identity \
                          without core state — use identity_create first"
                    .to_owned(),
                code: codes::IDENT_1005.to_owned(),
            })?;
            let core_doc = self
                .core_document
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "cannot add agent key without a retained DID document".to_owned(),
                    code: codes::IDENT_1005.to_owned(),
                })?;
            let custody = self
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "cannot add agent key without in-memory custody".to_owned(),
                    code: codes::IDENT_1008.to_owned(),
                })?
                .clone();

            // Clone what we need for the spawned task.
            let identity_clone = core_id.clone();
            let doc_clone = core_doc.clone();
            let did = self.did.clone();
            let custody_type = self.custody_type.clone();
            let in_memory_custody = Some(custody.clone());
            let instance_id = self.instance_id;
            // Agent-key operations don't change the pre-rotation commitment
            // — preserve the existing handle and custody.
            let pre_rotation_handle = self.pre_rotation_handle;
            let pre_rotation_custody = Arc::clone(&self.pre_rotation_custody);
            let dht = make_dht_with_signer(&custody)?;

            runtime()
                .spawn(async move {
                    let (updated_identity, updated_doc) = dht
                        .add_agent_key(&identity_clone, &doc_clone, &custody.0)
                        .await
                        .map_err(ScpError::from)?;

                    let verifying_key_hex =
                        snapshot_verifying_key_hex(&custody.0, &updated_identity.identity_key)
                            .await;

                    let handle = Arc::new(Self {
                        did,
                        custody_type,
                        core_id: Some(updated_identity),
                        core_document: Some(updated_doc),
                        in_memory_custody,
                        callback_custody: None,
                        verifying_key_hex,
                        instance_id,
                        rotation_event_json: None,
                        pre_rotation_handle,
                        pre_rotation_custody,
                    });
                    increment_handle_count();
                    Ok(handle)
                })
                .await
                .map_err(|e| ScpError::Identity {
                    msg: format!("tokio task join error during add_agent_key: {e}"),
                    code: codes::IDENT_1007.to_owned(),
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
        // Phase D (#1695): lifecycle gate deleted — handle's own custody
        // `Arc` keeps state alive; DID resolver is per-`Scp` now.
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            Err(ScpError::Identity {
                msg: "agent key operations require in-memory custody — \
                          enable the \"allow_in_memory_custody\" feature or use \
                          the platform KeyCustodyProvider interface"
                    .to_owned(),
                code: codes::IDENT_1008.to_owned(),
            })
        }

        #[cfg(feature = "allow_in_memory_custody")]
        {
            let core_id = self.core_id.as_ref().ok_or_else(|| ScpError::Identity {
                msg: "cannot remove agent key from an external/loaded identity \
                          without core state"
                    .to_owned(),
                code: codes::IDENT_1005.to_owned(),
            })?;
            let core_doc = self
                .core_document
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "cannot remove agent key without a retained DID document".to_owned(),
                    code: codes::IDENT_1005.to_owned(),
                })?;

            let custody = self
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "cannot remove agent key without in-memory custody \
                              (needed for DHT publish signing)"
                        .to_owned(),
                    code: codes::IDENT_1008.to_owned(),
                })?;

            // Clone what we need for the spawned task.
            let identity_clone = core_id.clone();
            let doc_clone = core_doc.clone();
            let did = self.did.clone();
            let custody_type = self.custody_type.clone();
            let in_memory_custody = self.in_memory_custody.clone();
            let instance_id = self.instance_id;
            // Agent-key operations don't change the pre-rotation commitment
            // — preserve the existing handle and custody.
            let pre_rotation_handle = self.pre_rotation_handle;
            let pre_rotation_custody = Arc::clone(&self.pre_rotation_custody);
            let dht = make_dht_with_signer(custody)?;

            let custody_for_key = custody.clone();
            runtime()
                .spawn(async move {
                    let (updated_identity, updated_doc) = dht
                        .remove_agent_key(&identity_clone, &doc_clone)
                        .await
                        .map_err(ScpError::from)?;

                    let verifying_key_hex = snapshot_verifying_key_hex(
                        &custody_for_key.0,
                        &updated_identity.identity_key,
                    )
                    .await;

                    let handle = Arc::new(Self {
                        did,
                        custody_type,
                        core_id: Some(updated_identity),
                        core_document: Some(updated_doc),
                        in_memory_custody,
                        callback_custody: None,
                        verifying_key_hex,
                        instance_id,
                        rotation_event_json: None,
                        pre_rotation_handle,
                        pre_rotation_custody,
                    });
                    increment_handle_count();
                    Ok(handle)
                })
                .await
                .map_err(|e| ScpError::Identity {
                    msg: format!("tokio task join error during remove_agent_key: {e}"),
                    code: codes::IDENT_1007.to_owned(),
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
        // Phase D (#1695): lifecycle gate deleted — handle's own custody
        // `Arc` keeps state alive; DID resolver is per-`Scp` now.
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            Err(ScpError::Identity {
                msg: "agent key operations require in-memory custody — \
                          enable the \"allow_in_memory_custody\" feature or use \
                          the platform KeyCustodyProvider interface"
                    .to_owned(),
                code: codes::IDENT_1008.to_owned(),
            })
        }

        #[cfg(feature = "allow_in_memory_custody")]
        {
            let core_id = self.core_id.as_ref().ok_or_else(|| ScpError::Identity {
                msg: "cannot rotate agent key on an external/loaded identity \
                          without core state"
                    .to_owned(),
                code: codes::IDENT_1005.to_owned(),
            })?;
            let core_doc = self
                .core_document
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "cannot rotate agent key without a retained DID document".to_owned(),
                    code: codes::IDENT_1005.to_owned(),
                })?;
            let custody = self
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "cannot rotate agent key without in-memory custody".to_owned(),
                    code: codes::IDENT_1008.to_owned(),
                })?
                .clone();

            // Clone what we need for the spawned task.
            let identity_clone = core_id.clone();
            let doc_clone = core_doc.clone();
            let did = self.did.clone();
            let custody_type = self.custody_type.clone();
            let in_memory_custody = Some(custody.clone());
            let instance_id = self.instance_id;
            // Agent-key rotation doesn't change the pre-rotation commitment
            // — preserve the existing handle and custody.
            let pre_rotation_handle = self.pre_rotation_handle;
            let pre_rotation_custody = Arc::clone(&self.pre_rotation_custody);
            let dht = make_dht_with_signer(&custody)?;

            runtime()
                .spawn(async move {
                    let (updated_identity, updated_doc) = dht
                        .rotate_agent_key(&identity_clone, &doc_clone, &custody.0)
                        .await
                        .map_err(ScpError::from)?;

                    let verifying_key_hex =
                        snapshot_verifying_key_hex(&custody.0, &updated_identity.identity_key)
                            .await;

                    let handle = Arc::new(Self {
                        did,
                        custody_type,
                        core_id: Some(updated_identity),
                        core_document: Some(updated_doc),
                        in_memory_custody,
                        callback_custody: None,
                        verifying_key_hex,
                        instance_id,
                        rotation_event_json: None,
                        pre_rotation_handle,
                        pre_rotation_custody,
                    });
                    increment_handle_count();
                    Ok(handle)
                })
                .await
                .map_err(|e| ScpError::Identity {
                    msg: format!("tokio task join error during rotate_agent_key: {e}"),
                    code: codes::IDENT_1007.to_owned(),
                })?
        }
    }
}

impl Drop for Identity {
    /// Decrements the global FFI handle count.
    ///
    /// Called when the last `Arc<Identity>` is dropped, releasing the handle.
    /// This allows `crate::scp_shutdown` to detect when all handles are
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
    /// Retained [`InMemoryKeyCustody`] for UCAN signing.
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
    /// Handle to the creator's active signing key for UCAN minting.
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
    /// Core context parameters, retained for `finalize_close` (`memory_scope`
    /// governs key destruction) and `restore_context`.
    pub(crate) core_context_params: scp_core::context::ContextParams,
    /// Monotonic identifier of the bridge instance that minted this handle.
    ///
    /// Consumed by [`uniffi_check_handle!`](crate::uniffi_check_handle) at
    /// every `#[uniffi::export]` entry that accepts a `ContextHandle`.
    /// Mismatches map to `ScpError::Permission` with code `SCP-PERM-3030`.
    pub(crate) instance_id: u64,
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

impl ContextHandle {
    /// Returns the monotonic identifier of the bridge instance that minted
    /// this handle.
    ///
    /// Rust-internal only: consumed by `CoreFields::check_handle` for
    /// per-instance handle affinity. NOT exposed through `#[uniffi::export]`
    /// (see ADR-048 — per-handle `instanceId` is not host-visible).
    #[must_use]
    pub(crate) const fn instance_id(&self) -> u64 {
        self.instance_id
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
    /// One of: `"creating"`, `"active"`, `"closing"`, `"closed"`, `"expired"`,
    /// `"migrating_out"`, `"tombstoned"`.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` if the state lock is poisoned.
    pub fn state(&self) -> Result<String, ScpError> {
        let guard = self.state.try_lock().map_err(|_| ScpError::Context {
            msg: "context state lock is contended — retry".to_owned(),
            code: codes::CTX_2012.to_owned(),
        })?;
        Ok(match *guard {
            ContextState::Creating => "creating".to_owned(),
            ContextState::Active => "active".to_owned(),
            ContextState::Closing => "closing".to_owned(),
            ContextState::Closed => "closed".to_owned(),
            ContextState::Expired => "expired".to_owned(),
            ContextState::MigratingOut => "migrating_out".to_owned(),
            ContextState::Tombstoned => "tombstoned".to_owned(),
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
    /// `crate::scp_shutdown` to detect when all handles are released
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
    /// Raw encoded JWT string — used by `ucan_revoke` and `ucan_validate`.
    pub(crate) encoded: String,
    /// Monotonic identifier of the bridge instance that minted this handle.
    ///
    /// Affinity substrate: retained so that any future `#[uniffi::export]`
    /// entry accepting a `UcanToken` can gate on
    /// `CoreFields::check_handle(token.instance_id())`. No such entry exists
    /// today (`UcanToken` is only ever returned, never passed back in), so the
    /// field has no live reader — hence `#[allow(dead_code)]`. It is NOT
    /// host-visible (see ADR-048 — per-handle `instanceId` is not exported).
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
}

impl UcanToken {
    /// Returns the monotonic identifier of the bridge instance that minted
    /// this handle.
    ///
    /// Rust-internal affinity substrate consumed by
    /// `CoreFields::check_handle`. No caller passes a `UcanToken` back across
    /// the FFI boundary yet, so this has no live caller — hence
    /// `#[allow(dead_code)]`. NOT exposed through `#[uniffi::export]`
    /// (see ADR-048 — per-handle `instanceId` is not host-visible).
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn instance_id(&self) -> u64 {
        self.instance_id
    }
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

    /// Returns the full encoded JWT string of this token.
    ///
    /// Needed for revocation (`ucan_revoke`) and validation (`ucan_validate`)
    /// which operate on the raw JWT.
    #[must_use]
    pub fn encoded(&self) -> String {
        self.encoded.clone()
    }
}

// `ucan_mint` calls `increment_handle_count()`, so this `Drop` impl
// decrements the counter to maintain `scp_shutdown` handle-drain
// correctness.
impl Drop for UcanToken {
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

/// Opaque handle to the transport layer.
///
/// Wraps a real [`scp_transport::TransportManager`] that is stored in the
/// shared [`UniffiBridgeInstance`](crate::runtime::UniffiBridgeInstance).
/// This handle provides Swift/Kotlin callers with
/// the full multi-relay API: `addRelay`, `assignRelaySet`, `adapterCount`,
/// `reliabilityScore`. All operations delegate to the `BridgeInstance`'s
/// transport slot, so `suspend()` / `shutdown()` lifecycle events
/// automatically clear the transport.
///
/// Generated as `class TransportManager` in both Swift and Kotlin.
///
/// See ADR-005 (Transport Abstraction) and ADR-012 (Multi-transport routing).
#[derive(uniffi::Object)]
pub struct TransportManager {
    /// Current connection state (relay URL, latency).
    pub(crate) status: std::sync::Mutex<TransportStatus>,
    /// Owning `UniffiBridgeInstance` whose `CoreFields::transport` slot this
    /// handle operates against.
    ///
    /// Phase D (#1695) replaces the old process-wide `DEFAULT_BRIDGE_INSTANCE`
    /// lookup with a per-handle `Arc` — the `Scp` that minted the handle
    /// keeps its transport state alive through this field, and
    /// `suspend()`/`shutdown()` on that `Scp` transparently clears the
    /// transport the handle reads from.
    pub(crate) bi: Arc<crate::runtime::UniffiBridgeInstance>,
    /// Monotonic identifier of the bridge instance that minted this handle.
    ///
    /// Consumed by [`uniffi_check_handle!`](crate::uniffi_check_handle) at
    /// every `#[uniffi::export]` entry that accepts a `TransportManager`.
    pub(crate) instance_id: u64,
}

impl fmt::Debug for TransportManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let adapter_count = self
            .bi
            .core
            .with_transport(scp_transport::TransportManager::adapter_count)
            .unwrap_or(0);
        f.debug_struct("TransportManager")
            .field("adapter_count", &adapter_count)
            .finish_non_exhaustive()
    }
}

/// Per-adapter reliability score record exposed to Swift/Kotlin.
///
/// Contains the key fields from [`scp_transport::scoring::ReliabilityScore`]
/// needed for relay health monitoring and selection decisions.
///
/// See ADR-012 acceptance criterion 5.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ReliabilityScoreRecord {
    /// The relay URL this score tracks.
    pub relay_url: String,
    /// Delivery success rate (0.0 to 1.0).
    pub delivery_success_rate: f64,
    /// Average latency in milliseconds.
    pub average_latency_ms: u64,
    /// Deletion compliance rate (0.0 to 1.0).
    pub deletion_compliance_rate: f64,
    /// Total number of send attempts.
    pub total_sends: u64,
    /// Total number of send failures.
    pub total_failures: u64,
}

impl TransportManager {
    /// Returns the monotonic identifier of the bridge instance that minted
    /// this handle.
    ///
    /// Rust-internal only: consumed by `CoreFields::check_handle` for
    /// per-instance handle affinity. NOT exposed through `#[uniffi::export]`
    /// (see ADR-048 — per-handle `instanceId` is not host-visible).
    #[must_use]
    pub(crate) const fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

#[uniffi::export]
impl TransportManager {
    /// Returns the current transport connection status record.
    ///
    /// Reflects actual connection state: `connected` is `true` only if the
    /// inner transport manager has at least one adapter registered.
    pub fn status(&self) -> TransportStatus {
        let has_adapters = self
            .bi
            .core
            .with_transport(|mgr| mgr.adapter_count() > 0)
            .unwrap_or(false);
        let status = self.status.lock().map_or(
            TransportStatus {
                connected: false,
                relay_url: None,
                latency_ms: None,
            },
            |s| s.clone(),
        );
        TransportStatus {
            connected: has_adapters && status.connected,
            relay_url: if has_adapters { status.relay_url } else { None },
            latency_ms: status.latency_ms,
        }
    }

    /// Returns `true` if the transport is currently connected (has adapters).
    pub fn is_connected(&self) -> bool {
        self.bi
            .core
            .with_transport(|mgr| mgr.adapter_count() > 0)
            .unwrap_or(false)
    }

    /// Returns the number of adapters registered in the transport manager.
    #[allow(clippy::cast_possible_truncation)] // Adapter count is bounded by connection budget (<<u32::MAX).
    pub fn adapter_count(&self) -> u32 {
        self.bi
            .core
            .with_transport(|mgr| mgr.adapter_count() as u32)
            .unwrap_or(0)
    }

    /// Registers an additional relay adapter with the transport manager.
    ///
    /// Connects to the specified relay URL and adds the resulting adapter to
    /// the manager. Returns the total adapter count after adding.
    ///
    /// # Arguments
    ///
    /// * `relay_url` -- The URL of the additional SCP relay to connect to.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Transport` if the URL is invalid or the connection
    /// fails.
    pub fn add_relay(self: Arc<Self>, relay_url: String) -> Result<u32, ScpError> {
        use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

        validate_relay_url(&relay_url)?;

        // Phase D (#1695): the handle's `bi` field is the owning
        // `UniffiBridgeInstance` — mutate its transport slot directly.
        let rt = runtime();
        let sourced = SourcedRelayUrl {
            url: relay_url.clone(),
            source: RelayUrlSource::Explicit,
        };
        // Route through the instance-scoped transport selector for transparent
        // QUIC↔WebSocket selection (spec §10.14.3 item 4; ADR-037). The
        // discovering variant reads the relay's advertised transports from
        // `.well-known/scp` (spec §10.5.1) at connect time to enable QUIC,
        // failing open to WebSocket when discovery is unavailable. Cover traffic
        // auto-starts per adapter via the profile inside `finalize_connection`
        // (#1532 AC6). The selector surfaces the suppression receiver (drained
        // into reliability scoring, #1533 AC5). Mirrors the PyO3 reference
        // bridge's `transport_add_relay`.
        let profile = scp_transport::profile::TransportProfile::platform_default();
        let selector = self.bi.core.transport_selector();
        let (adapter, suppression_rx) = rt
            .block_on(async {
                selector
                    .select_and_connect_discovering_with_suppression(&sourced, Some(&profile))
                    .await
            })
            .map_err(ScpError::from)?;

        let count = self
            .bi
            .core
            .with_transport_mut(|mgr| {
                let _eviction = mgr.add_adapter(adapter);
                #[allow(clippy::cast_possible_truncation)] // Bounded by connection budget.
                let count = mgr.adapter_count() as u32;
                count
            })
            .map_err(|e| ScpError::Transport {
                msg: e.to_string(),
                code: codes::TRANS_5003.to_owned(),
            })?;

        // Spawn suppression → scoring bridge task against this handle's
        // owning `UniffiBridgeInstance`.
        //
        // Pass `Weak<UniffiBridgeInstance>` + the instance's cancel token
        // so the task cannot pin the instance alive. See the
        // `spawn_suppression_scoring_task` doc comment for the Arc-cycle
        // rationale (#1549 round-2 bug-catcher).
        if let Some(rx) = suppression_rx {
            spawn_suppression_scoring_task(
                Arc::downgrade(&self.bi),
                self.bi.core.cancel_token(),
                rx,
                relay_url,
            );
        }

        Ok(count)
    }

    /// Assigns a relay set for the given context.
    ///
    /// Delegates to [`scp_transport::TransportManager::assign_relay_set`]
    /// which selects adapters using round-robin spread to minimize overlap.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context to assign relays for.
    ///
    /// # Returns
    ///
    /// A list of adapter indices assigned to this context.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Transport` if no adapters are registered.
    pub fn assign_relay_set(&self, context_id: String) -> Result<Vec<u32>, ScpError> {
        validate_context_id(&context_id)?;
        // Phase D (#1695): mutate this handle's owning instance's transport.
        let indices = self
            .bi
            .core
            .with_transport(|mgr| {
                mgr.assign_relay_set(&context_id)
                    .map_err(|e| ScpError::Transport {
                        msg: format!("relay set assignment failed: {e}"),
                        code: codes::TRANS_5004.to_owned(),
                    })
            })
            .map_err(|e| ScpError::Transport {
                msg: e.to_string(),
                code: codes::TRANS_5003.to_owned(),
            })??;
        #[allow(clippy::cast_possible_truncation)] // Adapter indices bounded by adapter count.
        Ok(indices.into_iter().map(|i| i as u32).collect())
    }

    /// Returns the reliability score for an adapter by index.
    ///
    /// Returns `None` if no score exists for the given adapter index.
    ///
    /// # Arguments
    ///
    /// * `adapter_index` -- The adapter index (0-based) to query.
    pub fn reliability_score(&self, adapter_index: u32) -> Option<ReliabilityScoreRecord> {
        let score = self
            .bi
            .core
            .with_transport(|mgr| mgr.get_reliability_score(adapter_index as usize))
            .ok()??;
        Some(ReliabilityScoreRecord {
            relay_url: score.relay_url.clone(),
            delivery_success_rate: score.delivery_success_rate,
            average_latency_ms: score.average_latency_ms,
            deletion_compliance_rate: score.deletion_compliance_rate,
            total_sends: score.total_sends,
            total_failures: score.total_failures,
        })
    }
}

impl Drop for TransportManager {
    /// Decrements the global FFI handle count.
    ///
    /// Called when the last `Arc<TransportManager>` is dropped. This allows
    /// `crate::scp_shutdown` to detect when all handles are released
    /// before tearing down the tokio runtime.
    fn drop(&mut self) {
        decrement_handle_count();
    }
}

// ---------------------------------------------------------------------------
// Suppression → scoring bridge task
// ---------------------------------------------------------------------------

/// Spawns a background task that drains heartbeat suppression events from a
/// per-adapter receiver and records each as a delivery failure in the
/// `TransportManager`'s reliability scoring.
///
/// This bridges the per-adapter heartbeat monitor (spec §9.9.2) with the
/// `TransportManager`'s cross-relay `SuppressionTracker` (spec §9.9.4,
/// #1533 AC5). Each suppression event downgrades the relay's reliability
/// score via `DeliveryOutcome::Failure`.
///
/// # Arc-cycle avoidance (#1549 round-2 bug-catcher)
///
/// The bridge instance is captured as a [`std::sync::Weak`], not an `Arc`.
/// Holding an `Arc<UniffiBridgeInstance>` here would keep the instance
/// alive forever because this task is spawned on the shared tokio runtime
/// (`crate::runtime().spawn(...)`) and is NOT enrolled in the per-instance
/// [`JoinSet`](scp_ffi_common::bridge_instance::CoreFields::task_handle)
/// that `emergency_cancel_tasks` aborts.
///
/// # Runtime context (must spawn on the shared runtime handle)
///
/// This is spawned via `crate::runtime().spawn(...)` — the shared
/// `&'static tokio::runtime::Runtime` handle — NOT a bare
/// `tokio::spawn(...)`. The sole sync caller, `TransportManager::add_relay`,
/// is a sync `#[uniffi::export]` method, which `UniFFI` runs on the foreign
/// caller thread with NO ambient tokio runtime entered. After
/// `add_relay`'s internal `runtime().block_on(...)` returns, the runtime
/// context is gone, so a bare `tokio::spawn(...)` would panic ("there is no
/// reactor running"). Spawning through the runtime handle works regardless
/// of ambient context. This mirrors the `PyO3` reference bridge's
/// `spawn_suppression_scoring_task` (`crates/scp-ffi/src/transport.rs`),
/// which uses `rt.spawn(...)` for the same reason.
///
/// Without a `Weak`, dropping the last `Arc<UniffiBridgeInstance>` from
/// the caller side would not actually drop the instance: the task body
/// holds a strong reference, the task never exits on its own (the
/// `recv()` future is awaited until the relay adapter closes its
/// sender), and so the `ContextManager`, identity registry, relay
/// connection, and the rest of `BridgeInstance`'s state would leak for
/// the remainder of the process.
///
/// The task exits gracefully when:
/// 1. The sender half is dropped (adapter dropped or disconnected), OR
/// 2. The `cancel_token` fires (instance shutdown via Drop), OR
/// 3. `Weak::upgrade` returns `None` (the instance has been dropped).
fn spawn_suppression_scoring_task(
    bi: std::sync::Weak<crate::runtime::UniffiBridgeInstance>,
    cancel_token: tokio_util::sync::CancellationToken,
    mut rx: tokio::sync::mpsc::Receiver<scp_transport::heartbeat::SuppressionSuspected>,
    relay_url: String,
) {
    // Spawn on the shared runtime handle, not a bare `tokio::spawn`: the sync
    // `TransportManager::add_relay` caller runs outside any tokio runtime
    // context (see this fn's doc comment), so a bare spawn would panic.
    crate::runtime().spawn(async move {
        loop {
            let suppression = tokio::select! {
                () = cancel_token.cancelled() => {
                    tracing::debug!(
                        relay_url = %relay_url,
                        "suppression scoring task exiting — bridge instance cancelled"
                    );
                    break;
                }
                ev = rx.recv() => ev,
            };
            if suppression.is_none() {
                // Sender dropped (adapter disconnected).
                break;
            }
            // Upgrade on every event so a dropped instance releases the Arc
            // immediately on the next iteration rather than pinning it alive
            // for the remainder of the relay session.
            let Some(bi_arc) = bi.upgrade() else {
                tracing::debug!(
                    relay_url = %relay_url,
                    "suppression scoring task exiting — bridge instance dropped"
                );
                break;
            };
            if bi_arc.core.is_shutdown() {
                // Bridge shut down — exit gracefully.
                break;
            }
            tracing::debug!(
                relay_url = %relay_url,
                "heartbeat suppression → downgrading relay reliability score"
            );
            let _ = bi_arc.core.with_transport(|inner| {
                inner.update_score(&relay_url, scp_transport::scoring::DeliveryOutcome::Failure);
            });
            // Drop the Arc before the next `recv().await` so the caller's
            // `Arc::strong_count` can reach zero while this task is parked.
            drop(bi_arc);
        }
        tracing::debug!(
            relay_url = %relay_url,
            "suppression scoring task exited — adapter disconnected"
        );
    });
}

// ---------------------------------------------------------------------------
// Identity operations — implementation helpers
//
// See ADR-021 acceptance criterion 2. Entry points are the `Scp` methods
// later in this file; each method calls into a matching `_impl` helper
// here after running the affinity check and acquiring the per-instance
// DID resolver slot.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Device attestation — implementation helpers (#419)
//
// See §9.3 (Sybil Resistance and Identity Uniqueness). Dispatched from the
// `Scp::identity_attest_device` / `identity_verify_device_attestation`
// methods.
// ---------------------------------------------------------------------------

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
                    msg: "device attestation requires retained identity state — the identity \
                          was externally loaded via identity_load"
                        .to_owned(),
                    code: codes::IDENT_1007.to_owned(),
                })?;

            let attestation = InMemoryDeviceAttestation::new();
            let token = attestation.attest().await.map_err(|e| ScpError::Identity {
                msg: format!("device attestation failed: {e}"),
                code: codes::IDENT_1010.to_owned(),
            })?;

            use base64::Engine;
            Ok(base64::engine::general_purpose::STANDARD.encode(token.as_bytes()))
        })
        .await
        .map_err(|e| ScpError::Identity {
            msg: format!("tokio task join error during device attestation: {e}"),
            code: codes::IDENT_1007.to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)]
async fn identity_attest_device_impl(_identity: Arc<Identity>) -> Result<String, ScpError> {
    Err(ScpError::Identity {
        msg: "device attestation requires in-memory custody — the in_memory custody \
                  path is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use."
            .to_owned(),
        code: codes::IDENT_1010.to_owned(),
    })
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
                    msg: format!("invalid base64 attestation token: {e}"),
                    code: codes::IDENT_1011.to_owned(),
                })?;

            let token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
            let attestation = InMemoryDeviceAttestation::new();

            attestation
                .verify(&token)
                .await
                .map_err(|e| ScpError::Identity {
                    msg: format!("device attestation verification failed: {e}"),
                    code: codes::IDENT_1012.to_owned(),
                })
        })
        .await
        .map_err(|e| ScpError::Identity {
            msg: format!("tokio task join error during device attestation verification: {e}"),
            code: codes::IDENT_1007.to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)]
async fn identity_verify_device_attestation_impl(
    _did: String,
    _token_base64: String,
) -> Result<bool, ScpError> {
    Err(ScpError::Identity {
        msg: "device attestation verification requires in-memory custody — the in_memory \
                  custody path is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use."
            .to_owned(),
        code: codes::IDENT_1010.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Free functions — identity link attestation (§3.5.1, §3.5.2)
//
// Uses a global DashMap to store attestations per DID. The Identity object
// retains custody for signing; attestations are stored separately.
// ---------------------------------------------------------------------------

/// Maximum number of entries in the identity custody registry.
#[cfg(feature = "allow_in_memory_custody")]
const UNIFFI_CUSTODY_REGISTRY_CAP: usize = 10_000;

/// Maximum number of DID entries in the identity link attestation registry.
#[cfg(feature = "allow_in_memory_custody")]
const UNIFFI_LINK_ATTESTATION_REGISTRY_CAP: usize = 10_000;

#[cfg(feature = "allow_in_memory_custody")]
use scp_ffi_common::validate::MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID;

/// Returns a reference to this `UniffiBridgeInstance`'s identity link
/// attestation registry.
///
/// Migrated from a process-global `OnceLock<DashMap<...>>` singleton onto the
/// typed `identity_link_attestation_registry` field on
/// [`crate::runtime::UniffiBridgeInstance`] in #1549 Phase 4 PR 2 commit 6.
/// Phase D (#1695) deletes the empty-fallback branch — every caller now
/// threads through its owning `Scp`.
fn identity_link_attestation_registry(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
) -> &dashmap::DashMap<String, Vec<scp_core::identity::attestation::IdentityLinkAttestation>> {
    bi.identity_link_attestation_registry().as_ref()
}

/// Retained identity custody for attestation verification (keyed by DID).
///
/// Stores the custody and active signing key handle for identities that have
/// created attestations, so that `identity_verify_link_attestation` can look
/// up the issuer's public key without requiring the caller to pass the
/// Identity object.
///
/// Phase D (#1695): operates directly on the caller's `Scp`'s
/// `UniffiBridgeInstance` — there is no process-wide fallback.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn identity_custody_registry(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
) -> &dashmap::DashMap<String, (Arc<OpaqueInMemoryKeyCustody>, scp_platform::KeyHandle)> {
    bi.identity_custody_registry.as_ref()
}

/// Registers an in-memory identity's custody + active signing key in the
/// per-instance identity custody registry, keyed by `did`.
///
/// Shared by `identity_create` (so a freshly created in-memory identity is
/// immediately present in the registry, matching the NAPI bridge whose
/// `identity_create` registers a bundled entry) and the link-attestation
/// path (which needs the custody retained for later re-signing). Centralizing
/// the entry/cap logic keeps the two call sites in sync and avoids duplicating
/// the TOCTOU-safe capacity check.
///
/// Uses the `entry()` API to avoid a TOCTOU window between `contains_key` and
/// `insert`:
/// - Occupied: always updates to the caller's current key. The `UniFFI`
///   `Identity` is an immutable `Arc` snapshot — the held key is the one the
///   caller signs with; after a legitimate rotation the stale handle is
///   replaced.
/// - Vacant: enforces `UNIFFI_CUSTODY_REGISTRY_CAP` before inserting,
///   surfacing `SCP-VALID-7403` on overflow.
#[cfg(feature = "allow_in_memory_custody")]
fn register_identity_custody(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    did: &str,
    custody: &Arc<OpaqueInMemoryKeyCustody>,
    active_key: scp_platform::KeyHandle,
) -> Result<(), ScpError> {
    use scp_ffi_common::error_codes as codes;

    let registry = identity_custody_registry(bi);
    let len = registry.len();
    match registry.entry(did.to_owned()) {
        dashmap::mapref::entry::Entry::Occupied(mut occ) => {
            occ.insert((Arc::clone(custody), active_key));
        }
        dashmap::mapref::entry::Entry::Vacant(vac) => {
            if len >= UNIFFI_CUSTODY_REGISTRY_CAP {
                return Err(ScpError::Identity {
                    msg: format!(
                        "custody registry has reached capacity \
                         ({UNIFFI_CUSTODY_REGISTRY_CAP}) — cannot store additional entries"
                    ),
                    code: codes::VALID_7403.to_owned(),
                });
            }
            vac.insert((Arc::clone(custody), active_key));
        }
    }
    Ok(())
}

/// Creates an identity link attestation for an external platform identity.
///
/// See spec §3.5.1, §3.5.2.
#[cfg(feature = "allow_in_memory_custody")]
async fn identity_create_link_attestation_impl(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    identity: Arc<Identity>,
    platform: String,
    handle: String,
    proof: String,
    verification_method: String,
    platform_id: Option<String>,
) -> Result<String, ScpError> {
    use scp_ffi_common::error_codes as codes;
    use scp_platform::traits::KeyCustody;

    // Validate attestation input field sizes.
    scp_ffi_common::validate::validate_attestation_fields(&platform, &handle, &proof).map_err(
        |e| ScpError::Validation {
            msg: format!("attestation field validation failed: {e}"),
            code: codes::VALID_7037.to_owned(),
        },
    )?;

    let core_id = identity
        .core_id
        .as_ref()
        .ok_or_else(|| ScpError::Identity {
            msg: "identity link attestation requires retained identity state".to_owned(),
            code: codes::IDENT_1040.to_owned(),
        })?;
    let custody = identity
        .in_memory_custody
        .as_ref()
        .ok_or_else(|| ScpError::Identity {
            msg: "identity link attestation requires in-memory custody".to_owned(),
            code: codes::IDENT_1040.to_owned(),
        })?;

    // Build unsigned attestation using shared pipeline.
    let built = scp_ffi_common::attestation::build_unsigned_attestation(
        &identity.did,
        platform,
        handle,
        proof,
        &verification_method,
        platform_id,
    )
    .map_err(|e| {
        let code = match &e {
            scp_ffi_common::attestation::AttestationBuildError::InvalidMethod(_)
            | scp_ffi_common::attestation::AttestationBuildError::ClockError => codes::IDENT_1040,
            _ => codes::IDENT_1041,
        };
        ScpError::Identity {
            msg: e.to_string(),
            code: code.to_owned(),
        }
    })?;

    let mut attestation = built.attestation;

    let active_key = core_id.active_signing_key;
    let custody_clone = Arc::clone(custody);
    let canonical = built.canonical_bytes;

    let sig = runtime()
        .spawn(async move { custody_clone.0.sign(&active_key, &canonical).await })
        .await
        .map_err(|e| ScpError::Identity {
            msg: format!("tokio join error: {e}"),
            code: codes::IDENT_1041.to_owned(),
        })?
        .map_err(|e| ScpError::Identity {
            msg: format!("Ed25519 signing failed: {e}"),
            code: codes::IDENT_1041.to_owned(),
        })?;
    attestation.signature = sig.as_bytes().to_vec();

    // Store custody for later verification lookups. Shared with
    // `identity_create` so the registry contract stays in sync.
    register_identity_custody(bi, &identity.did, custody, active_key)?;

    // Use entry() API to avoid TOCTOU between contains_key and insert.
    {
        let registry = identity_link_attestation_registry(bi);
        let len = registry.len();
        match registry.entry(identity.did.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                if occ.get().len() >= MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID {
                    return Err(ScpError::Identity {
                        msg: format!(
                            "DID has reached the per-identity attestation limit \
                             ({MAX_IDENTITY_LINK_ATTESTATIONS_PER_DID}) — cannot store additional attestations"
                        ),
                        code: codes::VALID_7403.to_owned(),
                    });
                }
                occ.get_mut().push(attestation.clone());
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                if len >= UNIFFI_LINK_ATTESTATION_REGISTRY_CAP {
                    return Err(ScpError::Identity {
                        msg: format!(
                            "link attestation registry has reached capacity \
                             ({UNIFFI_LINK_ATTESTATION_REGISTRY_CAP}) — cannot store additional attestations"
                        ),
                        code: codes::VALID_7402.to_owned(),
                    });
                }
                vac.insert(vec![attestation.clone()]);
            }
        }
    }

    serde_json::to_string(&attestation).map_err(|e| ScpError::Identity {
        msg: format!("failed to serialize attestation: {e}"),
        code: codes::IDENT_1042.to_owned(),
    })
}

/// Resolves a DID to its document.
///
/// DID resolution uses a fresh `DidDht::new()` and reads zero per-instance
/// state — it is a pure helper per ADR-048 §1.
#[uniffi::export(async_runtime = "tokio")]
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
            msg: format!("tokio task join error during DID resolution: {e}"),
            code: codes::IDENT_1006.to_owned(),
        })?
}

/// Verifies a device attestation token.
///
/// Uses `InMemoryDeviceAttestation` to check the token format. ADR-048 §1:
/// pure helper, no per-instance state.
///
/// See §9.3.
#[uniffi::export(async_runtime = "tokio")]
pub async fn identity_verify_device_attestation(
    did: String,
    token_base64: String,
) -> Result<bool, ScpError> {
    identity_verify_device_attestation_impl(did, token_base64).await
}

/// Verifies the Ed25519 signature on an identity link attestation.
///
/// Signature verification is a pure function and does not require
/// in-memory custody — only the issuer's Ed25519 public key. ADR-048 §1:
/// pure helper, no per-instance state.
///
/// See spec §3.5.1.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)]
pub fn identity_verify_link_attestation(
    attestation_json: String,
    issuer_public_key_hex: String,
) -> Result<bool, ScpError> {
    use scp_core::identity::attestation::IdentityLinkAttestation;

    let attestation: IdentityLinkAttestation =
        serde_json::from_str(&attestation_json).map_err(|e| ScpError::Identity {
            msg: format!("failed to parse attestation JSON: {e}"),
            code: codes::IDENT_1044.to_owned(),
        })?;

    let pub_bytes = hex::decode(&issuer_public_key_hex).map_err(|e| ScpError::Identity {
        msg: format!("invalid issuer_public_key_hex: {e}"),
        code: codes::IDENT_1044.to_owned(),
    })?;
    Ok(attestation.verify_signature(&pub_bytes).is_ok())
}

// ---------------------------------------------------------------------------
// Free functions — context lifecycle operations
//
// See ADR-021 acceptance criterion 3.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — tool operations
//
// See ADR-021 acceptance criterion 4.
// ---------------------------------------------------------------------------

/// Validates a UCAN token for tool invocation authorization (`UniFFI` bridge).
///
/// Runs the full 11-step ADR-016 pipeline, requiring `tool_invoke:{tool_id}`
/// or `tool_invoke:*` capability. Extracted to keep `tool_invoke` focused.
fn validate_tool_ucan_uniffi(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
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
                msg: format!("malformed proof token: {e}"),
                code: codes::PERM_3002.to_owned(),
            })?;
            let cid = scp_core::crypto::ucan::mint::compute_cid(&proof_token);
            proofs.insert(cid, proof_token);
        }
    }
    let proof_resolver = scp_ffi_common::BridgeProofResolver { proofs };

    // Ensure UCAN state is registered for this context on the caller's instance.
    bi.ensure_ucan_registered(
        &handle.context_id,
        &handle.creator_did,
        &handle.ceiling_strings,
    );

    bi.with_ucan_state(&handle.context_id, |ucan_state| {
        let production_resolver = bi.did_resolver();
        let did_resolver = scp_ffi_common::DispatchDidResolver::new(production_resolver.as_deref());
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
            clock: &scp_primitives::SystemClock,
        };

        validate_tool_invocation_ucan(ucan_token, &handle.context_id, tool_id, &mut ctx).map_err(
            |e| ScpError::Permission {
                msg: format!("UCAN authorization failed for tool '{tool_id}': {e}"),
                code: codes::PERM_3002.to_owned(),
            },
        )
    })
    .ok_or_else(|| ScpError::Permission {
        msg: format!("context '{}' not found in UCAN registry", handle.context_id),
        code: codes::PERM_3002.to_owned(),
    })?
}

// ---------------------------------------------------------------------------
// Free functions — cross-context tool invocation (spec section 6.2)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — stateful tool sessions (spec section 6.2.1)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — bidirectional consent protocol (spec §6.2.0.1)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — transport operations
//
// See ADR-021 acceptance criterion 5.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — MCP operations
//
// MCP (Model Context Protocol) server and client operations for Swift/Kotlin.
// Mirrors the PyO3 and NAPI MCP bridges. See ADR-015.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MCP UniFFI records
// ---------------------------------------------------------------------------

/// Configuration for starting an MCP server.
#[derive(Debug, Clone, uniffi::Record)]
pub struct McpServerConfig {
    /// DID of the identity running the server.
    pub identity_did: String,
    /// Context IDs to expose via MCP.
    pub context_ids: Vec<String>,
    /// Transport mode: `"stdio"` or `"sse"`.
    pub transport: String,
    /// Optional JWT-encoded UCAN token for tool invocation authorization.
    ///
    /// When present, `validate_capability` runs the full 11-step ADR-016
    /// validation pipeline. When absent, capability validation rejects
    /// immediately (UCAN is required for tool invocation per §6.2).
    pub ucan_token: Option<String>,
    /// Optional proof tokens for UCAN delegation chain verification.
    pub proof_tokens: Option<Vec<String>>,
}

/// Tool definition from an external MCP server.
#[derive(Debug, Clone, uniffi::Record)]
pub struct McpToolInfo {
    /// Tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for tool input (as a JSON string).
    pub input_schema_json: String,
}

/// Result of invoking an external MCP tool with SCP provenance.
#[derive(Debug, Clone, uniffi::Record)]
pub struct McpInvokeResult {
    /// Tool output content as serialized JSON.
    pub content_json: String,
    /// Whether the tool call resulted in an error.
    pub is_error: bool,
    /// Source of the result, formatted as `"mcp:{tool_name}"`.
    pub source: String,
    /// DID of the invoking agent.
    pub invoked_by: String,
    /// SCP context ID for the invocation.
    pub context_id: String,
    /// Invocation timestamp (milliseconds since Unix epoch).
    pub timestamp: u64,
}

/// Snapshot of the current stdio allowlist state.
#[derive(Debug, Clone, uniffi::Record)]
pub struct McpAllowlistState {
    /// Sorted list of allowed binary basenames.
    pub allowed: Vec<String>,
    /// Whether the allowlist is bypassed entirely (unrestricted mode).
    pub unrestricted: bool,
}

// ---------------------------------------------------------------------------
// Context handle registry — maps context_id → Arc<ContextHandle>
//
// The MCP bridge provider needs to look up per-context state (tool registry,
// tool handlers, event log) by context ID, but UniFFI passes handles as
// opaque Arc<ContextHandle> objects. This registry bridges the gap by
// storing a weak reference to each active context handle, registered during
// context_create and deregistered during context_close/leave.
// ---------------------------------------------------------------------------

/// Returns a reference to this `UniffiBridgeInstance`'s context handle
/// registry.
///
/// Migrated from a process-global `OnceLock<DashMap<...>>` singleton onto the
/// typed `context_handle_registry` field on
/// [`crate::runtime::UniffiBridgeInstance`] in #1549 Phase 4 PR 2 commit 6.
/// Phase D (#1695) deletes the empty-fallback branch — every caller threads
/// through the owning `Scp`.
///
/// Used by `McpUniFfiBridgeProvider` to look up per-context tool registries,
/// handlers, and event log state. The `Arc<ContextHandle>` keeps the handle
/// alive as long as it is in the registry (the caller also holds an Arc).
fn context_handle_registry(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
) -> &dashmap::DashMap<String, Arc<ContextHandle>> {
    bi.context_handle_registry().as_ref()
}

/// Registers a context handle in the owning instance's registry.
///
/// Called from `context_create` after the handle is constructed. If a handle
/// with the same context ID is already registered, the old one is replaced
/// (last-writer-wins — should not happen in practice since context IDs are
/// UUIDs).
fn register_context_handle(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    handle: &Arc<ContextHandle>,
) {
    context_handle_registry(bi).insert(handle.context_id.clone(), Arc::clone(handle));
}

/// Removes a context handle from the owning instance's registry.
///
/// Called from `context_close` and `context_leave`. No-op if the context ID
/// is not registered.
fn deregister_context_handle(bi: &Arc<crate::runtime::UniffiBridgeInstance>, context_id: &str) {
    context_handle_registry(bi).remove(context_id);
}

// ---------------------------------------------------------------------------
// MCP registries
// ---------------------------------------------------------------------------

/// Internal state for a running MCP server.
pub(crate) struct McpServerEntry {
    /// Shutdown signal sender. Dropping this signals the transport task to stop.
    pub(crate) shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Handle to the tokio task running the transport.
    pub(crate) _task_handle: tokio::task::JoinHandle<()>,
    /// Whether the server has been stopped.
    pub(crate) stopped: bool,
}

/// Internal state for an active MCP client connection.
pub(crate) struct McpClientEntry {
    /// The real MCP client, connected and initialized.
    pub(crate) client: std::sync::Mutex<scp_mcp::client::McpClient<McpUniFFITransportWrapper>>,
}

/// Returns a reference to this `UniffiBridgeInstance`'s MCP server registry.
///
/// Migrated from a process-global `OnceLock<DashMap<...>>` singleton onto the
/// typed `mcp_server_registry` field on
/// [`crate::runtime::UniffiBridgeInstance`] in #1549 Phase 4 PR 2 commit 4.
/// Phase D (#1695) deletes the empty-fallback branch — every caller threads
/// through the owning `Scp`.
fn mcp_server_registry(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
) -> &dashmap::DashMap<String, McpServerEntry> {
    bi.mcp_server_registry().as_ref()
}

/// Returns a reference to this `UniffiBridgeInstance`'s MCP client registry.
fn mcp_client_registry(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
) -> &dashmap::DashMap<String, McpClientEntry> {
    bi.mcp_client_registry().as_ref()
}

fn mcp_handle_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// MCP transport implementations
// ---------------------------------------------------------------------------

/// Maximum bytes per line from MCP transport (10 MiB). Prevents OOM from
/// unbounded line reads by a malicious or broken peer.
const MCP_MAX_LINE_BYTES: u64 = 10 * 1024 * 1024;

/// Transport wrapper that delegates to either stdio or SSE.
pub(crate) enum McpUniFFITransportWrapper {
    Stdio(McpStdioTransport),
    Sse(McpSseTransport),
}

impl scp_mcp::client::McpTransport for McpUniFFITransportWrapper {
    fn send_request(
        &self,
        request: &scp_mcp::protocol::JsonRpcRequest,
    ) -> Result<scp_mcp::protocol::JsonRpcResponse, String> {
        match self {
            Self::Stdio(t) => t.send_request(request),
            #[allow(clippy::match_same_arms)]
            Self::Sse(t) => t.send_request(request),
        }
    }

    fn send_notification(
        &self,
        notification: &scp_mcp::protocol::JsonRpcNotification,
    ) -> Result<(), String> {
        match self {
            Self::Stdio(t) => t.send_notification(notification),
            #[allow(clippy::match_same_arms)]
            Self::Sse(t) => t.send_notification(notification),
        }
    }
}

/// Stdio MCP transport: communicates with a subprocess via stdin/stdout.
pub(crate) struct McpStdioTransport {
    inner: std::sync::Mutex<McpStdioTransportInner>,
}

struct McpStdioTransportInner {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: std::io::BufReader<std::process::ChildStdout>,
}

impl McpStdioTransport {
    fn spawn(
        allowlist: &std::sync::Mutex<scp_mcp::allowlist::StdioAllowlist>,
        command: &[String],
    ) -> Result<Self, String> {
        use std::process::{Command, Stdio};

        let (cmd, args) = command
            .split_first()
            .ok_or_else(|| "command list is empty".to_owned())?;

        // Validate the command against the per-instance stdio allowlist
        // (defense-in-depth). Hold the lock only across `validate_command`,
        // then drop before spawning.
        let basename = {
            let guard = allowlist
                .lock()
                .map_err(|_| "stdio allowlist lock poisoned".to_owned())?;
            guard.validate_command(cmd).map_err(|e| e.to_string())?
        };

        let mut child = Command::new(&basename)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("failed to spawn '{basename}': {e}"))?;

        let stdin = child.stdin.take().ok_or("failed to capture child stdin")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to capture child stdout")?;
        let reader = std::io::BufReader::new(stdout);

        Ok(Self {
            inner: std::sync::Mutex::new(McpStdioTransportInner {
                child,
                stdin,
                reader,
            }),
        })
    }
}

impl scp_mcp::client::McpTransport for McpStdioTransport {
    fn send_request(
        &self,
        request: &scp_mcp::protocol::JsonRpcRequest,
    ) -> Result<scp_mcp::protocol::JsonRpcResponse, String> {
        use std::io::{BufRead, Read, Write};

        let mut guard = self
            .inner
            .lock()
            .map_err(|e| format!("transport lock poisoned: {e}"))?;

        let json = serde_json::to_string(request).map_err(|e| format!("serialize error: {e}"))?;
        guard
            .stdin
            .write_all(json.as_bytes())
            .map_err(|e| format!("write error: {e}"))?;
        guard
            .stdin
            .write_all(b"\n")
            .map_err(|e| format!("write newline error: {e}"))?;
        guard
            .stdin
            .flush()
            .map_err(|e| format!("flush error: {e}"))?;

        // Read response line with bounded read to prevent OOM.
        let mut line = String::new();
        let n = {
            let mut bounded = (&mut guard.reader).take(MCP_MAX_LINE_BYTES);
            bounded
                .read_line(&mut line)
                .map_err(|e| format!("read error: {e}"))?
        };
        if n == 0 {
            return Err("EOF from subprocess".to_owned());
        }

        serde_json::from_str(line.trim()).map_err(|e| format!("parse error: {e}"))
    }

    fn send_notification(
        &self,
        notification: &scp_mcp::protocol::JsonRpcNotification,
    ) -> Result<(), String> {
        use std::io::Write;

        let mut guard = self
            .inner
            .lock()
            .map_err(|e| format!("transport lock poisoned: {e}"))?;

        let json =
            serde_json::to_string(notification).map_err(|e| format!("serialize error: {e}"))?;
        guard
            .stdin
            .write_all(json.as_bytes())
            .map_err(|e| format!("write error: {e}"))?;
        guard
            .stdin
            .write_all(b"\n")
            .map_err(|e| format!("write newline error: {e}"))?;
        guard
            .stdin
            .flush()
            .map_err(|e| format!("flush error: {e}"))?;

        Ok(())
    }
}

impl Drop for McpStdioTransport {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.lock() {
            let _ = guard.child.kill();
            let _ = guard.child.wait();
        }
    }
}

/// SSE MCP transport: communicates via HTTP with Server-Sent Events.
///
/// SSE transport is a placeholder — stdio is the primary transport for
/// mobile clients. SSE methods return descriptive errors.
pub(crate) struct McpSseTransport {
    _url: String,
}

impl McpSseTransport {
    fn connect(url: &str) -> Self {
        Self {
            _url: url.to_owned(),
        }
    }
}

impl scp_mcp::client::McpTransport for McpSseTransport {
    fn send_request(
        &self,
        _request: &scp_mcp::protocol::JsonRpcRequest,
    ) -> Result<scp_mcp::protocol::JsonRpcResponse, String> {
        Err("SSE client transport not yet implemented for UniFFI — use stdio transport".to_owned())
    }

    fn send_notification(
        &self,
        _notification: &scp_mcp::protocol::JsonRpcNotification,
    ) -> Result<(), String> {
        Err("SSE client transport not yet implemented for UniFFI — use stdio transport".to_owned())
    }
}

// ---------------------------------------------------------------------------
// MCP FFI bridge context provider
// ---------------------------------------------------------------------------

/// Default tool handler timeout in milliseconds (30 seconds).
const UNIFFI_TOOL_TIMEOUT_MS: u64 = scp_core::context::tools::DEFAULT_TIMEOUT_MS as u64;

/// FFI bridge provider for the MCP server. Implements `ContextProvider` by
/// reading tool registrations, role state, and event log data from the
/// context handle registry and `ContextManager`.
///
/// This mirrors the `PyO3` bridge's `FfiBridgeProvider` architecture:
/// - `context_tools()` reads from the per-context `ToolRegistry`
/// - `agent_role()` reads from `ContextManager::get_role_state()`
/// - `validate_capability()` runs UCAN validation + role-state capability check
/// - `invoke_tool()` dispatches to registered handlers with schema validation
/// - `context_members()` reads from `ContextManager::member_dids()` + `member_role()`
/// - `context_events()` reads from the per-context event log (UCAN state)
struct McpUniFfiBridgeProvider {
    /// Weak reference to the owning `UniffiBridgeInstance` — source for the
    /// context handle registry, `ContextManager`, and UCAN state lookups.
    ///
    /// # Why `Weak` and not `Arc` (#1549 round-2 bug-catcher)
    ///
    /// The provider is installed in an [`McpServer`] that lives inside a
    /// background task spawned on the shared tokio runtime
    /// (`runtime().spawn(...)`). That task is NOT enrolled in the
    /// per-instance
    /// [`JoinSet`](scp_ffi_common::bridge_instance::CoreFields::task_handle)
    /// aborted by `emergency_cancel_tasks`, so it survives
    /// [`crate::runtime::UniffiBridgeInstance::drop`] unless the caller
    /// explicitly sends a shutdown via [`mcp_server_stop`].
    ///
    /// If this field were `Arc<UniffiBridgeInstance>`, the server task
    /// would keep the instance alive forever when the caller forgets to
    /// stop it. With `Weak`, callers that drop their last strong
    /// reference release `ContextManager`, identity registry, relay
    /// connection, and the rest of `BridgeInstance`'s state. Provider
    /// methods upgrade per call; once `None` is returned, they emit a
    /// stable error so the MCP server can propagate it to the peer.
    ///
    /// Phase D (#1695): replaces process-wide `DEFAULT_BRIDGE_INSTANCE`
    /// lookups with per-provider affinity. Round-2 changes strong
    /// affinity to weak.
    bi: std::sync::Weak<crate::runtime::UniffiBridgeInstance>,
    agent_did: String,
    context_ids: Vec<String>,
    /// Maximum time (in milliseconds) to wait for a tool handler to complete.
    tool_timeout_ms: u64,
    /// JWT-encoded UCAN token for tool invocation authorization.
    agent_ucan_token: Option<String>,
    /// Optional proof tokens for UCAN delegation chain verification.
    agent_proof_tokens: Option<Vec<String>>,
}

impl McpUniFfiBridgeProvider {
    /// Upgrades the stored [`Weak`] to a live [`Arc<UniffiBridgeInstance>`].
    ///
    /// Returns an error string if the bridge instance has been dropped.
    /// Callers MUST drop the returned `Arc` before the next `.await` so
    /// they do not pin the instance alive across suspension points.
    fn upgrade_bi(&self) -> Result<Arc<crate::runtime::UniffiBridgeInstance>, String> {
        self.bi.upgrade().ok_or_else(|| {
            "bridge instance has been dropped — MCP provider cannot service request".to_owned()
        })
    }
}

impl scp_mcp::server::ContextProvider for McpUniFfiBridgeProvider {
    fn active_context_ids(&self) -> Vec<scp_mcp::namespace::ContextId> {
        self.context_ids.clone()
    }

    fn agent_role(&self, context_id: &str) -> Option<String> {
        // Read the agent's role assignment from this instance's Supervisor
        // role state via the ADR-049 query shim
        // ([`Supervisor::dispatch_query`](scp_core::context::supervisor::Supervisor::dispatch_query)).
        // Returns None if the bridge instance has been dropped (#1549 round-2).
        use scp_core::context::actor::commands::QueriesCommand;
        let bi = self.upgrade_bi().ok()?;
        let sup = bi.context_manager_expect().ok()?.clone();
        let role_state = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = QueriesCommand::GetRoleState {
                    context_id: context_id.to_owned(),
                    reply: tx,
                };
                sup.dispatch_query(cmd).await.ok()?;
                rx.await.ok()?.ok().flatten()
            })
        })?;
        role_state
            .assignments
            .get(&self.agent_did)
            .map(|assignment| assignment.role_name.clone())
    }

    fn agent_did(&self) -> &str {
        &self.agent_did
    }

    fn context_tools(&self, context_id: &str) -> Vec<scp_mcp::server::ContextToolInfo> {
        // Look up the ContextHandle from this provider's instance registry
        // and read its tool_registry.
        // Returns empty if the bridge instance has been dropped (#1549 round-2).
        let Ok(bi) = self.upgrade_bi() else {
            return Vec::new();
        };
        let registry = context_handle_registry(&bi);
        let Some(handle) = registry.get(context_id) else {
            return Vec::new();
        };
        let tool_registry = handle.tool_registry.blocking_lock();
        tool_registry
            .registrations()
            .map(|t| scp_mcp::server::ContextToolInfo {
                name: t.name.clone(),
                description: Some(t.description.clone()),
                input_schema: t.schema.input_schema.clone(),
                output_schema: Some(t.schema.output_schema.clone()),
                admin_only: false,
            })
            .collect()
    }

    fn validate_capability(&self, context_id: &str, tool_name: &str) -> Result<(), String> {
        // Upgrade the bridge instance handle up-front so every check below
        // sees a stable `&UniffiBridgeInstance`. If the instance has been
        // dropped, fail fast rather than silently accepting the capability
        // (#1549 round-2).
        let bi = self.upgrade_bi()?;
        // Primary check: UCAN token validation via the full 11-step ADR-016
        // pipeline. Verifies the token grants tool_invoke:{tool_name} or
        // tool_invoke:* for this context.
        if let Some(ref token) = self.agent_ucan_token {
            // Build proof resolver from optional proof tokens.
            let mut proofs = std::collections::HashMap::new();
            if let Some(ref tokens) = self.agent_proof_tokens {
                for encoded in tokens {
                    let proof_token = scp_core::crypto::ucan::validate::parse_ucan(encoded)
                        .map_err(|e| format!("malformed proof token: {e}"))?;
                    let cid = scp_core::crypto::ucan::mint::compute_cid(&proof_token);
                    proofs.insert(cid, proof_token);
                }
            }
            let proof_resolver = scp_ffi_common::BridgeProofResolver { proofs };

            // Ensure UCAN state is registered for this context.
            // Scope the DashMap Ref so the shard lock is released before
            // entering with_ucan_state (which uses a different DashMap).
            {
                let handle = context_handle_registry(&bi)
                    .get(context_id)
                    .ok_or_else(|| {
                        format!("context '{context_id}' not found in handle registry")
                    })?;
                bi.ensure_ucan_registered(context_id, &handle.creator_did, &handle.ceiling_strings);
            }

            let agent_did = self.agent_did.clone();
            bi.with_ucan_state(context_id, |ucan_state| {
                let production_resolver = bi.did_resolver();
                let did_resolver =
                    scp_ffi_common::DispatchDidResolver::new(production_resolver.as_deref());
                let revocation_checker = scp_ffi_common::BridgeRevocationChecker {
                    revocation_list: &ucan_state.revocation_list,
                };
                let mut nonce_adapter = scp_ffi_common::BridgeNonceTracker {
                    inner: &mut ucan_state.nonce_tracker,
                };

                let mut ctx = scp_core::crypto::ucan::validate::ValidationContext {
                    did_resolver: &did_resolver,
                    nonce_tracker: &mut nonce_adapter,
                    revocation_checker: &revocation_checker,
                    proof_resolver: &proof_resolver,
                    ceiling: &ucan_state.ceiling_strings,
                    context_creator_did: &ucan_state.creator_did,
                    presenting_agent_did: &agent_did,
                    clock_skew_tolerance_secs:
                        scp_core::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
                    clock: &scp_primitives::SystemClock,
                };

                scp_core::context::tools::validate_tool_invocation_ucan(
                    token, context_id, tool_name, &mut ctx,
                )
                .map_err(|e| {
                    tracing::warn!(
                        agent = %agent_did,
                        tool = %tool_name,
                        context = %context_id,
                        error = %e,
                        "UCAN validation failed for tool invocation"
                    );
                    format!("UCAN authorization failed for tool '{tool_name}': {e}")
                })
            })
            .ok_or_else(|| format!("UCAN state not found for context '{context_id}'"))??;
        } else {
            tracing::warn!(
                agent = %self.agent_did,
                tool = %tool_name,
                context = %context_id,
                "no UCAN token provided for tool invocation — authorization bypass risk"
            );
            return Err("UCAN token required for tool invocation — no token provided".to_owned());
        }

        // Defense-in-depth: check role-state capabilities in addition to the
        // UCAN layer. See §7.2 and ADR-010 for the dual-check design.
        //
        // Routed through the ADR-049 query shim
        // ([`Supervisor::dispatch_query`](scp_core::context::supervisor::Supervisor::dispatch_query)).
        use scp_core::context::actor::commands::QueriesCommand;
        let sup = bi
            .context_manager_expect()
            .map_err(|e| format!("Supervisor not initialized: {e}"))?
            .clone();
        let role_state = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = QueriesCommand::GetRoleState {
                    context_id: context_id.to_owned(),
                    reply: tx,
                };
                sup.dispatch_query(cmd)
                    .await
                    .map_err(|e| format!("supervisor dispatch_query failed: {e}"))?;
                rx.await
                    .map_err(|e| format!("query shim reply dropped: {e}"))?
                    .map_err(|e| e.to_string())
            })
        })?
        .ok_or_else(|| {
            format!("context '{context_id}' not registered with Supervisor for capability check")
        })?;

        if scp_core::context::tools::invoke::has_tool_invoke_capability(
            &role_state,
            &self.agent_did,
            tool_name,
        ) {
            Ok(())
        } else {
            tracing::warn!(
                agent = %self.agent_did,
                tool = %tool_name,
                context = %context_id,
                "capability check failed: agent lacks ToolInvoke capability"
            );
            Err("insufficient permissions to invoke tool".to_owned())
        }
    }

    #[allow(clippy::too_many_lines)]
    fn invoke_tool(
        &self,
        context_id: &str,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let start = std::time::Instant::now();
        let agent_did = self.agent_did.clone();
        let timeout = std::time::Duration::from_millis(self.tool_timeout_ms);

        // Upgrade the bridge instance handle up-front. `invoke_tool` is a
        // sync trait method so the Arc is bounded by this function's return
        // and cannot survive across an `await` point (#1549 round-2).
        let bi = self.upgrade_bi()?;

        // Phase 1: Validate input and extract handler + output schema under
        // the ContextHandle's tool_registry lock. The lock is released before
        // handler execution to avoid blocking concurrent context operations.
        // The DashMap Ref (shard lock) is scoped to this block.
        let (dispatch, input_hash) = {
            let handle = context_handle_registry(&bi)
                .get(context_id)
                .ok_or_else(|| format!("context '{context_id}' not found in handle registry"))?;

            let tool_registry = handle.tool_registry.blocking_lock();
            let registration = tool_registry
                .get(tool_name)
                .ok_or_else(|| format!("tool '{tool_name}' not found in context '{context_id}'"))?;

            // Validate input against the tool's input schema.
            scp_core::context::tools::schema::validate_value_against_schema(
                &arguments,
                &registration.schema.input_schema,
            )
            .map_err(|msg| format!("input validation failed for tool '{tool_name}': {msg}"))?;

            let input_hash = scp_core::context::tools::sha256_json(&arguments);

            let handler_dispatch = {
                let tool_handlers = handle.tool_handlers.blocking_lock();
                tool_handlers
                    .get(tool_name)
                    .map(|handler| (handler.clone(), registration.schema.output_schema.clone()))
            };

            (handler_dispatch, input_hash)
        };

        // Phase 2: Execute handler OUTSIDE the locks so that concurrent
        // same-context operations are not blocked. Handler execution is
        // bounded by `tool_timeout_ms` (matching PyO3 pattern, issue #123).
        let output = match dispatch {
            Some((handler, output_schema)) => {
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let result = handler(arguments);
                    let _ = tx.send(result);
                });

                let handler_result = rx.recv_timeout(timeout).map_err(|_| {
                    format!(
                        "tool handler for '{tool_name}' timed out after {}ms",
                        timeout.as_millis()
                    )
                })?;

                let output = handler_result
                    .map_err(|e| format!("tool handler for '{tool_name}' failed: {e}"))?;

                // Validate output against the tool's output schema (defense-in-depth).
                scp_core::context::tools::schema::validate_value_against_schema(
                    &output,
                    &output_schema,
                )
                .map_err(|msg| format!("output validation failed for tool '{tool_name}': {msg}"))?;

                output
            }
            None => {
                // No handler registered — fall back to echo mode.
                serde_json::json!({
                    "tool": tool_name,
                    "context": context_id,
                    "status": "validated",
                    "input_valid": true,
                    "validated_input": arguments,
                })
            }
        };

        // Phase 3: Append ToolInvokedEvent to the event log (ADR-010
        // criterion 3). Uses append_unsigned_event because ContextProvider
        // is sync (same as PyO3 bridge).
        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = {
            let millis = start.elapsed().as_millis();
            if millis > u128::from(u64::MAX) {
                u64::MAX
            } else {
                millis as u64
            }
        };

        let tool_event = scp_core::context::tools::ToolInvokedEvent {
            request_id: uuid::Uuid::new_v4().to_string(),
            tool_id: tool_name.to_owned(),
            invoker_did: agent_did.clone().into(),
            status: scp_core::context::tools::ToolStatus::Success,
            execution_time_ms: elapsed_ms,
            input_hash,
            output_hash: Some(scp_core::context::tools::sha256_json(&output)),
            cost: None,
        };

        let payload_data = serde_json::to_vec(&tool_event).unwrap_or_default();

        #[allow(clippy::cast_possible_truncation)]
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        // Ensure UCAN state is registered before appending the event.
        if let Some(handle) = context_handle_registry(&bi).get(context_id) {
            bi.ensure_ucan_registered(context_id, &handle.creator_did, &handle.ceiling_strings);
        }

        let append_result = bi.with_ucan_state(context_id, |ucan_state| {
            let sequence = scp_event_log::tree::event_count(&ucan_state.event_log);
            let prev_hash = if ucan_state.event_log.leaves().is_empty() {
                scp_event_log::tree::GENESIS_PREV_HASH
            } else {
                let leaves = ucan_state.event_log.leaves();
                leaves[leaves.len() - 1]
            };

            let event = scp_event_log::Event {
                event_type: scp_event_log::EventType::ToolInvoked,
                actor_did: agent_did.into(),
                timestamp,
                sequence,
                payload: scp_event_log::EventPayload { data: payload_data },
                prev_hash,
                signature: Vec::new(),
            };

            scp_event_log::tree::append_unsigned_event(&mut ucan_state.event_log, &event)
                .map_err(|e| e.to_string())
        });

        match append_result {
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                tracing::warn!(
                    tool = %tool_name,
                    context = %context_id,
                    error = %e,
                    "failed to append ToolInvokedEvent to event log"
                );
            }
            None => {
                tracing::warn!(
                    tool = %tool_name,
                    context = %context_id,
                    "UCAN state not found — could not append ToolInvokedEvent"
                );
            }
        }

        Ok(output)
    }

    fn context_members(&self, context_id: &str) -> Vec<scp_mcp::server::MemberInfo> {
        // Read member list and role assignments via the ADR-049 query shim
        // ([`Supervisor::dispatch_query`](scp_core::context::supervisor::Supervisor::dispatch_query)).
        // Returns empty if the bridge instance has been dropped (#1549 round-2).
        use scp_core::context::actor::commands::QueriesCommand;
        let Ok(bi) = self.upgrade_bi() else {
            return Vec::new();
        };
        let Ok(sup) = bi.context_manager_expect().map(Arc::clone) else {
            return Vec::new();
        };

        let (member_dids, role_state) = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                let (dids_tx, dids_rx) = tokio::sync::oneshot::channel();
                let dids_cmd = QueriesCommand::MemberDids {
                    context_id: context_id.to_owned(),
                    reply: dids_tx,
                };
                let dids = if sup.dispatch_query(dids_cmd).await.is_ok() {
                    dids_rx.await.ok().and_then(Result::ok).unwrap_or_default()
                } else {
                    Vec::new()
                };

                let (roles_tx, roles_rx) = tokio::sync::oneshot::channel();
                let roles_cmd = QueriesCommand::GetRoleState {
                    context_id: context_id.to_owned(),
                    reply: roles_tx,
                };
                let roles = if sup.dispatch_query(roles_cmd).await.is_ok() {
                    roles_rx.await.ok().and_then(Result::ok).flatten()
                } else {
                    None
                };
                (dids, roles)
            })
        });

        member_dids
            .into_iter()
            .map(|did| {
                let role = role_state
                    .as_ref()
                    .and_then(|rs| rs.assignments.get(&did))
                    .map_or_else(|| "member".to_owned(), |a| a.role_name.clone());
                scp_mcp::server::MemberInfo { did, role }
            })
            .collect()
    }

    fn context_events(&self, context_id: &str) -> serde_json::Value {
        // The EventLog stores Merkle tree hashes, not event payloads.
        // Return the event count and Merkle root as metadata (matching PyO3).
        // Falls back to zero-count JSON if the bridge has been dropped
        // (#1549 round-2).
        let Ok(bi) = self.upgrade_bi() else {
            return serde_json::json!({ "event_count": 0 });
        };
        if let Some(handle) = context_handle_registry(&bi).get(context_id) {
            bi.ensure_ucan_registered(context_id, &handle.creator_did, &handle.ceiling_strings);
        }

        bi.with_ucan_state(context_id, |ucan_state| {
            let leaf_count = ucan_state.event_log.leaves().len();
            let root = scp_event_log::tree::root(&ucan_state.event_log);
            serde_json::json!({
                "event_count": leaf_count,
                "merkle_root": hex::encode(root),
            })
        })
        .unwrap_or_else(|| serde_json::json!({ "event_count": 0 }))
    }

    fn subscribe_resource(&self, _uri: &str) -> Result<(), String> {
        // Resource subscriptions are not yet wired to the transport layer.
        // Accept the subscription silently (matching PyO3 behavior).
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MCP stdio server loop
// ---------------------------------------------------------------------------

async fn run_mcp_stdio_server_uniffi(
    server: Arc<std::sync::Mutex<scp_mcp::server::McpServer<McpUniFfiBridgeProvider>>>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    cancel_token: tokio_util::sync::CancellationToken,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    // Wire both `shutdown_rx` (mcp_server_stop) AND the bridge instance's
    // `cancel_token` (emergency_cancel_tasks from Drop) so either signal
    // terminates this task. Without the `cancel_token` arm, a caller that
    // drops `SCP` without calling `mcp_server_stop` would leave this task
    // running indefinitely (#1549 round-2).
    tokio::select! {
        _ = shutdown_rx => {}
        () = cancel_token.cancelled() => {
            tracing::debug!("MCP stdio server task exiting — bridge instance cancelled");
        }
        () = async {
            let stdin = tokio::io::stdin();
            let mut stdout = tokio::io::stdout();
            let mut reader = tokio::io::BufReader::new(stdin);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                if line.len() as u64 > MCP_MAX_LINE_BYTES {
                    break;
                }

                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let response = {
                    let request: Result<scp_mcp::protocol::JsonRpcRequest, _> =
                        serde_json::from_str(trimmed);
                    match request {
                        Ok(req) => {
                            server
                                .lock()
                                .map_or(None, |mut srv| srv.handle_request(&req))
                        }
                        Err(e) => {
                            Some(scp_mcp::protocol::JsonRpcResponse::error(
                                scp_mcp::protocol::RequestId::Number(0),
                                scp_mcp::protocol::JsonRpcError {
                                    code: scp_mcp::protocol::PARSE_ERROR,
                                    message: format!("failed to parse: {e}"),
                                    data: None,
                                },
                            ))
                        }
                    }
                };

                if let Some(resp) = response
                    && let Ok(json) = serde_json::to_string(&resp) {
                        let _ = stdout.write_all(json.as_bytes()).await;
                        let _ = stdout.write_all(b"\n").await;
                        let _ = stdout.flush().await;
                    }
            }
        } => {}
    }
}

// ---------------------------------------------------------------------------
// MCP allowlist error mapping
// ---------------------------------------------------------------------------

/// Maps [`AllowlistError`] to the appropriate [`ScpError`] variant.
///
/// Input-validation errors map to `Validation`. Runtime/policy errors
/// map to `Transport`. Exhaustive match ensures new variants produce
/// a compile error instead of silently falling through.
///
/// Mutex poisoning is NOT modelled by `AllowlistError` — the allowlist is
/// per-instance (`CoreFields::mcp_allowlist`). Each call site maps
/// `PoisonError` to a transport error before invoking allowlist methods.
// `clippy::match_same_arms` — the explicit wildcard arm at the end is intentional:
// `AllowlistError` is `#[non_exhaustive]`, so future variants must compile, and
// classifying them as a validation error fails closed. Folding the wildcard into
// the named OR-chain would erase that documentation.
#[allow(clippy::match_same_arms)]
fn mcp_allowlist_err(e: scp_mcp::allowlist::AllowlistError) -> ScpError {
    use scp_mcp::allowlist::AllowlistError;
    let msg = e.to_string();
    match e {
        AllowlistError::EmptyEntry
        | AllowlistError::PathInEntry(_)
        | AllowlistError::NulInEntry(_)
        | AllowlistError::ControlCharInEntry(_)
        | AllowlistError::PathInCommand(_)
        | AllowlistError::InvalidCommand(_) => ScpError::Validation {
            msg,
            code: codes::VALID_7033.to_owned(),
        },
        AllowlistError::NotAllowed { .. } => ScpError::Transport {
            msg,
            code: codes::TRANS_5030.to_owned(),
        },
        // `AllowlistError` is `#[non_exhaustive]` — fail closed for any
        // future variant by classifying as a validation error rather than
        // letting an unknown policy decision become a permissive path.
        _ => ScpError::Validation {
            msg,
            code: codes::VALID_7033.to_owned(),
        },
    }
}

/// Maps a `PoisonError` from the per-instance allowlist mutex to a `UniFFI`
/// transport error.
fn mcp_allowlist_lock_poisoned() -> ScpError {
    ScpError::Transport {
        msg: "stdio allowlist lock poisoned".to_owned(),
        code: codes::TRANS_5030.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// MCP bridge functions
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Stdio allowlist configuration
//
// All four operations are exposed as **methods on `Scp`** (see
// `impl Scp { mcp_configure_stdio_allowlist / … }` below). The legacy
// `#[uniffi::export]` free functions were removed when the
// allowlist became per-instance (`CoreFields::mcp_allowlist`); the SDKs
// already wrap the per-instance methods.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — UCAN operations
//
// See ADR-021 acceptance criterion 6.
// ---------------------------------------------------------------------------

/// Inner implementation of [`ucan_mint`], split out for cfg-gating clarity.
#[cfg(feature = "allow_in_memory_custody")]
async fn ucan_mint_impl(
    handle: Arc<ContextHandle>,
    member_did: String,
    capabilities: Vec<String>,
    proofs: Option<Vec<String>>,
) -> Result<Arc<UcanToken>, ScpError> {
    runtime()
        .spawn(async move {
            // Extract key custody and signing key from the context handle.
            let custody = handle
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "UCAN minting requires retained signing custody — the context \
                              creator identity has no retained custody (it was externally loaded)"
                        .to_owned(),
                    code: codes::IDENT_1017.to_owned(),
                })?;
            let signing_key = handle.signing_key.ok_or_else(|| ScpError::Identity {
                msg: "UCAN minting requires retained signing custody — the context creator \
                          identity has no active signing key"
                    .to_owned(),
                code: codes::IDENT_1017.to_owned(),
            })?;

            let params = scp_core::crypto::ucan::mint::MintParams {
                issuer_did: &handle.creator_did,
                issuer_key: &signing_key,
                audience_did: &member_did,
                context_id: &handle.context_id,
                capabilities: &capabilities,
                lifetime_secs: 3600, // 1 hour default
                not_before: None,
                proofs: proofs.unwrap_or_default(),
                facts: None,
                key_scope: None,
                signing_key_id: None,
                // Empty ceiling means the user passed `[]` — apply the default
                // ceiling instead of `None` (which would mean unlimited). #1419.
                ceiling: Some(if handle.ceiling_strings.is_empty() {
                    scp_core::context::roles::default_ceiling().to_ucan_string_set()
                } else {
                    handle.ceiling_strings.iter().cloned().collect()
                }),
            };

            let token = scp_core::crypto::ucan::mint::mint_ucan(
                &params,
                &custody.0,
                &scp_primitives::SystemClock,
            )
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
                instance_id: handle.instance_id,
            }))
        })
        .await
        .map_err(|e| ScpError::Permission {
            msg: format!("tokio task join error during UCAN mint: {e}"),
            code: codes::PERM_3005.to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)] // Must be async to match the cfg(feature) variant's signature.
async fn ucan_mint_impl(
    _handle: Arc<ContextHandle>,
    _member_did: String,
    _capabilities: Vec<String>,
    _proofs: Option<Vec<String>>,
) -> Result<Arc<UcanToken>, ScpError> {
    Err(ScpError::Identity {
        msg: "UCAN minting requires retained signing custody — the in_memory custody path \
                  is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use, or wire \
                  a KeyCustodyProvider for production."
            .to_owned(),
        code: codes::IDENT_1017.to_owned(),
    })
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
            let custody = handle
                .in_memory_custody
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "UCAN delegation requires retained signing custody — the context \
                              creator identity has no retained custody (it was externally loaded)"
                        .to_owned(),
                    code: codes::IDENT_1017.to_owned(),
                })?;
            let signing_key = handle.signing_key.ok_or_else(|| ScpError::Identity {
                msg: "UCAN delegation requires retained signing custody — the context creator \
                          identity has no active signing key"
                    .to_owned(),
                code: codes::IDENT_1017.to_owned(),
            })?;

            // Parse the parent token.
            let parsed_parent = parse_ucan(&parent_token).map_err(|e| ScpError::Permission {
                msg: format!("malformed parent UCAN token: {e}"),
                code: codes::PERM_3002.to_owned(),
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
            // Empty ceiling means the user passed `[]` — apply the default
            // ceiling instead of `None` (which would mean unlimited). #1419.
            let ceiling = Some(if handle.ceiling_strings.is_empty() {
                scp_core::context::roles::default_ceiling().to_ucan_string_set()
            } else {
                handle.ceiling_strings.iter().cloned().collect()
            });

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

            let token = delegate_ucan(&params, &custody.0, &scp_primitives::SystemClock)
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
                instance_id: handle.instance_id,
            }))
        })
        .await
        .map_err(|e| ScpError::Permission {
            msg: format!("tokio task join error during UCAN delegation: {e}"),
            code: codes::PERM_3005.to_owned(),
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
    Err(ScpError::Identity {
        msg: "UCAN delegation requires retained signing custody — the in_memory custody path \
                  is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use, or wire \
                  a KeyCustodyProvider for production."
            .to_owned(),
        code: codes::IDENT_1017.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Free functions — event log operations
//
// See ADR-021 acceptance criterion 7.
// ---------------------------------------------------------------------------

#[cfg(feature = "allow_in_memory_custody")]
async fn event_log_checkpoint_impl(
    bi: Arc<crate::runtime::UniffiBridgeInstance>,
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
                    .ok_or_else(|| ScpError::Identity {
                        msg: "event log checkpoint requires retained signing custody — this \
                              identity has no retained custody (it was externally loaded)"
                            .to_owned(),
                        code: codes::IDENT_1017.to_owned(),
                    })?;
            let core_id = identity
                .core_id
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "event log checkpoint requires retained identity state — the identity \
                          was externally loaded"
                        .to_owned(),
                    code: codes::IDENT_1007.to_owned(),
                })?;

            // Ensure UCAN state (which contains the event log) is registered
            // on this bridge instance.
            bi.ensure_ucan_registered(
                &handle.context_id,
                &handle.creator_did,
                &handle.ceiling_strings,
            );

            let sender_did = scp_identity::DID(identity.did.clone());
            let context_id = handle.context_id.clone();

            let checkpoint = bi
                .with_ucan_state(&context_id, |ucan_state| {
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
                                msg: format!("checkpoint generation failed: {e}"),
                                code: codes::CTX_2027.to_owned(),
                            })
                        })
                    })
                })
                .ok_or_else(|| ScpError::Context {
                    msg: format!("context '{context_id}' not found in UCAN registry"),
                    code: codes::CTX_2027.to_owned(),
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
            msg: format!("tokio task join error during event log checkpoint: {e}"),
            code: codes::CTX_2028.to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)]
async fn event_log_checkpoint_impl(
    _bi: Arc<crate::runtime::UniffiBridgeInstance>,
    _handle: Arc<ContextHandle>,
    _identity: Arc<Identity>,
    _epoch: u64,
) -> Result<Checkpoint, ScpError> {
    Err(ScpError::Identity {
        msg: "event log checkpoint requires retained signing custody — the in_memory custody \
                  path is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use, or wire \
                  a KeyCustodyProvider for production."
            .to_owned(),
        code: codes::IDENT_1017.to_owned(),
    })
}

/// Generates a signed consistency checkpoint scoped to a member DID.
///
/// The `UniFFI` bridge holds no DID-keyed identity registry — identities are
/// opaque `Arc<Identity>` handles, not entries looked up by string. So unlike
/// the PyO3/NAPI/WASM bridges (which resolve key material from a registry keyed
/// by DID), this variant takes the `Identity` handle for key material AND an
/// explicit `did` string that is recorded as the checkpoint's `sender_did`.
/// This honours the per-SDK idiom (ADR-048 §7): the no-registry constraint of
/// the `UniFFI` object model is respected rather than forcing a registry into
/// existence.
///
/// The `did` is validated for syntactic well-formedness (matching the `PyO3`
/// bridge) AND must equal the supplied `identity`'s own DID. The other bridges
/// bind the signing key to the recorded `sender_did` implicitly via the
/// DID-keyed registry lookup; this bridge has no registry, so the binding is
/// enforced here explicitly. Without it, a caller could record a checkpoint as
/// having been signed by an arbitrary `sender_did` while signing with an
/// unrelated identity's key — a provenance forgery. The argument is retained
/// (rather than dropped in favour of `identity.did`) so the call site reads
/// symmetrically with the other bridges' `*_by_did` signatures.
#[cfg(feature = "allow_in_memory_custody")]
async fn event_log_checkpoint_by_did_impl(
    bi: Arc<crate::runtime::UniffiBridgeInstance>,
    handle: Arc<ContextHandle>,
    identity: Arc<Identity>,
    did: String,
    epoch: u64,
) -> Result<Checkpoint, ScpError> {
    validate_did(&did)?;
    // Bind the recorded sender_did to the signing identity. The key material
    // comes from `identity`; recording any other DID as the signer would be a
    // provenance forgery (the registry-backed bridges get this binding for
    // free via DID-keyed lookup).
    if did != identity.did {
        return Err(ScpError::Validation {
            msg: format!(
                "checkpoint sender_did '{did}' does not match the signing identity's \
                 DID '{}' — the checkpoint must be attributed to the identity that \
                 signs it",
                identity.did
            ),
            code: codes::VALID_7000.to_owned(),
        });
    }
    runtime()
        .spawn(async move {
            let custody =
                identity
                    .in_memory_custody
                    .as_ref()
                    .ok_or_else(|| ScpError::Identity {
                        msg: "event log checkpoint requires retained signing custody — this \
                              identity has no retained custody (it was externally loaded)"
                            .to_owned(),
                        code: codes::IDENT_1017.to_owned(),
                    })?;
            let core_id = identity
                .core_id
                .as_ref()
                .ok_or_else(|| ScpError::Identity {
                    msg: "event log checkpoint requires retained identity state — the identity \
                          was externally loaded"
                        .to_owned(),
                    code: codes::IDENT_1007.to_owned(),
                })?;

            // Ensure UCAN state (which contains the event log) is registered
            // on this bridge instance.
            bi.ensure_ucan_registered(
                &handle.context_id,
                &handle.creator_did,
                &handle.ceiling_strings,
            );

            let sender_did = scp_identity::DID(did);
            let context_id = handle.context_id.clone();

            let checkpoint = bi
                .with_ucan_state(&context_id, |ucan_state| {
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
                                msg: format!("checkpoint generation failed: {e}"),
                                code: codes::CTX_2027.to_owned(),
                            })
                        })
                    })
                })
                .ok_or_else(|| ScpError::Context {
                    msg: format!("context '{context_id}' not found in UCAN registry"),
                    code: codes::CTX_2027.to_owned(),
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
            msg: format!("tokio task join error during event log checkpoint: {e}"),
            code: codes::CTX_2028.to_owned(),
        })?
}

#[cfg(not(feature = "allow_in_memory_custody"))]
#[allow(clippy::unused_async)]
async fn event_log_checkpoint_by_did_impl(
    _bi: Arc<crate::runtime::UniffiBridgeInstance>,
    _handle: Arc<ContextHandle>,
    _identity: Arc<Identity>,
    _did: String,
    _epoch: u64,
) -> Result<Checkpoint, ScpError> {
    Err(ScpError::Identity {
        msg: "event log checkpoint requires retained signing custody — the in_memory custody \
                  path is not available in this build. Enable the \
                  \"allow_in_memory_custody\" feature for dev/desktop use, or wire \
                  a KeyCustodyProvider for production."
            .to_owned(),
        code: codes::IDENT_1017.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Free functions — governance operations (#387)
//
// All 24 GovernanceAction variants are dispatchable via
// ContextManager::execute_governance_action.
// ---------------------------------------------------------------------------

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
        msg: "no signing key on context handle — governance lifecycle \
                  requires an identity with an active signing key"
            .to_owned(),
        code: codes::CTX_2040.to_owned(),
    })?;

    if let Some(ref cb) = handle.callback_custody {
        return cb
            .export_ed25519_signing_key(&key_handle)
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("failed to export signing key from platform custody: {e}"),
                code: codes::CTX_2040.to_owned(),
            });
    }

    #[cfg(feature = "allow_in_memory_custody")]
    if let Some(ref imc) = handle.in_memory_custody {
        return imc
            .0
            .export_ed25519_signing_key(&key_handle)
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("failed to export signing key from in-memory custody: {e}"),
                code: codes::CTX_2040.to_owned(),
            });
    }

    Err(ScpError::Context {
        msg: "no custody provider on context handle — governance lifecycle \
                  requires an identity created with custody"
            .to_owned(),
        code: codes::CTX_2040.to_owned(),
    })
}

/// Signs the §23.16.8 context-export snapshot digest via the exporter
/// identity's [`KeyCustody::sign`] — delegating to whichever backend backs the
/// handle (platform/software callback custody OR in-memory custody) — instead
/// of extracting a raw Ed25519 signing key.
///
/// This is the export-path analogue of [`resolve_uniffi_signing_key`]: the
/// governance lifecycle paths still extract a raw key (they sign with
/// `ed25519_dalek::Signer` directly), but context export only needs a detached
/// signature over the canonical snapshot digest, so it can route through
/// `custody.sign` and never materialize private key bytes. A sign-only /
/// keychain / HSM-shaped callback custody — one that implements `sign` but
/// intentionally does NOT implement `export_ed25519_signing_key` — can
/// therefore still produce a verifiable signed export. Private key material
/// never crosses the FFI boundary (ADR-006).
///
/// Checks `callback_custody` first (platform/software), then falls back to
/// `in_memory_custody`, matching the resolution order of every other
/// key-bearing `UniFFI` path.
///
/// Fail-closed: returns `ScpError::Context` (CTX-2040) when no signing-key
/// handle or custody provider is present, and validates that the returned
/// signature is exactly 64 bytes (Ed25519) — so a misbehaving custody can
/// never yield an under-length signature that would later fail verification
/// in a confusing place. The caller (`context_export`) never emits an
/// unsigned export on any error path.
async fn sign_export_snapshot_via_custody(
    handle: &ContextHandle,
    hash: &[u8; 32],
) -> Result<[u8; 64], ScpError> {
    let key_handle = handle.signing_key.ok_or_else(|| ScpError::Context {
        msg: "no signing key on context handle — context export \
                  requires an identity with an active signing key"
            .to_owned(),
        code: codes::CTX_2040.to_owned(),
    })?;

    let signature = if let Some(ref cb) = handle.callback_custody {
        cb.sign(&key_handle, hash)
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("platform custody failed to sign context export snapshot: {e}"),
                code: codes::CTX_2040.to_owned(),
            })?
    } else {
        #[cfg(feature = "allow_in_memory_custody")]
        {
            if let Some(ref imc) = handle.in_memory_custody {
                imc.0
                    .sign(&key_handle, hash)
                    .await
                    .map_err(|e| ScpError::Context {
                        msg: format!(
                            "in-memory custody failed to sign context export snapshot: {e}"
                        ),
                        code: codes::CTX_2040.to_owned(),
                    })?
            } else {
                return Err(ScpError::Context {
                    msg: "no custody provider on context handle — context export \
                              requires an identity created with custody"
                        .to_owned(),
                    code: codes::CTX_2040.to_owned(),
                });
            }
        }
        #[cfg(not(feature = "allow_in_memory_custody"))]
        {
            return Err(ScpError::Context {
                msg: "no custody provider on context handle — context export \
                          requires an identity created with custody"
                    .to_owned(),
                code: codes::CTX_2040.to_owned(),
            });
        }
    };

    let bytes: [u8; 64] = signature
        .as_bytes()
        .try_into()
        .map_err(|_| ScpError::Context {
            msg: format!(
                "custody sign returned {} bytes, expected 64 (Ed25519) for context export snapshot",
                signature.as_bytes().len()
            ),
            code: codes::CTX_2040.to_owned(),
        })?;
    Ok(bytes)
}

/// Resolves the snapshot creator's Ed25519 verification key for
/// snapshot-signature verification on context import (§23.16.8, ADR-050,
/// ADR-039).
///
/// Per §23.16.8 step 1 the verifying key is derived from the snapshot's
/// `creator_did` (`role_state.creator_did`), never from the unauthenticated
/// envelope `exporter_did`. The runtime separately asserts
/// `exporter_did == creator_did` (§23.16.8 step 2), so the bridge MUST resolve
/// from the creator identity.
///
/// Resolution order (local-custody-first, then DID resolver) is shared across
/// all non-WASM bridges via
/// [`scp_ffi_common::export_verify::resolve_export_verifying_key`]:
/// 1. **Local identity custody** — if the creator is a local identity (the
///    common self-export case: a device importing a context it exported), the
///    verifying key is derived directly from its `#active` custody signing key
///    held in this instance's [`identity_custody_registry`]. This works even
///    when the DID document has not been published to the DHT (in-memory
///    identities are not auto-published), which is exactly the self-import
///    round-trip the previous resolver-only path could not satisfy.
/// 2. **DID resolver** — otherwise resolve the creator DID's `#active` (then
///    `#agent`, ADR-039 shared-DID model) verification-method key.
///
/// Fails closed: if the creator is neither local nor resolvable, the import is
/// rejected with [`codes::CTX_2093`] rather than proceeding unverified.
///
/// This is `async` because the local-custody public-key export is `async`. The
/// custody lookup is awaited up front and fed to the (synchronous) shared
/// helper closure as a pre-resolved `Option<VerifyingKey>`.
async fn resolve_uniffi_creator_verifying_key(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    creator_did: &str,
) -> Result<ed25519_dalek::VerifyingKey, ScpError> {
    // Local custody: if the creator is a local in-memory identity, derive the
    // public verifying key from its retained `#active` custody key. Awaited up
    // front so the shared helper's synchronous closure just returns the
    // already-resolved key. Only the public key leaves custody — private key
    // material never crosses this boundary. Returns `None` when the creator is
    // not a local identity (or when in-memory custody is not compiled in), so
    // resolution falls through to the DID resolver.
    let local_verifying_key = resolve_local_custody_verifying_key(bi, creator_did).await;

    let resolver = bi.did_resolver();

    scp_ffi_common::export_verify::resolve_export_verifying_key(
        resolver.as_deref(),
        |_did| local_verifying_key,
        creator_did,
    )
    .map_err(|e| ScpError::Context {
        msg: format!("{}: {e}", codes::CTX_2093),
        code: codes::CTX_2093.to_owned(),
    })
}

/// Derives the `#active` Ed25519 verifying key for `did` from this instance's
/// in-memory identity custody, if `did` is a local in-memory identity.
///
/// Returns `None` when `did` is not registered locally, when the custody key
/// cannot be exported, or when the in-memory custody feature is not compiled
/// in. The returned key is the *public* verifying key only — private key
/// material never leaves custody.
///
/// This backs the local-custody-first leg of
/// [`resolve_uniffi_creator_verifying_key`] (§23.16.8 step 1), enabling a
/// self-export → self-import round-trip before any DID resolver is configured.
#[cfg(feature = "allow_in_memory_custody")]
async fn resolve_local_custody_verifying_key(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    did: &str,
) -> Option<ed25519_dalek::VerifyingKey> {
    // Clone the custody Arc and key handle out of the registry under a short
    // guard scope so no DashMap reference is held across the `.await`.
    let (custody, key_handle) = {
        let registry = identity_custody_registry(bi);
        let entry = registry.get(did)?;
        let (custody, handle) = entry.value();
        (Arc::clone(custody), *handle)
    };

    let public_key = custody.0.public_key(&key_handle).await.ok()?;
    // 32-byte length + canonical-point decode: the shared conversion tail in
    // scp-ffi-common, identical across all non-WASM bridges.
    scp_ffi_common::export_verify::verifying_key_from_public_key(&public_key)
}

/// No-custody build: local identities are never resolvable from in-memory
/// custody, so the local-custody leg always yields `None` and resolution
/// falls through to the DID resolver.
#[cfg(not(feature = "allow_in_memory_custody"))]
async fn resolve_local_custody_verifying_key(
    _bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    _did: &str,
) -> Option<ed25519_dalek::VerifyingKey> {
    None
}

/// Parses a hex-encoded proposal ID into a 32-byte array.
fn parse_uniffi_proposal_id(hex_str: &str) -> Result<[u8; 32], ScpError> {
    let bytes = hex::decode(hex_str).map_err(|e| ScpError::Validation {
        msg: format!("invalid proposal ID hex: {e}"),
        code: codes::CTX_2040.to_owned(),
    })?;
    bytes.try_into().map_err(|v: Vec<u8>| ScpError::Validation {
        msg: format!("proposal ID must be 32 bytes, got {}", v.len()),
        code: codes::CTX_2040.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Free functions — ceiling modification, close, checkpoint, restore (#559)
// ---------------------------------------------------------------------------

/// Parses a hex string into a 32-byte array for the `UniFFI` bridge.
fn parse_uniffi_hex_32(hex_str: &str, field_name: &str) -> Result<[u8; 32], ScpError> {
    let bytes = hex::decode(hex_str).map_err(|e| ScpError::Validation {
        msg: format!("invalid {field_name} hex: {e}"),
        code: codes::CTX_2066.to_owned(),
    })?;
    bytes.try_into().map_err(|v: Vec<u8>| ScpError::Validation {
        msg: format!("{field_name} must be 32 bytes, got {}", v.len()),
        code: codes::CTX_2066.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Free functions — context migration (§5.11A, #580)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — broadcast operations (#387)
// ---------------------------------------------------------------------------

/// An asset to publish to a broadcast context (SCP-290).
///
/// Typed struct to prevent positional transposition of path/`content_type`/body.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AssetEntry {
    /// Validated URL path (e.g., `/index.html`, `/styles.css`).
    pub path: String,
    /// Validated MIME type (e.g., `text/html`, `text/css`).
    pub content_type: String,
    /// Raw content bytes.
    pub body: Vec<u8>,
}

/// Result of publishing an asset to a broadcast context (SCP-290, SCP-292).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PublishResult {
    /// Hex-encoded SHA-256 of the serialized broadcast envelope.
    pub blob_id: String,
    /// Hex-encoded SHA-256 of the asset body.
    pub etag: String,
    /// The deploy ID for this asset (auto-generated or caller-provided).
    pub deploy_id: String,
}

/// Result of publishing multiple assets to a broadcast context (SCP-292).
///
/// Groups per-asset results with the shared deploy ID used across the batch.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BatchPublishResult {
    /// Per-asset publish results.
    pub results: Vec<PublishResult>,
    /// The shared deploy ID for this batch.
    pub deploy_id: String,
}

// NOTE: SiteConfig is defined at the SDK layer (Swift Governance.swift, Kotlin Types.kt)
// with client-side validation. It is NOT a UniFFI record to avoid type ambiguity with
// the auto-generated ScpBindings.swift. The SDK types will be mapped to the Rust
// `scp_node::projection::SiteConfig` at the FFI call site when lifecycle methods
// are wired (SCP-295).

// ---------------------------------------------------------------------------
// Free functions — membership queries (#387)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — events (#387)
// ---------------------------------------------------------------------------

/// Formats a [`ContextEvent`] as a human-readable string.
///
/// Consequence events (`ConsequenceTriggered`, `ConsequenceEnforced`) are
/// formatted with structured key=value pairs for observability. All other
/// events use their `Debug` representation.
fn format_context_event(event: &scp_core::context::membership::ContextEvent) -> String {
    use scp_core::context::membership::ContextEvent::{ConsequenceEnforced, ConsequenceTriggered};
    match event {
        ConsequenceTriggered {
            context_id,
            member_did,
            rule_index,
            trigger_type,
            action_type,
        } => format!(
            "consequence_triggered:member={member_did},\
             rule={rule_index},trigger={trigger_type},\
             action={action_type},context={context_id}"
        ),
        ConsequenceEnforced {
            context_id,
            member_did,
            action_type,
            success,
        } => format!(
            "consequence_enforced:member={member_did},\
             action={action_type},success={success},\
             context={context_id}"
        ),
        other => scp_ffi_common::html_escape_event_string(&format!("{other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Free functions — access key lifecycle (#1529)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — TTL operations (#387)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Free functions — local DID management (#387)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Converts bridge `ContextParams` to scp-core `ContextParams`.
fn bridge_params_to_core(
    params: &ContextParams,
) -> Result<scp_core::context::ContextParams, ScpError> {
    // Convert UniFFI bridge enums/fields to canonical string values for the
    // shared context-params builder (#1447).
    let mode_str = match params.mode {
        ContextMode::Encrypted => "encrypted",
        ContextMode::Broadcast => "broadcast",
    };

    let ceiling_policy_str = match params.ceiling_policy {
        CeilingPolicy::Immutable => "immutable",
        CeilingPolicy::Governed => "governed",
    };

    let memory_scope_str = match params.memory_scope {
        MemoryScope::Ephemeral => "ephemeral",
        MemoryScope::Summary => "summary",
        MemoryScope::Full => "full",
    };

    let governance_str = match params.governance {
        GovernanceModel::SingleAdmin => "single_admin",
        GovernanceModel::Multisig => "multisig",
        GovernanceModel::TokenVoting => "token_voting",
    };

    let promotion_policy_str = if params.promotable {
        "promotable"
    } else {
        "no_promotion"
    };

    let min_protocol_version = if params.min_protocol_version == 0 {
        None
    } else {
        let (major, minor) =
            scp_core::context::decode_protocol_version(params.min_protocol_version);
        Some((major, minor))
    };

    let ttl = if params.ttl_seconds > 0 {
        Some(std::time::Duration::from_secs(params.ttl_seconds))
    } else {
        None
    };

    let common = scp_ffi_common::context_params::CommonContextParams {
        mode: mode_str.to_owned(),
        ceiling: params.ceiling.clone(),
        ceiling_policy: ceiling_policy_str.to_owned(),
        promotion_policy: promotion_policy_str.to_owned(),
        memory_scope: memory_scope_str.to_owned(),
        governance: governance_str.to_owned(),
        ttl,
        min_protocol_version,
        max_chain_depth: params.max_chain_depth,
        max_nesting_depth: params.max_nesting_depth,
        session_cap: params.session_cap,
        economic_policy_json: params.economic_policy.clone(),
        consequence_rules_json: params.consequence_rules_json.clone(),
        consequence_config_json: params.consequence_config_json.clone(),
        ..Default::default()
    };

    scp_ffi_common::context_params::build_context_params(&common).map_err(|e| {
        ScpError::Validation {
            msg: e,
            code: codes::VALID_7000.to_owned(),
        }
    })
}

/// Parses a custody type string into a `CustodyMethod`.
pub(crate) fn parse_custody_method(custody: &str) -> Result<CustodyMethod, ScpError> {
    match custody {
        "in_memory" => Ok(CustodyMethod::InMemory),
        "platform" => Ok(CustodyMethod::Platform),
        "software" => Ok(CustodyMethod::Software),
        // VALID_7005 ("invalid field value") matches the semantic: an
        // unrecognized enum string is a wrong-value error, not the
        // malformed/wrong-shape byte input that VALID_7007 is reserved
        // for (api-design J2, M1). PyO3's `parse_custody_inner` emits
        // the same class of error (VALID_7001 via
        // `ScpPyError::validation`), both distinct from the narrower
        // 7007.
        other => Err(ScpError::Validation {
            msg: format!(
                "unknown custody type: {other:?} — expected \"in_memory\", \"platform\", or \"software\""
            ),
            code: codes::VALID_7005.to_owned(),
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
                msg: format!(
                    "invalid source_type '{other}': expected 'persistent', 'ephemeral', or 'summary'"
                ),
                code: codes::VALID_7000.to_owned(),
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
                msg: format!(
                    "invalid context_state '{other}': expected 'active', \
                     'closed_with_summary_verified', 'closed_with_summary_unverified', \
                     'closed_ephemeral', or 'unknown'"
                ),
                code: codes::VALID_7000.to_owned(),
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
        discovery_method: DiscoveryMethod::OutOfBand,
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

/// Queries a trust score for the given DID in the given context.
///
/// Trust event counts are queried from the module-level helper (a
/// stateless `(0, 0)` stub today — see
/// `runtime::query_trust_event_counts`). The composite score is
/// `min(1.0, log10(1 + message_count + governance_count))`.
///
/// ADR-048 §1: pure helper, no per-instance state.
#[uniffi::export]
pub fn trust_query_score(did: String, context_id: String) -> Result<TrustScoreResult, ScpError> {
    if did.is_empty() {
        return Err(ScpError::Validation {
            msg: "DID must not be empty".to_owned(),
            code: codes::VALID_7010.to_owned(),
        });
    }
    if context_id.is_empty() {
        return Err(ScpError::Validation {
            msg: "context_id must not be empty".to_owned(),
            code: codes::VALID_7011.to_owned(),
        });
    }

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
            msg: format!("failed to parse attestation JSON: {e}"),
            code: codes::VALID_7012.to_owned(),
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
            msg: "target DID must not be empty".to_owned(),
            code: codes::VALID_7013.to_owned(),
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
        std::time::Duration::from_mins(5),
        &signer,
    )
    .map_err(|e| ScpError::Validation {
        msg: format!("challenge creation failed: {e}"),
        code: codes::VALID_7014.to_owned(),
    })?;

    let challenge_json = serde_json::to_string(&request).map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize challenge: {e}"),
        code: codes::VALID_7015.to_owned(),
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
            msg: format!("failed to parse challenge JSON: {e}"),
            code: codes::VALID_7016.to_owned(),
        })?;

    let response: scp_core::trust::ChallengeResponse = serde_json::from_str(&response_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("failed to parse response JSON: {e}"),
            code: codes::VALID_7017.to_owned(),
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
/// - `profile_json`: JSON array of `ParticipationProfile` objects.
/// - `requirements_json`: JSON array of `RequireParticipation` objects.
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
            msg: format!("failed to parse participation profiles JSON: {e}"),
            code: codes::VALID_7030.to_owned(),
        })?;

    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(&requirements_json).map_err(|e| ScpError::Validation {
            msg: format!("failed to parse participation requirements JSON: {e}"),
            code: codes::VALID_7031.to_owned(),
        })?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    scp_core::trust::verify_participation_requirements(current_time, &requirements, &profiles)
        .map_err(|e| ScpError::Validation {
            msg: format!("participation admission verification failed: {e}"),
            code: codes::VALID_7032.to_owned(),
        })?;

    Ok(true)
}

// ---------------------------------------------------------------------------
// aggregate_trust_input (§7.3)
// ---------------------------------------------------------------------------

/// Per-instance equivalent of [`uniffi_append_provenance_event`].
///
/// Appends a provenance event to the UCAN event log on `bi`. Phase D
/// (#1695, ADR-048) replaces the prior free function that consulted the
/// deleted process-wide `DEFAULT_BRIDGE_INSTANCE`.
fn uniffi_append_provenance_event_on(
    bi: &crate::runtime::UniffiBridgeInstance,
    context_id: &str,
    actor_did: &str,
    event_type: scp_event_log::EventType,
    provenance_hash: &[u8; 32],
) -> Result<(), ScpError> {
    #[allow(clippy::cast_possible_truncation)]
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    bi.with_ucan_state(context_id, |state| {
        let sequence = scp_event_log::tree::event_count(&state.event_log);
        let prev_hash = if state.event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            state.event_log.leaves()[state.event_log.leaves().len() - 1]
        };

        let event = scp_event_log::Event {
            event_type,
            actor_did: scp_identity::DID::from(actor_did.to_owned()),
            timestamp,
            sequence,
            payload: scp_event_log::EventPayload {
                data: provenance_hash.to_vec(),
            },
            prev_hash,
            signature: Vec::new(),
        };

        scp_event_log::tree::append_unsigned_event(&mut state.event_log, &event)
            .map(|_| ())
            .map_err(|e| ScpError::Context {
                msg: format!("failed to append provenance event: {e}"),
                code: codes::CTX_2060.to_owned(),
            })
    })
    .unwrap_or_else(|| {
        Err(ScpError::Context {
            msg: format!("context '{context_id}' not found in UCAN state registry"),
            code: codes::CTX_2066.to_owned(),
        })
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
        discovery_method: scp_core::provenance::DiscoveryMethod::OutOfBand,
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

/// Redacts counterparties from a provenance record (§24.3.5).
///
/// Accepts a JSON-serialized provenance record, removes all counterparty DIDs,
/// and returns the modified record as a JSON string.
///
/// # Errors
///
/// Returns [`ScpError::Validation`] if the JSON is invalid or cannot be
/// deserialized as a provenance record.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI requires owned String parameters
pub fn provenance_redact_counterparties(provenance_json: String) -> Result<String, ScpError> {
    let mut prov: scp_core::provenance::DataProvenance = serde_json::from_str(&provenance_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid provenance JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })?;

    scp_core::provenance::attach::redact_counterparties(&mut prov);

    serde_json::to_string(&prov).map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize provenance: {e}"),
        code: codes::VALID_7051.to_owned(),
    })
}

/// Pseudonymizes counterparties in a provenance record (§24.3.5).
///
/// Accepts a JSON-serialized provenance record and a hex-encoded pseudonym key.
/// Replaces real counterparty DIDs with deterministic context-scoped pseudonyms.
/// Returns the modified record as a JSON string.
///
/// # Errors
///
/// Returns [`ScpError::Validation`] if the JSON is invalid, cannot be
/// deserialized as a provenance record, or if `pseudonym_key_hex` is not
/// valid hex.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI requires owned String parameters
pub fn provenance_pseudonymize_counterparties(
    provenance_json: String,
    pseudonym_key_hex: String,
) -> Result<String, ScpError> {
    let mut prov: scp_core::provenance::DataProvenance = serde_json::from_str(&provenance_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid provenance JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })?;

    let key =
        Zeroizing::new(
            hex::decode(&pseudonym_key_hex).map_err(|e| ScpError::Validation {
                msg: format!("invalid pseudonym_key_hex: {e}"),
                code: codes::VALID_7052.to_owned(),
            })?,
        );

    scp_core::provenance::attach::pseudonymize_counterparties(&mut prov, &key);

    serde_json::to_string(&prov).map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize provenance: {e}"),
        code: codes::VALID_7051.to_owned(),
    })
}

/// Updates the source type of a provenance record to reflect a new context
/// state (ADR-019 AC5).
///
/// Accepts a JSON-serialized provenance record and a context state string.
/// Returns the modified record as a JSON string.
///
/// # Errors
///
/// Returns [`ScpError::Validation`] if the JSON is invalid, cannot be
/// deserialized as a provenance record, or if `new_state` is not a
/// recognized context state value.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI requires owned String parameters
pub fn provenance_update_source_type(
    provenance_json: String,
    new_state: String,
) -> Result<String, ScpError> {
    use scp_core::provenance::evaluate::{SourceContextState, update_source_type};

    let mut prov: scp_core::provenance::DataProvenance = serde_json::from_str(&provenance_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid provenance JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })?;

    let state = match new_state.as_str() {
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
                msg: format!(
                    "invalid context_state '{other}': expected 'active', \
                     'closed_with_summary_verified', 'closed_with_summary_unverified', \
                     'closed_ephemeral', or 'unknown'"
                ),
                code: codes::VALID_7053.to_owned(),
            });
        }
    };

    update_source_type(&mut prov, &state);

    serde_json::to_string(&prov).map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize provenance: {e}"),
        code: codes::VALID_7051.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Media — session lifecycle and signaling (#597)
// ---------------------------------------------------------------------------

/// Checks that a media capability is present in the context's capability ceiling.
///
/// Returns `true` if the capability is present in the ceiling.
///
/// # Arguments
///
/// * `ceiling` - List of capability name strings from the context ceiling.
/// * `capability` - Media capability: `"voice"`, `"video"`, or `"screen_share"`.
#[uniffi::export]
pub fn media_check_capability(ceiling: Vec<String>, capability: String) -> Result<bool, ScpError> {
    let cap = parse_media_capability(&capability)?;
    let param_caps: Vec<scp_core::context::params::Capability> = ceiling
        .iter()
        .map(scp_core::context::params::Capability::new)
        .collect();
    scp_media::session::check_media_capability(&param_caps, &cap).map_err(|e| {
        ScpError::Context {
            msg: e.to_string(),
            code: codes::CTX_2500.to_owned(),
        }
    })?;
    Ok(true)
}

/// Initiates a media session after validating capabilities against the ceiling.
///
/// Returns a JSON string with session fields.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn media_initiate_session(
    context_id: String,
    ceiling: Vec<String>,
    capabilities: Vec<String>,
    participants: Vec<String>,
    timestamp: u64,
) -> Result<String, ScpError> {
    let caps: Vec<scp_media::session::MediaCapability> = capabilities
        .iter()
        .map(|s| parse_media_capability(s))
        .collect::<Result<Vec<_>, _>>()?;

    let param_caps: Vec<scp_core::context::params::Capability> = ceiling
        .iter()
        .map(scp_core::context::params::Capability::new)
        .collect();

    let session = scp_media::session::initiate_media_session(
        context_id,
        &param_caps,
        caps,
        participants
            .into_iter()
            .map(scp_identity::DID::from)
            .collect(),
        timestamp,
    )
    .map_err(|e| ScpError::Context {
        msg: e.to_string(),
        code: codes::CTX_2500.to_owned(),
    })?;

    media_session_to_json(&session)
}

/// Activates a media session (transitions from Initiating to Active).
///
/// Takes a JSON string representing the session and returns the updated session.
#[uniffi::export]
pub fn media_activate_session(session_json: String) -> Result<String, ScpError> {
    let mut session: scp_media::session::MediaSession = serde_json::from_str(&session_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid session JSON: {e}"),
            code: codes::VALID_7301.to_owned(),
        })?;

    scp_media::session::activate_session(&mut session).map_err(|e| ScpError::Context {
        msg: e.to_string(),
        code: codes::CTX_2500.to_owned(),
    })?;

    media_session_to_json(&session)
}

/// Adds a participant to a media session.
///
/// Takes a JSON string and returns the updated session.
#[uniffi::export]
pub fn media_join_session(
    session_json: String,
    participant_did: String,
) -> Result<String, ScpError> {
    let mut session: scp_media::session::MediaSession = serde_json::from_str(&session_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid session JSON: {e}"),
            code: codes::VALID_7301.to_owned(),
        })?;

    scp_media::session::join_media_session(&mut session, participant_did.into()).map_err(|e| {
        ScpError::Context {
            msg: e.to_string(),
            code: codes::CTX_2500.to_owned(),
        }
    })?;

    media_session_to_json(&session)
}

/// Ends a media session and returns metadata for event log recording.
///
/// Returns a JSON string with `session` and `metadata` keys.
#[uniffi::export]
pub fn media_end_session(session_json: String, timestamp: u64) -> Result<String, ScpError> {
    let mut session: scp_media::session::MediaSession = serde_json::from_str(&session_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid session JSON: {e}"),
            code: codes::VALID_7301.to_owned(),
        })?;

    let metadata = scp_media::session::end_media_session(&mut session, timestamp).map_err(|e| {
        ScpError::Context {
            msg: e.to_string(),
            code: codes::CTX_2500.to_owned(),
        }
    })?;

    serde_json::to_string(&serde_json::json!({
        "session": {
            "session_id": session.session_id,
            "context_id": session.context_id,
            "participants": session.participants,
            "capabilities": session.capabilities.iter().map(media_capability_to_string).collect::<Vec<_>>(),
            "state": media_state_to_string(&session.state),
            "started_at": session.started_at,
        },
        "metadata": {
            "session_id": metadata.session_id,
            "context_id": metadata.context_id,
            "participants": metadata.participants,
            "capabilities": metadata.capabilities.iter().map(media_capability_to_string).collect::<Vec<_>>(),
            "started_at": metadata.started_at,
            "ended_at": metadata.ended_at,
        },
    }))
    .map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize result: {e}"),
        code: codes::VALID_7301.to_owned(),
    })
}

/// Creates an SDP offer signaling message.
///
/// Returns a JSON string with `session_id` and `message` keys.
#[uniffi::export]
pub fn media_create_offer(
    session_id: String,
    sdp: String,
    sender_did: String,
) -> Result<String, ScpError> {
    let (sid, msg) = scp_media::signaling::create_offer(&session_id, sdp, sender_did.into());
    signaling_to_json(&sid, &msg)
}

/// Creates an SDP answer signaling message.
///
/// Returns a JSON string with `session_id` and `message` keys.
#[uniffi::export]
pub fn media_create_answer(
    session_id: String,
    sdp: String,
    sender_did: String,
) -> Result<String, ScpError> {
    let (sid, msg) = scp_media::signaling::create_answer(&session_id, sdp, sender_did.into());
    signaling_to_json(&sid, &msg)
}

/// Creates an ICE candidate signaling message.
///
/// Returns a JSON string with `session_id` and `message` keys.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn media_create_ice_candidate(
    session_id: String,
    candidate: String,
    sender_did: String,
    sdp_mid: Option<String>,
    sdp_mline_index: Option<u16>,
) -> Result<String, ScpError> {
    let (sid, msg) = scp_media::signaling::create_ice_candidate(
        &session_id,
        candidate,
        sdp_mid,
        sdp_mline_index,
        sender_did.into(),
    );
    signaling_to_json(&sid, &msg)
}

/// Creates a session-end signaling message.
///
/// Returns a JSON string with `session_id` and `message` keys.
#[uniffi::export]
pub fn media_create_session_end(
    session_id: String,
    sender_did: String,
) -> Result<String, ScpError> {
    let (sid, msg) = scp_media::signaling::create_session_end(&session_id, sender_did.into());
    signaling_to_json(&sid, &msg)
}

/// Serializes a signaling message and returns payload bytes with message type.
///
/// Returns a JSON string with `payload` (base64-encoded bytes) and `message_type` keys.
#[uniffi::export]
pub fn media_send_signaling(signaling_json: String) -> Result<String, ScpError> {
    let msg =
        scp_media::signaling::deserialize_signaling(signaling_json.as_bytes()).map_err(|e| {
            ScpError::Validation {
                msg: format!("invalid signaling JSON: {e}"),
                code: codes::VALID_7303.to_owned(),
            }
        })?;
    let (payload, message_type) =
        scp_media::signaling::send_signaling(&msg).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize signaling: {e}"),
            code: codes::VALID_7302.to_owned(),
        })?;

    use base64::Engine;
    serde_json::to_string(&serde_json::json!({
        "payload": base64::engine::general_purpose::STANDARD.encode(&payload),
        "message_type": format!("{message_type:?}"),
    }))
    .map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize result: {e}"),
        code: codes::VALID_7302.to_owned(),
    })
}

/// Verifies that the sender DID in a signaling message matches the envelope sender.
///
/// Returns `true` if valid.
#[uniffi::export]
pub fn media_verify_sender_attribution(
    signaling_json: String,
    envelope_sender_did: String,
) -> Result<bool, ScpError> {
    let msg =
        scp_media::signaling::deserialize_signaling(signaling_json.as_bytes()).map_err(|e| {
            ScpError::Validation {
                msg: format!("invalid signaling JSON: {e}"),
                code: codes::VALID_7303.to_owned(),
            }
        })?;
    scp_media::signaling::verify_sender_attribution(&msg, &envelope_sender_did).map_err(|e| {
        ScpError::Context {
            msg: format!("sender attribution verification failed: {e}"),
            code: codes::CTX_2501.to_owned(),
        }
    })?;
    Ok(true)
}

// Media helpers

fn parse_media_capability(s: &str) -> Result<scp_media::session::MediaCapability, ScpError> {
    match s {
        "voice" => Ok(scp_media::session::MediaCapability::Voice),
        "video" => Ok(scp_media::session::MediaCapability::Video),
        "screen_share" => Ok(scp_media::session::MediaCapability::ScreenShare),
        other => Err(ScpError::Validation {
            msg: format!(
                "invalid media capability '{other}': expected 'voice', 'video', or 'screen_share'"
            ),
            code: codes::VALID_7300.to_owned(),
        }),
    }
}

const fn media_capability_to_string(cap: &scp_media::session::MediaCapability) -> &'static str {
    match cap {
        scp_media::session::MediaCapability::Voice => "voice",
        scp_media::session::MediaCapability::Video => "video",
        scp_media::session::MediaCapability::ScreenShare => "screen_share",
    }
}

const fn media_state_to_string(state: &scp_media::session::MediaSessionState) -> &'static str {
    match state {
        scp_media::session::MediaSessionState::Initiating => "initiating",
        scp_media::session::MediaSessionState::Active => "active",
        scp_media::session::MediaSessionState::Ended => "ended",
    }
}

fn media_session_to_json(session: &scp_media::session::MediaSession) -> Result<String, ScpError> {
    serde_json::to_string(&serde_json::json!({
        "session_id": session.session_id,
        "context_id": session.context_id,
        "participants": session.participants,
        "capabilities": session.capabilities.iter().map(media_capability_to_string).collect::<Vec<_>>(),
        "state": media_state_to_string(&session.state),
        "started_at": session.started_at,
    }))
    .map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize session: {e}"),
        code: codes::VALID_7301.to_owned(),
    })
}

fn signaling_to_json(
    session_id: &str,
    msg: &scp_media::signaling::SignalingMessage,
) -> Result<String, ScpError> {
    let msg_json =
        String::from_utf8(scp_media::signaling::serialize_signaling(msg).map_err(|e| {
            ScpError::Validation {
                msg: format!("failed to serialize signaling: {e}"),
                code: codes::VALID_7302.to_owned(),
            }
        })?)
        .map_err(|e| ScpError::Validation {
            msg: format!("signaling bytes are not valid UTF-8: {e}"),
            code: codes::VALID_7302.to_owned(),
        })?;

    serde_json::to_string(&serde_json::json!({
        "session_id": session_id,
        "message": msg_json,
    }))
    .map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize result: {e}"),
        code: codes::VALID_7302.to_owned(),
    })
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
                msg: format!("invalid shadow_status '{other}': expected 'shadow' or 'claimed'"),
                code: codes::VALID_7051.to_owned(),
            });
        }
    };

    let base = scp_core::provenance::DataProvenance {
        source_context: String::new(),
        source_type: scp_core::provenance::SourceType::Persistent,
        counterparties: vec![],
        purpose: None,
        discovery_method: scp_core::provenance::DiscoveryMethod::OutOfBand,
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
            msg: format!("invalid address '{address}': {e}"),
            code: codes::VALID_7044.to_owned(),
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
        msg: format!("failed to serialize parsed address: {e}"),
        code: codes::VALID_7045.to_owned(),
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
        msg: format!("failed to serialize query: {e}"),
        code: codes::VALID_7046.to_owned(),
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

// Shared helper for petname/handle/scope/address_resolve methods on `Scp`.
use scp_ffi_common::petname_helpers;

/// Parses a [`HandleTarget`] from a JSON string, delegating to `scp-ffi-common`.
fn uniffi_parse_handle_target(
    json: &str,
) -> Result<scp_core::discovery::addressing::HandleTarget, ScpError> {
    petname_helpers::parse_handle_target(json).map_err(|e| ScpError::Validation {
        msg: e.message,
        code: codes::VALID_7126.to_owned(),
    })
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
//
// `BridgeContextState` type is defined in `scp_ffi_common::bridge_state`.
// Per-context state is owned by `BridgeInstance::bridge_state`.

use scp_ffi_common::bridge_state::BridgeContextState;

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

/// Bridge credential metadata result.
///
/// Returned by `bridge_credential_provision` and `bridge_credential_rotate`.
/// Mirrors the `PyO3` dict (`bridge_id`, `credential_type`, `created_at`).
/// The encrypted credential bytes never cross the FFI boundary — only
/// non-secret metadata.
///
/// See spec section 12.11 (Credential Lifecycle) and ADR-023.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BridgeCredentialResult {
    /// The bridge instance this credential belongs to.
    pub bridge_id: String,
    /// The credential type string (e.g. `"ApiKey"`, `"OAuthAccessToken"`,
    /// `"Custom:<name>"`).
    pub credential_type: String,
    /// Unix timestamp (seconds) when the credential was created.
    pub created_at: u64,
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
/// * `webhook_url` — For cooperative mode: the platform's webhook receiver URL.
/// * `platform_key` — For cooperative mode: the platform's Ed25519 public key (32 bytes).
/// * `max_shadows` — Governance-configured shadow limit (default 10,000).
/// * `metadata_display_name` — Human-readable display name for the bridge.
/// * `metadata_description` — Free-text description of the bridge.
/// * `metadata_operator_contact` — Contact information for the bridge operator.
///
/// # Returns
///
/// A `BridgeRegistrationResult` with the registration details.
///
/// # Errors
///
/// Returns `ScpError::Validation` if `operator_did` or `governance_did`
/// is not a valid DID string (empty, exceeds 512 bytes, missing
/// `did:{method}:{id}` structure, method not lowercase alphanumeric, or
/// contains control characters), or if `mode` is not recognized. Returns
/// `ScpError::Context` if registration or approval fails (including
/// self-approval).
///
/// See spec section 12 (Bridge System) and ADR-023.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn bridge_register(
    context_id: String,
    operator_did: String,
    governance_did: String,
    platform: String,
    mode: String,
    webhook_url: Option<String>,
    platform_key: Option<Vec<u8>>,
    max_shadows: Option<u32>,
    metadata_display_name: Option<String>,
    metadata_description: Option<String>,
    metadata_operator_contact: Option<String>,
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
                msg: format!(
                    "invalid bridge mode '{other}': expected 'relay', 'puppet', 'api', or 'cooperative'"
                ),
                code: codes::VALID_7050.to_owned(),
            });
        }
    };

    let parsed_platform_key = platform_key
        .map(|k| {
            scp_ffi_common::validate::expect_fixed_bytes::<32>(k.as_slice(), "platform_key")
                .map_err(|msg| ScpError::Validation {
                    msg,
                    code: codes::VALID_7052.to_owned(),
                })
        })
        .transpose()?;

    let mut registry = scp_core::bridge::registration::BridgeRegistry::new(context_id.clone());

    // Bridge ID per spec §12.2.1: SHA-256(context_id || operator_did || platform || timestamp).
    let (bridge_id, now_secs) =
        scp_ffi_common::generate_bridge_id(&context_id, &operator_did, &platform);
    let request = scp_core::bridge::registration::BridgeRegistrationRequest {
        bridge_id: bridge_id.clone(),
        operator_did: operator_did.clone().into(),
        platform: platform.clone(),
        mode: bridge_mode,
        context_id: context_id.clone(),
        requested_at: now_secs,
        self_hosted: false,
        webhook_url,
        platform_key: parsed_platform_key,
        max_shadows: max_shadows.unwrap_or(10_000),
        metadata: scp_core::bridge::registration::BridgeRegistrationMetadata {
            display_name: metadata_display_name.unwrap_or_default(),
            description: metadata_description.unwrap_or_default(),
            operator_contact: metadata_operator_contact.unwrap_or_default(),
        },
    };

    scp_core::bridge::registration::register_bridge(&mut registry, request).map_err(|e| {
        ScpError::Context {
            msg: format!("bridge registration failed: {e}"),
            code: codes::CTX_2100.to_owned(),
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
        msg: format!("bridge approval failed: {e}"),
        code: codes::CTX_2101.to_owned(),
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
/// Uses the persistent per-context `ShadowRegistry` and `SenderKeyStore`
/// from the process-global bridge state registry, ensuring that shadow
/// identity state and sender keys survive across function calls.
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
///
/// Phase D (#1695): moved from a module-level free function to a method on
/// `Scp`. The bridge state it mutates (`CoreFields::bridge_state`) is now
/// per-instance and can only be reached via a caller-owned `Scp` handle.
fn bridge_create_shadow_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
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
                msg: format!(
                    "invalid bridge mode '{other}': expected 'relay', 'puppet', 'api', or 'cooperative'"
                ),
                code: codes::VALID_7050.to_owned(),
            });
        }
    };

    let shadow_id = format!("shadow-{bridge_id}-{}", platform_handle.replace('@', ""));

    let params = scp_core::bridge::shadow::CreateShadowParams {
        shadow_id: &shadow_id,
        bridge_id: &bridge_id,
        bridge_mode: mode,
        platform_handle: &platform_handle,
        context_member_dids: &[],
        timestamp: 0,
    };

    let mut entry = bi
        .core
        .bridge_state()
        .entry(context_id.clone())
        .or_insert_with(|| BridgeContextState {
            shadow_registry: scp_core::bridge::shadow::ShadowRegistry::new(context_id),
            sender_key_store: scp_core::crypto::sender_keys::SenderKeyStore::new(),
        });
    let state = entry.value_mut();

    let (shadow, _event) = scp_core::bridge::shadow::create_shadow(
        &mut state.shadow_registry,
        &mut state.sender_key_store,
        &params,
    )
    .map_err(|e| ScpError::Context {
        msg: format!("shadow creation failed: {e}"),
        code: codes::CTX_2102.to_owned(),
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
// Bridge credential store operations (§12.11)
//
// Per-bridge-instance helpers mirroring the PyO3 `*_impl` functions in
// `crates/scp-ffi/src/bridge_connector.rs`. Each resolves the credential
// store from `bi.credential_store()` and drives the async
// `BridgeCredentialStore` trait via the shared tokio runtime
// (`crate::runtime().block_on(...)`). UniFFI bridge methods are sync; the
// shared runtime supplies the async context.
// ---------------------------------------------------------------------------

use scp_core::bridge::credentials::{BridgeCredentialStore, CredentialType};

/// Parses a credential type string into a [`CredentialType`].
///
/// Accepts the four standard variants plus the `Custom:<name>` prefix form,
/// mirroring the `PyO3` `parse_credential_type` helper.
fn parse_credential_type(s: &str) -> Result<CredentialType, ScpError> {
    match s {
        "OAuthAccessToken" => Ok(CredentialType::OAuthAccessToken),
        "OAuthRefreshToken" => Ok(CredentialType::OAuthRefreshToken),
        "ApiKey" => Ok(CredentialType::ApiKey),
        "WebhookSecret" => Ok(CredentialType::WebhookSecret),
        other => other.strip_prefix("Custom:").map_or_else(
            || {
                Err(ScpError::Validation {
                    msg: format!(
                        "invalid credential type '{other}': expected 'OAuthAccessToken', \
                         'OAuthRefreshToken', 'ApiKey', 'WebhookSecret', or 'Custom:<name>'"
                    ),
                    code: codes::VALID_7058.to_owned(),
                })
            },
            |name| Ok(CredentialType::Custom(name.to_owned())),
        ),
    }
}

/// Validates that a credential key is exactly 32 bytes, returning it
/// wrapped in [`Zeroizing`] so the copy is zeroed on drop.
fn parse_credential_key_bytes(key: &[u8]) -> Result<Zeroizing<[u8; 32]>, ScpError> {
    <[u8; 32]>::try_from(key)
        .map(Zeroizing::new)
        .map_err(|_| ScpError::Validation {
            msg: format!(
                "bridge_credential_key must be exactly 32 bytes, got {}",
                key.len()
            ),
            code: codes::VALID_7057.to_owned(),
        })
}

/// Maps a `scp-core` `BridgeCredential` to the FFI metadata result. The
/// encrypted bytes are intentionally dropped — only non-secret metadata
/// crosses the boundary.
fn credential_to_result(
    credential: &scp_core::bridge::credentials::BridgeCredential,
) -> BridgeCredentialResult {
    BridgeCredentialResult {
        bridge_id: credential.bridge_id.clone(),
        credential_type: credential.credential_type.to_string(),
        created_at: credential.created_at,
    }
}

/// Per-instance implementation of `bridge_credential_provision`.
fn bridge_credential_provision_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    bridge_id: &str,
    credential_type: &str,
    plaintext: &[u8],
    bridge_credential_key: &[u8],
) -> Result<BridgeCredentialResult, ScpError> {
    let ct = parse_credential_type(credential_type)?;
    let key_bytes = parse_credential_key_bytes(bridge_credential_key)?;
    let store = bi.credential_store();

    let credential = crate::runtime()
        .block_on(store.provision(bridge_id, ct, plaintext, &key_bytes))
        .map_err(|e| ScpError::Context {
            msg: format!("credential provision failed: {e}"),
            code: codes::CTX_2105.to_owned(),
        })?;

    Ok(credential_to_result(&credential))
}

/// Per-instance implementation of `bridge_credential_retrieve`.
fn bridge_credential_retrieve_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    bridge_id: &str,
    credential_type: &str,
    bridge_credential_key: &[u8],
) -> Result<Vec<u8>, ScpError> {
    let ct = parse_credential_type(credential_type)?;
    let key_bytes = parse_credential_key_bytes(bridge_credential_key)?;
    let store = bi.credential_store();

    let plaintext = crate::runtime()
        .block_on(store.retrieve(bridge_id, &ct, &key_bytes))
        .map_err(|e| ScpError::Context {
            msg: format!("credential retrieve failed: {e}"),
            code: codes::CTX_2106.to_owned(),
        })?;

    Ok(plaintext.to_vec())
}

/// Per-instance implementation of `bridge_credential_rotate`.
fn bridge_credential_rotate_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    bridge_id: &str,
    credential_type: &str,
    new_plaintext: &[u8],
    bridge_credential_key: &[u8],
) -> Result<BridgeCredentialResult, ScpError> {
    let ct = parse_credential_type(credential_type)?;
    let key_bytes = parse_credential_key_bytes(bridge_credential_key)?;
    let store = bi.credential_store();

    let credential = crate::runtime()
        .block_on(store.rotate(bridge_id, &ct, new_plaintext, &key_bytes))
        .map_err(|e| ScpError::Context {
            msg: format!("credential rotate failed: {e}"),
            code: codes::CTX_2107.to_owned(),
        })?;

    Ok(credential_to_result(&credential))
}

/// Per-instance implementation of `bridge_credential_revoke`.
fn bridge_credential_revoke_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    bridge_id: &str,
) -> Result<(), ScpError> {
    let store = bi.credential_store();

    crate::runtime()
        .block_on(store.revoke(bridge_id))
        .map_err(|e| ScpError::Context {
            msg: format!("credential revoke failed: {e}"),
            code: codes::CTX_2108.to_owned(),
        })?;

    Ok(())
}

/// Per-instance implementation of `bridge_credential_list`.
fn bridge_credential_list_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    bridge_id: &str,
) -> Result<Vec<String>, ScpError> {
    let store = bi.credential_store();

    let types = crate::runtime()
        .block_on(store.list(bridge_id))
        .map_err(|e| ScpError::Context {
            msg: format!("credential list failed: {e}"),
            code: codes::CTX_2109.to_owned(),
        })?;

    Ok(types.iter().map(std::string::ToString::to_string).collect())
}

/// Per-instance implementation of `bridge_credential_store_key`.
fn bridge_credential_store_key_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    bridge_id: &str,
    key: &[u8],
) -> Result<(), ScpError> {
    let key_bytes = parse_credential_key_bytes(key)?;
    let store = bi.credential_store();

    crate::runtime()
        .block_on(store.store_bridge_credential_key(bridge_id, key_bytes))
        .map_err(|e| ScpError::Context {
            msg: format!("credential key store failed: {e}"),
            code: codes::CTX_2111.to_owned(),
        })?;

    Ok(())
}

/// Per-instance implementation of `bridge_credential_get_key`.
fn bridge_credential_get_key_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    bridge_id: &str,
) -> Result<Vec<u8>, ScpError> {
    let store = bi.credential_store();

    let key = crate::runtime()
        .block_on(store.get_bridge_credential_key(bridge_id))
        .map_err(|e| ScpError::Context {
            msg: format!("credential key retrieval failed: {e}"),
            code: codes::CTX_2112.to_owned(),
        })?;

    Ok(key.to_vec())
}

/// Per-instance implementation of `bridge_credential_delete_key`.
fn bridge_credential_delete_key_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    bridge_id: &str,
) -> Result<(), ScpError> {
    let store = bi.credential_store();

    crate::runtime()
        .block_on(store.delete_bridge_credential_key(bridge_id))
        .map_err(|e| ScpError::Context {
            msg: format!("credential key deletion failed: {e}"),
            code: codes::CTX_2113.to_owned(),
        })?;

    Ok(())
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
                msg: format!("failed to resolve scp:// URI: {e}"),
                code: codes::CTX_2020.to_owned(),
            })?;

        let results = vec![
            discovery_result_to_json(&result).map_err(|e| ScpError::Context {
                msg: e,
                code: codes::CTX_2020.to_owned(),
            })?,
        ];
        serde_json::to_string(&results).map_err(|e| ScpError::Context {
            msg: format!("failed to serialize discovery results: {e}"),
            code: codes::CTX_2021.to_owned(),
        })
    } else if query.starts_with("did:") {
        validate_did(&query)?;

        runtime()
            .spawn(async move {
                let did_dht = DidDht::new();
                let results = scp_core::discovery::resolve_contexts_from_did(&query, &did_dht)
                    .await
                    .map_err(|e| ScpError::Context {
                        msg: format!("DHT discovery failed for '{query}': {e}"),
                        code: codes::CTX_2022.to_owned(),
                    })?;

                let json_results: Vec<serde_json::Value> = results
                    .iter()
                    .map(|r| {
                        discovery_result_to_json(r).map_err(|e| ScpError::Context {
                            msg: e,
                            code: codes::CTX_2022.to_owned(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                serde_json::to_string(&json_results).map_err(|e| ScpError::Context {
                    msg: format!("failed to serialize discovery results: {e}"),
                    code: codes::CTX_2023.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during discovery: {e}"),
                code: codes::CTX_2024.to_owned(),
            })?
    } else {
        Err(ScpError::Validation {
            msg: format!(
                "query must be a DID (starts with 'did:') or an scp:// URI \
                 (starts with 'scp://'), got: {query}"
            ),
            code: codes::VALID_7062.to_owned(),
        })
    }
}

// `discovery_result_to_json` lives in scp-ffi-common::discovery.
use scp_ffi_common::discovery::discovery_result_to_json;

// ---------------------------------------------------------------------------
// App Sandboxing (#595, spec §8.4.1, §8.4.2)
// ---------------------------------------------------------------------------

/// Validates a capability declaration JSON string against a context ceiling and
/// role capabilities.
///
/// Returns a JSON string with fields: `valid` (bool), `granted_capabilities`
/// (string[]), `error` (string | null), `app_did` (string).
#[uniffi::export]
pub fn sandbox_validate_declaration(
    declaration_json: String,
    ceiling_capabilities: Vec<String>,
    role_capabilities: Vec<String>,
) -> Result<String, ScpError> {
    use scp_core::context::app_sandbox::{CapabilityDeclaration, validate_declaration};
    use scp_core::context::roles::Capability;
    use scp_core::context::{ContextHandle as CoreContextHandle, ContextParams};

    let decl: CapabilityDeclaration =
        serde_json::from_str(&declaration_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid declaration JSON: {e}"),
            code: codes::VALID_7070.to_owned(),
        })?;

    let ceiling: Vec<Capability> = ceiling_capabilities.iter().map(Capability::new).collect();
    let role_caps: Vec<Capability> = role_capabilities.iter().map(Capability::new).collect();

    let handle = CoreContextHandle::new("validation-context".to_owned(), ContextParams::default());

    match validate_declaration(&decl, &ceiling, &role_caps, handle) {
        Ok(scoped) => {
            let granted: Vec<String> = scoped
                .allowed_capabilities()
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            serde_json::to_string(&serde_json::json!({
                "valid": true,
                "granted_capabilities": granted,
                "error": null,
                "app_did": decl.app_id.to_string()
            }))
            .map_err(|e| ScpError::Context {
                msg: format!("serialization failed: {e}"),
                code: codes::CTX_2030.to_owned(),
            })
        }
        Err(e) => serde_json::to_string(&serde_json::json!({
            "valid": false,
            "granted_capabilities": [],
            "error": e.to_string(),
            "app_did": decl.app_id.to_string()
        }))
        .map_err(|e| ScpError::Context {
            msg: format!("serialization failed: {e}"),
            code: codes::CTX_2031.to_owned(),
        }),
    }
}

/// Checks whether a given capability is allowed for an app binding.
#[uniffi::export]
#[must_use]
pub fn sandbox_check_capability(
    granted_capabilities: Vec<String>,
    required_capability: String,
) -> bool {
    use scp_core::context::roles::Capability;
    use std::collections::HashSet;

    let granted: HashSet<Capability> = granted_capabilities.iter().map(Capability::new).collect();
    let required = Capability::new(&required_capability);

    if granted.contains(&required) {
        return true;
    }
    if matches!(&required, Capability::ToolInvoke(_))
        && granted.contains(&Capability::ToolInvokeAll)
    {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Invitation evaluation pipeline (#614)
// ---------------------------------------------------------------------------

/// FFI-concrete implementation of `TrustOracle`.
struct UniffiBridgeTrustOracle {
    trusted_dids: Vec<scp_identity::DID>,
}

impl scp_core::context::invitation::TrustOracle for UniffiBridgeTrustOracle {
    fn satisfies_trust(
        &self,
        inviter: &scp_identity::DID,
        requirement: &scp_core::context::policy::TrustRequirement,
    ) -> bool {
        match requirement {
            scp_core::context::policy::TrustRequirement::Any => true,
            scp_core::context::policy::TrustRequirement::SharedContext => {
                self.trusted_dids.contains(inviter)
            }
            scp_core::context::policy::TrustRequirement::Explicit(dids) => dids.contains(inviter),
        }
    }
}

// ---------------------------------------------------------------------------
// SCPID authentication (§3.11)
// ---------------------------------------------------------------------------

/// Generates an SCPID challenge for the given audience (§3.11.8).
///
/// Returns the challenge as a JSON string containing `protocol`, `nonce`,
/// `audience`, `issued_at`, and `expires_at` fields.
///
/// # Arguments
///
/// * `audience` — URI identifying the relying party.
/// * `ttl_seconds` — Challenge validity window in seconds (1–300).
///
/// # Errors
///
/// Returns `ScpError::Validation` if `audience` is empty, exceeds 2048 bytes,
/// or `ttl_seconds` is 0 or exceeds 300.
#[uniffi::export]
// ttl_seconds is u64 to match the `Duration::from_secs` parameter type.
// NAPI/WASM bridges use u32 (idiomatic for JS/WASM; max valid TTL is 300s).
pub fn scpid_challenge(audience: String, ttl_seconds: u64) -> Result<String, ScpError> {
    use scp_core::identity::scpid_challenge as core_challenge;
    use std::time::Duration;

    let challenge = core_challenge(&audience, Duration::from_secs(ttl_seconds)).map_err(|e| {
        ScpError::Validation {
            msg: e.to_string(),
            code: codes::IDENT_1038.to_owned(),
        }
    })?;

    serde_json::to_string(&challenge).map_err(|e| ScpError::Identity {
        msg: format!("failed to serialize SCPID challenge: {e}"),
        code: codes::IDENT_1037.to_owned(),
    })
}

/// Signs an SCPID challenge with the identity's key (§3.11.3).
///
/// Selects the appropriate signing key (`#active` or `#agent`) from the
/// identity handle, and produces a signed SCPID response as a JSON string.
///
/// # Arguments
///
/// * `identity` — The identity handle (from `identity_create`).
/// * `signing_key_id` — `"#active"` or `"#agent"`.
/// * `challenge_json` — JSON string of the challenge (from [`scpid_challenge`]).
///
/// # Errors
///
/// Returns `ScpError::Validation` if `signing_key_id` is invalid or the
/// challenge JSON is malformed.
/// Returns `ScpError::Identity` if the identity has no agent key when
/// `#agent` is requested, or if signing fails.
/// Phase D (#1695): moved from a free function exported via
/// `#[uniffi::export]` to an `Scp::scpid_sign` method so that the
/// `Identity` handle-affinity check routes against the caller's `Scp`
/// rather than the deleted process-wide `DEFAULT_BRIDGE_INSTANCE`.
///
/// The body is retained as a `pub(crate)` helper; `Scp::scpid_sign`
/// performs the check and then delegates here.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn scpid_sign_impl(
    identity: Arc<Identity>,
    signing_key_id: String,
    challenge_json: String,
    signed_at_override: Option<u64>,
) -> Result<String, ScpError> {
    use scp_core::identity::scpid_sign as core_sign;

    // Reject `signed_at_override` on non-testing builds: the override is a
    // parity-harness affordance (ADR-046), not a production API.
    #[cfg(not(feature = "testing"))]
    if signed_at_override.is_some() {
        return Err(ScpError::Validation {
            msg:
                "signed_at_override requires the scp-core `testing` feature — not available in production builds"
                    .to_owned(),
            code: codes::VALID_7008.to_owned(),
        });
    }

    let key_id = parse_scpid_signing_key_id(&signing_key_id)?;

    let challenge: scp_core::identity::ScpIdChallenge = serde_json::from_str(&challenge_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid challenge JSON: {e}"),
            code: codes::IDENT_1038.to_owned(),
        })?;

    let core_id = identity
        .core_id
        .as_ref()
        .ok_or_else(|| ScpError::Identity {
            msg: "identity has no core identity handle — was it created with identity_create?"
                .to_owned(),
            code: codes::IDENT_1010.to_owned(),
        })?;

    let key_handle = match key_id {
        scp_identity::SigningKeyId::Active => core_id.active_signing_key,
        scp_identity::SigningKeyId::Agent => {
            core_id
                .agent_signing_key
                .ok_or_else(|| ScpError::Identity {
                    msg: format!(
                        "identity '{}' has no agent signing key — \
                         add one with identity_add_agent_key first",
                        identity.did
                    ),
                    code: codes::IDENT_1034.to_owned(),
                })?
        }
    };

    let custody = identity
        .in_memory_custody
        .as_ref()
        .ok_or_else(|| ScpError::Identity {
            msg: "scpid_sign requires in-memory custody (only supported with \
                  allow_in_memory_custody feature)"
                .to_owned(),
            code: codes::IDENT_1008.to_owned(),
        })?;

    let rt = crate::runtime();
    let response = rt.block_on(core_sign(
        &custody.0,
        &key_handle,
        &identity.did,
        key_id,
        &challenge,
        signed_at_override,
    ));

    let response = response.map_err(|e| ScpError::Identity {
        msg: e.to_string(),
        code: codes::IDENT_1037.to_owned(),
    })?;

    serde_json::to_string(&response).map_err(|e| ScpError::Identity {
        msg: format!("failed to serialize SCPID response: {e}"),
        code: codes::IDENT_1037.to_owned(),
    })
}

/// Verifies a signed SCPID response against the original challenge (§3.11.4).
///
/// Resolves the signer's DID document via the global production DID resolver
/// (initialized during `identityCreate`), then runs the 11-step verification
/// pipeline from `scp-core`. Returns the `ScpIdAuthentication` result as a
/// JSON string on success.
///
/// # Arguments
///
/// * `response_json` — JSON string of the signed response (from `scpid_sign`).
/// * `challenge_json` — JSON string of the original challenge (from `scpid_challenge`).
///
/// # Errors
///
/// Returns `ScpError::Identity` if the DID resolver is not initialized
/// (no identity created yet).
/// Returns `ScpError::Validation` if either JSON string is malformed.
/// Returns `ScpError::Identity` if DID resolution fails, the signature is
/// invalid, the challenge has expired, or any other verification step fails.
///
/// Phase D (#1695): formerly a `#[uniffi::export] pub fn`; migrated to an
/// `Scp` method so the DID resolver lookup routes against the caller's
/// per-instance `UniffiBridgeInstance`. The body lives in this `_on` helper
/// and is invoked from `Scp::scpid_verify`.
fn scpid_verify_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    response_json: String,
    challenge_json: String,
) -> Result<String, ScpError> {
    use scp_core::identity::scpid_verify as core_verify;

    let response: scp_core::identity::ScpIdResponse = serde_json::from_str(&response_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid response JSON: {e}"),
            code: codes::IDENT_1038.to_owned(),
        })?;

    let challenge: scp_core::identity::ScpIdChallenge = serde_json::from_str(&challenge_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid challenge JSON: {e}"),
            code: codes::IDENT_1038.to_owned(),
        })?;

    let resolver = bi.did_resolver().ok_or_else(|| ScpError::Identity {
        msg: "DID resolver not initialized — create an identity with \
              identityCreate before calling scpidVerify"
            .to_owned(),
        code: codes::IDENT_1033.to_owned(),
    })?;

    let rt = crate::runtime();
    let auth = rt
        .block_on(core_verify(resolver.as_ref(), &response, &challenge))
        .map_err(|e| ScpError::Identity {
            msg: e.to_string(),
            code: scpid_error_code(&e).to_owned(),
        })?;

    serde_json::to_string(&auth).map_err(|e| ScpError::Identity {
        msg: format!("failed to serialize SCPID authentication: {e}"),
        code: codes::IDENT_1037.to_owned(),
    })
}

/// Parses an SCPID signing key ID string (`"#active"` or `"#agent"`).
// Called from `#[uniffi::export]` `scpid_sign` which the dead_code lint cannot trace.
#[allow(dead_code)]
fn parse_scpid_signing_key_id(s: &str) -> Result<scp_identity::SigningKeyId, ScpError> {
    match s {
        "#active" => Ok(scp_identity::SigningKeyId::Active),
        "#agent" => Ok(scp_identity::SigningKeyId::Agent),
        other => Err(ScpError::Validation {
            msg: format!("invalid signing_key_id '{other}': expected '#active' or '#agent'"),
            code: codes::IDENT_1034.to_owned(),
        }),
    }
}

/// Maps an [`ScpIdError`] variant to its canonical SCP error code.
const fn scpid_error_code(e: &scp_core::identity::ScpIdError) -> &'static str {
    use scp_core::identity::ScpIdError;
    match e {
        ScpIdError::ChallengeExpired => codes::IDENT_1030,
        ScpIdError::AudienceMismatch => codes::IDENT_1031,
        ScpIdError::TimestampInvalid => codes::IDENT_1032,
        ScpIdError::DidResolutionFailed(_) => codes::IDENT_1033,
        ScpIdError::KeyNotAuthorized => codes::IDENT_1034,
        ScpIdError::SignatureInvalid => codes::IDENT_1035,
        ScpIdError::DidDocumentStale => codes::IDENT_1036,
        ScpIdError::SigningFailed(_) => codes::IDENT_1037,
        ScpIdError::InvalidInput(_) => codes::IDENT_1038,
    }
}

// ---------------------------------------------------------------------------
// Economic governance
// ---------------------------------------------------------------------------

/// Estimates the cost for a given action in a context.
///
/// Returns the estimated cost (smallest currency unit), or `None` on overflow.
/// Pass empty string or `"null"` for free contexts (returns 0).
#[uniffi::export]
pub fn economy_estimate_cost(
    policy_json: String,
    action_type: String,
    metrics_json: String,
) -> Result<Option<u64>, ScpError> {
    let action = parse_paid_action_type(&action_type)?;
    let metrics = parse_observable_metrics(&metrics_json)?;

    let policy = if policy_json.is_empty() || policy_json == "null" {
        None
    } else {
        let p: scp_core::economy::EconomicPolicy =
            serde_json::from_str(&policy_json).map_err(|e| ScpError::Validation {
                msg: format!("invalid economic policy JSON: {e}"),
                code: codes::VALID_7050.to_owned(),
            })?;
        Some(p)
    };

    Ok(
        scp_core::economy::estimate_cost(policy.as_ref(), &action, &metrics)
            .map(scp_core::economy::Amount::value),
    )
}

/// Returns `true` if the economic policy requires payment for any action.
#[uniffi::export]
pub fn economy_policy_requires_payment(policy_json: String) -> Result<bool, ScpError> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy =
        serde_json::from_str(&policy_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid economic policy JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })?;
    Ok(scp_core::economy::policy_requires_payment(&policy))
}

/// Returns `true` if auto-accept is blocked by economic policy.
#[uniffi::export]
pub fn economy_auto_accept_blocked(policy_json: String) -> Result<bool, ScpError> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy =
        serde_json::from_str(&policy_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid economic policy JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })?;
    Ok(scp_core::economy::auto_accept_blocked_by_economics(Some(
        &policy,
    )))
}

/// Returns `true` if the economic policy is locked (immutable).
#[uniffi::export]
pub fn economy_check_policy_lock(policy_json: String) -> Result<bool, ScpError> {
    if policy_json.is_empty() || policy_json == "null" {
        return Ok(false);
    }
    let policy: scp_core::economy::EconomicPolicy =
        serde_json::from_str(&policy_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid economic policy JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })?;
    Ok(scp_core::economy::check_policy_lock(&policy).is_err())
}

/// Validates a proposed economic policy change.
#[uniffi::export]
pub fn economy_validate_policy_change(
    current_policy_json: String,
    proposed_policy_json: String,
) -> Result<bool, ScpError> {
    let current: scp_core::economy::EconomicPolicy = serde_json::from_str(&current_policy_json)
        .map_err(|e| ScpError::Validation {
            msg: format!("invalid current policy JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })?;
    let proposed: scp_core::economy::EconomicPolicy = serde_json::from_str(&proposed_policy_json)
        .map_err(|e| ScpError::Validation {
        msg: format!("invalid proposed policy JSON: {e}"),
        code: codes::VALID_7050.to_owned(),
    })?;
    scp_core::economy::validate_policy_change(&current, &proposed).map_err(|e| {
        ScpError::Validation {
            msg: format!("policy change rejected: {e}"),
            code: codes::VALID_7051.to_owned(),
        }
    })?;
    Ok(true)
}

/// Evaluates a pricing formula against observable metrics.
#[uniffi::export]
pub fn economy_evaluate_formula(
    formula_json: String,
    metrics_json: String,
) -> Result<Option<u64>, ScpError> {
    let formula: scp_core::economy::PricingFormula =
        serde_json::from_str(&formula_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid formula JSON: {e}"),
            code: codes::VALID_7050.to_owned(),
        })?;
    let metrics = parse_observable_metrics(&metrics_json)?;
    Ok(scp_core::economy::evaluate_formula(&formula, &metrics)
        .map(scp_core::economy::Amount::value))
}

// ---------------------------------------------------------------------------
// Economy helpers
// ---------------------------------------------------------------------------

fn parse_paid_action_type(s: &str) -> Result<scp_core::economy::PaidActionType, ScpError> {
    match s {
        "MessageSend" | "message_send" => Ok(scp_core::economy::PaidActionType::MessageSend),
        "ToolInvoke" | "tool_invoke" => Ok(scp_core::economy::PaidActionType::ToolInvoke),
        "ContextJoin" | "context_join" => Ok(scp_core::economy::PaidActionType::ContextJoin),
        "SubscriptionPeriod" | "subscription_period" => {
            Ok(scp_core::economy::PaidActionType::SubscriptionPeriod)
        }
        "ByteStored" | "byte_stored" => Ok(scp_core::economy::PaidActionType::ByteStored),
        _ => Err(ScpError::Validation {
            msg: format!(
                "invalid action type: {s:?} — expected one of: MessageSend, ToolInvoke, \
                 ContextJoin, SubscriptionPeriod, ByteStored"
            ),
            code: codes::VALID_7050.to_owned(),
        }),
    }
}

// ---------------------------------------------------------------------------
// MetadataRecord inspection (§5.7.2, #615)
// ---------------------------------------------------------------------------

/// Serializes a `MetadataRecord` to a JSON string.
///
/// Constructs a `MetadataRecord` from the provided fields and returns its
/// JSON representation. The `signature` field is provided as a hex-encoded
/// string (64 bytes = 128 hex characters).
#[uniffi::export]
pub fn metadata_record_to_json(
    context_id: String,
    sequence: u64,
    signer_did: String,
    timestamp: u64,
    structural_json: String,
    operational_json: String,
    signature_hex: String,
) -> Result<String, ScpError> {
    use scp_core::context::metadata::{MetadataRecord, OperationalMetadata, StructuralMetadata};

    validate_context_id(&context_id)?;
    validate_did(&signer_did)?;

    if sequence == 0 {
        return Err(ScpError::Validation {
            msg: "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
            code: codes::VALID_7001.to_owned(),
        });
    }

    let structural: StructuralMetadata =
        serde_json::from_str(&structural_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid structural metadata JSON: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;

    let operational: OperationalMetadata =
        serde_json::from_str(&operational_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid operational metadata JSON: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;

    let signature =
        Zeroizing::new(
            hex::decode(&signature_hex).map_err(|e| ScpError::Validation {
                msg: format!("invalid signature hex: {e}"),
                code: codes::VALID_7001.to_owned(),
            })?,
        );
    if signature.len() != 64 {
        return Err(ScpError::Validation {
            msg: format!("signature must be 64 bytes (got {})", signature.len()),
            code: codes::VALID_7001.to_owned(),
        });
    }

    let record = MetadataRecord {
        context_id,
        sequence,
        signer_did: scp_identity::DID::from(signer_did),
        timestamp,
        structural,
        operational,
        signature: (*signature).clone(),
    };

    serde_json::to_string(&record).map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize MetadataRecord: {e}"),
        code: codes::VALID_7001.to_owned(),
    })
}

/// Deserializes a `MetadataRecord` from a JSON string.
///
/// Returns the validated and re-serialized JSON.
#[uniffi::export]
pub fn metadata_record_from_json(json_str: String) -> Result<String, ScpError> {
    use scp_core::context::metadata::MetadataRecord;

    let record: MetadataRecord =
        serde_json::from_str(&json_str).map_err(|e| ScpError::Validation {
            msg: format!("invalid MetadataRecord JSON: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;

    // F6: sequence must be >= 1 (spec §5.7.2)
    if record.sequence == 0 {
        return Err(ScpError::Validation {
            msg: "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
            code: codes::VALID_7001.to_owned(),
        });
    }

    // F7: signature must be exactly 64 bytes (Ed25519)
    if record.signature.len() != 64 {
        return Err(ScpError::Validation {
            msg: format!(
                "signature must be 64 bytes (got {})",
                record.signature.len()
            ),
            code: codes::VALID_7001.to_owned(),
        });
    }

    serde_json::to_string(&record).map_err(|e| ScpError::Validation {
        msg: format!("failed to re-serialize MetadataRecord: {e}"),
        code: codes::VALID_7001.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Context template inspection (§5.14, #615)
// ---------------------------------------------------------------------------

/// Returns the canonical `ContextParams` for a given template ID as JSON.
#[uniffi::export]
pub fn template_get_params(template_id: String) -> Result<String, ScpError> {
    use scp_core::context::templates::template_params;

    let tid = parse_template_id_uniffi(&template_id)?;
    let params = template_params(&tid);
    serde_json::to_string(&params).map_err(|e| ScpError::Validation {
        msg: format!("failed to serialize template params: {e}"),
        code: codes::VALID_7001.to_owned(),
    })
}

/// Validates that a `ContextParams` JSON matches its template definition.
///
/// Returns `None` on success, or a string error message on validation failure.
#[uniffi::export]
pub fn validate_against_template(params_json: String) -> Result<Option<String>, ScpError> {
    use scp_core::context::templates::validate_against_template as core_validate;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid ContextParams JSON: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;

    match core_validate(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Validates cross-field invariants for `ContextParams` regardless of template.
///
/// Returns `None` on success, or a string error message on validation failure.
#[uniffi::export]
pub fn validate_context_params(params_json: String) -> Result<Option<String>, ScpError> {
    use scp_core::context::templates::validate_context_params as core_validate;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| ScpError::Validation {
            msg: format!("invalid ContextParams JSON: {e}"),
            code: codes::VALID_7001.to_owned(),
        })?;

    match core_validate(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Parses a template ID string into a `TemplateId` enum value.
fn parse_template_id_uniffi(
    template_id: &str,
) -> Result<scp_core::context::params::TemplateId, ScpError> {
    use scp_core::context::params::TemplateId;

    match template_id {
        "BilateralEphemeral" => Ok(TemplateId::BilateralEphemeral),
        "BilateralPersistent" => Ok(TemplateId::BilateralPersistent),
        "Coordination" => Ok(TemplateId::Coordination),
        "GroupDiscussion" => Ok(TemplateId::GroupDiscussion),
        "PublicBroadcast" => Ok(TemplateId::PublicBroadcast),
        "GatedBroadcast" => Ok(TemplateId::GatedBroadcast),
        "scp:template/tool-interface" | "ToolInterfaceTemplate" => {
            Ok(TemplateId::ToolInterfaceTemplate)
        }
        "PaidService" => Ok(TemplateId::PaidService),
        "PaidBroadcast" => Ok(TemplateId::PaidBroadcast),
        "scp:template/handle-registry"
        | "HandleRegistry"
        | "scp:template/discovery-context"
        | "DiscoveryContext" => Ok(TemplateId::HandleRegistry),
        _ => Err(ScpError::Validation {
            msg: format!(
                "unknown template ID: {template_id:?} — valid values: BilateralEphemeral, \
                 BilateralPersistent, Coordination, GroupDiscussion, PublicBroadcast, \
                 GatedBroadcast, scp:template/tool-interface, PaidService, PaidBroadcast, \
                 HandleRegistry, scp:template/handle-registry, DiscoveryContext, \
                 scp:template/discovery-context"
            ),
            code: codes::VALID_7001.to_owned(),
        }),
    }
}

fn parse_observable_metrics(json: &str) -> Result<scp_core::economy::ObservableMetrics, ScpError> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| ScpError::Validation {
        msg: format!("invalid metrics JSON: {e}"),
        code: codes::VALID_7050.to_owned(),
    })?;
    Ok(scp_core::economy::ObservableMetrics {
        context_message_rate: v
            .get("context_message_rate")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        member_count: v
            .get("member_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        relay_queue_depth: v
            .get("relay_queue_depth")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        time_of_day: v
            .get("time_of_day")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        sender_velocity: v
            .get("sender_velocity")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        storage_usage: v
            .get("storage_usage")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
    })
}

// ===== Identity operations — per-instance methods on `Scp` =====
//
// The 10 identity operations (`identity_create`,
// `identity_create_with_custody`, `identity_load`, `identity_resolve`,
// `identity_attest_device`, `identity_verify_device_attestation`,
// `identity_create_link_attestation`, `identity_link_attestations`,
// `identity_remove_link_attestation`, `identity_verify_link_attestation`)
// live on `impl crate::scp::Scp`, routing through `&self.inner` (the
// caller's `UniffiBridgeInstance`). The free-function façade was deleted
// in Phase 4 PR 4 (#1549, ADR-048).

/// Per-instance DID-resolver initializer.
///
/// Stores the resolver on the caller's [`UniffiBridgeInstance`] rather than
/// any process-wide slot. Invoked lazily on first use by the
/// [`crate::scp::Scp`] identity methods to keep "init on first use"
/// semantics scoped to the owning instance.
fn ensure_did_resolver_initialized_on(
    bi: &Arc<crate::runtime::UniffiBridgeInstance>,
    handle: tokio::runtime::Handle,
) -> Result<(), ScpError> {
    if bi.did_resolver().is_some() {
        return Ok(());
    }

    let dht_client = Arc::new(new_ffi_dht_client!().map_err(ScpError::from)?);
    let relay_querier = Arc::new(NoOpRelayQuerier);
    let cache = Arc::new(DidCache::new());
    let bootstrap_relays = Vec::new();

    let resolver = Arc::new(DualLayerResolver::new(
        relay_querier,
        dht_client,
        cache,
        bootstrap_relays,
    ));

    bi.set_did_resolver(resolver, handle);
    Ok(())
}

use crate::scp::Scp;

#[uniffi::export(async_runtime = "tokio")]
impl Scp {
    /// Per-instance equivalent of the free-function `identity_create`.
    ///
    /// Creates a new SCP identity under this instance. Routes through
    /// `&*self.inner` instead of the process-wide
    /// `DEFAULT_BRIDGE_INSTANCE` — every side-effect (DID resolver
    /// initialization, handle `instance_id` stamping) is scoped to this
    /// `SCP`.
    ///
    /// When `testing_seed` is supplied (32 bytes), the in-memory custody
    /// is backed by a deterministic RNG so subsequent `generate_keypair`
    /// calls produce byte-identical Ed25519 keys across bridges — the
    /// basis of the cross-bridge parity test (ADR-046). `testing_seed`
    /// is only valid for `"in_memory"` custody; other custody types
    /// reject it with `SCP-VALID-7009`.
    pub async fn identity_create(
        &self,
        custody: String,
        testing_seed: Option<Vec<u8>>,
    ) -> Result<Arc<Identity>, ScpError> {
        let custody_method = parse_custody_method(&custody)?;
        let bi = Arc::clone(&self.inner);

        // Validate the optional 32-byte `testing_seed` at the FFI
        // boundary so we fail early rather than panicking inside
        // `InMemoryKeyCustody::from_seed_bytes`. UniFFI's FFI scalar set
        // forbids fixed-size arrays, so the wire type stays
        // `Option<Vec<u8>>`; we immediately narrow to `[u8; 32]` via
        // `TryFrom` and surface a length mismatch as `SCP-VALID-7007`.
        // A seed paired with a non-InMemory custody type is caught
        // below as `SCP-VALID-7009`. Wrap the narrowed array in
        // `Zeroizing` so the seed bytes are wiped when dropped — they
        // feed `Ed25519 SigningKey::from_bytes` inside the custody's
        // RNG.
        //
        // Take ownership of the `Vec<u8>` carrying the seed across the
        // FFI boundary and zero its heap buffer before it drops.
        // Otherwise the allocator's freelist retains the bytes for the
        // process lifetime even after the narrow copy lands in
        // `Zeroizing<[u8; 32]>` (bug-catcher + security round 2).
        let testing_seed_bytes: Option<zeroize::Zeroizing<[u8; 32]>> = match testing_seed {
            None => None,
            Some(mut source) => {
                let narrowed =
                    scp_ffi_common::validate::expect_fixed_bytes::<32>(&source, "testing_seed")
                        .map_err(|msg| ScpError::Validation {
                            msg,
                            code: codes::VALID_7007.to_owned(),
                        })?;
                use zeroize::Zeroize;
                source.zeroize();
                Some(zeroize::Zeroizing::new(narrowed))
            }
        };

        runtime()
            .spawn(async move {
                match custody_method {
                    CustodyMethod::InMemory => {
                        // Gate: `"in_memory"` custody is only available when the
                        // `allow_in_memory_custody` feature is enabled. Production
                        // mobile builds MUST NOT enable this feature. See #88.
                        #[cfg(not(feature = "allow_in_memory_custody"))]
                        {
                            let _ = &bi;
                            // Mirrors PyO3 `parse_custody_with_seed`
                            // (cfg(not(allow_in_memory_custody))):
                            // `testing_seed` is a parity-harness affordance
                            // gated on the `allow_in_memory_custody` feature,
                            // so surface it as SCP-VALID-7008 ahead of the
                            // generic custody-unavailable error.
                            if testing_seed_bytes.is_some() {
                                return Err(ScpError::Validation {
                                    msg: "`testing_seed` parameter requires the \
                                          allow_in_memory_custody feature"
                                        .to_owned(),
                                    code: codes::VALID_7008.to_owned(),
                                });
                            }
                            Err(ScpError::Identity {
                                msg: "\"in_memory\" custody is not available in this build \
                                      — enable the \"allow_in_memory_custody\" feature for \
                                      dev/desktop use. Production mobile builds must use \
                                      \"platform\" custody (Secure Enclave / Android Keystore)."
                                    .to_owned(),
                                code: codes::IDENT_1008.to_owned(),
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
                            //
                            // When `testing_seed` is supplied, the custody is
                            // backed by a deterministic RNG (ADR-046 parity).
                            // Deref through `Zeroizing<[u8; 32]>` so the seed
                            // bytes are wiped at end-of-scope. `from_seed_bytes`
                            // consumes a by-value Copy of the inner array,
                            // discarded inside `StdRng::from_seed`.
                            let in_memory = testing_seed_bytes.as_ref().map_or_else(
                                InMemoryKeyCustody::new,
                                |seed| InMemoryKeyCustody::from_seed_bytes(**seed),
                            );
                            let key_custody = Arc::new(OpaqueInMemoryKeyCustody(in_memory));
                            let dht = DidDht::new();
                            // Mint a fresh per-identity pre-rotation custody.
                            // ADR-003 §4b: the pre-rotation key lives in a
                            // separate substrate from operational
                            // `key_custody`. The same `Arc` is preserved
                            // across migrations.
                            let pre_rotation_custody =
                                Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                            let (identity, document, pre_rotation_handle) = dht
                                .create(&key_custody.0, pre_rotation_custody.as_ref())
                                .await
                                .map_err(ScpError::from)?;

                            // Snapshot the #0 (identity) verifying key for ADR-046 parity.
                            let verifying_key_hex =
                                snapshot_verifying_key_hex(&key_custody.0, &identity.identity_key).await;

                            // Initialize the production DID resolver for UCAN
                            // validation on this instance (H4 — matching
                            // PyO3/NAPI behavior).
                            ensure_did_resolver_initialized_on(
                                &bi,
                                tokio::runtime::Handle::current(),
                            )?;

                            // Register the freshly created in-memory identity
                            // in the per-instance custody registry, keyed by DID,
                            // so `identity_remove_if_present` reports presence —
                            // matching the NAPI bridge whose identity creation
                            // paths register a bundled entry. Shares the
                            // entry/cap logic with the link-attestation path.
                            // Done before `identity` is moved into the handle so
                            // the DID and active signing key are still available.
                            register_identity_custody(
                                &bi,
                                &identity.did,
                                &key_custody,
                                identity.active_signing_key,
                            )?;

                            let handle = Arc::new(Identity {
                                did: identity.did.clone(),
                                custody_type: CustodyMethod::InMemory,
                                core_id: Some(identity),
                                core_document: Some(document),
                                in_memory_custody: Some(key_custody),
                                callback_custody: None,
                                verifying_key_hex,
                                instance_id: bi.core.instance_id(),
                                rotation_event_json: None,
                                pre_rotation_handle,
                                pre_rotation_custody,
                            });
                            increment_handle_count();
                            Ok(handle)
                        }
                    }
                    CustodyMethod::Platform | CustodyMethod::Software => {
                        if testing_seed_bytes.is_some() {
                            return Err(ScpError::Validation {
                                msg:
                                    "`testing_seed` parameter is only valid for custody=\"in_memory\""
                                        .to_owned(),
                                code: codes::VALID_7009.to_owned(),
                            });
                        }
                        // Platform and software custody require a wired
                        // KeyCustodyProvider (ADR-006 platform abstraction).
                        // Use `identity_create_with_custody` to inject a
                        // platform-backed KeyCustodyProvider callback.
                        Err(ScpError::Identity {
                            msg: format!(
                                "custody type {custody:?} requires a KeyCustodyProvider — \
                             use identity_create_with_custody() to inject a Secure \
                             Enclave (iOS) or Android Keystore (Android) backed \
                             custody provider"
                            ),
                            code: codes::IDENT_1003.to_owned(),
                        })
                    }
                    CustodyMethod::External => {
                        // `parse_custody_method` never produces External — it is only
                        // constructed internally by `identity_load` for DID-string-only
                        // handles that have no local key material. Reaching this arm
                        // in `identity_create` is a bridge-layer bug.
                        Err(ScpError::Identity {
                            msg: "internal: CustodyMethod::External cannot be used with \
                                  identity_create — use identity_load for external DID handles"
                                .to_owned(),
                            code: codes::IDENT_1005.to_owned(),
                        })
                    }
                }
            })
            .await
            .map_err(|e| ScpError::Identity {
                msg: format!("tokio task join error during identity creation: {e}"),
                code: codes::IDENT_1007.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `identity_create_with_custody`.
    ///
    /// Creates a new SCP identity under this instance using an injected
    /// [`KeyCustodyProvider`](crate::KeyCustodyProvider). Routes through
    /// `&*self.inner` — the handle's `instance_id` is stamped against this
    /// `SCP` so cross-instance misuse is rejected.
    ///
    /// See SCP-214 acceptance criteria 2-3.
    pub async fn identity_create_with_custody(
        &self,
        provider: Box<dyn crate::KeyCustodyProvider>,
    ) -> Result<Arc<Identity>, ScpError> {
        let bi = Arc::clone(&self.inner);

        runtime()
            .spawn(async move {
                let callback_custody = Arc::new(CallbackKeyCustody::new(provider));

                let dht = DidDht::new();
                // Mint a fresh per-identity pre-rotation custody (ADR-003 §4b).
                // Production callback custody integration is a follow-up
                // workstream; in-memory custody is used here so the
                // commitment invariant holds for tests and dev/desktop builds.
                let pre_rotation_custody =
                    Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                let (identity, document, pre_rotation_handle) = dht
                    .create(callback_custody.as_ref(), pre_rotation_custody.as_ref())
                    .await
                    .map_err(ScpError::from)?;

                // Snapshot the #0 (identity) verifying key for ADR-046 parity.
                let verifying_key_hex =
                    snapshot_verifying_key_hex(callback_custody.as_ref(), &identity.identity_key)
                        .await;

                // Initialize the production DID resolver for UCAN validation
                // on this instance.
                ensure_did_resolver_initialized_on(&bi, tokio::runtime::Handle::current())?;

                let handle = Arc::new(Identity {
                    did: identity.did.clone(),
                    custody_type: CustodyMethod::Platform,
                    core_id: Some(identity),
                    core_document: Some(document),
                    #[cfg(feature = "allow_in_memory_custody")]
                    in_memory_custody: None,
                    callback_custody: Some(callback_custody),
                    verifying_key_hex,
                    instance_id: bi.core.instance_id(),
                    rotation_event_json: None,
                    pre_rotation_handle,
                    pre_rotation_custody,
                });
                increment_handle_count();
                Ok(handle)
            })
            .await
            .map_err(|e| ScpError::Identity {
                msg: format!("tokio task join error during identity creation: {e}"),
                code: codes::IDENT_1007.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `identity_load`.
    ///
    /// Loads an external identity handle under this instance. Routes through
    /// `&*self.inner` — the returned handle's `instance_id` is stamped
    /// against this `SCP`. Key operations on the returned handle still
    /// require a `KeyCustodyProvider` callback to be wired.
    pub async fn identity_load(&self, did: String) -> Result<Arc<Identity>, ScpError> {
        let bi = Arc::clone(&self.inner);

        runtime()
            .spawn(async move {
                if !did.starts_with("did:dht:") {
                    return Err(ScpError::Identity {
                        msg: format!("unsupported DID method: {did} — only did:dht is supported"),
                        code: codes::IDENT_1004.to_owned(),
                    });
                }

                // identity_load returns a DID-string-only handle. Key operations
                // require the KeyCustodyProvider callback interface to be wired.
                // No live key material, so `verifying_key_hex` is `None`.
                //
                // Pre-rotation state is unused on externally loaded handles —
                // `identity_migrate` rejects this path before the handle is
                // consulted (`core_id` is `None`, surface as IDENT_1009). The
                // empty in-memory custody is a placeholder so the field is
                // populated; it never receives a key.
                let pre_rotation_custody =
                    Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                let handle = Arc::new(Identity {
                    did,
                    custody_type: CustodyMethod::External,
                    core_id: None,
                    core_document: None,
                    #[cfg(feature = "allow_in_memory_custody")]
                    in_memory_custody: None,
                    callback_custody: None,
                    verifying_key_hex: None,
                    instance_id: bi.core.instance_id(),
                    rotation_event_json: None,
                    pre_rotation_handle: scp_platform::PreRotationKeyHandle::new(0),
                    pre_rotation_custody,
                });
                increment_handle_count();
                Ok(handle)
            })
            .await
            .map_err(|e| ScpError::Identity {
                msg: format!("tokio task join error during identity load: {e}"),
                code: codes::IDENT_1005.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `identity_attest_device`.
    ///
    /// Rejects any `Identity` whose `instance_id` does not match this
    /// `SCP`'s — cross-instance handle misuse surfaces as
    /// `ScpError::Permission` with code `SCP-PERM-3030`.
    pub async fn identity_attest_device(
        &self,
        identity: Arc<Identity>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        identity_attest_device_impl(identity).await
    }

    /// Per-instance equivalent of the free-function
    /// `identity_create_link_attestation`.
    ///
    /// Signs the link attestation with the identity's active signing key
    /// and stores the entry in the per-instance link-attestation and
    /// custody registries on `&*self.inner`. Rejects any cross-instance
    /// `Identity` handle.
    ///
    /// See spec §3.5.1, §3.5.2.
    #[cfg(feature = "allow_in_memory_custody")]
    pub async fn identity_create_link_attestation(
        &self,
        identity: Arc<Identity>,
        platform: String,
        handle: String,
        proof: String,
        verification_method: String,
        platform_id: Option<String>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        identity_create_link_attestation_impl(
            &self.inner,
            identity,
            platform,
            handle,
            proof,
            verification_method,
            platform_id,
        )
        .await
    }

    /// Per-instance equivalent of the free-function
    /// `identity_link_attestations`.
    ///
    /// Reads the link-attestation registry on `&*self.inner`.
    ///
    /// See spec §3.5.1.
    pub fn identity_link_attestations(&self, did: String) -> Result<String, ScpError> {
        // Phase D (#1695): registry lookup routes through this `Scp`'s
        // `UniffiBridgeInstance` directly — the process-wide default is gone.
        let attestations = identity_link_attestation_registry(&self.inner)
            .get(&did)
            .map(|v| v.value().clone())
            .unwrap_or_default();
        serde_json::to_string(&attestations).map_err(|e| ScpError::Identity {
            msg: format!("failed to serialize attestations: {e}"),
            code: codes::IDENT_1043.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function
    /// `identity_remove_link_attestation`.
    ///
    /// Mutates the link-attestation registry on `&*self.inner`.
    ///
    /// See spec §3.5.1.
    #[cfg(feature = "allow_in_memory_custody")]
    #[must_use]
    pub fn identity_remove_link_attestation(&self, did: String, attestation_id: String) -> bool {
        // Phase D (#1695): per-`Scp` registry lookups — no default fallback.
        // Verify the caller owns the DID by checking the identity custody registry.
        if !identity_custody_registry(&self.inner).contains_key(&did) {
            return false;
        }

        let Some(mut entry) = identity_link_attestation_registry(&self.inner).get_mut(&did) else {
            return false;
        };
        let before = entry.len();
        entry.retain(|a| a.id != attestation_id);
        entry.len() < before
    }

    /// Removes a DID from this instance's SCP-side identity registry.
    ///
    /// Drops the retained identity state — the custody provider / key
    /// handle and any link attestations — for `did` on `&*self.inner`.
    /// Idempotent: succeeds silently when the DID is not in the registry,
    /// matching the NAPI bridge's `identity_remove` semantics (where a
    /// single registry entry bundles custody and attestations).
    ///
    /// The DID document published to the DHT is unaffected; this only
    /// releases the bridge's in-memory state.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Validation` when `did` is not a syntactically
    /// valid DID, mirroring the `PyO3` reference bridge's `identity_remove`.
    #[cfg(feature = "allow_in_memory_custody")]
    pub fn identity_remove(&self, did: String) -> Result<(), ScpError> {
        validate_did(&did)?;
        identity_custody_registry(&self.inner).remove(&did);
        identity_link_attestation_registry(&self.inner).remove(&did);
        Ok(())
    }

    /// Removes a DID from this instance's SCP-side identity registry if
    /// present, reporting whether the identity was removed.
    ///
    /// Returns `true` if the identity was found in the custody registry and
    /// removed, `false` if the DID was not present. Any link attestations
    /// for the DID are dropped alongside the identity. Companion to
    /// [`Scp::identity_remove`] (which is unconditional), matching the NAPI
    /// bridge's `identity_remove_if_present` semantics.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Validation` when `did` is not a syntactically
    /// valid DID, mirroring the `PyO3` reference bridge's
    /// `identity_remove_if_present`.
    #[cfg(feature = "allow_in_memory_custody")]
    pub fn identity_remove_if_present(&self, did: String) -> Result<bool, ScpError> {
        validate_did(&did)?;
        let removed = identity_custody_registry(&self.inner)
            .remove(&did)
            .is_some();
        identity_link_attestation_registry(&self.inner).remove(&did);
        Ok(removed)
    }

    // ===== Context lifecycle — per-instance methods on `Scp` =====
    //
    // The 6 context lifecycle operations (`context_create`, `context_join`,
    // `context_leave`, `context_close`, `context_send`, `context_subscribe`)
    // live on `impl crate::scp::Scp`, routing through `&self.inner` (the
    // caller's `UniffiBridgeInstance`). The free-function façade was
    // deleted in Phase 4 PR 4 (#1549, ADR-048).

    /// Per-instance equivalent of the free-function `context_create`.
    ///
    /// Creates a new SCP context under this instance. Routes through
    /// `&*self.inner` instead of the process-wide
    /// `DEFAULT_BRIDGE_INSTANCE` — the `ContextManager` initialization
    /// (`init_context_manager_with_did`), the per-context UCAN registry,
    /// and the returned handle's `instance_id` stamping are all scoped to
    /// this `SCP`. The context handle is rejected on any other `SCP`.
    ///
    /// See the documentation on the free `context_create` function for
    /// argument semantics and MLS group / event-log initialization
    /// details.
    pub async fn context_create(
        &self,
        identity: Arc<Identity>,
        params: ContextParams,
    ) -> Result<Arc<ContextHandle>, ScpError> {
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                validate_did(&identity.did)?;

                // Spec §18.4.1: context IDs MUST be 64-char lowercase hex so
                // they embed in `scp://context/<context_id_hex>` URIs. The
                // shared helper in `scp-ffi-common` is the single source of
                // truth for all four bridges — see ADR-048 §7a.
                let context_id = scp_ffi_common::generate_context_id();

                // Convert bridge ContextParams to scp-core ContextParams.
                let core_params = bridge_params_to_core(&params)?;
                // Retain a clone for the FFI handle — finalize_close needs the real
                // memory_scope to decide key destruction behavior.
                let retained_core_params = core_params.clone();

                // Initialize the ContextManager with the creator's DID if not
                // already done. `init_context_manager_with_did` is idempotent
                // (`OnceLock` — first call wins). The bridge no longer supports
                // a DID-less stub crypto path; the creator DID becomes the
                // process-wide MLS credential identity.
                bi.init_context_manager_with_did(&identity.did);

                // Extract key custody and signing key from the identity.
                #[cfg(feature = "allow_in_memory_custody")]
                let in_memory_custody = identity.in_memory_custody.clone();
                let callback_custody = identity.callback_custody.clone();
                let signing_key = identity.core_id.as_ref().map(|id| id.active_signing_key);

                // §9.10.4: Derive the context-scoped pseudonym routing ID via the
                // retained KeyCustody BEFORE context creation so it can be passed
                // to the ContextManager for per-member routing.
                //
                // ENCRYPTED contexts hard-fail derivation (a zero pseudonym
                // produces a silently unusable context — the member cannot send
                // app-data on a pseudonymous routing axis), carrying granular
                // codes (missing material → 1054, derivation failure → 1055,
                // wrong length → 1057, custody unavailable → 1056) that match the
                // PyO3 reference. BROADCAST contexts soft-fail to `None` (no
                // per-member pseudonym, spec §5.14 — the runtime ignores it).
                let create_is_broadcast = matches!(
                    core_params.mode,
                    scp_core::context::params::ContextMode::Broadcast
                );
                let local_pseudonym: Option<[u8; 32]> = if create_is_broadcast {
                    None
                } else {
                    Some(derive_member_pseudonym_required(&identity, &context_id).await?)
                };

                // Route through the ADR-049 lifecycle dispatch surface
                // ([`Supervisor::dispatch_lifecycle_command`](scp_core::context::supervisor::Supervisor::dispatch_lifecycle_command))
                // rather than calling a `ContextManager` method directly. The
                // actor mailbox wraps the delegated call in the 30s
                // transport-timeout budget.
                let sup = bi.context_manager_or_error()?;
                {
                    use scp_core::context::actor::commands::{
                        CreateContextPayload, LifecycleCommand,
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = LifecycleCommand::CreateContext {
                        payload: Box::new(CreateContextPayload {
                            context_id: context_id.clone(),
                            params: core_params,
                            creator_did: identity.did.clone().into(),
                            local_pseudonym,
                        }),
                        reply: tx,
                    };
                    sup.dispatch_lifecycle_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("create_context shim reply dropped: {e}"),
                            code: codes::CTX_2011.to_owned(),
                        })?
                        .map_err(ScpError::from)?;
                }

                // Register the creator's DID as a local DID for defense-in-depth,
                // matching NAPI's behavior. Routes through the supervisor's direct
                // method — the local-DID set is supervisor-wide.
                sup.register_local_did(identity.did.clone().into())
                    .await
                    .map_err(ScpError::from)?;

                // Register per-context UCAN validation state (revocation list,
                // nonce tracker, event log) for the UCAN pipeline on this instance.
                bi.ensure_ucan_registered(&context_id, &identity.did, &params.ceiling);

                // §9.10.4: Send pseudonym announcement to inform other members of
                // the creator's per-context routing ID. For freshly created
                // single-member contexts this is a no-op (no recipients), but on
                // restored/imported contexts with existing members the announcement
                // is needed. Best-effort: if signing key is not available, skip.
                if local_pseudonym.is_some() {
                    let sender_did = scp_identity::DID(identity.did.clone());
                    let core_handle = scp_core::context::ContextHandle::new(
                        context_id.clone(),
                        retained_core_params.clone(),
                    );
                    let _ = core_handle
                        .transition_to(&scp_core::context::ContextState::Active)
                        .await;
                    let sk_opt: Option<ed25519_dalek::SigningKey> =
                        if let Some(ref ik) = identity.core_id {
                            if let Some(ref cb) = identity.callback_custody {
                                cb.export_ed25519_signing_key(&ik.active_signing_key)
                                    .await
                                    .ok()
                            } else {
                                #[cfg(feature = "allow_in_memory_custody")]
                                {
                                    if let Some(ref custody) = identity.in_memory_custody {
                                        custody
                                            .0
                                            .export_ed25519_signing_key(&ik.active_signing_key)
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
                            }
                        } else {
                            None
                        };
                    if let Some(sk) = sk_opt {
                        use scp_core::context::actor::commands::{
                            MessagingCommand, SendPseudonymAnnouncementPayload, SigningKeyBytes,
                        };
                        let ann_ctx_id = core_handle.context_id().to_owned();
                        let ann_params = core_handle.params().clone();
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let cmd = MessagingCommand::SendPseudonymAnnouncement {
                            payload: Box::new(SendPseudonymAnnouncementPayload {
                                context_id: ann_ctx_id.clone(),
                                params: ann_params,
                                sender_did,
                                signing_key: SigningKeyBytes::from_signing_key(&sk),
                            }),
                            reply: tx,
                        };
                        if sup.dispatch_command(&ann_ctx_id, cmd).await.is_ok() {
                            let _ = rx.await;
                        }
                    }
                }

                let handle = Arc::new(ContextHandle {
                    context_id,
                    state: tokio::sync::Mutex::new(ContextState::Active),
                    creator_did: identity.did.clone(),
                    #[cfg(feature = "allow_in_memory_custody")]
                    in_memory_custody,
                    callback_custody,
                    signing_key,
                    ceiling_strings: params
                        .ceiling
                        .iter()
                        .map(|s| {
                            scp_core::context::roles::Capability::new(s).ucan_capability_name()
                        })
                        .collect(),
                    tool_registry: tokio::sync::Mutex::new(
                        scp_core::context::tools::ToolRegistry::new(),
                    ),
                    tool_handlers: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                    session_store: tokio::sync::Mutex::new(
                        scp_core::context::tools::SessionStore::new(),
                    ),
                    economic_policy: std::sync::Mutex::new(None),
                    core_context_params: retained_core_params,
                    instance_id: bi.core.instance_id(),
                });
                // Register in this instance's context handle registry so the
                // MCP bridge provider can look up per-context state by
                // context ID.
                register_context_handle(&bi, &handle);
                increment_handle_count();
                Ok(handle)
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during context creation: {e}"),
                code: codes::CTX_2011.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `context_join`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` /
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    ///
    /// See the documentation on the free `context_join` function for
    /// argument semantics and the spending-UCAN AND-composition path.
    pub async fn context_join(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
        spending_ucan_jwt: Option<String>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                validate_did(&identity.did)?;

                let state = handle.state.lock().await;

                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Context {
                        msg: format!(
                            "cannot join context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::CTX_2013.to_owned(),
                    });
                }
                drop(state);

                // Parse the optional spending UCAN JWT once at the bridge boundary
                // so malformed tokens are rejected before the manager is touched.
                // Mirrors PyO3 (`scp-ffi/src/context.rs`) and NAPI parity.
                let spending_ucan = spending_ucan_jwt
                    .as_deref()
                    .map(|jwt| {
                        scp_core::crypto::ucan::validate::parse_ucan(jwt).map_err(|e| {
                            ScpError::Context {
                                msg: format!("invalid spending UCAN: {e}"),
                                code: codes::ECON_12061.to_owned(),
                            }
                        })
                    })
                    .transpose()?;

                // Ensure the ContextManager is initialized with the joining
                // identity's DID — context_join is a valid first operation
                // (e.g. a device joining a context without creating one).
                // `init_context_manager_with_did` is idempotent (`OnceLock`). #1073
                bi.init_context_manager_with_did(&identity.did);

                // Delegate to the shared ContextManager. Build a core ContextHandle
                // to pass the context_id, then join via the manager.
                //
                // This ephemeral ContextHandle carries default params — the
                // ContextManager ignores them, performing version compatibility
                // checks against the stored context's params instead.
                let sup = bi.context_manager_or_error()?;
                let core_handle = scp_core::context::ContextHandle::new(
                    handle.context_id.clone(),
                    scp_core::context::ContextParams::default(),
                );
                // Transition core handle to Active so join_context accepts it.
                let _ = core_handle
                    .transition_to(&scp_core::context::ContextState::Active)
                    .await;

                // Generate a real MLS key package for the joining member. The
                // `MlsCryptoProvider` requires `Some(bytes)` — the old DID-less
                // `FfiBridgeCrypto` stub accepted `None`, but commit 4 replaced
                // it with real MLS crypto across every bridge entry point.
                let kp_bytes = generate_mls_key_package_bytes(&identity.did)?;
                let key_package = KeyPackage {
                    owner_did: identity.did.clone().into(),
                    mls_key_package_bytes: Some(kp_bytes),
                };

                // §9.10.4: Derive pseudonym for per-member routing. Uses the
                // identity's custody provider (callback or in-memory).
                //
                // ENCRYPTED contexts hard-fail derivation: a soft-failed join
                // into an encrypted context yields `None`, which the runtime
                // maps to the reserved `[0u8; 32]` sentinel — peers reject any
                // announce of a reserved value, so the joiner becomes
                // permanently unaddressable with no error surfaced. Carry the
                // granular codes (missing material → 1054, derivation failure →
                // 1055, wrong length → 1057, custody unavailable → 1056) at
                // create/import granularity. BROADCAST contexts soft-fail to
                // `None` (no per-member pseudonym, spec §5.14 — the runtime
                // ignores it). Branch on the joined context's mode.
                let join_is_broadcast = matches!(
                    handle.core_context_params.mode,
                    scp_core::context::params::ContextMode::Broadcast
                );
                let local_pseudonym: Option<[u8; 32]> = if join_is_broadcast {
                    None
                } else {
                    Some(derive_member_pseudonym_required(&identity, &handle.context_id).await?)
                };

                // Route through the ADR-049 lifecycle dispatch surface.
                {
                    use scp_core::context::actor::commands::{
                        JoinContextPayload, LifecycleCommand,
                    };
                    let join_ctx_id = core_handle.context_id().to_owned();
                    let join_params = core_handle.params().clone();
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = LifecycleCommand::JoinContext {
                        payload: Box::new(JoinContextPayload {
                            context_id: join_ctx_id,
                            params: join_params,
                            key_package,
                            spending_ucan,
                            local_pseudonym,
                        }),
                        reply: tx,
                    };
                    sup.dispatch_lifecycle_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("join_context shim reply dropped: {e}"),
                            code: codes::CTX_2014.to_owned(),
                        })?
                        .map_err(ScpError::from)?;
                }

                // §9.10.4: Send pseudonym announcement to inform existing members.
                // Best-effort: if signing key is not available, skip silently.
                if local_pseudonym.is_some() {
                    let sender_did = scp_identity::DID(identity.did.clone());
                    let sk_opt: Option<ed25519_dalek::SigningKey> =
                        if let Some(ref ik) = identity.core_id {
                            if let Some(ref cb) = identity.callback_custody {
                                cb.export_ed25519_signing_key(&ik.active_signing_key)
                                    .await
                                    .ok()
                            } else {
                                #[cfg(feature = "allow_in_memory_custody")]
                                {
                                    if let Some(ref custody) = identity.in_memory_custody {
                                        custody
                                            .0
                                            .export_ed25519_signing_key(&ik.active_signing_key)
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
                            }
                        } else {
                            None
                        };
                    if let Some(sk) = sk_opt {
                        use scp_core::context::actor::commands::{
                            MessagingCommand, SendPseudonymAnnouncementPayload, SigningKeyBytes,
                        };
                        let ann_ctx_id = core_handle.context_id().to_owned();
                        let ann_params = core_handle.params().clone();
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let cmd = MessagingCommand::SendPseudonymAnnouncement {
                            payload: Box::new(SendPseudonymAnnouncementPayload {
                                context_id: ann_ctx_id.clone(),
                                params: ann_params,
                                sender_did,
                                signing_key: SigningKeyBytes::from_signing_key(&sk),
                            }),
                            reply: tx,
                        };
                        if sup.dispatch_command(&ann_ctx_id, cmd).await.is_ok() {
                            let _ = rx.await;
                        }
                    }
                }

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during context join: {e}"),
                code: codes::CTX_2014.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `context_leave`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` /
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    pub async fn context_leave(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let state = handle.state.lock().await;

                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Context {
                        msg: format!(
                            "cannot leave context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::CTX_2015.to_owned(),
                    });
                }
                drop(state);

                // Route through the ADR-049 lifecycle dispatch surface.
                let sup = bi.context_manager_or_error()?;
                let core_handle = scp_core::context::ContextHandle::new(
                    handle.context_id.clone(),
                    scp_core::context::ContextParams::default(),
                );
                let _ = core_handle
                    .transition_to(&scp_core::context::ContextState::Active)
                    .await;

                let member_did: scp_identity::DID = identity.did.clone().into();
                {
                    use scp_core::context::actor::commands::{
                        LeaveContextPayload, LifecycleCommand,
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = LifecycleCommand::LeaveContext {
                        payload: Box::new(LeaveContextPayload {
                            context_id: core_handle.context_id().to_owned(),
                            params: core_handle.params().clone(),
                            caller_did: member_did.clone(),
                            member_did,
                        }),
                        reply: tx,
                    };
                    sup.dispatch_lifecycle_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("leave_context shim reply dropped: {e}"),
                            code: codes::CTX_2016.to_owned(),
                        })?
                        .map_err(ScpError::from)?;
                }

                // Deregister the context handle from the MCP lookup registry.
                deregister_context_handle(&bi, &handle.context_id);

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during context leave: {e}"),
                code: codes::CTX_2016.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `context_close`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` /
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    ///
    /// Authorization is enforced by the `ContextManager` (which delegates
    /// to `ttl::close_context` checking the `ContextClose` capability) —
    /// no bridge-layer auth check.
    pub async fn context_close(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                // Authorization is enforced by the ContextManager (which delegates
                // to ttl::close_context checking the ContextClose capability). No
                // bridge-layer auth check — the ContextManager is authoritative.
                let identity_did = identity.did.clone();

                let mut state = handle.state.lock().await;
                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Context {
                        msg: format!(
                            "cannot close context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::CTX_2017.to_owned(),
                    });
                }

                // Route through the ADR-049 lifecycle dispatch surface. The
                // actor mailbox preserves byte-identical close semantics; the
                // Supervisor is the authoritative auth layer (ttl::close_context
                // ContextClose capability check).
                let sup = bi.context_manager_or_error()?;
                let core_handle = scp_core::context::ContextHandle::new(
                    handle.context_id.clone(),
                    scp_core::context::ContextParams::default(),
                );
                let _ = core_handle
                    .transition_to(&scp_core::context::ContextState::Active)
                    .await;

                let initiator_did: scp_identity::DID = identity_did.clone().into();
                {
                    use scp_core::context::actor::commands::{
                        CloseContextPayload, LifecycleCommand,
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = LifecycleCommand::CloseContext {
                        payload: Box::new(CloseContextPayload {
                            context_id: core_handle.context_id().to_owned(),
                            params: core_handle.params().clone(),
                            initiator_did,
                        }),
                        reply: tx,
                    };
                    sup.dispatch_lifecycle_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("close_context shim reply dropped: {e}"),
                            code: codes::CTX_2017.to_owned(),
                        })?
                        .map_err(ScpError::from)?;
                }

                // Wire CloseOrchestrator for contexts with summary verification.
                // After the ContextManager has processed the close, check the
                // context's memory scope and initiate the appropriate destruction
                // path via CloseOrchestrator (#365).
                let memory_scope = core_handle.params().memory_scope;
                let now = scp_primitives::SystemClock.now_secs();

                // Build a fresh `MlsCryptoProvider` for key-destruction scoped to
                // the initiator's DID. The bridge no longer caches a global stub
                // crypto provider (commit 4 removed `FfiBridgeCrypto`). The
                // `CloseOrchestrator` only uses this provider to destroy MLS group
                // and sender-key material for the context being closed; a fresh
                // per-call instance is correct.
                let crypto_provider =
                    scp_core::crypto::mls::provider::MlsCryptoProvider::new(identity_did);
                let orchestrator =
                    scp_core::context::key_destruction::CloseOrchestrator::new(&crypto_provider);

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
                        msg: format!("close orchestration failed: {e}"),
                        code: codes::CTX_2017.to_owned(),
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

                // Clean up per-context UCAN state on this instance.
                bi.remove_ucan_state(&handle.context_id);

                // Clean up per-context bridge connector state and economy state.
                bi.core.remove_bridge_state(&handle.context_id);
                bi.core.remove_economy_state(&handle.context_id);

                // Deregister the context handle from the MCP lookup registry.
                deregister_context_handle(&bi, &handle.context_id);

                *state = ContextState::Closed;
                drop(state);

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during context close: {e}"),
                code: codes::CTX_2018.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `context_send`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` /
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    pub async fn context_send(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
        payload: Vec<u8>,
        spending_ucan_jwt: Option<String>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                validate_did(&identity.did)?;

                let state = handle.state.lock().await;

                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Context {
                        msg: format!(
                            "cannot send to context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::CTX_2019.to_owned(),
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
                    let now_ms = scp_primitives::SystemClock.now_millis();

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
                            msg: format!("inner envelope signing failed: {e}"),
                            code: codes::CRYPTO_4001.to_owned(),
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
                                msg: format!("inner envelope signing failed: {e}"),
                                code: codes::CRYPTO_4001.to_owned(),
                            })?;
                        }
                    }
                }

                // Resolve the signing key from the handle's retained custody so the
                // ContextManager can produce a valid inner envelope signature. Passing
                // None would cause the encrypted send path to fail with "signing key
                // required".
                let resolved_signing_key = resolve_uniffi_signing_key(&handle).await.ok();

                // Delegate to the shared ContextManager for message delivery
                // through the transport provider.
                let manager = bi.context_manager_or_error()?;
                let core_handle = scp_core::context::ContextHandle::new(
                    handle.context_id.clone(),
                    scp_core::context::ContextParams::default(),
                );
                let _ = core_handle
                    .transition_to(&scp_core::context::ContextState::Active)
                    .await;

                // Parse optional spending UCAN JWT into a UcanToken for AND-composition.
                let spending_ucan = spending_ucan_jwt
                    .as_deref()
                    .map(scp_core::crypto::ucan::validate::parse_ucan)
                    .transpose()
                    .map_err(|e| ScpError::Context {
                        msg: format!("invalid spending UCAN: {e}"),
                        code: codes::ECON_12061.to_owned(),
                    })?;

                let sender_did: scp_identity::DID = identity.did.clone().into();
                manager
                    .send_message(
                        &core_handle,
                        &sender_did,
                        &payload,
                        resolved_signing_key.as_ref(),
                        None,
                        spending_ucan.as_ref(),
                    )
                    .await
                    .map_err(ScpError::from)?;

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during message send: {e}"),
                code: codes::CTX_2020.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `context_subscribe`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    ///
    /// The current implementation is a stub that signals stream
    /// completion immediately — full transport wiring lands in a later
    /// slice. When background tasks are introduced, they will register
    /// into the per-instance `CoreFields` task set rather than a shared
    /// global registry.
    pub async fn context_subscribe(
        &self,
        handle: Arc<ContextHandle>,
        listener: Box<dyn crate::MessageListener>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let state = handle.state.lock().await;

        if !matches!(*state, ContextState::Active) {
            return Err(ScpError::Context {
                msg: format!(
                    "cannot subscribe to context in {:?} state — context must be active",
                    *state
                ),
                code: codes::CTX_2021.to_owned(),
            });
        }
        drop(state);

        // Signal stream completion — full transport wiring connects this
        // listener to the message pipeline in integration stories.
        listener.on_complete();
        Ok(())
    }

    // ===== UniFFI sub-slice D — governance + close/restore/migration =====
    //
    // Migrates the 15 governance / ceiling / close / checkpoint / restore /
    // migration free functions (`governance_execute`, `governance_propose`,
    // `governance_approve`, `governance_reject`, `governance_withdraw`,
    // `governance_get_proposal`, `governance_list_proposals`,
    // `apply_pending_ceiling_modification`, `finalize_close`,
    // `create_governance_checkpoint`, `add_checkpoint_cosignature`,
    // `restore_context`, `restore_all_contexts`,
    // `tombstone_migrated_context`, `migration_state`) to
    // `impl crate::scp::Scp` methods routing through `&self.inner` (the
    // `UniffiBridgeInstance` owned by the caller).
    //
    // Free functions above are retained (they still compile and are still
    // exported via `#[uniffi::export]`) — the demolition slice at the end
    // of PR 4 removes them in one shot after every caller is migrated.
    // Bodies are preserved verbatim except for the
    // `crate::runtime::context_manager()` → `bi.context_manager_or_error()?`
    // swap and the handle-affinity inline check described in the PR 4
    // sub-slice D plan.
    //
    // Part of #1549 Phase 4 PR 4.

    /// Per-instance equivalent of the free-function `governance_execute`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn governance_execute(
        &self,
        handle: Arc<ContextHandle>,
        proposal_json: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();

        let (result, action_name) = runtime()
            .spawn(async move {
                let proposal: scp_core::context::governance::GovernanceProposal =
                    serde_json::from_str(&proposal_json)?;
                // Defense-in-depth: validate user-controlled string fields at the
                // FFI boundary before the action reaches the ContextManager (#1601).
                scp_ffi_common::validate::validate_governance_action_strings(&proposal.action)
                    .map_err(|e| ScpError::Validation {
                        msg: e.message,
                        code: codes::VALID_7000.to_owned(),
                    })?;
                let action_name = proposal.action.variant_name();
                // Route through the ADR-049 governance dispatch surface.
                let sup = bi.context_manager_or_error()?;
                let result = {
                    use scp_core::context::actor::commands::{
                        ExecuteGovernanceActionPayload, GovernanceCommand,
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = GovernanceCommand::ExecuteGovernanceAction {
                        payload: Box::new(ExecuteGovernanceActionPayload {
                            context_id: context_id.clone(),
                            proposal,
                        }),
                        reply: tx,
                    };
                    sup.dispatch_governance_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("execute_governance_action shim reply dropped: {e}"),
                            code: codes::CTX_2000.to_owned(),
                        })?
                        .map_err(ScpError::from)?
                };
                // Serialize the result variant name for the caller.
                use scp_core::context::state::GovernanceActionResult;
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
                    GovernanceActionResult::MemberSuspended(_) => "MemberSuspended",
                    GovernanceActionResult::AccessRevoked(_) => "AccessRevoked",
                    GovernanceActionResult::AccessRestored(_) => "AccessRestored",
                    GovernanceActionResult::ContentKeysRotated(_) => "ContentKeysRotated",
                    GovernanceActionResult::GovernanceReconfigured(_) => "GovernanceReconfigured",
                    GovernanceActionResult::SubscriberBanned(_) => "SubscriberBanned",
                    GovernanceActionResult::SubscriberUnbanned { .. } => "SubscriberUnbanned",
                    GovernanceActionResult::Executed => "Executed",
                    GovernanceActionResult::MigrationProposed(_) => "MigrationProposed",
                    GovernanceActionResult::MigrationCancelled => "MigrationCancelled",
                    GovernanceActionResult::ContextTombstoned => "ContextTombstoned",
                };
                Ok::<_, ScpError>((result_str.to_owned(), action_name))
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during governance execution: {e}"),
                code: codes::CTX_2032.to_owned(),
            })??;

        // Re-sync role state from ContextManager after governance execution (#796).
        // Governance actions may modify roles/membership; without this sync the
        // Swift/Kotlin SDKs see stale role state for UCAN/tool capability checks.
        if let Err(e) = self
            .inner
            .sync_role_state_from_manager(&handle.context_id)
            .await
        {
            tracing::warn!(
                context_id = %handle.context_id,
                action = action_name,
                error = %e,
                "failed to sync role state after governance execution"
            );
        }

        // Sync FFI handle state for migration transitions (§5.11A).
        match result.as_str() {
            "MigrationProposed" => {
                *handle.state.lock().await = ContextState::MigratingOut;
            }
            "MigrationCancelled" => {
                *handle.state.lock().await = ContextState::Active;
            }
            "ContextTombstoned" => {
                *handle.state.lock().await = ContextState::Tombstoned;
            }
            _ => {}
        }

        Ok(result)
    }

    /// Per-instance equivalent of the free-function `governance_propose`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn governance_propose(
        &self,
        handle: Arc<ContextHandle>,
        proposer_did: String,
        action_json: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let signing_key = resolve_uniffi_signing_key(&handle).await?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();

        let (result, action_name) = runtime()
            .spawn(async move {
                let action: scp_core::context::governance::GovernanceAction =
                    serde_json::from_str(&action_json)?;
                // Defense-in-depth: validate user-controlled string fields at the
                // FFI boundary before the action reaches the ContextManager (#1601).
                scp_ffi_common::validate::validate_governance_action_strings(&action).map_err(
                    |e| ScpError::Validation {
                        msg: e.message,
                        code: codes::CTX_2041.to_owned(),
                    },
                )?;
                let action_name = action.variant_name();
                let did = scp_identity::DID(proposer_did);
                let manager = bi.context_manager_or_error()?;
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
                Ok::<_, ScpError>((response.to_string(), action_name))
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during governance proposal: {e}"),
                code: codes::CTX_2041.to_owned(),
            })??;

        if let Err(e) = self
            .inner
            .sync_role_state_from_manager(&handle.context_id)
            .await
        {
            tracing::warn!(
                context_id = %handle.context_id,
                action = action_name,
                error = %e,
                "failed to sync role state after governance proposal"
            );
        }

        Ok(result)
    }

    /// Per-instance equivalent of the free-function `governance_approve`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn governance_approve(
        &self,
        handle: Arc<ContextHandle>,
        voter_did: String,
        proposal_id_hex: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let signing_key = resolve_uniffi_signing_key(&handle).await?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();
        let proposal_id = parse_uniffi_proposal_id(&proposal_id_hex)?;

        let result = runtime()
            .spawn(async move {
                let did = scp_identity::DID(voter_did);
                let sup = bi.context_manager_or_error()?;
                let status = {
                    use scp_core::context::actor::commands::{
                        GovernanceCommand, SigningKeyBytes, VoteOnProposalPayload,
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = GovernanceCommand::ApproveGovernanceProposal {
                        payload: Box::new(VoteOnProposalPayload {
                            context_id: context_id.clone(),
                            proposal_id,
                            voter_did: did,
                            signing_key: SigningKeyBytes::from_signing_key(&signing_key),
                        }),
                        reply: tx,
                    };
                    sup.dispatch_governance_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("approve_governance_proposal shim reply dropped: {e}"),
                            code: codes::CTX_2042.to_owned(),
                        })?
                        .map_err(ScpError::from)?
                };

                Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during governance approval: {e}"),
                code: codes::CTX_2042.to_owned(),
            })?;

        if let Err(e) = self
            .inner
            .sync_role_state_from_manager(&handle.context_id)
            .await
        {
            tracing::warn!(
                context_id = %handle.context_id,
                error = %e,
                "failed to sync role state after governance approval"
            );
        }

        result
    }

    /// Per-instance equivalent of the free-function `governance_reject`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn governance_reject(
        &self,
        handle: Arc<ContextHandle>,
        voter_did: String,
        proposal_id_hex: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let signing_key = resolve_uniffi_signing_key(&handle).await?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();
        let proposal_id = parse_uniffi_proposal_id(&proposal_id_hex)?;

        let result = runtime()
            .spawn(async move {
                let did = scp_identity::DID(voter_did);
                let sup = bi.context_manager_or_error()?;
                let status = {
                    use scp_core::context::actor::commands::{
                        GovernanceCommand, SigningKeyBytes, VoteOnProposalPayload,
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = GovernanceCommand::RejectGovernanceProposal {
                        payload: Box::new(VoteOnProposalPayload {
                            context_id: context_id.clone(),
                            proposal_id,
                            voter_did: did,
                            signing_key: SigningKeyBytes::from_signing_key(&signing_key),
                        }),
                        reply: tx,
                    };
                    sup.dispatch_governance_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("reject_governance_proposal shim reply dropped: {e}"),
                            code: codes::CTX_2043.to_owned(),
                        })?
                        .map_err(ScpError::from)?
                };

                Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during governance rejection: {e}"),
                code: codes::CTX_2043.to_owned(),
            })?;

        if let Err(e) = self
            .inner
            .sync_role_state_from_manager(&handle.context_id)
            .await
        {
            tracing::warn!(
                context_id = %handle.context_id,
                error = %e,
                "failed to sync role state after governance rejection"
            );
        }

        result
    }

    /// Per-instance equivalent of the free-function `governance_withdraw`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn governance_withdraw(
        &self,
        handle: Arc<ContextHandle>,
        voter_did: String,
        proposal_id_hex: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();
        let proposal_id = parse_uniffi_proposal_id(&proposal_id_hex)?;

        let result = runtime()
            .spawn(async move {
                let did = scp_identity::DID(voter_did);
                let manager = bi.context_manager_or_error()?;
                let status = manager
                    .withdraw_governance_vote(&context_id, &proposal_id, &did)
                    .await
                    .map_err(ScpError::from)?;

                Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during governance withdrawal: {e}"),
                code: codes::CTX_2044.to_owned(),
            })?;

        if let Err(e) = self
            .inner
            .sync_role_state_from_manager(&handle.context_id)
            .await
        {
            tracing::warn!(
                context_id = %handle.context_id,
                error = %e,
                "failed to sync role state after governance withdrawal"
            );
        }

        result
    }

    /// Per-instance equivalent of the free-function `governance_get_proposal`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn governance_get_proposal(
        &self,
        handle: Arc<ContextHandle>,
        proposal_id_hex: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();
        let proposal_id = parse_uniffi_proposal_id(&proposal_id_hex)?;

        runtime()
            .spawn(async move {
                let manager = bi.context_manager_or_error()?;
                let proposal = manager
                    .get_proposal(&context_id, &proposal_id)
                    .await
                    .map_err(ScpError::from)?;

                serde_json::to_string(&proposal).map_err(|e| ScpError::Context {
                    msg: format!("serialization failed: {e}"),
                    code: codes::CTX_2045.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during get proposal: {e}"),
                code: codes::CTX_2045.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `governance_list_proposals`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn governance_list_proposals(
        &self,
        handle: Arc<ContextHandle>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();

        runtime()
            .spawn(async move {
                let manager = bi.context_manager_or_error()?;
                let proposals = manager
                    .list_proposals(&context_id)
                    .await
                    .map_err(ScpError::from)?;

                serde_json::to_string(&proposals).map_err(|e| ScpError::Context {
                    msg: format!("serialization failed: {e}"),
                    code: codes::CTX_2046.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during list proposals: {e}"),
                code: codes::CTX_2046.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `apply_pending_ceiling_modification`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn apply_pending_ceiling_modification(
        &self,
        handle: Arc<ContextHandle>,
        current_timestamp: u64,
    ) -> Result<bool, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();

        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                use scp_core::context::actor::commands::GovernanceCommand;
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = GovernanceCommand::ApplyPendingCeilingModification {
                    context_id: context_id.clone(),
                    current_timestamp,
                    reply: tx,
                };
                sup.dispatch_governance_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                rx.await
                    .map_err(|e| ScpError::Context {
                        msg: format!("apply_pending_ceiling_modification shim reply dropped: {e}"),
                        code: codes::CTX_2060.to_owned(),
                    })?
                    .map_err(ScpError::from)
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!(
                    "tokio task join error during apply_pending_ceiling_modification: {e}"
                ),
                code: codes::CTX_2060.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `finalize_close`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn finalize_close(&self, handle: Arc<ContextHandle>) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();
        let handle_ref = handle.clone();

        // Use the handle's stored core_context_params (which carries correct
        // memory_scope) instead of ContextParams::default(). memory_scope
        // governs key destruction behavior in finalize_close — Ephemeral scope
        // destroys keys, Full scope retains them.
        let core_params = handle.core_context_params.clone();

        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let core_handle = scp_core::context::ContextHandle::new(context_id, core_params);
                let _ = core_handle
                    .transition_to(&scp_core::context::ContextState::Active)
                    .await;
                let _ = core_handle
                    .transition_to(&scp_core::context::ContextState::Closing)
                    .await;

                {
                    use scp_core::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = TtlCloseCommand::FinalizeClose {
                        payload: Box::new(TtlContextPayload {
                            context_id: core_handle.context_id().to_owned(),
                            params: core_handle.params().clone(),
                        }),
                        reply: tx,
                    };
                    sup.dispatch_ttl_close_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("finalize_close shim reply dropped: {e}"),
                            code: codes::CTX_2061.to_owned(),
                        })?
                        .map_err(ScpError::from)?;
                }

                // Update FFI handle state to Closed.
                *handle_ref.state.lock().await = ContextState::Closed;

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during finalize_close: {e}"),
                code: codes::CTX_2061.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `create_governance_checkpoint`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_governance_checkpoint(
        &self,
        handle: Arc<ContextHandle>,
        checkpoint_seq: u64,
        merkle_root_hex: String,
        event_count: u64,
        last_event_hash_hex: String,
        state_snapshot_hash_hex: String,
        creator_did: String,
        creator_signature_hex: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();

        let merkle_root = parse_uniffi_hex_32(&merkle_root_hex, "merkle_root")?;
        let last_event_hash = parse_uniffi_hex_32(&last_event_hash_hex, "last_event_hash")?;
        let state_snapshot_hash =
            parse_uniffi_hex_32(&state_snapshot_hash_hex, "state_snapshot_hash")?;
        let creator_signature =
            Zeroizing::new(hex::decode(&creator_signature_hex).map_err(|e| {
                ScpError::Validation {
                    msg: format!("invalid creator_signature hex: {e}"),
                    code: codes::CTX_2066.to_owned(),
                }
            })?);
        let did = scp_identity::DID(creator_did);

        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let checkpoint = {
                    use scp_core::context::actor::commands::{
                        CreateGovernanceCheckpointPayload, TrustRecoveryCommand,
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = TrustRecoveryCommand::CreateGovernanceCheckpoint {
                        payload: Box::new(CreateGovernanceCheckpointPayload {
                            context_id: context_id.clone(),
                            checkpoint_seq,
                            merkle_root,
                            event_count,
                            last_event_hash,
                            state_snapshot_hash,
                            creator_did: did,
                            creator_signature: (*creator_signature).clone(),
                        }),
                        reply: tx,
                    };
                    sup.dispatch_trust_recovery_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("create_governance_checkpoint shim reply dropped: {e}"),
                            code: codes::CTX_2066.to_owned(),
                        })?
                        .map_err(ScpError::from)?
                };

                serde_json::to_string(&checkpoint).map_err(|e| ScpError::Context {
                    msg: format!("serialization failed: {e}"),
                    code: codes::CTX_2066.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during create_governance_checkpoint: {e}"),
                code: codes::CTX_2066.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `add_checkpoint_cosignature`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn add_checkpoint_cosignature(
        &self,
        handle: Arc<ContextHandle>,
        checkpoint_json: String,
        signer_did: String,
        signature_hex: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();

        let checkpoint: scp_core::context::governance::ContextCheckpoint =
            serde_json::from_str(&checkpoint_json).map_err(|e| ScpError::Validation {
                msg: format!("invalid checkpoint JSON: {e}"),
                code: codes::CTX_2063.to_owned(),
            })?;

        let signature =
            Zeroizing::new(
                hex::decode(&signature_hex).map_err(|e| ScpError::Validation {
                    msg: format!("invalid signature hex: {e}"),
                    code: codes::CTX_2063.to_owned(),
                })?,
            );

        let cosignature = scp_core::context::governance::CosignedCheckpoint {
            signer_did: scp_identity::DID(signer_did),
            signature: (*signature).clone(),
        };

        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let (updated_checkpoint, status) = {
                    use scp_core::context::actor::commands::TrustRecoveryCommand;
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = TrustRecoveryCommand::AddCheckpointCosignature {
                        context_id: context_id.clone(),
                        checkpoint: Box::new(checkpoint),
                        cosignature: Box::new(cosignature),
                        reply: tx,
                    };
                    sup.dispatch_trust_recovery_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("add_checkpoint_cosignature shim reply dropped: {e}"),
                            code: codes::CTX_2063.to_owned(),
                        })?
                        .map_err(ScpError::from)?
                };

                let response = serde_json::json!({
                    "attestation_status": format!("{status:?}"),
                    "checkpoint": serde_json::to_value(&updated_checkpoint).unwrap_or_default(),
                });
                Ok(response.to_string())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during add_checkpoint_cosignature: {e}"),
                code: codes::CTX_2063.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `restore_context`.
    ///
    /// Routes through `&*self.inner`.
    pub async fn restore_context(&self, context_id: String) -> Result<(), ScpError> {
        let bi = Arc::clone(&self.inner);
        let ctx_id = context_id.clone();

        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                // The actor loads its own persisted snapshot (including the
                // correct ContextParams / memory_scope) inside the
                // RestoreContext handler — the bridge no longer pre-loads it.
                use scp_core::context::actor::commands::{LifecycleCommand, RestoreContextPayload};
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = LifecycleCommand::RestoreContext {
                    payload: Box::new(RestoreContextPayload {
                        context_id: ctx_id.clone(),
                        params: scp_core::context::ContextParams::default(),
                    }),
                    reply: tx,
                };
                sup.dispatch_lifecycle_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                rx.await
                    .map_err(|e| ScpError::Context {
                        msg: format!("restore_context shim reply dropped: {e}"),
                        code: codes::CTX_2064.to_owned(),
                    })?
                    .map_err(ScpError::from)
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during restore_context: {e}"),
                code: codes::CTX_2064.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `restore_all_contexts`.
    ///
    /// Routes through `&*self.inner`.
    pub async fn restore_all_contexts(&self) -> Result<String, ScpError> {
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let manager = bi.context_manager_or_error()?;
                let restored = manager
                    .restore_all_contexts()
                    .await
                    .map_err(ScpError::from)?;

                serde_json::to_string(&restored).map_err(|e| ScpError::Context {
                    msg: format!("serialization failed: {e}"),
                    code: codes::CTX_2065.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during restore_all_contexts: {e}"),
                code: codes::CTX_2065.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `tombstone_migrated_context`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn tombstone_migrated_context(
        &self,
        handle: Arc<ContextHandle>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();
        let handle_ref = handle.clone();

        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                {
                    use scp_core::context::actor::commands::GovernanceCommand;
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = GovernanceCommand::TombstoneMigratedContext {
                        context_id: context_id.clone(),
                        reply: tx,
                    };
                    sup.dispatch_governance_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("tombstone_migrated_context shim reply dropped: {e}"),
                            code: codes::CTX_2050.to_owned(),
                        })?
                        .map_err(ScpError::from)?;
                }

                // Sync FFI handle state to Tombstoned (§5.11A.5).
                *handle_ref.state.lock().await = ContextState::Tombstoned;

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during tombstone: {e}"),
                code: codes::CTX_2050.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `migration_state`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn migration_state(
        &self,
        handle: Arc<ContextHandle>,
    ) -> Result<Option<String>, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        let context_id = handle.context_id.clone();

        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let state = {
                    use scp_core::context::actor::commands::GovernanceCommand;
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = GovernanceCommand::MigrationState {
                        context_id: context_id.clone(),
                        reply: tx,
                    };
                    sup.dispatch_governance_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("migration_state shim reply dropped: {e}"),
                            code: codes::CTX_2050.to_owned(),
                        })?
                        .map_err(ScpError::from)?
                };
                match state {
                    Some(ms) => {
                        let json = serde_json::json!({
                            "destination_context_id": ms.destination_context_id,
                            "reason": ms.reason,
                            "grace_period_end": ms.grace_period_end,
                            "auto_invite": ms.auto_invite,
                            "proposal_id": hex::encode(ms.proposal_id),
                        });
                        Ok(Some(json.to_string()))
                    }
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during migration_state: {e}"),
                code: codes::CTX_2050.to_owned(),
            })?
    }

    // ===== UniFFI sub-slice E — broadcast + membership queries + events =====
    //
    // Migrates the 16 broadcast / membership-query / drain free functions
    // (`broadcast_subscribe`, `broadcast_unsubscribe`, `broadcast_publish`,
    // `broadcast_publish_asset`, `broadcast_publish_assets`,
    // `broadcast_block_subscriber`, `broadcast_unblock_subscriber`,
    // `broadcast_handle_key_request`, `broadcast_subscriber_count`,
    // `broadcast_is_subscriber`, `broadcast_admission`,
    // `context_member_count`, `context_is_member`, `context_member_dids`,
    // `context_member_role`, `context_drain_events`) to
    // `impl crate::scp::Scp` methods routing through `&self.inner` (the
    // `UniffiBridgeInstance` owned by the caller).
    //
    // Free functions above are retained (they still compile and are still
    // exported via `#[uniffi::export]`) — the demolition slice at the end
    // of PR 4 removes them in one shot after every caller is migrated.
    // Bodies are preserved verbatim except for the
    // `crate::runtime::context_manager()` → `bi.context_manager_or_error()?`
    // and `crate::runtime::context_manager_expect()` →
    // `self.inner.context_manager_expect()?` swap and the handle-affinity
    // inline check described in the PR 4 sub-slice E plan.
    //
    // Part of #1549 Phase 4 PR 4.

    /// Per-instance equivalent of the free-function `broadcast_subscribe`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_subscribe(
        &self,
        handle: Arc<ContextHandle>,
        subscriber_did: String,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let did: scp_identity::DID = subscriber_did.into();
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                use scp_core::context::actor::commands::{
                    BroadcastCommand, SubscribeBroadcastPayload,
                };
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = BroadcastCommand::SubscribeBroadcast {
                    payload: Box::new(SubscribeBroadcastPayload {
                        context_id: handle.context_id.clone(),
                        subscriber_did: did,
                        ucan: None,
                        timestamp,
                    }),
                    reply: tx,
                };
                sup.dispatch_broadcast_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                rx.await
                    .map_err(|e| ScpError::Context {
                        msg: format!("subscribe_broadcast shim reply dropped: {e}"),
                        code: codes::CTX_2033.to_owned(),
                    })?
                    .map_err(ScpError::from)?;
                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during broadcast subscribe: {e}"),
                code: codes::CTX_2033.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `broadcast_unsubscribe`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_unsubscribe(
        &self,
        handle: Arc<ContextHandle>,
        subscriber_did: String,
        rotate_keys: bool,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let did: scp_identity::DID = subscriber_did.into();
                use scp_core::context::actor::commands::{
                    BroadcastCommand, UnsubscribeBroadcastPayload,
                };
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = BroadcastCommand::UnsubscribeBroadcast {
                    payload: Box::new(UnsubscribeBroadcastPayload {
                        context_id: handle.context_id.clone(),
                        subscriber_did: did,
                        rotate_keys,
                    }),
                    reply: tx,
                };
                sup.dispatch_broadcast_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                rx.await
                    .map_err(|e| ScpError::Context {
                        msg: format!("unsubscribe_broadcast shim reply dropped: {e}"),
                        code: codes::CTX_2034.to_owned(),
                    })?
                    .map_err(ScpError::from)?;
                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during broadcast unsubscribe: {e}"),
                code: codes::CTX_2034.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `broadcast_publish`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` or
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_publish(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
        payload: Vec<u8>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let did: scp_identity::DID = identity.did.clone().into();

                // Validate retained signing custody before depending on
                // supervisor state, so an externally-loaded identity surfaces
                // the missing-custody condition deterministically.
                let core_id = identity
                    .core_id
                    .as_ref()
                    .ok_or_else(|| ScpError::Identity {
                        msg: "broadcast publish requires retained signing custody — this \
                              identity was loaded externally and has no retained signing key \
                              material"
                            .to_owned(),
                        code: codes::IDENT_1017.to_owned(),
                    })?;
                let signing_key_handle = core_id.active_signing_key;

                let sup = bi.context_manager_or_error()?;

                use scp_core::context::actor::commands::{
                    BroadcastCommand, PublishBroadcastPayload,
                };

                // Dispatch to the correct custody path (callback > in-memory).
                if let Some(ref cb) = identity.callback_custody {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = BroadcastCommand::PublishBroadcast {
                        payload: Box::new(PublishBroadcastPayload {
                            context_id: handle.context_id.clone(),
                            author_did: did,
                            payload,
                            signing_key_handle,
                        }),
                        reply: tx,
                    };
                    sup.dispatch_broadcast_command_with_custody(cmd, cb.as_ref())
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("publish_broadcast shim reply dropped: {e}"),
                            code: codes::CTX_2035.to_owned(),
                        })?
                        .map_err(ScpError::from)?;
                } else {
                    #[cfg(feature = "allow_in_memory_custody")]
                    {
                        let imc = identity.in_memory_custody.as_ref().ok_or_else(|| {
                            ScpError::Identity {
                                msg: "broadcast publish requires retained signing custody — this \
                                          identity has no retained custody (it was externally \
                                          loaded). Use identity_create(\"in_memory\") or \
                                          identity_create_with_custody()"
                                    .to_owned(),
                                code: codes::IDENT_1017.to_owned(),
                            }
                        })?;
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let cmd = BroadcastCommand::PublishBroadcast {
                            payload: Box::new(PublishBroadcastPayload {
                                context_id: handle.context_id.clone(),
                                author_did: did,
                                payload,
                                signing_key_handle,
                            }),
                            reply: tx,
                        };
                        sup.dispatch_broadcast_command_with_custody(cmd, &imc.0)
                            .await
                            .map_err(ScpError::from)?;
                        rx.await
                            .map_err(|e| ScpError::Context {
                                msg: format!("publish_broadcast shim reply dropped: {e}"),
                                code: codes::CTX_2035.to_owned(),
                            })?
                            .map_err(ScpError::from)?;
                    }
                    #[cfg(not(feature = "allow_in_memory_custody"))]
                    {
                        let _ = (signing_key_handle, payload, did);
                        return Err(ScpError::Identity {
                            msg: "broadcast publish requires retained signing custody — use \
                                      identity_create_with_custody() to inject a platform \
                                      custody provider"
                                .to_owned(),
                            code: codes::IDENT_1017.to_owned(),
                        });
                    }
                }

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during broadcast publish: {e}"),
                code: codes::CTX_2035.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `broadcast_publish_asset`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` or
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_publish_asset(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
        asset: AssetEntry,
        deploy_id: Option<String>,
    ) -> Result<PublishResult, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let did: scp_identity::DID = identity.did.clone().into();

                // Validate retained signing custody before depending on
                // supervisor state, so an externally-loaded identity surfaces
                // the missing-custody condition deterministically.
                let core_id = identity
                    .core_id
                    .as_ref()
                    .ok_or_else(|| ScpError::Identity {
                        msg: "broadcast publish asset requires retained signing custody — this \
                              identity was loaded externally and has no retained signing key \
                              material"
                            .to_owned(),
                        code: codes::IDENT_1017.to_owned(),
                    })?;
                let signing_key_handle = core_id.active_signing_key;

                let sup = bi.context_manager_or_error()?;

                // Validate fields.
                let content_path =
                    scp_core::context::ContentPath::new(asset.path).map_err(|e| {
                        ScpError::Context {
                            msg: format!("invalid path: {e}"),
                            code: codes::CTX_2040.to_owned(),
                        }
                    })?;
                let mime_type =
                    scp_core::context::MimeType::new(asset.content_type).map_err(|e| {
                        ScpError::Context {
                            msg: format!("invalid content_type: {e}"),
                            code: codes::CTX_2041.to_owned(),
                        }
                    })?;
                // Auto-generate deploy_id when None, matching batch behavior.
                let deploy_id = Some(deploy_id.unwrap_or_else(|| {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(handle.context_id.as_bytes());
                    hasher.update(identity.did.as_bytes());
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis();
                    hasher.update(ts.to_le_bytes());
                    hex::encode(&Sha256::digest(hasher.finalize())[..16])
                }));
                if let Some(ref did_str) = deploy_id {
                    scp_core::context::validate_deploy_id(did_str).map_err(|e| {
                        ScpError::Context {
                            msg: format!("invalid deploy_id: {e}"),
                            code: codes::CTX_2042.to_owned(),
                        }
                    })?;
                }

                let etag = scp_core::context::compute_etag(&asset.body);
                // Capture deploy_id string before moving into BroadcastContent (SCP-292).
                let deploy_id_str = deploy_id.clone().unwrap_or_default();
                let content = scp_core::context::BroadcastContent {
                    version: scp_core::context::BROADCAST_CONTENT_VERSION,
                    metadata: scp_core::context::ContentMetadata {
                        path: Some(content_path),
                        content_type: Some(mime_type),
                        deploy_id,
                        etag: Some(etag.clone()),
                        immutable: false,
                    },
                    body: asset.body,
                };

                use scp_core::context::actor::commands::{
                    BroadcastCommand, PublishBroadcastContentPayload,
                };

                // Dispatch to the correct custody path (callback > in-memory).
                let envelope = if let Some(ref cb) = identity.callback_custody {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = BroadcastCommand::PublishBroadcastContent {
                        payload: Box::new(PublishBroadcastContentPayload {
                            context_id: handle.context_id.clone(),
                            author_did: did,
                            content,
                            signing_key_handle,
                        }),
                        reply: tx,
                    };
                    sup.dispatch_broadcast_command_with_custody(cmd, cb.as_ref())
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("publish_broadcast_content shim reply dropped: {e}"),
                            code: codes::CTX_2043.to_owned(),
                        })?
                        .map_err(ScpError::from)?
                } else {
                    #[cfg(feature = "allow_in_memory_custody")]
                    {
                        let imc = identity.in_memory_custody.as_ref().ok_or_else(|| {
                            ScpError::Identity {
                                msg: "broadcast publish asset requires retained signing custody — \
                                      this identity has no retained custody (it was externally \
                                      loaded). Use identity_create(\"in_memory\") or \
                                      identity_create_with_custody()"
                                    .to_owned(),
                                code: codes::IDENT_1017.to_owned(),
                            }
                        })?;
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let cmd = BroadcastCommand::PublishBroadcastContent {
                            payload: Box::new(PublishBroadcastContentPayload {
                                context_id: handle.context_id.clone(),
                                author_did: did,
                                content,
                                signing_key_handle,
                            }),
                            reply: tx,
                        };
                        sup.dispatch_broadcast_command_with_custody(cmd, &imc.0)
                            .await
                            .map_err(ScpError::from)?;
                        rx.await
                            .map_err(|e| ScpError::Context {
                                msg: format!("publish_broadcast_content shim reply dropped: {e}"),
                                code: codes::CTX_2043.to_owned(),
                            })?
                            .map_err(ScpError::from)?
                    }
                    #[cfg(not(feature = "allow_in_memory_custody"))]
                    {
                        let _ = (content, signing_key_handle, did);
                        return Err(ScpError::Identity {
                            msg: "broadcast publish asset requires retained signing custody — use \
                                  identity_create_with_custody() to inject a platform \
                                  custody provider"
                                .to_owned(),
                            code: codes::IDENT_1017.to_owned(),
                        });
                    }
                };

                let envelope_bytes =
                    rmp_serde::to_vec_named(&envelope).map_err(|e| ScpError::Context {
                        msg: format!("failed to serialize envelope for blob_id: {e}"),
                        code: codes::CTX_2043.to_owned(),
                    })?;
                let blob_id = {
                    use sha2::{Digest, Sha256};
                    hex::encode(Sha256::digest(&envelope_bytes))
                };

                Ok(PublishResult {
                    blob_id,
                    etag,
                    deploy_id: deploy_id_str,
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during broadcast publish asset: {e}"),
                code: codes::CTX_2035.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `broadcast_publish_assets`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` or
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_publish_assets(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
        assets: Vec<AssetEntry>,
        deploy_id: Option<String>,
    ) -> Result<BatchPublishResult, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        const MAX_BATCH_ASSETS: usize = 10_000;
        if assets.len() > MAX_BATCH_ASSETS {
            return Err(ScpError::Context {
                msg: format!(
                    "batch too large: {} assets (max {MAX_BATCH_ASSETS})",
                    assets.len()
                ),
                code: codes::CTX_2074.to_owned(),
            });
        }
        let bi = Arc::clone(&self.inner);

        runtime()
            .spawn(async move {
                let did: scp_identity::DID = identity.did.clone().into();

                // Validate retained signing custody before depending on
                // supervisor state, so an externally-loaded identity surfaces
                // the missing-custody condition deterministically.
                let core_id = identity
                    .core_id
                    .as_ref()
                    .ok_or_else(|| ScpError::Identity {
                        msg: "broadcast publish assets requires retained signing custody — this \
                              identity was loaded externally and has no retained signing key \
                              material"
                            .to_owned(),
                        code: codes::IDENT_1017.to_owned(),
                    })?;
                let signing_key_handle = core_id.active_signing_key;

                let sup = bi.context_manager_or_error()?;

                use scp_core::context::actor::commands::{
                    BroadcastCommand, PublishBroadcastContentPayload,
                };

                // Generate deploy_id if not provided.
                let deploy_id_val = deploy_id.unwrap_or_else(|| {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(handle.context_id.as_bytes());
                    hasher.update(identity.did.as_bytes());
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis();
                    hasher.update(ts.to_le_bytes());
                    hex::encode(&Sha256::digest(hasher.finalize())[..16])
                });

                scp_core::context::validate_deploy_id(&deploy_id_val).map_err(|e| {
                    ScpError::Context {
                        msg: format!("invalid deploy_id: {e}"),
                        code: codes::CTX_2042.to_owned(),
                    }
                })?;

                let mut results = Vec::with_capacity(assets.len());
                for asset in assets {
                    let content_path =
                        scp_core::context::ContentPath::new(asset.path).map_err(|e| {
                            ScpError::Context {
                                msg: format!("invalid path: {e}"),
                                code: codes::CTX_2040.to_owned(),
                            }
                        })?;
                    let mime_type =
                        scp_core::context::MimeType::new(asset.content_type).map_err(|e| {
                            ScpError::Context {
                                msg: format!("invalid content_type: {e}"),
                                code: codes::CTX_2041.to_owned(),
                            }
                        })?;

                    let etag = scp_core::context::compute_etag(&asset.body);
                    let content = scp_core::context::BroadcastContent {
                        version: scp_core::context::BROADCAST_CONTENT_VERSION,
                        metadata: scp_core::context::ContentMetadata {
                            path: Some(content_path),
                            content_type: Some(mime_type),
                            deploy_id: Some(deploy_id_val.clone()),
                            etag: Some(etag.clone()),
                            immutable: false,
                        },
                        body: asset.body,
                    };

                    let envelope = if let Some(ref cb) = identity.callback_custody {
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        let cmd = BroadcastCommand::PublishBroadcastContent {
                            payload: Box::new(PublishBroadcastContentPayload {
                                context_id: handle.context_id.clone(),
                                author_did: did.clone(),
                                content,
                                signing_key_handle,
                            }),
                            reply: tx,
                        };
                        sup.dispatch_broadcast_command_with_custody(cmd, cb.as_ref())
                            .await
                            .map_err(ScpError::from)?;
                        rx.await
                            .map_err(|e| ScpError::Context {
                                msg: format!("publish_broadcast_content shim reply dropped: {e}"),
                                code: codes::CTX_2043.to_owned(),
                            })?
                            .map_err(ScpError::from)?
                    } else {
                        #[cfg(feature = "allow_in_memory_custody")]
                        {
                            let imc = identity.in_memory_custody.as_ref().ok_or_else(|| {
                                ScpError::Identity {
                                    msg: "broadcast publish assets requires retained signing \
                                          custody — this identity has no retained custody (it was \
                                          externally loaded)"
                                        .to_owned(),
                                    code: codes::IDENT_1017.to_owned(),
                                }
                            })?;
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            let cmd = BroadcastCommand::PublishBroadcastContent {
                                payload: Box::new(PublishBroadcastContentPayload {
                                    context_id: handle.context_id.clone(),
                                    author_did: did.clone(),
                                    content,
                                    signing_key_handle,
                                }),
                                reply: tx,
                            };
                            sup.dispatch_broadcast_command_with_custody(cmd, &imc.0)
                                .await
                                .map_err(ScpError::from)?;
                            rx.await
                                .map_err(|e| ScpError::Context {
                                    msg: format!(
                                        "publish_broadcast_content shim reply dropped: {e}"
                                    ),
                                    code: codes::CTX_2043.to_owned(),
                                })?
                                .map_err(ScpError::from)?
                        }
                        #[cfg(not(feature = "allow_in_memory_custody"))]
                        {
                            let _ = (content, signing_key_handle, &did);
                            return Err(ScpError::Identity {
                                msg: "broadcast publish assets requires retained signing custody \
                                      — this identity has no retained custody (it was externally \
                                      loaded)"
                                    .to_owned(),
                                code: codes::IDENT_1017.to_owned(),
                            });
                        }
                    };

                    let envelope_bytes =
                        rmp_serde::to_vec_named(&envelope).map_err(|e| ScpError::Context {
                            msg: format!("failed to serialize envelope for blob_id: {e}"),
                            code: codes::CTX_2043.to_owned(),
                        })?;
                    let blob_id = {
                        use sha2::{Digest, Sha256};
                        hex::encode(Sha256::digest(&envelope_bytes))
                    };

                    results.push(PublishResult {
                        blob_id,
                        etag,
                        deploy_id: deploy_id_val.clone(),
                    });
                }

                Ok(BatchPublishResult {
                    results,
                    deploy_id: deploy_id_val,
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during broadcast publish assets: {e}"),
                code: codes::CTX_2035.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `broadcast_block_subscriber`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_block_subscriber(
        &self,
        handle: Arc<ContextHandle>,
        subscriber_did: String,
        blocker_did: String,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let subscriber: scp_identity::DID = subscriber_did.into();
                let blocker: scp_identity::DID = blocker_did.into();
                use scp_core::context::actor::commands::{BroadcastBlockPayload, BroadcastCommand};
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = BroadcastCommand::BlockBroadcastSubscriber {
                    payload: Box::new(BroadcastBlockPayload {
                        context_id: handle.context_id.clone(),
                        author_did: blocker,
                        subscriber_did: subscriber,
                    }),
                    reply: tx,
                };
                sup.dispatch_broadcast_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                rx.await
                    .map_err(|e| ScpError::Context {
                        msg: format!("block_broadcast_subscriber shim reply dropped: {e}"),
                        code: codes::CTX_2036.to_owned(),
                    })?
                    .map_err(ScpError::from)?;
                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during broadcast block: {e}"),
                code: codes::CTX_2036.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `broadcast_unblock_subscriber`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_unblock_subscriber(
        &self,
        handle: Arc<ContextHandle>,
        subscriber_did: String,
        unblocker_did: String,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let subscriber: scp_identity::DID = subscriber_did.into();
                let unblocker: scp_identity::DID = unblocker_did.into();
                use scp_core::context::actor::commands::{BroadcastBlockPayload, BroadcastCommand};
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = BroadcastCommand::UnblockBroadcastSubscriber {
                    payload: Box::new(BroadcastBlockPayload {
                        context_id: handle.context_id.clone(),
                        author_did: unblocker,
                        subscriber_did: subscriber,
                    }),
                    reply: tx,
                };
                sup.dispatch_broadcast_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                rx.await
                    .map_err(|e| ScpError::Context {
                        msg: format!("unblock_broadcast_subscriber shim reply dropped: {e}"),
                        code: codes::CTX_2037.to_owned(),
                    })?
                    .map_err(ScpError::from)?;
                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during broadcast unblock: {e}"),
                code: codes::CTX_2037.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `broadcast_handle_key_request`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_handle_key_request(
        &self,
        handle: Arc<ContextHandle>,
        author_did: String,
        requester_did: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let author: scp_identity::DID = author_did.into();
                let requester: scp_identity::DID = requester_did.into();
                use scp_core::context::actor::commands::BroadcastCommand;
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = BroadcastCommand::HandleBroadcastKeyRequest {
                    context_id: handle.context_id.clone(),
                    author_did: author,
                    requester_did: requester,
                    reply: tx,
                };
                sup.dispatch_broadcast_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                let decision = rx
                    .await
                    .map_err(|e| ScpError::Context {
                        msg: format!("handle_broadcast_key_request shim reply dropped: {e}"),
                        code: codes::CTX_2037.to_owned(),
                    })?
                    .map_err(ScpError::from)?;
                Ok(format!("{decision:?}"))
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during key request handling: {e}"),
                code: codes::CTX_2037.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `broadcast_subscriber_count`.
    ///
    /// Routes through `&*self.inner`. Returns `None` when the handle's
    /// `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_subscriber_count(&self, handle: Arc<ContextHandle>) -> Option<u64> {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return None;
        }
        let Ok(sup) = self.inner.context_manager_expect() else {
            return None;
        };
        use scp_core::context::actor::commands::BroadcastCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::BroadcastSubscriberCount {
            context_id: handle.context_id.clone(),
            reply: tx,
        };
        if sup.dispatch_broadcast_command(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(count)) => count.map(|n| n as u64),
            _ => None,
        }
    }

    /// Per-instance equivalent of the free-function
    /// `broadcast_is_subscriber`.
    ///
    /// Routes through `&*self.inner`. Returns `false` when the handle's
    /// `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_is_subscriber(&self, handle: Arc<ContextHandle>, did: String) -> bool {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return false;
        }
        let Ok(sup) = self.inner.context_manager_expect() else {
            return false;
        };
        use scp_core::context::actor::commands::BroadcastCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::IsBroadcastSubscriber {
            context_id: handle.context_id.clone(),
            did,
            reply: tx,
        };
        if sup.dispatch_broadcast_command(cmd).await.is_err() {
            return false;
        }
        matches!(rx.await, Ok(Ok(true)))
    }

    /// Per-instance equivalent of the free-function `broadcast_admission`.
    ///
    /// Routes through `&*self.inner`. Returns `None` when the handle's
    /// `instance_id` does not match this `SCP`'s.
    pub async fn broadcast_admission(&self, handle: Arc<ContextHandle>) -> Option<String> {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return None;
        }
        let Ok(sup) = self.inner.context_manager_expect() else {
            return None;
        };
        use scp_core::context::actor::commands::BroadcastCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::BroadcastAdmission {
            context_id: handle.context_id.clone(),
            reply: tx,
        };
        if sup.dispatch_broadcast_command(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(admission)) => admission.map(|a| format!("{a:?}")),
            _ => None,
        }
    }

    /// Per-instance equivalent of the free-function `context_member_count`.
    ///
    /// Routes through `&*self.inner`. Returns `None` when the handle's
    /// `instance_id` does not match this `SCP`'s.
    pub async fn context_member_count(&self, handle: Arc<ContextHandle>) -> Option<u64> {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return None;
        }
        let Ok(manager) = self.inner.context_manager_expect() else {
            return None;
        };
        manager
            .member_count(&handle.context_id)
            .await
            .map(|n| n as u64)
    }

    /// Per-instance equivalent of the free-function `context_is_member`.
    ///
    /// Routes through `&*self.inner`. Returns `false` when the handle's
    /// `instance_id` does not match this `SCP`'s.
    pub async fn context_is_member(&self, handle: Arc<ContextHandle>, did: String) -> bool {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return false;
        }
        let Ok(manager) = self.inner.context_manager_expect() else {
            return false;
        };
        manager.is_member(&handle.context_id, &did).await
    }

    /// Per-instance equivalent of the free-function `context_member_dids`.
    ///
    /// Routes through `&*self.inner`. Returns an empty `Vec` when the
    /// handle's `instance_id` does not match this `SCP`'s.
    pub async fn context_member_dids(&self, handle: Arc<ContextHandle>) -> Vec<String> {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return Vec::new();
        }
        let Ok(manager) = self.inner.context_manager_expect() else {
            return Vec::new();
        };
        manager.member_dids(&handle.context_id).await
    }

    /// Per-instance equivalent of the free-function `context_member_role`.
    ///
    /// Routes through `&*self.inner`. Returns `None` when the handle's
    /// `instance_id` does not match this `SCP`'s.
    pub async fn context_member_role(
        &self,
        handle: Arc<ContextHandle>,
        did: String,
    ) -> Option<String> {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return None;
        }
        let Ok(manager) = self.inner.context_manager_expect() else {
            return None;
        };
        manager
            .member_role(&handle.context_id, &did)
            .await
            .map(|r| format!("{r:?}"))
    }

    /// Per-instance equivalent of the free-function `context_drain_events`.
    ///
    /// Routes through `&*self.inner`. Returns an empty `Vec` when the
    /// handle's `instance_id` does not match this `SCP`'s.
    pub async fn context_drain_events(&self, handle: Arc<ContextHandle>) -> Vec<String> {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return Vec::new();
        }
        let Ok(manager) = self.inner.context_manager_expect() else {
            return Vec::new();
        };
        manager
            .drain_events(&handle.context_id)
            .await
            .iter()
            .map(format_context_event)
            .collect()
    }

    // ===== UniFFI sub-slice F — tools + access keys + TTL + event log + UCAN =====
    //
    // Migrates the tool / access-key / TTL / event-log / UCAN free functions
    // (`tool_register`, `tool_invoke`, `tool_verify`,
    // `tool_invoke_cross_context`, `tool_session_create`,
    // `tool_session_invoke`, `tool_session_close`,
    // `tool_interface_expose`, `tool_interface_accept`,
    // `tool_interface_revoke`, `access_key_generate`, `access_key_revoke`,
    // `access_key_restore`, `context_handle_ttl_expiry`,
    // `context_propose_ttl_extension`, `context_reset_ttl_timer`,
    // `event_log_query`, `event_log_verify`, `event_log_checkpoint`,
    // `ucan_validate`, `ucan_mint`, `ucan_revoke`, `ucan_delegate`) to
    // `impl crate::scp::Scp` methods routing through `&self.inner` (the
    // `UniffiBridgeInstance` owned by the caller).
    //
    // Free functions above are retained (they still compile and are still
    // exported via `#[uniffi::export]`) — the demolition slice at the end
    // of PR 4 removes them in one shot after every caller is migrated.
    // Bodies are preserved verbatim except for the
    // `crate::runtime::context_manager()` → `bi.context_manager_or_error()?`
    // and `crate::runtime::context_manager_expect()` →
    // `self.inner.context_manager_expect()?` (or `bi.context_manager_expect()?`
    // inside spawned closures) swap and the handle-affinity inline check.
    //
    // Part of #1549 Phase 4 PR 4.

    /// Per-instance equivalent of the free-function `tool_register`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn tool_register(
        &self,
        handle: Arc<ContextHandle>,
        definition: ToolDefinition,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        runtime()
            .spawn(async move {
                validate_tool_name(&definition.name)?;

                let state = handle.state.lock().await;

                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot register tool in context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::TOOL_6003.to_owned(),
                    });
                }
                drop(state);

                let input_schema: serde_json::Value =
                    serde_json::from_str(&definition.input_schema_json).map_err(|e| {
                        ScpError::Validation {
                            msg: format!("invalid input_schema_json: {e}"),
                            code: codes::VALID_7035.to_owned(),
                        }
                    })?;
                if !input_schema.is_object() {
                    return Err(ScpError::Validation {
                        msg: format!(
                            "invalid input_schema_json: expected a JSON object, got {}",
                            json_value_type_name(&input_schema)
                        ),
                        code: codes::VALID_7035.to_owned(),
                    });
                }
                let output_schema: serde_json::Value =
                    serde_json::from_str(&definition.output_schema_json).map_err(|e| {
                        ScpError::Validation {
                            msg: format!("invalid output_schema_json: {e}"),
                            code: codes::VALID_7036.to_owned(),
                        }
                    })?;
                if !output_schema.is_object() {
                    return Err(ScpError::Validation {
                        msg: format!(
                            "invalid output_schema_json: expected a JSON object, got {}",
                            json_value_type_name(&output_schema)
                        ),
                        code: codes::VALID_7036.to_owned(),
                    });
                }

                let test_vectors: Vec<scp_core::context::tools::TestVector> =
                    match definition.test_vectors_json.as_deref() {
                        None => Vec::new(),
                        Some(json) => serde_json::from_str(json).map_err(|e| ScpError::Validation {
                            msg: format!("invalid test_vectors_json: {e}"),
                            code: codes::VALID_7037.to_owned(),
                        })?,
                    };

                let implementation_hash: [u8; 32] = match definition.implementation_hash.as_deref() {
                    None => [0u8; 32],
                    Some(bytes) => scp_ffi_common::validate::expect_fixed_bytes::<32>(
                        bytes,
                        "implementation_hash",
                    )
                    .map_err(|msg| ScpError::Validation {
                        msg,
                        code: codes::VALID_7038.to_owned(),
                    })?,
                };

                let tool_id = format!("tool-{}", definition.name.replace(' ', "-").to_lowercase());

                let cost = definition.cost.map(|c| scp_core::context::tools::ToolCost {
                    amount: c.amount,
                    currency: c.currency,
                    payee: c.payee.into(),
                    cost_formula: c.cost_formula,
                });

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
                    cost,
                    registered_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                    signature: Vec::new(),
                };

                // Build a role state for capability checking.
                let ceiling = scp_core::context::roles::default_ceiling();
                let role_state = scp_core::context::roles::ContextRoleState::new(
                    &handle.context_id,
                    &handle.creator_did,
                    ceiling,
                    vec![],
                    &scp_primitives::SystemClock,
                )
                .map_err(|e| ScpError::Tool {
                    msg: format!("failed to create role state: {e}"),
                    code: codes::TOOL_6003.to_owned(),
                })?;

                let mut registry = handle.tool_registry.lock().await;
                let (registered_id, _event) = scp_core::context::tools::register_tool(
                    &mut registry,
                    &role_state,
                    core_registration,
                    &handle.creator_did,
                )
                .map_err(|e| ScpError::Tool {
                    msg: format!("tool registration failed: {e}"),
                    code: codes::TOOL_6001.to_owned(),
                })?;

                Ok(registered_id)
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during tool registration: {e}"),
                code: codes::TOOL_6004.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `tool_invoke`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` or
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    #[allow(clippy::too_many_arguments)] // Mirrors the runtime's economy entry point.
    pub async fn tool_invoke(
        &self,
        handle: Arc<ContextHandle>,
        tool_id: String,
        input_json: String,
        identity: Arc<Identity>,
        ucan_token: Option<String>,
        proof_tokens: Option<Vec<String>>,
        spending_ucan_jwt: Option<String>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                validate_tool_id(&tool_id)?;
                validate_did(&identity.did)?;

                // UCAN token is mandatory for tool invocation — all bridges
                // enforce this. Reject early if missing (§6.2, ADR-016, #423).
                let ucan_token = ucan_token.ok_or_else(|| ScpError::Permission {
                    msg: "UCAN token is required for tool invocation — \
                              pass a valid JWT-encoded UCAN with tool_invoke:{tool_id} \
                              or tool_invoke:* capability"
                        .to_owned(),
                    code: codes::PERM_3001.to_owned(),
                })?;
                validate_ucan_token(&ucan_token)?;
                if let Some(jwt) = spending_ucan_jwt.as_deref() {
                    validate_ucan_token(jwt)?;
                }

                let state = handle.state.lock().await;

                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot invoke tool in context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::TOOL_6005.to_owned(),
                    });
                }
                drop(state);

                // Primary authorization: UCAN token validation via the full
                // 11-step ADR-016 pipeline. Bridge-owned because the proof
                // resolver, revocation list, and nonce tracker live in the
                // bridge UCAN registry, not in the runtime.
                validate_tool_ucan_uniffi(
                    &bi,
                    &handle,
                    &tool_id,
                    &ucan_token,
                    &identity.did,
                    proof_tokens.as_ref(),
                )?;

                // Parse the optional spending UCAN JWT (§19.5
                // AND-composition). Mirrors `context_send`. An invalid JWT
                // surfaces as `SCP-ECON-12061` before the manager call.
                let spending_ucan_token = spending_ucan_jwt
                    .as_deref()
                    .map(scp_core::crypto::ucan::validate::parse_ucan)
                    .transpose()
                    .map_err(|e| ScpError::Context {
                        msg: format!("invalid spending UCAN: {e}"),
                        code: codes::ECON_12061.to_owned(),
                    })?;

                // Snapshot the bridge-owned tool registry and (optionally) the
                // registered handler closure BEFORE entering the runtime call.
                // The runtime requires a `&ToolRegistry` so we clone the
                // registry once (cheap — Vec of registrations); the handler
                // is an `Arc<dyn Fn>` so cloning is a refcount bump. Doing
                // this OUTSIDE the manager call means the bridge handle's
                // `tool_registry` mutex is released before Phase 1 of
                // `invoke_tool_with_economy` acquires the manager mutex.
                let registry = {
                    let reg = handle.tool_registry.lock().await;
                    reg.clone()
                };
                let handler = {
                    let handlers = handle.tool_handlers.lock().await;
                    handlers.get(&tool_id).cloned()
                };

                // Parse input JSON once (the runtime expects
                // `serde_json::Value`).
                let input_value: serde_json::Value =
                    serde_json::from_str(&input_json).map_err(|e| ScpError::Tool {
                        msg: format!("invalid input JSON: {e}"),
                        code: codes::TOOL_6002.to_owned(),
                    })?;

                let context_id = handle.context_id.clone();
                let identity_did_for_executor = identity.did.clone();
                let tool_id_for_executor = tool_id.clone();
                let context_id_for_executor = context_id.clone();

                // Build the executor closure. Phase 2 of
                // `invoke_tool_with_economy` runs WITHOUT holding the
                // `contexts` mutex; the runtime calls the executor exactly
                // once with the validated input value.
                let executor = move |input: serde_json::Value| {
                    let handler = handler.clone();
                    let input_for_echo = input.clone();
                    async move {
                        handler.map_or_else(
                            || {
                                Ok(serde_json::json!({
                                    "tool": tool_id_for_executor,
                                    "context": context_id_for_executor,
                                    "status": "validated",
                                    "input_valid": true,
                                    "invoker_did": identity_did_for_executor,
                                    "validated_input": input_for_echo,
                                }))
                            },
                            |h| {
                                h(input).map_err(|e| {
                                    format!("tool handler for '{tool_id_for_executor}' failed: {e}")
                                })
                            },
                        )
                    }
                };

                let manager = bi.context_manager_expect()?;
                let invoker_did_typed: scp_primitives::DID = identity.did.clone().into();
                let tool_id_typed = scp_core::context::tools::ToolId::from(tool_id.as_str());
                let outcome = manager
                    .invoke_tool_with_economy(
                        &context_id,
                        &registry,
                        &tool_id_typed,
                        input_value,
                        &invoker_did_typed,
                        spending_ucan_token.as_ref(),
                        None,
                        executor,
                    )
                    .await
                    .map_err(ScpError::from)?;

                // The runtime built the canonical `ToolInvokedEvent`; the
                // transport / event-log layer is responsible for signing
                // and appending it. Pull the JSON output back out for the
                // Swift / Kotlin caller.
                serde_json::to_string(&outcome.output).map_err(|e| ScpError::Tool {
                    msg: format!("failed to serialize tool output: {e}"),
                    code: codes::TOOL_6006.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during tool invocation: {e}"),
                code: codes::TOOL_6006.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `tool_verify`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn tool_verify(
        &self,
        handle: Arc<ContextHandle>,
        tool_id: String,
    ) -> Result<ToolVerificationResult, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        runtime()
            .spawn(async move {
                let state = handle.state.lock().await;

                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot verify tool in context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::TOOL_6007.to_owned(),
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
                msg: format!("tokio task join error during tool verification: {e}"),
                code: codes::TOOL_6008.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `tool_invoke_cross_context`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` or
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    #[allow(clippy::too_many_arguments)] // FFI boundary: UniFFI requires explicit params
    pub async fn tool_invoke_cross_context(
        &self,
        source_handle: Arc<ContextHandle>,
        target_handle: Arc<ContextHandle>,
        tool_id: String,
        input_json: String,
        identity: Arc<Identity>,
        ucan_token: String,
        chain_depth: u8,
        proof_tokens: Option<Vec<String>>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(source_handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(target_handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                // Validate source context is active.
                let source_state = source_handle.state.lock().await;
                if !matches!(*source_state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot invoke cross-context tool: source context in {:?} state",
                            *source_state
                        ),
                        code: codes::TOOL_6010.to_owned(),
                    });
                }
                drop(source_state);

                // Validate target context is active.
                let target_state = target_handle.state.lock().await;
                if !matches!(*target_state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot invoke cross-context tool: target context in {:?} state",
                            *target_state
                        ),
                        code: codes::TOOL_6011.to_owned(),
                    });
                }
                drop(target_state);

                // Validate chain depth (context-configurable, default 8 per ADR-043).
                let max_chain_depth = {
                    let mgr = bi.context_manager_or_error()?;
                    let source_max = mgr
                        .context_params(&source_handle.context_id)
                        .await
                        .and_then(|p| p.max_chain_depth);
                    scp_core::provenance::attach::effective_max_chain_depth(source_max)
                };
                if chain_depth > max_chain_depth {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cross-context chain depth {chain_depth} exceeds maximum {max_chain_depth}"
                        ),
                        code: codes::TOOL_6012.to_owned(),
                    });
                }

                // Primary authorization: UCAN token validation via the full 11-step
                // ADR-016 pipeline against the TARGET context's ceiling.
                // See spec §6.2, §8, ADR-016, and issue #319.
                validate_tool_ucan_uniffi(
                    &bi,
                    &target_handle,
                    &tool_id,
                    &ucan_token,
                    &identity.did,
                    proof_tokens.as_ref(),
                )?;

                let input_value: serde_json::Value =
                    serde_json::from_str(&input_json).map_err(|e| ScpError::Tool {
                        msg: format!("invalid input JSON: {e}"),
                        code: codes::TOOL_6002.to_owned(),
                    })?;

                let registry = target_handle.tool_registry.lock().await;
                let registration = registry.get(&tool_id).ok_or_else(|| ScpError::Tool {
                    msg: format!(
                        "tool '{tool_id}' not found in target context '{}'",
                        target_handle.context_id
                    ),
                    code: codes::TOOL_6002.to_owned(),
                })?;

                scp_core::context::tools::validate_value_against_schema(
                    &input_value,
                    &registration.schema.input_schema,
                )
                .map_err(|e| ScpError::Tool {
                    msg: format!("input validation failed: {e}"),
                    code: codes::TOOL_6002.to_owned(),
                })?;

                let output_schema = registration.schema.output_schema.clone();
                drop(registry);

                let handlers = target_handle.tool_handlers.lock().await;
                let output = if let Some(handler) = handlers.get(&tool_id) {
                    let handler = handler.clone();
                    drop(handlers);
                    let out = handler(input_value.clone()).map_err(|e| ScpError::Tool {
                        msg: format!("cross-context tool handler for '{tool_id}' failed: {e}"),
                        code: codes::TOOL_6002.to_owned(),
                    })?;
                    scp_core::context::tools::validate_value_against_schema(&out, &output_schema)
                        .map_err(|msg| ScpError::Tool {
                            msg: format!("output validation failed for tool '{tool_id}': {msg}"),
                            code: codes::TOOL_6002.to_owned(),
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
                    msg: format!("failed to serialize cross-context output: {e}"),
                    code: codes::TOOL_6013.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during cross-context invocation: {e}"),
                code: codes::TOOL_6009.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `tool_session_create`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn tool_session_create(
        &self,
        handle: Arc<ContextHandle>,
        tool_id: String,
        source_context_id: String,
        ttl_seconds: Option<u64>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let state = handle.state.lock().await;
                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot create session in context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::TOOL_6014.to_owned(),
                    });
                }
                drop(state);

                let mut store = handle.session_store.lock().await;

                // Enforce per-caller session cap (context-configured, default 1000, ADR-043).
                let cap = {
                    let mgr = bi.context_manager_or_error()?;
                    mgr.context_params(&handle.context_id)
                        .await
                        .and_then(|p| p.session_cap)
                        .unwrap_or(scp_core::context::tools::DEFAULT_SESSION_CAP_PER_CALLER)
                        as usize
                };
                let current = store.count_by_source(&source_context_id);
                if current >= cap {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "session cap exceeded for caller '{source_context_id}': {current} active (max {cap})"
                        ),
                        code: codes::TOOL_6015.to_owned(),
                    });
                }

                let session_id = Uuid::new_v4().to_string();
                let now_ms = scp_primitives::SystemClock.now_millis();

                let session = scp_core::context::tools::ToolSession {
                    session_id: session_id.clone(),
                    tool_id,
                    source_context: source_context_id,
                    state: serde_json::Value::Null,
                    created_at: now_ms,
                    ttl: ttl_seconds.map(std::time::Duration::from_secs),
                    call_count: 0,
                };

                store.insert(session);
                Ok(session_id)
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during session creation: {e}"),
                code: codes::TOOL_6009.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `tool_session_invoke`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` or
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    pub async fn tool_session_invoke(
        &self,
        handle: Arc<ContextHandle>,
        session_id: String,
        input_json: String,
        identity: Arc<Identity>,
        ucan_token: String,
        proof_tokens: Option<Vec<String>>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let state = handle.state.lock().await;
                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot invoke session in context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::TOOL_6017.to_owned(),
                    });
                }
                drop(state);

                // Look up tool_id from session for UCAN validation.
                let tool_id_for_ucan = {
                    let store = handle.session_store.lock().await;
                    let session = store.get(&session_id).ok_or_else(|| ScpError::Tool {
                        msg: format!("session '{session_id}' not found"),
                        code: codes::TOOL_6018.to_owned(),
                    })?;
                    session.tool_id.clone()
                };

                // Primary authorization: UCAN token validation via the full 11-step
                // ADR-016 pipeline. See spec §6.2, §8, ADR-016, and issue #319.
                validate_tool_ucan_uniffi(
                    &bi,
                    &handle,
                    &tool_id_for_ucan,
                    &ucan_token,
                    &identity.did,
                    proof_tokens.as_ref(),
                )?;

                let mut store = handle.session_store.lock().await;

                let session = store.get(&session_id).ok_or_else(|| ScpError::Tool {
                    msg: format!("session '{session_id}' not found"),
                    code: codes::TOOL_6018.to_owned(),
                })?;

                // Check expiry.
                let now_ms = scp_primitives::SystemClock.now_millis();
                if session.is_expired(now_ms) {
                    store.remove(&session_id);
                    return Err(ScpError::Tool {
                        msg: format!("session '{session_id}' has expired"),
                        code: codes::TOOL_6019.to_owned(),
                    });
                }

                let tool_id = session.tool_id.clone();
                let current_state = session.state.clone();
                let call_count = session.call_count;
                drop(store);

                let input_value: serde_json::Value =
                    serde_json::from_str(&input_json).map_err(|e| ScpError::Tool {
                        msg: format!("invalid input JSON: {e}"),
                        code: codes::TOOL_6002.to_owned(),
                    })?;

                // Validate input against tool's input schema if tool is registered.
                let registry = handle.tool_registry.lock().await;
                if let Some(registration) = registry.get(&tool_id) {
                    scp_core::context::tools::validate_value_against_schema(
                        &input_value,
                        &registration.schema.input_schema,
                    )
                    .map_err(|e| ScpError::Tool {
                        msg: format!("input validation failed: {e}"),
                        code: codes::TOOL_6002.to_owned(),
                    })?;
                }
                drop(registry);

                // Execute via handler or echo mode.
                let handlers = handle.tool_handlers.lock().await;
                let (new_state, output) = if let Some(handler) = handlers.get(&tool_id) {
                    let handler = handler.clone();
                    drop(handlers);
                    let out = handler(input_value.clone()).map_err(|e| ScpError::Tool {
                        msg: format!("tool handler for '{tool_id}' failed: {e}"),
                        code: codes::TOOL_6002.to_owned(),
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
                    msg: format!("failed to serialize session invoke output: {e}"),
                    code: codes::TOOL_6020.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during session invocation: {e}"),
                code: codes::TOOL_6009.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `tool_session_close`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn tool_session_close(
        &self,
        handle: Arc<ContextHandle>,
        session_id: String,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        runtime()
            .spawn(async move {
                let mut store = handle.session_store.lock().await;
                if store.remove(&session_id).is_none() {
                    return Err(ScpError::Tool {
                        msg: format!("session '{session_id}' not found"),
                        code: codes::TOOL_6021.to_owned(),
                    });
                }
                Ok(())
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during session close: {e}"),
                code: codes::TOOL_6009.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `tool_interface_expose`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn tool_interface_expose(
        &self,
        handle: Arc<ContextHandle>,
        tool_id: String,
        target_context_id: String,
        rate_limit_json: Option<String>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        runtime()
            .spawn(async move {
                validate_tool_id(&tool_id)?;

                let state = handle.state.lock().await;
                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot expose tool interface in context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::TOOL_6030.to_owned(),
                    });
                }
                drop(state);

                let rate_limit = match rate_limit_json {
                    Some(ref json) => {
                        let parsed: scp_core::context::tools::interface::RateLimit =
                            serde_json::from_str(json).map_err(|e| ScpError::Validation {
                                msg: format!("invalid rate_limit_json: {e}"),
                                code: codes::VALID_7040.to_owned(),
                            })?;
                        Some(parsed)
                    }
                    None => None,
                };

                let ceiling = scp_core::context::roles::default_ceiling();
                let role_state = scp_core::context::roles::ContextRoleState::new(
                    &handle.context_id,
                    &handle.creator_did,
                    ceiling,
                    vec![],
                    &scp_primitives::SystemClock,
                )
                .map_err(|e| ScpError::Tool {
                    msg: format!("failed to create role state: {e}"),
                    code: codes::TOOL_6030.to_owned(),
                })?;

                let context_handle = scp_core::context::ContextHandle::new(
                    handle.context_id.clone(),
                    scp_core::context::ContextParams::default(),
                );

                let registry = handle.tool_registry.lock().await;

                let interface = scp_core::context::tools::interface::expose_tool(
                    context_handle.context_id(),
                    &tool_id,
                    &target_context_id,
                    &role_state,
                    &handle.creator_did,
                    &registry,
                    rate_limit,
                    None,
                )
                .map_err(|e| ScpError::Tool {
                    msg: format!("expose_tool failed: {e}"),
                    code: codes::TOOL_6030.to_owned(),
                })?;

                serde_json::to_string(&interface).map_err(|e| ScpError::Tool {
                    msg: format!("failed to serialize ToolInterface: {e}"),
                    code: codes::TOOL_6031.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during tool_interface_expose: {e}"),
                code: codes::TOOL_6009.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `tool_interface_accept`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn tool_interface_accept(
        &self,
        handle: Arc<ContextHandle>,
        interface_json: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        runtime()
            .spawn(async move {
                let state = handle.state.lock().await;
                if !matches!(*state, ContextState::Active) {
                    return Err(ScpError::Tool {
                        msg: format!(
                            "cannot accept tool interface in context in {:?} state — context must be active",
                            *state
                        ),
                        code: codes::TOOL_6032.to_owned(),
                    });
                }
                drop(state);

                let mut interface: scp_core::context::tools::interface::ToolInterface =
                    serde_json::from_str(&interface_json).map_err(|e| ScpError::Validation {
                        msg: format!("invalid interface_json: {e}"),
                        code: codes::VALID_7041.to_owned(),
                    })?;

                let ceiling = scp_core::context::roles::default_ceiling();
                let role_state = scp_core::context::roles::ContextRoleState::new(
                    &handle.context_id,
                    &handle.creator_did,
                    ceiling,
                    vec![],
                    &scp_primitives::SystemClock,
                )
                .map_err(|e| ScpError::Tool {
                    msg: format!("failed to create role state: {e}"),
                    code: codes::TOOL_6032.to_owned(),
                })?;

                let context_handle = scp_core::context::ContextHandle::new(
                    handle.context_id.clone(),
                    scp_core::context::ContextParams::default(),
                );

                scp_core::context::tools::interface::accept_tool_interface(
                    context_handle.context_id(),
                    &mut interface,
                    &role_state,
                    &handle.creator_did,
                    None,
                )
                .map_err(|e| ScpError::Tool {
                    msg: format!("accept_tool_interface failed: {e}"),
                    code: codes::TOOL_6032.to_owned(),
                })?;

                serde_json::to_string(&interface).map_err(|e| ScpError::Tool {
                    msg: format!("failed to serialize ToolInterface: {e}"),
                    code: codes::TOOL_6033.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during tool_interface_accept: {e}"),
                code: codes::TOOL_6009.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `tool_interface_revoke`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn tool_interface_revoke(
        &self,
        handle: Arc<ContextHandle>,
        interface_id_hex: String,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        runtime()
            .spawn(async move {
                let interface_id_bytes =
                    hex::decode(&interface_id_hex).map_err(|e| ScpError::Validation {
                        msg: format!("invalid interface_id_hex: not valid hex: {e}"),
                        code: codes::VALID_7042.to_owned(),
                    })?;
                let interface_id: [u8; 32] = scp_ffi_common::validate::expect_fixed_bytes::<32>(
                    interface_id_bytes.as_slice(),
                    "interface_id_hex",
                )
                .map_err(|msg| ScpError::Validation {
                    msg,
                    code: codes::VALID_7042.to_owned(),
                })?;

                let now_ms = scp_primitives::SystemClock.now_millis();

                let event = scp_core::context::tools::interface::revoke_tool_interface(
                    interface_id,
                    &handle.context_id,
                    now_ms,
                );

                serde_json::to_string(&event).map_err(|e| ScpError::Tool {
                    msg: format!("failed to serialize InterfaceRevoked: {e}"),
                    code: codes::TOOL_6035.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Tool {
                msg: format!("tokio task join error during tool_interface_revoke: {e}"),
                code: codes::TOOL_6009.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `access_key_generate`.
    ///
    /// Routes through `&*self.inner`.
    pub async fn access_key_generate(
        &self,
        context_id: String,
        member_did: String,
        caller_did: String,
    ) -> Result<(), ScpError> {
        let sup = self.inner.context_manager_expect()?;
        use scp_core::context::actor::commands::LifecycleCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::GenerateContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd)
            .await
            .map_err(ScpError::from)?;
        rx.await
            .map_err(|e| ScpError::Context {
                msg: format!("generate_context_access_key shim reply dropped: {e}"),
                code: codes::CTX_2000.to_owned(),
            })?
            .map_err(ScpError::from)
    }

    /// Per-instance equivalent of the free-function `access_key_revoke`.
    ///
    /// Routes through `&*self.inner`.
    pub async fn access_key_revoke(
        &self,
        context_id: String,
        member_did: String,
        caller_did: String,
    ) -> Result<(), ScpError> {
        let sup = self.inner.context_manager_expect()?;
        use scp_core::context::actor::commands::LifecycleCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::RevokeContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd)
            .await
            .map_err(ScpError::from)?;
        rx.await
            .map_err(|e| ScpError::Context {
                msg: format!("revoke_context_access_key shim reply dropped: {e}"),
                code: codes::CTX_2000.to_owned(),
            })?
            .map_err(ScpError::from)
    }

    /// Per-instance equivalent of the free-function `access_key_restore`.
    ///
    /// Routes through `&*self.inner`.
    pub async fn access_key_restore(
        &self,
        context_id: String,
        member_did: String,
        caller_did: String,
    ) -> Result<(), ScpError> {
        let sup = self.inner.context_manager_expect()?;
        use scp_core::context::actor::commands::LifecycleCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::RestoreContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd)
            .await
            .map_err(ScpError::from)?;
        rx.await
            .map_err(|e| ScpError::Context {
                msg: format!("restore_context_access_key shim reply dropped: {e}"),
                code: codes::CTX_2000.to_owned(),
            })?
            .map_err(ScpError::from)
    }

    /// Per-instance equivalent of the free-function
    /// `context_handle_ttl_expiry`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn context_handle_ttl_expiry(
        &self,
        handle: Arc<ContextHandle>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                {
                    use scp_core::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = TtlCloseCommand::ExecuteTtlClose {
                        payload: Box::new(TtlContextPayload {
                            context_id: handle.context_id.clone(),
                            params: scp_core::context::ContextParams::default(),
                        }),
                        reply: tx,
                    };
                    sup.dispatch_ttl_close_command(cmd)
                        .await
                        .map_err(ScpError::from)?;
                    rx.await
                        .map_err(|e| ScpError::Context {
                            msg: format!("handle_ttl_expiry shim reply dropped: {e}"),
                            code: codes::CTX_2038.to_owned(),
                        })?
                        .map_err(ScpError::from)?;
                }

                // Update the FFI handle state to reflect expiry.
                let mut state = handle.state.lock().await;
                *state = ContextState::Expired;

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during TTL expiry: {e}"),
                code: codes::CTX_2038.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `context_propose_ttl_extension`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn context_propose_ttl_extension(
        &self,
        handle: Arc<ContextHandle>,
        member_did: String,
        proposed_seconds: u64,
    ) -> Result<bool, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let sup = bi.context_manager_or_error()?;
                let did: scp_identity::DID = member_did.into();
                let duration = std::time::Duration::from_secs(proposed_seconds);
                use scp_core::context::actor::commands::TtlCloseCommand;
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = TtlCloseCommand::ExtendTtl {
                    context_id: handle.context_id.clone(),
                    member_did: did,
                    proposed_duration: duration,
                    reply: tx,
                };
                sup.dispatch_ttl_close_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                rx.await
                    .map_err(|e| ScpError::Context {
                        msg: format!("propose_ttl_extension shim reply dropped: {e}"),
                        code: codes::CTX_2039.to_owned(),
                    })?
                    .map_err(ScpError::from)
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during TTL extension proposal: {e}"),
                code: codes::CTX_2039.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function
    /// `context_reset_ttl_timer`.
    ///
    /// Routes through `&*self.inner`. Silently returns when the handle's
    /// `instance_id` does not match this `SCP`'s (matches the free-function
    /// fire-and-forget signature).
    pub async fn context_reset_ttl_timer(&self, handle: Arc<ContextHandle>, new_seconds: u64) {
        if self.inner.core.check_handle(handle.instance_id()).is_err() {
            return;
        }
        let Ok(sup) = self.inner.context_manager_expect() else {
            return;
        };
        let duration = std::time::Duration::from_secs(new_seconds);
        use scp_core::context::actor::commands::{TtlCloseCommand, TtlTimerPayload};
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = TtlCloseCommand::ResetTtlTimer {
            payload: Box::new(TtlTimerPayload {
                context_id: handle.context_id.clone(),
                params: scp_core::context::ContextParams::default(),
                duration,
            }),
            reply: tx,
        };
        if sup.dispatch_ttl_close_command(cmd).await.is_err() {
            return;
        }
        // Fire-and-forget: drain the reply so the handler is not left with a
        // dropped sender, but the public signature is `()` (matches the
        // free-function's fire-and-forget contract).
        let _ = rx.await;
    }

    /// Per-instance equivalent of the free-function `event_log_query`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn event_log_query(
        &self,
        handle: Arc<ContextHandle>,
        filter_json: Option<String>,
    ) -> Result<Vec<Event>, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                // Ensure UCAN state (which contains the event log) is registered.
                bi.ensure_ucan_registered(
                    &handle.context_id,
                    &handle.creator_did,
                    &handle.ceiling_strings,
                );

                // Parse optional filter JSON.
                let filter: Option<serde_json::Value> =
                    match filter_json {
                        Some(ref json_str) => Some(serde_json::from_str(json_str).map_err(
                            |e| ScpError::Context {
                                msg: format!("invalid filter JSON: {e}"),
                                code: codes::CTX_2023.to_owned(),
                            },
                        )?),
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

                // Pre-compute timestamp for the fallback summary event outside the
                // closure so we can propagate clock errors properly.
                let fallback_now = scp_primitives::SystemClock.now_secs();

                // First, try the ContextManager's event log provider — the
                // authoritative source populated by `create_context`
                // (`ContextCreated` at step 7) and subsequent manager
                // operations. The per-context UCAN-state `EventLog` is a
                // separate tree used for UCAN-layer writes (revocations,
                // tests bypassing the manager); it starts empty on context
                // create and never receives the manager's lifecycle events
                // unless explicitly synced (see `event_log_verify` below).
                //
                // Mirrors `scp-ffi/src/event_log.rs::query_manager_entries`
                // (PyO3) and `scp-ffi-napi/src/event_log.rs::event_log_query_on`
                // (NAPI). Aligned across PyO3/NAPI/UniFFI — pinned by the
                // cross-bridge parity harness's `OP_EVENT_LOG_APPEND` and
                // `OP_EVENT_LOG_FILTERED` (ADR-046).
                if let Some(manager) = bi.try_context_manager_ready() {
                    let ctx_id_bytes = scp_core::context::context_id_bytes(&handle.context_id);
                    if let Ok(Some(entries)) = manager.event_log_entries(&ctx_id_bytes)
                        && !entries.is_empty()
                    {
                        // Canonical filter — pinned across PyO3/NAPI/UniFFI by
                        // `scp_ffi_common::event_log::filter_manager_entries`
                        // so the three bridges cannot drift on
                        // `after_sequence` / `before_sequence` / `event_type` /
                        // `actor_did` / `limit`. Each bridge still owns its
                        // native `Event` mapping below.
                        let filter = scp_ffi_common::event_log::EventLogFilter {
                            after_sequence: filter_after_seq,
                            before_sequence: filter_before_seq,
                            event_type: filter_event_type.as_deref(),
                            actor_did: filter_actor_did.as_deref(),
                            limit: filter_limit,
                        };
                        let filtered =
                            scp_ffi_common::event_log::filter_manager_entries(&entries, &filter);
                        let manager_events: Vec<Event> = filtered
                            .into_iter()
                            .map(|(seq, entry)| Event {
                                event_type: entry.event.clone(),
                                actor_did: entry.actor_did.clone(),
                                timestamp: entry.timestamp,
                                payload_json: serde_json::json!({
                                    "hash": hex::encode(entry.hash),
                                })
                                .to_string(),
                                sequence: seq,
                            })
                            .collect();
                        // Once the outer `!entries.is_empty()` guard passes we
                        // return the (possibly filtered-empty) manager result
                        // instead of falling through to the UCAN-state event
                        // log. Mirrors PyO3's `query_manager_entries` which
                        // unconditionally returns `Ok(Some(py_events))` once
                        // entries is non-empty, regardless of filter outcome.
                        return Ok(manager_events);
                    }
                }

                // Fallback: query the event log from per-context UCAN state.
                let events = bi
                    .with_ucan_state(&handle.context_id, |ucan_state| {
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
                                    .filter(|s| {
                                        serde_json::from_str::<serde_json::Value>(s).is_ok()
                                    })
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
                        let summary = Event {
                            event_type: "LogSummary".to_owned(),
                            actor_did: String::new(),
                            timestamp: fallback_now,
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
                        msg: format!("context '{}' not found in UCAN registry", handle.context_id),
                        code: codes::CTX_2023.to_owned(),
                    })?;

                Ok(events)
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during event log query: {e}"),
                code: codes::CTX_2024.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `event_log_verify`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn event_log_verify(
        &self,
        handle: Arc<ContextHandle>,
        claim_json: String,
    ) -> Result<Proof, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                // Parse the claim JSON.
                let claim: serde_json::Value =
                    serde_json::from_str(&claim_json).map_err(|e| ScpError::Context {
                        msg: format!("invalid claim JSON: {e}"),
                        code: codes::CTX_2025.to_owned(),
                    })?;

                let claim_type = claim.get("type").and_then(|v| v.as_str()).ok_or_else(|| {
                    ScpError::Context {
                        msg: "claim must include 'type' field ('inclusion' or 'absence')"
                            .to_owned(),
                        code: codes::CTX_2025.to_owned(),
                    }
                })?;

                // Ensure UCAN state (which contains the event log) is registered
                // on this instance.
                bi.ensure_ucan_registered(
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
                                msg: "inclusion claim must include 'leaf_index' (integer)"
                                    .to_owned(),
                                code: codes::CTX_2025.to_owned(),
                            })?;

                        bi.with_ucan_state(&handle.context_id, |ucan_state| {
                            let proof = scp_event_log::proof::prove_inclusion(
                                &ucan_state.event_log,
                                leaf_index,
                            )
                            .map_err(|e| ScpError::Context {
                                msg: format!("inclusion proof failed: {e}"),
                                code: codes::CTX_2025.to_owned(),
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
                            msg: format!(
                                "context '{}' not found in UCAN registry",
                                handle.context_id
                            ),
                            code: codes::CTX_2025.to_owned(),
                        })?
                    }
                    "absence" => {
                        let event_hash_hex = claim
                            .get("event_hash")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| ScpError::Context {
                                msg: "absence claim must include 'event_hash' (hex string)"
                                    .to_owned(),
                                code: codes::CTX_2025.to_owned(),
                            })?;

                        let event_hash_bytes =
                            hex::decode(event_hash_hex).map_err(|e| ScpError::Context {
                                msg: format!("invalid event_hash hex: {e}"),
                                code: codes::CTX_2025.to_owned(),
                            })?;
                        let event_hash: [u8; 32] =
                            event_hash_bytes.try_into().map_err(|v: Vec<u8>| {
                                ScpError::Context {
                                    msg: format!("event_hash must be 32 bytes, got {}", v.len()),
                                    code: codes::CTX_2025.to_owned(),
                                }
                            })?;

                        bi.with_ucan_state(&handle.context_id, |ucan_state| {
                            let proof = scp_event_log::proof::prove_absence(
                                &ucan_state.event_log,
                                &event_hash,
                            )
                            .map_err(|e| ScpError::Context {
                                msg: format!("absence proof failed: {e}"),
                                code: codes::CTX_2025.to_owned(),
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
                            msg: format!(
                                "context '{}' not found in UCAN registry",
                                handle.context_id
                            ),
                            code: codes::CTX_2025.to_owned(),
                        })?
                    }
                    other => Err(ScpError::Context {
                        msg: format!(
                            "unsupported claim type '{other}': expected 'inclusion' or 'absence'"
                        ),
                        code: codes::CTX_2025.to_owned(),
                    }),
                }
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during event log verification: {e}"),
                code: codes::CTX_2026.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `event_log_checkpoint`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` or
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    pub async fn event_log_checkpoint(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
        epoch: u64,
    ) -> Result<Checkpoint, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        event_log_checkpoint_impl(Arc::clone(&self.inner), handle, identity, epoch).await
    }

    /// Generates a signed consistency checkpoint scoped to a member DID.
    ///
    /// Signs with the supplied `identity`'s key material and records `did` as
    /// the checkpoint's `sender_did`. Unlike the PyO3/NAPI/WASM bridges, the
    /// `UniFFI` bridge has no DID-keyed identity registry, so the `Identity`
    /// handle is passed explicitly for key material while `did` names the
    /// member the checkpoint is attributed to (ADR-048 §7 per-SDK idiom). The
    /// `did` is validated for well-formedness and MUST equal the supplied
    /// identity's own DID — the recorded signer is always the actual signer.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` or
    /// `Identity` whose `instance_id` does not match this `SCP`'s.
    pub async fn event_log_checkpoint_by_did(
        &self,
        handle: Arc<ContextHandle>,
        identity: Arc<Identity>,
        did: String,
        epoch: u64,
    ) -> Result<Checkpoint, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        event_log_checkpoint_by_did_impl(Arc::clone(&self.inner), handle, identity, did, epoch)
            .await
    }

    /// Per-instance equivalent of the free-function `ucan_validate`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn ucan_validate(
        &self,
        handle: Arc<ContextHandle>,
        token: String,
        capability: String,
        presenting_agent_did: Option<String>,
        proof_tokens: Option<Vec<String>>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                validate_ucan_token(&token)?;
                validate_capability_uri(&capability)?;

                use scp_core::crypto::ucan::capability::CapabilityUri;
                use scp_core::crypto::ucan::validate::{
                    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, ValidationContext, parse_ucan, validate_ucan,
                };

                // Step 1: Parse the UCAN token. Route through the canonical
                // `From<UcanError>` impl so parse failures surface the same
                // error code as every other bridge (PyO3/NAPI/WASM all map
                // through `scp_ffi_common::ucan_errors::ucan_error_code`).
                // The prior ad-hoc `PERM_3002` mapping silently diverged
                // from the shared classification, which the cross-bridge
                // parity harness (`OP_UCAN_VALIDATE_MALFORMED`, ADR-046)
                // catches against the reference PyO3 output.
                let parsed_token = parse_ucan(&token).map_err(ScpError::from)?;

                // Parse the required capability URI.
                let required_cap: CapabilityUri = capability
                    .parse()
                    .map_err(|e: scp_core::crypto::ucan::UcanError| ScpError::from(e))?;

                // Determine the presenting agent DID: explicit parameter or token audience.
                let agent_did = presenting_agent_did
                    .as_deref()
                    .unwrap_or(&parsed_token.payload.aud);

                // Build proof resolver from optional proof tokens. Parse errors
                // use the same shared classification as the root token above.
                let mut proofs = std::collections::HashMap::new();
                if let Some(ref tokens) = proof_tokens {
                    for encoded in tokens {
                        let proof_token = parse_ucan(encoded).map_err(ScpError::from)?;
                        let cid = scp_core::crypto::ucan::mint::compute_cid(&proof_token);
                        proofs.insert(cid, proof_token);
                    }
                }
                let proof_resolver = scp_ffi_common::BridgeProofResolver { proofs };

                // Ensure UCAN state is registered for this context on this instance.
                bi.ensure_ucan_registered(
                    &handle.context_id,
                    &handle.creator_did,
                    &handle.ceiling_strings,
                );

                // Execute the full 11-step validation pipeline via per-context state.
                let validation_result = bi
                    .with_ucan_state(&handle.context_id, |ucan_state| {
                        let production_resolver = bi.did_resolver();
                        let did_resolver = scp_ffi_common::DispatchDidResolver::new(
                            production_resolver.as_deref(),
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
                            clock: &scp_primitives::SystemClock,
                        };

                        validate_ucan(&parsed_token, &required_cap, &mut ctx).map_err(|e| {
                            ScpError::Permission {
                                msg: format!("UCAN validation failed: {e}"),
                                code: codes::PERM_3002.to_owned(),
                            }
                        })
                    })
                    .ok_or_else(|| ScpError::Permission {
                        msg: format!("context '{}' not found in UCAN registry", handle.context_id),
                        code: codes::PERM_3002.to_owned(),
                    })?;
                validation_result?;

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Permission {
                msg: format!("tokio task join error during UCAN validation: {e}"),
                code: codes::PERM_3003.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `ucan_mint`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn ucan_mint(
        &self,
        handle: Arc<ContextHandle>,
        member_did: String,
        capabilities: Vec<String>,
        proofs: Option<Vec<String>>,
    ) -> Result<Arc<UcanToken>, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        validate_did(&member_did)?;
        if let Some(ref tokens) = proofs {
            for t in tokens {
                validate_ucan_token(t).map_err(|e| ScpError::Validation {
                    msg: e.to_string(),
                    code: codes::VALID_7010.to_owned(),
                })?;
            }
        }
        ucan_mint_impl(handle, member_did, capabilities, proofs).await
    }

    /// Per-instance equivalent of the free-function `ucan_revoke`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn ucan_revoke(
        &self,
        handle: Arc<ContextHandle>,
        token: String,
        revoker_did: String,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        validate_ucan_token(&token).map_err(|e| ScpError::Validation {
            msg: e.to_string(),
            code: codes::VALID_7010.to_owned(),
        })?;
        validate_did(&revoker_did).map_err(|e| ScpError::Validation {
            msg: e.to_string(),
            code: codes::VALID_7011.to_owned(),
        })?;

        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                use scp_core::crypto::ucan::validate::parse_ucan;
                use scp_ffi_common::{
                    BridgeRevocationAuthorizer, BridgeRevocationDistributor,
                    BridgeRevocationEventLogger,
                };
                use std::cell::RefCell;

                // Parse the token to extract the issuer DID for authorization.
                let parsed = parse_ucan(&token).map_err(ScpError::from)?;

                // Ensure UCAN state is registered for this context on this instance.
                bi.ensure_ucan_registered(
                    &handle.context_id,
                    &handle.creator_did,
                    &handle.ceiling_strings,
                );

                // Execute the full revocation pipeline within the UCAN state closure.
                bi.with_ucan_state(&handle.context_id, |ucan_state| {
                    let authorizer = BridgeRevocationAuthorizer {
                        issuer_did: parsed.payload.iss.clone(),
                        creator_did: ucan_state.creator_did.clone(),
                    };
                    let distributor = BridgeRevocationDistributor;
                    let event_log_cell = RefCell::new(&mut ucan_state.event_log);
                    let event_logger = BridgeRevocationEventLogger {
                        event_log: &event_log_cell,
                    };

                    scp_core::crypto::ucan::revoke::revoke_ucan(
                        &mut ucan_state.revocation_list,
                        &token,
                        &revoker_did,
                        &authorizer,
                        &distributor,
                        &event_logger,
                    )
                    .map_err(ScpError::from)
                })
                .ok_or_else(|| ScpError::Permission {
                    msg: format!("context '{}' not found in UCAN registry", handle.context_id),
                    code: codes::PERM_3006.to_owned(),
                })??;

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Permission {
                msg: format!("tokio task join error during UCAN revocation: {e}"),
                code: codes::PERM_3007.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `ucan_delegate`.
    ///
    /// Routes through `&*self.inner`. Rejects any `ContextHandle` whose
    /// `instance_id` does not match this `SCP`'s.
    pub async fn ucan_delegate(
        &self,
        handle: Arc<ContextHandle>,
        delegator_did: String,
        delegatee_did: String,
        parent_token: String,
        capabilities: Vec<String>,
    ) -> Result<Arc<UcanToken>, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
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

    // ===== UniFFI sub-slice G — transport + MCP + trust + misc =====
    //
    // Migrates the transport / MCP / local-DID / trust / sync-policy free
    // functions (`transport_connect`, `transport_status`,
    // `transport_disconnect`, `configure_relay_transport`,
    // `mcp_server_create`, `mcp_server_stop`, `mcp_client_connect_stdio`,
    // `mcp_client_connect_sse`, `mcp_client_disconnect`,
    // `mcp_client_list_tools`, `mcp_client_invoke`,
    // `mcp_configure_stdio_allowlist`, `mcp_disable_stdio_allowlist`,
    // `mcp_reset_stdio_allowlist`, `mcp_get_stdio_allowlist`,
    // `register_local_did`, `is_local_did`, `trust_query_score`,
    // `trust_verify_attestation`, `trust_create_challenge`,
    // `trust_verify_response`, `verify_participation_requirements`,
    // `aggregate_trust_input`, `bridge_evaluate_trust`,
    // `sync_classify_offline`, `sync_classify_offline_custom`,
    // `sync_get_policy`) to `impl crate::scp::Scp` methods routing through
    // `&self.inner` (the `UniffiBridgeInstance` owned by the caller).
    //
    // Free functions above are retained (they still compile and are still
    // exported via `#[uniffi::export]`) — the demolition slice at the end
    // of PR 4 removes them in one shot after every caller is migrated.
    // Bodies are preserved verbatim except for the
    // `crate::runtime::bridge_instance()` → `&*self.inner` and
    // `crate::runtime::init_context_manager_with_*` → `bi.init_context_manager_with_*`
    // and `crate::runtime::context_manager_expect()` →
    // `self.inner.context_manager_expect()?` (or `bi.context_manager_expect()?`
    // inside spawned closures) and `crate::runtime::protocol_repository()` →
    // `bi.protocol_repository()` swaps and the handle-affinity inline check.
    //
    // Purely stateless helpers (`bridge_evaluate_trust`,
    // `sync_classify_offline`, `sync_classify_offline_custom`,
    // `sync_get_policy`, `trust_verify_response`, `trust_verify_attestation`,
    // `trust_create_challenge`, `verify_participation_requirements`) are
    // exposed as thin delegating methods so SDK callers have a uniform
    // `scp.method(...)` API surface; the bodies simply forward to the free
    // functions.
    //
    // Part of #1549 Phase 4 PR 4.

    /// Per-instance equivalent of the free-function `transport_connect`.
    ///
    /// Routes through `&*self.inner`. The returned `TransportManager`
    /// handle's `instance_id` is stamped against this `SCP`'s
    /// `UniffiBridgeInstance`, so it will be rejected by any other
    /// `SCP` instance.
    pub async fn transport_connect(
        &self,
        relay_url: String,
    ) -> Result<Arc<TransportManager>, ScpError> {
        use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};

        validate_relay_url(&relay_url)?;

        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let sourced = SourcedRelayUrl {
                    url: relay_url.clone(),
                    source: RelayUrlSource::Explicit,
                };

                // Route through the instance-scoped transport selector for
                // transparent QUIC↔WebSocket selection (spec §10.14.3 item 4;
                // ADR-037). The discovering variant fetches the relay's
                // advertised transports from `.well-known/scp` (spec §10.5.1)
                // at connect time and feeds that list into the
                // QUIC-vs-WebSocket decision — failing open to WebSocket when
                // the relay serves no well-known. The selector is owned by the
                // bridge instance so its per-relay QUIC-suppression and
                // well-known caches survive across connects. Cover traffic
                // auto-starts per adapter via the profile inside
                // `finalize_connection`. The selector surfaces the suppression
                // receiver (drained into reliability scoring). Mirrors the PyO3
                // reference bridge's `transport_connect`.
                let profile = scp_transport::profile::TransportProfile::platform_default();
                let selector = bi.core.transport_selector();
                let (adapter, suppression_rx) = selector
                    .select_and_connect_discovering_with_suppression(&sourced, Some(&profile))
                    .await
                    .map_err(ScpError::from)?;

                // Wrap the selected adapter in a real TransportManager for
                // multi-relay support (ADR-012). The manager provides relay set
                // assignment, reliability scoring, and suppression detection.
                // The selector returns a `Box<dyn TransportAdapter>`; the
                // blanket `impl TransportAdapter for Box<dyn TransportAdapter>`
                // lets it be used where a concrete adapter is expected.
                let manager = scp_transport::TransportManager::new(adapter);

                // Install the manager on THIS instance's CoreFields — not on
                // the process-wide DEFAULT_BRIDGE_INSTANCE.
                bi.core
                    .set_transport(std::sync::Arc::new(manager))
                    .map_err(|e| ScpError::Transport {
                        msg: e.to_string(),
                        code: codes::TRANS_5002.to_owned(),
                    })?;

                // Register the URL on this bridge's pending-reconnect set
                // so `BridgeInstanceCore::resume` can rebuild the transport
                // after suspend/resume cycles (#1678).
                bi.core.add_relay_url(relay_url.clone());

                let handle = Arc::new(TransportManager {
                    status: std::sync::Mutex::new(TransportStatus {
                        connected: true,
                        relay_url: Some(relay_url.clone()),
                        latency_ms: None,
                    }),
                    bi: Arc::clone(&bi),
                    instance_id: bi.core.instance_id(),
                });
                increment_handle_count();

                // Spawn suppression → scoring bridge task bound to this
                // instance (not the process-wide default).
                //
                // Pass `Weak<UniffiBridgeInstance>` + the instance's cancel
                // token so the task cannot pin the instance alive. See the
                // `spawn_suppression_scoring_task` doc comment for the
                // Arc-cycle rationale (#1549 round-2 bug-catcher).
                if let Some(rx) = suppression_rx {
                    spawn_suppression_scoring_task(
                        Arc::downgrade(&bi),
                        bi.core.cancel_token(),
                        rx,
                        relay_url,
                    );
                }

                Ok(handle)
            })
            .await
            .map_err(|e| ScpError::Transport {
                msg: format!("tokio task join error during transport connect: {e}"),
                code: codes::TRANS_5002.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `transport_status`.
    ///
    /// Routes through `&*self.inner`. Rejects any `TransportManager`
    /// whose `instance_id` does not match this `SCP`'s.
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn transport_status(
        &self,
        manager: Arc<TransportManager>,
    ) -> Result<TransportStatus, ScpError> {
        self.inner
            .core
            .check_handle(manager.instance_id())
            .map_err(ScpError::from)?;
        Ok(manager.status())
    }

    /// Handleless transport-status probe — reports whether a
    /// `TransportManager` is currently installed on this `SCP`
    /// instance without requiring the caller to construct a
    /// [`TransportManager`] handle first.
    ///
    /// Mirrors `PyO3`'s `Scp::transport_status()`, NAPI's
    /// `Scp::transportStatus(undefined)`, and WASM's
    /// `transport_status()` so the cross-bridge parity harness
    /// (ADR-046) can compare the disconnected-state shape across all
    /// four bridges without needing a relay fixture for the `UniFFI`
    /// runners (ADR-048 §7a).
    ///
    /// Returns `connected = has_transport()`, and always `None` for
    /// both `relay_url` and `latency_ms` — matching the NAPI
    /// handleless probe's contract (the relay URL lives on the
    /// `TransportManager` handle, not on the bridge instance, so it
    /// is only observable via [`Self::transport_status`]). The
    /// disconnected shape — the only shape the parity harness
    /// exercises — is `(false, None, None)` across all four bridges.
    ///
    /// Since the result is stateless as far as the bridge is
    /// concerned (no cross-instance handle is passed in), there is no
    /// handle-affinity check to perform.
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn transport_manager_status(&self) -> Result<TransportStatus, ScpError> {
        let (connected, relay_url, latency_ms) =
            scp_ffi_common::handleless_transport_status(self.inner.core.has_transport());
        Ok(TransportStatus {
            connected,
            relay_url,
            latency_ms,
        })
    }

    /// Per-instance equivalent of the free-function `transport_disconnect`.
    ///
    /// Routes through `&*self.inner`. Rejects any `TransportManager`
    /// whose `instance_id` does not match this `SCP`'s.
    pub async fn transport_disconnect(
        &self,
        manager: Arc<TransportManager>,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(manager.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                // Clear the transport from THIS instance, dropping all adapters.
                bi.core.clear_transport().map_err(|e| ScpError::Transport {
                    msg: e.to_string(),
                    code: codes::TRANS_5003.to_owned(),
                })?;

                // Update the handle's status to disconnected and capture the
                // URL we were connected to before clearing it.
                let disconnecting_url = {
                    let mut status_guard =
                        manager.status.lock().map_err(|_| ScpError::Transport {
                            msg: "status mutex is poisoned — cannot update transport status"
                                .to_owned(),
                            code: codes::TRANS_5003.to_owned(),
                        })?;
                    let url = status_guard.relay_url.clone();
                    status_guard.connected = false;
                    status_guard.relay_url = None;
                    status_guard.latency_ms = None;
                    url
                };

                // Remove the URL from the bridge's pending-reconnect set so a
                // subsequent `resume()` does not re-open a URL the caller
                // explicitly disconnected (#1678).
                if let Some(ref url) = disconnecting_url {
                    bi.core.remove_relay_url(url);
                }

                Ok(())
            })
            .await
            .map_err(|e| ScpError::Transport {
                msg: format!("tokio task join error during transport disconnect: {e}"),
                code: codes::TRANS_5003.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `configure_relay_transport`.
    ///
    /// Routes through `&*self.inner`. Installs a real `MlsCryptoProvider`
    /// and `RelayTransportProvider` on this instance's `ContextManager`.
    pub async fn configure_relay_transport(
        &self,
        relay_url: String,
        local_did: String,
    ) -> Result<(), ScpError> {
        validate_relay_url(&relay_url)?;
        validate_did(&local_did)?;

        let sourced = scp_transport::relay::connection::SourcedRelayUrl {
            url: relay_url.clone(),
            source: scp_transport::relay::connection::RelayUrlSource::Explicit,
        };

        let profile = scp_transport::profile::TransportProfile::platform_default();
        // Route through the instance-scoped transport selector for transparent
        // QUIC↔WebSocket selection (spec §10.14.3 item 4; ADR-037). The
        // discovering variant reads the relay's advertised transports from
        // `.well-known/scp` (spec §10.5.1) at connect time to enable QUIC,
        // failing open to WebSocket when discovery is unavailable. Mirrors the
        // PyO3 reference bridge's `configure_relay_transport`.
        let selector = self.inner.core.transport_selector();
        let adapter = selector
            .select_and_connect_discovering(&sourced, Some(&profile))
            .await
            .map_err(|e| ScpError::Transport {
                msg: format!("failed to connect to relay '{relay_url}': {e}"),
                code: codes::TRANS_5001.to_owned(),
            })?;

        self.inner
            .init_context_manager_with_relay_transport(&local_did, adapter);
        Ok(())
    }

    /// Per-instance equivalent of the free-function `configure_local_transport`.
    ///
    /// Routes through `&*self.inner`. Installs a real `MlsCryptoProvider` and
    /// an in-process loopback `LocalTransportProvider` on this instance's
    /// `ContextManager`. Unlike `configure_relay_transport`, this performs no
    /// network I/O — it wires test infrastructure so `context_send` and
    /// `broadcast_publish` succeed (encryption included) without a real relay.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Validation` if `local_did` fails DID validation.
    pub fn configure_local_transport(&self, local_did: String) -> Result<(), ScpError> {
        validate_did(&local_did)?;
        self.inner
            .init_context_manager_with_local_transport(&local_did);
        Ok(())
    }

    /// Per-instance equivalent of the free-function `mcp_server_create`.
    ///
    /// Routes through `&*self.inner`. The MCP server registry is
    /// module-level (not per-instance) so the returned opaque handle
    /// string is globally unique; this method preserves that behaviour.
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn mcp_server_create(&self, config: McpServerConfig) -> Result<String, ScpError> {
        validate_did(&config.identity_did)?;
        validate_transport_mode(&config.transport)?;
        for ctx_id in &config.context_ids {
            validate_context_id(ctx_id)?;
        }

        if config.context_ids.is_empty() {
            return Err(ScpError::Transport {
                msg: "context_ids must not be empty".to_owned(),
                code: codes::TRANS_5011.to_owned(),
            });
        }

        // #1549 round-2: hold the bridge instance as a `Weak`, not an
        // `Arc`. The MCP server task is spawned on the shared tokio
        // runtime (`runtime().spawn(...)`) and is NOT enrolled in the
        // per-instance `JoinSet`, so an `Arc` would leak the
        // `UniffiBridgeInstance` (and with it `ContextManager`, identity
        // registry, relay connection) for the remainder of the process
        // when the caller drops `SCP` without calling `mcp_server_stop`.
        // The task body additionally selects on the instance's
        // `cancel_token` so `emergency_cancel_tasks()` from `Drop` can
        // wake it between requests.
        let provider = McpUniFfiBridgeProvider {
            bi: Arc::downgrade(&self.inner),
            agent_did: config.identity_did.clone(),
            context_ids: config.context_ids.clone(),
            tool_timeout_ms: UNIFFI_TOOL_TIMEOUT_MS,
            agent_ucan_token: config.ucan_token.clone(),
            agent_proof_tokens: config.proof_tokens.clone(),
        };
        let server = scp_mcp::server::McpServer::new(provider);
        let server = Arc::new(std::sync::Mutex::new(server));

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let server_clone = Arc::clone(&server);
        let transport_mode = config.transport;
        let sse_identity_did = config.identity_did;
        let sse_context_ids = config.context_ids;
        let sse_ucan_token = config.ucan_token;
        let sse_proof_tokens = config.proof_tokens;
        // `sse_bi` is a `Weak` reference so the SSE server task cannot
        // pin `UniffiBridgeInstance` alive. Same rationale as `provider.bi`.
        let sse_bi: std::sync::Weak<crate::runtime::UniffiBridgeInstance> =
            Arc::downgrade(&self.inner);
        // Capture the cancel token so the server task exits when the
        // instance is dropped, even if the caller never calls
        // `mcp_server_stop`. Cloning a `CancellationToken` does not
        // extend the instance's lifetime.
        let cancel_token = self.inner.core.cancel_token();

        let task_handle = runtime().spawn(async move {
            match transport_mode.as_str() {
                "stdio" => {
                    run_mcp_stdio_server_uniffi(server_clone, shutdown_rx, cancel_token).await;
                }
                "sse" => {
                    let provider = McpUniFfiBridgeProvider {
                        bi: sse_bi,
                        agent_did: sse_identity_did,
                        context_ids: sse_context_ids,
                        tool_timeout_ms: UNIFFI_TOOL_TIMEOUT_MS,
                        agent_ucan_token: sse_ucan_token,
                        agent_proof_tokens: sse_proof_tokens,
                    };
                    let sse_server = scp_mcp::server::McpServer::new(provider);
                    let sse_config = scp_mcp::sse::SseConfig::new(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        0,
                    )));
                    let sse_shutdown = scp_mcp::sse::ShutdownHandle::new();
                    let sse_shutdown_trigger = sse_shutdown.clone();
                    // Wire both shutdown_rx (mcp_server_stop) AND the bridge
                    // instance's cancel_token (emergency_cancel_tasks from
                    // Drop) so either signal tears down the SSE server
                    // (#1549 round-2).
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = shutdown_rx => {}
                            () = cancel_token.cancelled() => {}
                        }
                        sse_shutdown_trigger.shutdown();
                    });
                    let result = scp_mcp::sse::run_sse(sse_server, sse_config, sse_shutdown).await;
                    if let Err(e) = result {
                        tracing::error!("MCP SSE server error: {e}");
                    }
                }
                _ => {} // Already validated above.
            }
        });

        let handle_id = mcp_handle_id("mcp-server");
        mcp_server_registry(&self.inner).insert(
            handle_id.clone(),
            McpServerEntry {
                shutdown_tx: Some(shutdown_tx),
                _task_handle: task_handle,
                stopped: false,
            },
        );
        increment_handle_count();

        Ok(handle_id)
    }

    /// Per-instance equivalent of the free-function `mcp_server_stop`.
    ///
    /// Routes through the module-level MCP server registry (the registry
    /// is not per-instance; the opaque handle string is globally unique).
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn mcp_server_stop(&self, handle: String) -> Result<(), ScpError> {
        validate_mcp_handle(&handle)?;

        let mut entry = mcp_server_registry(&self.inner)
            .get_mut(&handle)
            .ok_or_else(|| ScpError::Transport {
                msg: format!("MCP server handle '{handle}' not found"),
                code: codes::TRANS_5012.to_owned(),
            })?;

        if entry.stopped {
            return Err(ScpError::Transport {
                msg: format!("MCP server '{handle}' is already stopped"),
                code: codes::TRANS_5013.to_owned(),
            });
        }

        entry.stopped = true;
        if let Some(tx) = entry.shutdown_tx.take() {
            let _ = tx.send(());
        }

        Ok(())
    }

    /// Per-instance equivalent of the free-function `mcp_client_connect_stdio`.
    ///
    /// Routes through the module-level MCP client registry.
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn mcp_client_connect_stdio(&self, command: Vec<String>) -> Result<String, ScpError> {
        if command.is_empty() {
            return Err(ScpError::Validation {
                msg: "command must be a non-empty list".to_owned(),
                code: codes::VALID_7034.to_owned(),
            });
        }

        let transport = McpStdioTransport::spawn(self.inner.core.mcp_allowlist(), &command)
            .map_err(|e| ScpError::Transport {
                msg: format!("failed to connect stdio MCP client: {e}"),
                code: codes::TRANS_5015.to_owned(),
            })?;

        let mut client =
            scp_mcp::client::McpClient::new(McpUniFFITransportWrapper::Stdio(transport));
        client.initialize().map_err(|e| ScpError::Transport {
            msg: format!("MCP initialize handshake failed: {e}"),
            code: codes::TRANS_5016.to_owned(),
        })?;

        let handle_id = mcp_handle_id("mcp-client");
        mcp_client_registry(&self.inner).insert(
            handle_id.clone(),
            McpClientEntry {
                client: std::sync::Mutex::new(client),
            },
        );
        increment_handle_count();

        Ok(handle_id)
    }

    /// Per-instance equivalent of the free-function `mcp_client_connect_sse`.
    ///
    /// Routes through the module-level MCP client registry.
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn mcp_client_connect_sse(&self, url: String) -> Result<String, ScpError> {
        validate_relay_url(&url)?;

        let transport = McpSseTransport::connect(&url);

        let mut client = scp_mcp::client::McpClient::new(McpUniFFITransportWrapper::Sse(transport));
        client.initialize().map_err(|e| ScpError::Transport {
            msg: format!("MCP initialize handshake failed: {e}"),
            code: codes::TRANS_5018.to_owned(),
        })?;

        let handle_id = mcp_handle_id("mcp-client");
        mcp_client_registry(&self.inner).insert(
            handle_id.clone(),
            McpClientEntry {
                client: std::sync::Mutex::new(client),
            },
        );
        increment_handle_count();

        Ok(handle_id)
    }

    /// Per-instance equivalent of the free-function `mcp_client_disconnect`.
    ///
    /// Routes through the module-level MCP client registry.
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn mcp_client_disconnect(&self, handle: String) -> Result<(), ScpError> {
        validate_mcp_handle(&handle)?;

        let removed = mcp_client_registry(&self.inner).remove(&handle);
        if removed.is_none() {
            return Err(ScpError::Transport {
                msg: format!("MCP client handle '{handle}' not found"),
                code: codes::TRANS_5019.to_owned(),
            });
        }

        Ok(())
    }

    /// Per-instance equivalent of the free-function `mcp_client_list_tools`.
    ///
    /// Routes through the module-level MCP client registry.
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn mcp_client_list_tools(
        &self,
        handle: String,
    ) -> Result<Vec<McpToolInfo>, ScpError> {
        validate_mcp_handle(&handle)?;

        let entry = mcp_client_registry(&self.inner)
            .get(&handle)
            .ok_or_else(|| ScpError::Transport {
                msg: format!("MCP client handle '{handle}' not found"),
                code: codes::TRANS_5020.to_owned(),
            })?;

        let client_guard = entry.client.lock().map_err(|e| ScpError::Transport {
            msg: format!("client lock poisoned: {e}"),
            code: codes::TRANS_5021.to_owned(),
        })?;

        let tools = client_guard.list_tools().map_err(|e| ScpError::Transport {
            msg: format!("tools/list failed: {e}"),
            code: codes::TRANS_5022.to_owned(),
        })?;

        Ok(tools
            .into_iter()
            .map(|t| McpToolInfo {
                name: t.name,
                description: t.description.unwrap_or_default(),
                input_schema_json: serde_json::to_string(&t.input_schema)
                    .unwrap_or_else(|_| "{}".to_owned()),
            })
            .collect())
    }

    /// Per-instance equivalent of the free-function `mcp_client_invoke`.
    ///
    /// Routes through the module-level MCP client registry.
    #[allow(clippy::unused_async)] // Must be async: UniFFI generates Swift async / Kotlin suspend.
    pub async fn mcp_client_invoke(
        &self,
        handle: String,
        tool_name: String,
        input_json: String,
        context_id: String,
        invoker_did: String,
    ) -> Result<McpInvokeResult, ScpError> {
        validate_mcp_handle(&handle)?;
        validate_tool_name(&tool_name)?;
        validate_context_id(&context_id)?;
        validate_did(&invoker_did)?;

        let entry = mcp_client_registry(&self.inner)
            .get(&handle)
            .ok_or_else(|| ScpError::Transport {
                msg: format!("MCP client handle '{handle}' not found"),
                code: codes::TRANS_5023.to_owned(),
            })?;

        let input: serde_json::Value =
            serde_json::from_str(&input_json).map_err(|e| ScpError::Validation {
                msg: format!("invalid input JSON: {e}"),
                code: codes::VALID_7021.to_owned(),
            })?;

        let client_guard = entry.client.lock().map_err(|e| ScpError::Transport {
            msg: format!("client lock poisoned: {e}"),
            code: codes::TRANS_5024.to_owned(),
        })?;

        let result = client_guard
            .invoke(&tool_name, input, &context_id, &invoker_did)
            .map_err(|e| ScpError::Transport {
                msg: format!("tools/call failed: {e}"),
                code: codes::TRANS_5025.to_owned(),
            })?;

        let content_json =
            serde_json::to_string(&result.content).unwrap_or_else(|_| "[]".to_owned());

        Ok(McpInvokeResult {
            content_json,
            is_error: result.is_error,
            source: result.provenance.source,
            invoked_by: result.provenance.invoked_by,
            context_id: result.provenance.context,
            timestamp: result.provenance.timestamp,
        })
    }

    /// Configures THIS instance's MCP stdio subprocess allowlist.
    ///
    /// Operates on `self.inner.core().mcp_allowlist()` — disabling
    /// enforcement on one `Scp` does NOT leak into another (ADR-048
    /// multi-instance neutrality).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Validation` if any entry is invalid (path, NUL,
    /// empty). Returns `ScpError::Transport` if the per-instance allowlist
    /// lock is poisoned.
    pub fn mcp_configure_stdio_allowlist(
        &self,
        additional_binaries: Vec<String>,
    ) -> Result<(), ScpError> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(|a| a.configure(&additional_binaries))
            .map_err(|_| mcp_allowlist_lock_poisoned())?
            .map_err(mcp_allowlist_err)?;
        tracing::info!(
            instance_id,
            added = ?additional_binaries,
            "MCP stdio allowlist extended"
        );
        Ok(())
    }

    /// Disable THIS instance's stdio allowlist (unrestricted mode).
    ///
    /// Other `Scp` instances remain unaffected.
    pub fn mcp_disable_stdio_allowlist(&self) -> Result<(), ScpError> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(|a| a.disable_enforcement(instance_id))
            .map_err(|_| mcp_allowlist_lock_poisoned())?;
        Ok(())
    }

    /// Reset THIS instance's stdio allowlist to defaults.
    ///
    /// Other `Scp` instances are unaffected.
    pub fn mcp_reset_stdio_allowlist(&self) -> Result<(), ScpError> {
        let instance_id = self.inner.core.instance_id();
        self.inner
            .core
            .with_mcp_allowlist(scp_mcp::allowlist::StdioAllowlist::reset)
            .map_err(|_| mcp_allowlist_lock_poisoned())?;
        tracing::info!(instance_id, "MCP stdio allowlist reset to defaults");
        Ok(())
    }

    /// Snapshot of THIS instance's stdio allowlist state.
    pub fn mcp_get_stdio_allowlist(&self) -> Result<McpAllowlistState, ScpError> {
        let state = self
            .inner
            .core
            .with_mcp_allowlist(|a| a.snapshot())
            .map_err(|_| mcp_allowlist_lock_poisoned())?;
        Ok(McpAllowlistState {
            allowed: state.allowed,
            unrestricted: state.unrestricted,
        })
    }

    /// Per-instance equivalent of the free-function `register_local_did`.
    ///
    /// Routes through `&*self.inner`. Initializes this instance's
    /// `ContextManager` if not yet attached (idempotent) and registers
    /// the DID on the per-instance local-DID set.
    pub async fn register_local_did(&self, did: String) -> Result<(), ScpError> {
        validate_did(&did)?;
        self.inner.init_context_manager_with_did(&did);
        let manager = self.inner.context_manager_expect()?;
        manager
            .register_local_did(did.into())
            .await
            .map_err(ScpError::from)?;
        Ok(())
    }

    /// Per-instance equivalent of the free-function `is_local_did`.
    ///
    /// Routes through `&*self.inner`. Returns `false` if the DID fails
    /// validation or the instance's `ContextManager` cannot be
    /// initialized / looked up.
    pub async fn is_local_did(&self, did: String) -> bool {
        if validate_did(&did).is_err() {
            return false;
        }
        // Initialize this instance's bridge with this DID as the local
        // identity. Idempotent — matches the free-function behaviour of
        // permitting `is_local_did` as the first operation.
        self.inner.init_context_manager_with_did(&did);
        let Ok(manager) = self.inner.context_manager_expect() else {
            return false;
        };
        let did_ref: scp_identity::DID = did.into();
        manager.is_local_did(&did_ref).await.unwrap_or(false)
    }

    /// Per-instance equivalent of the free-function `bridge_create_shadow`.
    ///
    /// Mutates this instance's per-context bridge state. Rejects any
    /// cross-instance caller (the method takes `&self` — the `bi` threaded
    /// into `bridge_create_shadow_on` is always this instance's).
    pub fn bridge_create_shadow(
        &self,
        bridge_id: String,
        platform_handle: String,
        bridge_mode: String,
        context_id: String,
    ) -> Result<ShadowIdentityResult, ScpError> {
        bridge_create_shadow_on(
            &self.inner,
            bridge_id,
            platform_handle,
            bridge_mode,
            context_id,
        )
    }

    /// Provisions (stores) an encrypted credential for a bridge instance
    /// (spec §12.11). Routes through `&self.inner` — credentials live in
    /// THIS instance's credential store (ADR-048 §1).
    pub fn bridge_credential_provision(
        &self,
        bridge_id: String,
        credential_type: String,
        plaintext: Vec<u8>,
        bridge_credential_key: Vec<u8>,
    ) -> Result<BridgeCredentialResult, ScpError> {
        bridge_credential_provision_on(
            &self.inner,
            &bridge_id,
            &credential_type,
            &plaintext,
            &bridge_credential_key,
        )
    }

    /// Retrieves and decrypts a credential for a bridge instance (spec §12.11).
    pub fn bridge_credential_retrieve(
        &self,
        bridge_id: String,
        credential_type: String,
        bridge_credential_key: Vec<u8>,
    ) -> Result<Vec<u8>, ScpError> {
        bridge_credential_retrieve_on(
            &self.inner,
            &bridge_id,
            &credential_type,
            &bridge_credential_key,
        )
    }

    /// Rotates (replaces) a credential for a bridge instance (spec §12.11).
    pub fn bridge_credential_rotate(
        &self,
        bridge_id: String,
        credential_type: String,
        new_plaintext: Vec<u8>,
        bridge_credential_key: Vec<u8>,
    ) -> Result<BridgeCredentialResult, ScpError> {
        bridge_credential_rotate_on(
            &self.inner,
            &bridge_id,
            &credential_type,
            &new_plaintext,
            &bridge_credential_key,
        )
    }

    /// Revokes all credentials for a bridge instance (spec §12.11).
    pub fn bridge_credential_revoke(&self, bridge_id: String) -> Result<(), ScpError> {
        bridge_credential_revoke_on(&self.inner, &bridge_id)
    }

    /// Lists all credential types stored for a bridge instance (spec §12.11).
    pub fn bridge_credential_list(&self, bridge_id: String) -> Result<Vec<String>, ScpError> {
        bridge_credential_list_on(&self.inner, &bridge_id)
    }

    /// Stores a bridge credential key in the custody boundary (spec §12.11).
    pub fn bridge_credential_store_key(
        &self,
        bridge_id: String,
        key: Vec<u8>,
    ) -> Result<(), ScpError> {
        bridge_credential_store_key_on(&self.inner, &bridge_id, &key)
    }

    /// Retrieves a bridge credential key from the custody boundary (spec §12.11).
    pub fn bridge_credential_get_key(&self, bridge_id: String) -> Result<Vec<u8>, ScpError> {
        bridge_credential_get_key_on(&self.inner, &bridge_id)
    }

    /// Deletes and zeroizes a bridge credential key (spec §12.11).
    pub fn bridge_credential_delete_key(&self, bridge_id: String) -> Result<(), ScpError> {
        bridge_credential_delete_key_on(&self.inner, &bridge_id)
    }

    /// Per-instance equivalent of the free-function `scpid_sign`.
    ///
    /// Signs an SCPID challenge with the identity's requested key. Rejects
    /// any `Identity` whose `instance_id` does not match this `Scp`'s.
    ///
    /// `signed_at_override` is a testing-only parameter for the ADR-046
    /// cross-bridge parity harness. Only accepted when scp-core is built
    /// with the `testing` feature; production builds reject any non-`None`
    /// value via `SCP-VALID-7008`.
    #[cfg(feature = "allow_in_memory_custody")]
    pub fn scpid_sign(
        &self,
        identity: Arc<Identity>,
        signing_key_id: String,
        challenge_json: String,
        signed_at_override: Option<u64>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        scpid_sign_impl(identity, signing_key_id, challenge_json, signed_at_override)
    }

    /// Per-instance equivalent of the free-function `scpid_verify`.
    ///
    /// Uses this `Scp`'s DID resolver (populated when the caller invokes
    /// `identity_create` / `identity_create_with_custody`). Phase D (#1695)
    /// replaces the old free function that consulted the process-wide
    /// `DEFAULT_BRIDGE_INSTANCE` DID resolver slot.
    pub fn scpid_verify(
        &self,
        response_json: String,
        challenge_json: String,
    ) -> Result<String, ScpError> {
        scpid_verify_on(&self.inner, response_json, challenge_json)
    }

    /// Per-instance equivalent of the free-function `relay_start_in_memory`.
    ///
    /// Starts a new in-memory relay server and returns a `RelayHandle`
    /// whose `instance_id` is stamped against this `Scp`. Phase D (#1695)
    /// replaces the old free function that looked up `DEFAULT_BRIDGE_INSTANCE`
    /// for the handle's `instance_id`.
    #[cfg(feature = "server")]
    pub async fn relay_start_in_memory(&self) -> Result<Arc<crate::server::RelayHandle>, ScpError> {
        crate::server::relay_start_in_memory_on(&self.inner).await
    }

    /// Per-instance equivalent of the free-function `relay_start_local`.
    ///
    /// Starts a new redb-backed relay at `data_dir/blobs.redb`.
    #[cfg(feature = "server")]
    pub async fn relay_start_local(
        &self,
        data_dir: String,
    ) -> Result<Arc<crate::server::RelayHandle>, ScpError> {
        crate::server::relay_start_local_on(&self.inner, data_dir).await
    }

    /// Per-instance equivalent of the free-function `node_start_in_memory`.
    ///
    /// Starts an in-memory application node. If `identity` is supplied, it
    /// must have been minted by this `Scp` (cross-instance handles are
    /// rejected via the `CoreFields::check_handle` call).
    #[cfg(feature = "server")]
    pub async fn node_start_in_memory(
        &self,
        identity: Option<Arc<Identity>>,
    ) -> Result<Arc<crate::server::NodeHandle>, ScpError> {
        if let Some(ref id) = identity {
            self.inner
                .core
                .check_handle(id.instance_id())
                .map_err(ScpError::from)?;
        }
        crate::server::node_start_in_memory_on(&self.inner, identity).await
    }

    /// Per-instance equivalent of the free-function `node_start_local`.
    ///
    /// Starts a file-backed application node at `data_dir`. If `identity`
    /// is supplied, it must have been minted by this `Scp`.
    #[cfg(feature = "server")]
    pub async fn node_start_local(
        &self,
        data_dir: String,
        identity: Option<Arc<Identity>>,
        passphrase: Option<String>,
    ) -> Result<Arc<crate::server::NodeHandle>, ScpError> {
        if let Some(ref id) = identity {
            self.inner
                .core
                .check_handle(id.instance_id())
                .map_err(ScpError::from)?;
        }
        crate::server::node_start_local_on(&self.inner, data_dir, identity, passphrase).await
    }

    /// Per-instance equivalent of the free-function [`trust_create_challenge`].
    ///
    /// Stateless helper — uses an ephemeral signing key per call.
    pub fn trust_create_challenge(&self, target_did: String) -> Result<ChallengeResult, ScpError> {
        if target_did.is_empty() {
            return Err(ScpError::Validation {
                msg: "target DID must not be empty".to_owned(),
                code: codes::VALID_7013.to_owned(),
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
            std::time::Duration::from_mins(5),
            &signer,
        )
        .map_err(|e| ScpError::Validation {
            msg: format!("challenge creation failed: {e}"),
            code: codes::VALID_7014.to_owned(),
        })?;

        let challenge_json = serde_json::to_string(&request).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize challenge: {e}"),
            code: codes::VALID_7015.to_owned(),
        })?;

        Ok(ChallengeResult {
            challenge_id: request.challenge_id,
            challenge_json,
        })
    }

    /// Per-instance equivalent of the free-function [`trust_verify_response`].
    ///
    /// Stateless helper — uses an ephemeral verification signer per call.
    pub fn trust_verify_response(
        &self,
        challenge_json: String,
        response_json: String,
    ) -> Result<bool, ScpError> {
        let request: scp_core::trust::ChallengeRequest = serde_json::from_str(&challenge_json)
            .map_err(|e| ScpError::Validation {
                msg: format!("failed to parse challenge JSON: {e}"),
                code: codes::VALID_7016.to_owned(),
            })?;

        let response: scp_core::trust::ChallengeResponse = serde_json::from_str(&response_json)
            .map_err(|e| ScpError::Validation {
                msg: format!("failed to parse response JSON: {e}"),
                code: codes::VALID_7017.to_owned(),
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

    /// Per-instance equivalent of the free-function `aggregate_trust_input`.
    ///
    /// Routes through `&*self.inner` — trust data is populated against
    /// THIS instance's `ProtocolRepository` variant (in-memory or `SQLite`),
    /// falling back to an ephemeral in-memory store when no repository
    /// is attached.
    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_trust_input(
        &self,
        context_id: String,
        subject_did: String,
        events_json: String,
        merkle_root_json: String,
        consequence_rules_json: String,
        threshold_requirements_json: String,
        attestor_sets_json: String,
        cached_attestations_json: String,
        challenge_results_json: String,
    ) -> Result<String, ScpError> {
        if context_id.is_empty() {
            return Err(ScpError::Validation {
                msg: "context_id must not be empty".to_owned(),
                code: codes::VALID_7040.to_owned(),
            });
        }
        if subject_did.is_empty() {
            return Err(ScpError::Validation {
                msg: "subject DID must not be empty".to_owned(),
                code: codes::VALID_7041.to_owned(),
            });
        }

        let events: Vec<scp_event_log::Event> =
            serde_json::from_str(&events_json).map_err(|e| ScpError::Validation {
                msg: format!("failed to parse events JSON: {e}"),
                code: codes::VALID_7042.to_owned(),
            })?;

        let merkle_root_vec: Vec<u8> =
            serde_json::from_str(&merkle_root_json).map_err(|e| ScpError::Validation {
                msg: format!("failed to parse merkle_root JSON: {e}"),
                code: codes::VALID_7043.to_owned(),
            })?;
        let merkle_root: [u8; 32] =
            merkle_root_vec
                .try_into()
                .map_err(|v: Vec<u8>| ScpError::Validation {
                    msg: format!("merkle_root must be exactly 32 bytes, got {}", v.len()),
                    code: codes::VALID_7044.to_owned(),
                })?;

        let consequence_rules: Vec<scp_core::trust::ConsequenceRule> =
            serde_json::from_str(&consequence_rules_json).map_err(|e| ScpError::Validation {
                msg: format!("failed to parse consequence_rules JSON: {e}"),
                code: codes::VALID_7045.to_owned(),
            })?;

        let threshold_requirements: std::collections::HashMap<
            scp_core::trust::AttestationType,
            scp_core::trust::ThresholdRequirement,
        > = serde_json::from_str(&threshold_requirements_json).map_err(|e| {
            ScpError::Validation {
                msg: format!("failed to parse threshold_requirements JSON: {e}"),
                code: codes::VALID_7046.to_owned(),
            }
        })?;

        let attestor_sets: std::collections::HashMap<
            scp_core::trust::AttestationType,
            Vec<scp_core::trust::AttestorInfo>,
        > = serde_json::from_str(&attestor_sets_json).map_err(|e| ScpError::Validation {
            msg: format!("failed to parse attestor_sets JSON: {e}"),
            code: codes::VALID_7047.to_owned(),
        })?;

        let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
            serde_json::from_str(&cached_attestations_json).map_err(|e| ScpError::Validation {
                msg: format!("failed to parse cached_attestations JSON: {e}"),
                code: codes::VALID_7048.to_owned(),
            })?;

        let challenge_results: Vec<scp_core::trust::ChallengeVerification> =
            serde_json::from_str(&challenge_results_json).map_err(|e| ScpError::Validation {
                msg: format!("failed to parse challenge_results JSON: {e}"),
                code: codes::VALID_7049.to_owned(),
            })?;

        // Route trust aggregation through THIS instance's
        // `ProtocolRepository` variant. Falls back to an ephemeral
        // in-memory store when no repository is attached yet.
        match self.inner.protocol_repository() {
            crate::runtime::ProtocolRepoVariant::InMemory(repo) => {
                let handle = runtime().handle().clone();
                let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(
                    std::sync::Arc::clone(repo),
                    handle,
                );
                scp_ffi_common::trust_store::populate_and_aggregate(
                    bridge,
                    &context_id,
                    &subject_did,
                    cached_attestations,
                    &challenge_results,
                    &events,
                    merkle_root,
                    &consequence_rules,
                    &threshold_requirements,
                    &attestor_sets,
                )
                .map_err(|e| ScpError::Validation {
                    msg: e.to_string(),
                    code: codes::VALID_7052.to_owned(),
                })
            }
            crate::runtime::ProtocolRepoVariant::Sqlite(repo) => {
                let handle = runtime().handle().clone();
                let bridge = scp_core::trust::ProtocolRepositoryTrustBridge::new(
                    std::sync::Arc::clone(repo),
                    handle,
                );
                scp_ffi_common::trust_store::populate_and_aggregate(
                    bridge,
                    &context_id,
                    &subject_did,
                    cached_attestations,
                    &challenge_results,
                    &events,
                    merkle_root,
                    &consequence_rules,
                    &threshold_requirements,
                    &attestor_sets,
                )
                .map_err(|e| ScpError::Validation {
                    msg: e.to_string(),
                    code: codes::VALID_7052.to_owned(),
                })
            }
        }
    }

    // ===== State-touching operations — per-instance methods on `Scp` =====
    //
    // The remaining state-touching operations live on `impl Scp`, routing
    // through `&self.inner` and the inline handle-affinity check. Covers:
    //   - `identity_migrate`, `identity_create_with_agent_key`,
    //     `identity_execute_recovery`, `identity_execute_custody_migration`
    //   - `provenance_attach`
    //   - `petname_*` (8), `handle_*` (3), `scope_*` (3), `address_resolve`
    //   - `economy_budget_*` (3), `economy_antispam_*` (3)
    //   - `set_economic_policy`, `get_economic_policy`
    //   - `context_export`, `context_import`
    //   - `evaluate_invitation`
    //
    // The free-function façade that forwarded to a process-wide bridge
    // instance was deleted in Phase 4 PR 4 (#1549, ADR-048).

    /// Per-instance equivalent of the free-function `identity_migrate`.
    ///
    /// Rejects any `Identity` whose `instance_id` does not match this
    /// `SCP`'s.
    pub async fn identity_migrate(
        &self,
        identity: Arc<Identity>,
    ) -> Result<Arc<Identity>, ScpError> {
        self.inner
            .core
            .check_handle(identity.instance_id())
            .map_err(ScpError::from)?;
        let core_id = identity
            .core_id
            .as_ref()
            .ok_or_else(|| ScpError::Identity {
                msg: "identity migration requires retained crypto state — this identity \
                      was loaded without key material (use identity_create or \
                      identity_create_with_custody)"
                    .to_owned(),
                code: codes::IDENT_1009.to_owned(),
            })?;
        let core_document = identity
            .core_document
            .as_ref()
            .ok_or_else(|| ScpError::Identity {
                msg: "identity migration requires a retained DID document".to_owned(),
                code: codes::IDENT_1009.to_owned(),
            })?;

        // We need a custody provider to generate new keys.
        #[cfg(feature = "allow_in_memory_custody")]
        let in_memory = identity.in_memory_custody.as_ref();

        let old_did = identity.did.clone();
        let old_identity = core_id.clone();
        let old_document = core_document.clone();
        let custody_type = identity.custody_type.clone();
        let instance_id = identity.instance_id;

        // Pre-rotation key state. The pre-rotation handle points into the
        // cold-storage custody; revealing it must yield a public key whose
        // SHA-256 matches the committed value (spec §9.7.4.1 §6 / ADR-003
        // §4b). The custody `Arc` is preserved across migrations; only the
        // handle changes per rotation.
        let pre_rotation_handle = identity.pre_rotation_handle;
        let pre_rotation_custody = Arc::clone(&identity.pre_rotation_custody);

        #[cfg(feature = "allow_in_memory_custody")]
        let custody_arc = in_memory.map(Arc::clone);
        let callback_custody = identity.callback_custody.as_ref().map(Arc::clone);
        let bi = Arc::clone(&self.inner);

        runtime()
            .spawn(async move {
                // Determine which custody to use for key generation.
                #[cfg(feature = "allow_in_memory_custody")]
                if let Some(ref kc) = custody_arc {
                    // Spec §9.7.4.1 / §9.12 / ADR-003 §4b: the pre-rotation
                    // key whose hash equals the committed value lives in
                    // a separate `PreRotationCustody` instance from
                    // creation. Generating a fresh key here would break
                    // `verify_migration`'s SHA-256(revealed) == commitment
                    // invariant.
                    let rotated_at = scp_primitives::SystemClock.now_secs();

                    // `migrate_identity` calls `publish_document` for the old
                    // and new DID documents — both BEP44 puts require a
                    // signing function bound to the identity custody.
                    // `DidDht::new()` would surface
                    // "no signing function configured".
                    let dht = make_dht_with_signer(kc)?;
                    let scp_identity::MigrationOutcome {
                        new_identity,
                        new_document,
                        rotation_event,
                        new_pre_rotation_handle,
                    } = dht
                        .migrate_identity(
                            &old_identity,
                            &old_document,
                            &pre_rotation_handle,
                            pre_rotation_custody.as_ref(),
                            &kc.0,
                            rotated_at,
                        )
                        .await
                        .map_err(ScpError::from)?;
                    let rotation_event_json =
                        serde_json::to_string(&rotation_event).map_err(|e| ScpError::Identity {
                            msg: format!("failed to serialize rotation event: {e}"),
                            code: codes::IDENT_1004.to_owned(),
                        })?;

                    let new_did = new_identity.did.clone();
                    let has_agent = new_document.has_agent_key();
                    let verifying_key_hex =
                        kc.0.public_key(&new_identity.identity_key)
                            .await
                            .ok()
                            .map(|pk| hex::encode(pk.as_bytes()));
                    let handle = Arc::new(Identity {
                        did: new_identity.did.clone(),
                        custody_type,
                        core_id: Some(new_identity),
                        core_document: Some(new_document),
                        #[cfg(feature = "allow_in_memory_custody")]
                        in_memory_custody: custody_arc,
                        callback_custody,
                        verifying_key_hex,
                        instance_id,
                        rotation_event_json: Some(rotation_event_json),
                        pre_rotation_handle: new_pre_rotation_handle,
                        pre_rotation_custody,
                    });
                    increment_handle_count();
                    let _ = has_agent; // suppress unused warning

                    // Migrate attestation and custody registries from old DID to new DID.
                    // The attestation block runs first; when `allow_in_memory_custody` is
                    // enabled, the custody block follows and consumes `new_did`, so the
                    // attestation block must clone. When the feature is disabled, the
                    // custody block is excluded and `new_did` can be moved into attestation.
                    #[cfg(feature = "allow_in_memory_custody")]
                    let attestation_did = new_did.clone();
                    #[cfg(not(feature = "allow_in_memory_custody"))]
                    let attestation_did = new_did;
                    {
                        let registry = identity_link_attestation_registry(&bi);
                        if let Some((_, attestations)) = registry.remove(&old_did) {
                            registry.insert(attestation_did, attestations);
                        }
                    }
                    #[cfg(feature = "allow_in_memory_custody")]
                    {
                        let registry = identity_custody_registry(&bi);
                        if let Some((_, entry)) = registry.remove(&old_did) {
                            registry.insert(new_did, entry);
                        }
                    }

                    return Ok(handle);
                }

                if let Some(ref cc) = callback_custody {
                    // Spec §9.7.4.1 / §9.12: pre-rotation key lives in the
                    // separate `PreRotationCustody` since creation; reusing
                    // its handle satisfies the SHA-256(revealed) ==
                    // commitment invariant. Callback custody MUST surface
                    // the same handle on resume.
                    let rotated_at = scp_primitives::SystemClock.now_secs();

                    let dht = DidDht::new();
                    let scp_identity::MigrationOutcome {
                        new_identity,
                        new_document,
                        rotation_event,
                        new_pre_rotation_handle,
                    } = dht
                        .migrate_identity(
                            &old_identity,
                            &old_document,
                            &pre_rotation_handle,
                            pre_rotation_custody.as_ref(),
                            cc.as_ref(),
                            rotated_at,
                        )
                        .await
                        .map_err(ScpError::from)?;
                    let rotation_event_json =
                        serde_json::to_string(&rotation_event).map_err(|e| ScpError::Identity {
                            msg: format!("failed to serialize rotation event: {e}"),
                            code: codes::IDENT_1004.to_owned(),
                        })?;

                    let new_did = new_identity.did.clone();
                    let verifying_key_hex =
                        snapshot_verifying_key_hex(cc.as_ref(), &new_identity.identity_key).await;
                    let handle = Arc::new(Identity {
                        did: new_identity.did.clone(),
                        custody_type,
                        core_id: Some(new_identity),
                        core_document: Some(new_document),
                        #[cfg(feature = "allow_in_memory_custody")]
                        in_memory_custody: None,
                        callback_custody: Some(Arc::clone(cc)),
                        verifying_key_hex,
                        instance_id,
                        rotation_event_json: Some(rotation_event_json),
                        pre_rotation_handle: new_pre_rotation_handle,
                        pre_rotation_custody,
                    });
                    increment_handle_count();

                    // Migrate attestation and custody registries from old DID to new DID.
                    // The attestation block runs first; when `allow_in_memory_custody` is
                    // enabled, the custody block follows and consumes `new_did`, so the
                    // attestation block must clone. When the feature is disabled, the
                    // custody block is excluded and `new_did` can be moved into attestation.
                    #[cfg(feature = "allow_in_memory_custody")]
                    let attestation_did = new_did.clone();
                    #[cfg(not(feature = "allow_in_memory_custody"))]
                    let attestation_did = new_did;
                    {
                        let registry = identity_link_attestation_registry(&bi);
                        if let Some((_, attestations)) = registry.remove(&old_did) {
                            registry.insert(attestation_did, attestations);
                        }
                    }
                    #[cfg(feature = "allow_in_memory_custody")]
                    {
                        let registry = identity_custody_registry(&bi);
                        if let Some((_, entry)) = registry.remove(&old_did) {
                            registry.insert(new_did, entry);
                        }
                    }

                    return Ok(handle);
                }

                Err(ScpError::Identity {
                    msg: "identity migration requires a retained custody provider \
                              (in-memory or callback)"
                        .to_owned(),
                    code: codes::IDENT_1009.to_owned(),
                })
            })
            .await
            .map_err(|e| ScpError::Identity {
                msg: format!("tokio task join error during identity migration: {e}"),
                code: codes::IDENT_1007.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `identity_create_with_agent_key`.
    ///
    /// Creates a new SCP identity with an agent signing key. Routes through
    /// `&*self.inner` so the returned `Identity`'s `instance_id` is stamped
    /// against this `SCP`.
    pub async fn identity_create_with_agent_key(
        &self,
        custody: String,
    ) -> Result<Arc<Identity>, ScpError> {
        let custody_method = parse_custody_method(&custody)?;
        let bi = Arc::clone(&self.inner);

        runtime()
            .spawn(async move {
                match custody_method {
                    CustodyMethod::InMemory => {
                        #[cfg(not(feature = "allow_in_memory_custody"))]
                        {
                            let _ = &bi;
                            Err(ScpError::Identity {
                                msg: "\"in_memory\" custody is not available in this build \
                                      — enable the \"allow_in_memory_custody\" feature for \
                                      dev/desktop use. Production mobile builds must use \
                                      \"platform\" custody (Secure Enclave / Android Keystore)."
                                    .to_owned(),
                                code: codes::IDENT_1008.to_owned(),
                            })
                        }

                        #[cfg(feature = "allow_in_memory_custody")]
                        {
                            let key_custody =
                                Arc::new(OpaqueInMemoryKeyCustody(InMemoryKeyCustody::new()));
                            let dht = DidDht::new();
                            // Fresh per-identity pre-rotation custody (ADR-003 §4b).
                            let pre_rotation_custody =
                                Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
                            let (identity, document, pre_rotation_handle) = dht
                                .create_with_agent_key(
                                    &key_custody.0,
                                    pre_rotation_custody.as_ref(),
                                )
                                .await
                                .map_err(ScpError::from)?;

                            // Snapshot the #0 verifying key for ADR-046 parity.
                            let verifying_key_hex =
                                snapshot_verifying_key_hex(&key_custody.0, &identity.identity_key)
                                    .await;

                            // Initialize the production DID resolver for UCAN
                            // validation on this instance.
                            ensure_did_resolver_initialized_on(
                                &bi,
                                tokio::runtime::Handle::current(),
                            )?;

                            // Register the freshly created in-memory identity
                            // in the per-instance custody registry, keyed by DID,
                            // so `identity_remove_if_present` reports presence —
                            // matching the NAPI bridge whose identity creation
                            // paths register a bundled entry. Shares the
                            // entry/cap logic with the link-attestation path.
                            // Done before `identity` is moved into the handle so
                            // the DID and active signing key are still available.
                            register_identity_custody(
                                &bi,
                                &identity.did,
                                &key_custody,
                                identity.active_signing_key,
                            )?;

                            let handle = Arc::new(Identity {
                                did: identity.did.clone(),
                                custody_type: CustodyMethod::InMemory,
                                core_id: Some(identity),
                                core_document: Some(document),
                                in_memory_custody: Some(key_custody),
                                callback_custody: None,
                                verifying_key_hex,
                                instance_id: bi.core.instance_id(),
                                rotation_event_json: None,
                                pre_rotation_handle,
                                pre_rotation_custody,
                            });
                            increment_handle_count();
                            Ok(handle)
                        }
                    }
                    CustodyMethod::Platform | CustodyMethod::Software => Err(ScpError::Identity {
                        msg: format!(
                            "custody type {custody:?} requires a KeyCustodyProvider — \
                                 use identity_create_with_custody() + add_agent_key() to create \
                                 an identity with an agent key using platform custody"
                        ),
                        code: codes::IDENT_1003.to_owned(),
                    }),
                    CustodyMethod::External => Err(ScpError::Identity {
                        msg: "internal: CustodyMethod::External cannot be used with \
                                      identity_create_with_agent_key — use identity_load for \
                                      external DID handles"
                            .to_owned(),
                        code: codes::IDENT_1005.to_owned(),
                    }),
                }
            })
            .await
            .map_err(|e| ScpError::Identity {
                msg: format!("tokio task join error during identity creation with agent key: {e}"),
                code: codes::IDENT_1007.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `identity_execute_recovery`.
    ///
    /// Pure orchestration — takes no handles. Routes through `&self.inner`
    /// only to preserve API uniformity; the underlying recovery backend is
    /// a local stub pending SDK-layer wiring.
    pub fn identity_execute_recovery(
        &self,
        did: String,
        tier: String,
        context_ids: Vec<String>,
    ) -> Result<String, ScpError> {
        use std::collections::HashSet;

        use scp_core::identity::recovery::{
            CompromiseRecoveryOrchestrator, CompromiseTier, KeyRotationOutcome, PskRotationParams,
            RecoveryBackend, RecoveryStepError, active_key_rotation_outcome,
            agent_key_rotation_outcome,
        };
        use scp_identity::DID;

        validate_did(&did)?;
        let did_val = DID::from(did.as_str());

        let compromise_tier = match tier.as_str() {
            "agent" => CompromiseTier::Agent,
            "active_signing" => CompromiseTier::ActiveSigning,
            "identity_key" => CompromiseTier::IdentityKey,
            other => {
                return Err(ScpError::Identity {
                    msg: format!(
                        "invalid compromise tier: {other}; expected 'agent', 'active_signing', or 'identity_key'"
                    ),
                    code: codes::IDENT_1020.to_owned(),
                });
            }
        };

        let now_ms = scp_primitives::SystemClock.now_millis();

        let key_rotation = match compromise_tier {
            CompromiseTier::Agent => agent_key_rotation_outcome(&did_val, now_ms),
            CompromiseTier::ActiveSigning => active_key_rotation_outcome(&did_val, now_ms),
            CompromiseTier::IdentityKey => {
                scp_core::identity::recovery::identity_key_rotation_outcome(
                    &did_val,
                    did_val.clone(),
                    now_ms,
                )
            }
        };

        struct UniffiRecoveryBackend;
        impl RecoveryBackend for UniffiRecoveryBackend {
            fn mls_update(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            fn revoke_ucans(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            fn rotate_key_packages(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            fn notify_contacts(
                &self,
                _did: &DID,
                _tier: CompromiseTier,
                _key_rotation: &KeyRotationOutcome,
                _contacts: &HashSet<DID>,
            ) -> bool {
                true
            }
            fn rotate_psk(&self, _params: &PskRotationParams) -> bool {
                true
            }
        }

        let orchestrator = CompromiseRecoveryOrchestrator::new(did_val, context_ids);
        let contacts = HashSet::new();
        let backend = UniffiRecoveryBackend;

        let rt = crate::runtime();

        let result = rt
            .block_on(orchestrator.execute_recovery(
                compromise_tier,
                &key_rotation,
                &contacts,
                None,
                &backend,
                &scp_primitives::SystemClock,
            ))
            .map_err(|e| ScpError::Identity {
                msg: format!("recovery failed: {e}"),
                code: codes::IDENT_1022.to_owned(),
            })?;

        serde_json::to_string(&result).map_err(|e| ScpError::Identity {
            msg: format!("failed to serialize recovery result: {e}"),
            code: codes::IDENT_1023.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `identity_execute_custody_migration`.
    pub fn identity_execute_custody_migration(
        &self,
        did: String,
        target: String,
        context_ids: Vec<String>,
    ) -> Result<String, ScpError> {
        use scp_core::identity::custody_migration::{
            CustodyMigrationBackend, CustodyMigrationOrchestrator, CustodyMigrationRequest,
            CustodyMigrationTarget,
        };
        use scp_identity::DID;

        validate_did(&did)?;
        let did_val = DID::from(did.as_str());

        let migration_target = match target.as_str() {
            "platform_managed" => CustodyMigrationTarget::PlatformManaged,
            "hardware" => CustodyMigrationTarget::Hardware,
            "software" => CustodyMigrationTarget::Software,
            "in_memory" => CustodyMigrationTarget::InMemory,
            other => {
                return Err(ScpError::Identity {
                    msg: format!(
                        "invalid custody migration target: {other}; expected 'platform_managed', 'hardware', 'software', or 'in_memory'"
                    ),
                    code: codes::IDENT_1024.to_owned(),
                });
            }
        };

        // Error-returning backend — custody migration requires a real backend
        // provided via the SDK layer. This placeholder ensures callers get an
        // actionable error instead of silently succeeding with fake keys.
        struct NotConfiguredMigrationBackend;
        impl CustodyMigrationBackend for NotConfiguredMigrationBackend {
            fn generate_key(&self, _target: CustodyMigrationTarget) -> Result<Vec<u8>, String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
            fn authorize(&self, _request: &CustodyMigrationRequest) -> Result<(), String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
            fn rotate_did_document(
                &self,
                _did: &DID,
                _request: &CustodyMigrationRequest,
                _context_ids: &[String],
            ) -> Result<(Vec<String>, Vec<String>), String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
            fn reissue_credentials(
                &self,
                _did: &DID,
                _request: &CustodyMigrationRequest,
            ) -> Result<(), String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
            fn destroy_old_key(&self, _did: &DID) -> Result<(), String> {
                Err(
                    "custody migration backend not configured — provide a real backend via SDK layer"
                        .to_owned(),
                )
            }
        }

        let orchestrator =
            CustodyMigrationOrchestrator::new(did_val, migration_target, context_ids);
        let backend = NotConfiguredMigrationBackend;

        let rt = crate::runtime();

        let result = rt
            .block_on(orchestrator.execute(&backend, &scp_primitives::SystemClock))
            .map_err(|e| ScpError::Identity {
                msg: format!("custody migration failed: {e}"),
                code: codes::IDENT_1025.to_owned(),
            })?;

        serde_json::to_string(&result).map_err(|e| ScpError::Identity {
            msg: format!("failed to serialize custody migration result: {e}"),
            code: codes::IDENT_1026.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `provenance_attach`.
    ///
    /// Appends `ProvenanceAttached` / `ProvenanceReceived` events to the
    /// source and target context event logs on this instance.
    #[allow(clippy::too_many_arguments)]
    pub fn provenance_attach(
        &self,
        source_context_id: String,
        source_type: String,
        memory_scope_str: String,
        members: Vec<String>,
        target_context_id: String,
        actor_did: String,
        existing_chain_depth: Option<u8>,
    ) -> Result<String, ScpError> {
        let st = match source_type.as_str() {
            "persistent" => scp_core::provenance::SourceType::Persistent,
            "ephemeral" => scp_core::provenance::SourceType::Ephemeral,
            "summary" => scp_core::provenance::SourceType::Summary,
            other => {
                return Err(ScpError::Validation {
                    msg: format!("invalid source_type '{other}'"),
                    code: codes::VALID_7040.to_owned(),
                });
            }
        };
        let ms = match memory_scope_str.as_str() {
            "full" => scp_core::context::MemoryScope::Full,
            "summary" => scp_core::context::MemoryScope::Summary,
            "ephemeral" => scp_core::context::MemoryScope::Ephemeral,
            other => {
                return Err(ScpError::Validation {
                    msg: format!("invalid memory_scope '{other}'"),
                    code: codes::VALID_7041.to_owned(),
                });
            }
        };

        let source_info = scp_core::provenance::attach::SourceContextInfo {
            context_id: source_context_id.clone(),
            source_type: st,
            memory_scope: ms,
            members: members.into_iter().map(scp_identity::DID::from).collect(),
            discovery_method: scp_core::provenance::DiscoveryMethod::OutOfBand,
            data_age: std::time::Duration::from_secs(0),
            purpose: None,
            counterparty_policy: scp_core::provenance::CounterpartyPolicy::default(),
        };

        let existing_prov =
            existing_chain_depth.map(|depth| scp_core::provenance::DataProvenance {
                source_context: String::new(),
                source_type: scp_core::provenance::SourceType::Persistent,
                counterparties: vec![],
                purpose: None,
                discovery_method: scp_core::provenance::DiscoveryMethod::OutOfBand,
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

        // Compute provenance hash: SHA-256 of JSON-serialized provenance record.
        let prov_json_bytes = serde_json::to_vec(&prov).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize provenance for hashing: {e}"),
            code: codes::VALID_7053.to_owned(),
        })?;
        let prov_hash: [u8; 32] = sha2::Sha256::digest(&prov_json_bytes).into();

        // Record ProvenanceAttached in the source context event log.
        if let Err(e) = uniffi_append_provenance_event_on(
            &self.inner,
            &source_context_id,
            &actor_did,
            scp_event_log::EventType::ProvenanceAttached,
            &prov_hash,
        ) {
            tracing::warn!(
                context = %source_context_id,
                error = %e,
                "failed to append ProvenanceAttached event to source context event log"
            );
        }

        // Record ProvenanceReceived in the target context event log.
        if let Err(e) = uniffi_append_provenance_event_on(
            &self.inner,
            &target_context_id,
            &actor_did,
            scp_event_log::EventType::ProvenanceReceived,
            &prov_hash,
        ) {
            tracing::warn!(
                context = %target_context_id,
                error = %e,
                "failed to append ProvenanceReceived event to target context event log"
            );
        }

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
            msg: format!("failed to serialize provenance: {e}"),
            code: codes::VALID_7042.to_owned(),
        })
    }

    // ----- Petname methods -----

    /// Per-instance equivalent of the free-function `petname_set`.
    pub fn petname_set(
        &self,
        owner_did: String,
        target_did: String,
        name: String,
    ) -> Result<(), ScpError> {
        validate_did(&owner_did)?;
        if target_did.is_empty() {
            return Err(ScpError::Validation {
                msg: "target_did must not be empty".to_owned(),
                code: codes::VALID_7111.to_owned(),
            });
        }
        let mut guard =
            self.inner
                .core
                .petname_maps()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("petname lock poisoned: {e}"),
                    code: codes::VALID_7112.to_owned(),
                })?;
        let map = guard.entry(owner_did).or_default();
        map.set_petname(scp_identity::DID::from(target_did.as_str()), name);
        Ok(())
    }

    /// Per-instance equivalent of the free-function `petname_remove`.
    pub fn petname_remove(&self, owner_did: String, target_did: String) -> Result<(), ScpError> {
        validate_did(&owner_did)?;
        let mut guard =
            self.inner
                .core
                .petname_maps()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("petname lock poisoned: {e}"),
                    code: codes::VALID_7112.to_owned(),
                })?;
        if let Some(map) = guard.get_mut(&owner_did) {
            map.remove_petname(&scp_identity::DID::from(target_did.as_str()));
        }
        Ok(())
    }

    /// Per-instance equivalent of the free-function `petname_set_context`.
    pub fn petname_set_context(
        &self,
        owner_did: String,
        context_id: String,
        name: String,
    ) -> Result<(), ScpError> {
        validate_did(&owner_did)?;
        if context_id.is_empty() {
            return Err(ScpError::Validation {
                msg: "context_id must not be empty".to_owned(),
                code: codes::VALID_7113.to_owned(),
            });
        }
        let mut guard =
            self.inner
                .core
                .petname_maps()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("petname lock poisoned: {e}"),
                    code: codes::VALID_7112.to_owned(),
                })?;
        let map = guard.entry(owner_did).or_default();
        map.set_context_petname(context_id, name);
        Ok(())
    }

    /// Per-instance equivalent of the free-function `petname_remove_context`.
    pub fn petname_remove_context(
        &self,
        owner_did: String,
        context_id: String,
    ) -> Result<(), ScpError> {
        validate_did(&owner_did)?;
        let mut guard =
            self.inner
                .core
                .petname_maps()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("petname lock poisoned: {e}"),
                    code: codes::VALID_7112.to_owned(),
                })?;
        if let Some(map) = guard.get_mut(&owner_did) {
            map.remove_context_petname(&context_id);
        }
        Ok(())
    }

    /// Per-instance equivalent of the free-function `petname_resolve_did`.
    pub fn petname_resolve_did(&self, owner_did: String, name: String) -> Result<String, ScpError> {
        validate_did(&owner_did)?;
        let guard = self
            .inner
            .core
            .petname_maps()
            .lock()
            .map_err(|e| ScpError::Validation {
                msg: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
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
            msg: format!("failed to serialize petname resolve result: {e}"),
            code: codes::VALID_7114.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `petname_resolve_context`.
    pub fn petname_resolve_context(
        &self,
        owner_did: String,
        name: String,
    ) -> Result<String, ScpError> {
        validate_did(&owner_did)?;
        let guard = self
            .inner
            .core
            .petname_maps()
            .lock()
            .map_err(|e| ScpError::Validation {
                msg: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })?;
        let ids: Vec<String> = guard
            .get(&owner_did)
            .map(|map| map.resolve_context(&name))
            .unwrap_or_default();
        serde_json::to_string(&ids).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize petname resolve result: {e}"),
            code: codes::VALID_7114.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `petname_get_for_did`.
    pub fn petname_get_for_did(
        &self,
        owner_did: String,
        target_did: String,
    ) -> Result<Option<String>, ScpError> {
        validate_did(&owner_did)?;
        let guard = self
            .inner
            .core
            .petname_maps()
            .lock()
            .map_err(|e| ScpError::Validation {
                msg: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })?;
        Ok(guard.get(&owner_did).and_then(|map| {
            map.petname_for_did(&scp_identity::DID::from(target_did.as_str()))
                .map(str::to_owned)
        }))
    }

    /// Per-instance equivalent of the free-function `petname_get_for_context`.
    pub fn petname_get_for_context(
        &self,
        owner_did: String,
        context_id: String,
    ) -> Result<Option<String>, ScpError> {
        validate_did(&owner_did)?;
        let guard = self
            .inner
            .core
            .petname_maps()
            .lock()
            .map_err(|e| ScpError::Validation {
                msg: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })?;
        Ok(guard
            .get(&owner_did)
            .and_then(|map| map.petname_for_context(&context_id).map(str::to_owned)))
    }

    /// Applies a serialized petname event to the owner's petname map.
    ///
    /// The event JSON must match the `PetnameEvent` serde format (§22.9.2).
    /// This is the event-driven mutation path matching `PetnameMap::apply_event`.
    pub fn petname_apply_event(
        &self,
        owner_did: String,
        event_json: String,
    ) -> Result<(), ScpError> {
        use scp_core::discovery::petnames::PetnameEvent;

        validate_did(&owner_did)?;
        let event: PetnameEvent =
            serde_json::from_str(&event_json).map_err(|e| ScpError::Validation {
                msg: format!("invalid petname event JSON: {e}"),
                code: codes::VALID_7115.to_owned(),
            })?;
        let mut guard =
            self.inner
                .core
                .petname_maps()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("petname lock poisoned: {e}"),
                    code: codes::VALID_7112.to_owned(),
                })?;
        let map = guard.entry(owner_did).or_default();
        map.apply_event(&event);
        Ok(())
    }

    /// Returns the number of DID petnames for an owner.
    ///
    /// Mirrors `PetnameMap::did_petname_count`.
    pub fn petname_did_count(&self, owner_did: String) -> Result<u32, ScpError> {
        validate_did(&owner_did)?;
        let guard = self
            .inner
            .core
            .petname_maps()
            .lock()
            .map_err(|e| ScpError::Validation {
                msg: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })?;
        let count = guard.get(&owner_did).map_or(
            0,
            scp_core::discovery::petnames::PetnameMap::did_petname_count,
        );
        u32::try_from(count).map_err(|_| ScpError::Validation {
            msg: "petname count exceeds u32::MAX".to_owned(),
            code: codes::VALID_7116.to_owned(),
        })
    }

    /// Returns the number of context petnames for an owner.
    ///
    /// Mirrors `PetnameMap::context_petname_count`.
    pub fn petname_context_count(&self, owner_did: String) -> Result<u32, ScpError> {
        validate_did(&owner_did)?;
        let guard = self
            .inner
            .core
            .petname_maps()
            .lock()
            .map_err(|e| ScpError::Validation {
                msg: format!("petname lock poisoned: {e}"),
                code: codes::VALID_7112.to_owned(),
            })?;
        let count = guard.get(&owner_did).map_or(
            0,
            scp_core::discovery::petnames::PetnameMap::context_petname_count,
        );
        u32::try_from(count).map_err(|_| ScpError::Validation {
            msg: "petname count exceeds u32::MAX".to_owned(),
            code: codes::VALID_7116.to_owned(),
        })
    }

    // ----- Handle registry methods -----

    /// Per-instance equivalent of the free-function `handle_register`.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_register(
        &self,
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
        let mut guard =
            self.inner
                .core
                .handle_registries()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("handle registry lock poisoned: {e}"),
                    code: codes::VALID_7120.to_owned(),
                })?;
        let registry = guard
            .entry(discovery_context_id.clone())
            .or_insert_with(|| scp_core::discovery::HandleRegistry::new(discovery_context_id));
        let result = registry.register(
            &params,
            &scp_identity::DID::from(registrant_did.as_str()),
            &scp_primitives::SystemClock,
        );
        serde_json::to_string(&result).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize handle register result: {e}"),
            code: codes::VALID_7122.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `handle_lookup`.
    pub fn handle_lookup(
        &self,
        discovery_context_id: String,
        handle: String,
        type_filter: Option<String>,
    ) -> Result<String, ScpError> {
        let filter = match type_filter.as_deref() {
            Some("identity") => Some(scp_core::discovery::HandleTypeFilter::Identity),
            Some("context") => Some(scp_core::discovery::HandleTypeFilter::Context),
            Some(other) => {
                return Err(ScpError::Validation {
                    msg: format!("invalid type_filter '{other}': expected 'identity' or 'context'"),
                    code: codes::VALID_7123.to_owned(),
                });
            }
            None => None,
        };
        let guard =
            self.inner
                .core
                .handle_registries()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("handle registry lock poisoned: {e}"),
                    code: codes::VALID_7120.to_owned(),
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
            msg: format!("failed to serialize handle lookup result: {e}"),
            code: codes::VALID_7124.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `handle_deregister`.
    pub fn handle_deregister(
        &self,
        discovery_context_id: String,
        handle: String,
        did: String,
    ) -> Result<String, ScpError> {
        let mut guard =
            self.inner
                .core
                .handle_registries()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("handle registry lock poisoned: {e}"),
                    code: codes::VALID_7120.to_owned(),
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
            msg: format!("failed to serialize handle deregister result: {e}"),
            code: codes::VALID_7125.to_owned(),
        })
    }

    // ----- Scope registry methods -----

    /// Per-instance equivalent of the free-function `scope_register`.
    #[allow(clippy::too_many_arguments)]
    pub fn scope_register(
        &self,
        scope_context_id: String,
        name: String,
        target_context_id: String,
        relay_urls: Vec<String>,
        registrant_did: String,
        description: Option<String>,
        tags: Option<Vec<String>>,
    ) -> Result<String, ScpError> {
        // Validate inputs at the FFI boundary (defense-in-depth)
        validate_context_id(&scope_context_id)?;
        validate_context_id(&target_context_id)?;
        validate_did(&registrant_did)?;

        // Validate relay URLs at the FFI boundary
        for url in &relay_urls {
            scp_ffi_common::validate::validate_relay_url(url).map_err(|e| {
                ScpError::Validation {
                    msg: e.to_string(),
                    code: codes::VALID_7135.to_owned(),
                }
            })?;
        }

        let params = scp_core::discovery::ScopeRegisterParams {
            name,
            target: scp_core::discovery::ScopeTarget {
                context_id: target_context_id,
                relay_urls,
            },
            metadata: if description.is_some() || tags.is_some() {
                Some(scp_core::discovery::ScopeMetadata { description, tags })
            } else {
                None
            },
        };

        let mut guard =
            self.inner
                .core
                .scope_registries()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("scope registry lock poisoned: {e}"),
                    code: codes::VALID_7130.to_owned(),
                })?;

        let registry = guard
            .entry(scope_context_id.clone())
            .or_insert_with(|| scp_core::discovery::ScopeRegistry::new(scope_context_id));

        let result = registry
            .register(
                &params,
                &scp_identity::DID::from(registrant_did.as_str()),
                &scp_primitives::SystemClock,
            )
            .map_err(|e| ScpError::Validation {
                msg: format!("scope registration failed: {e}"),
                code: codes::VALID_7131.to_owned(),
            })?;

        serde_json::to_string(&result).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize scope register result: {e}"),
            code: codes::VALID_7132.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `scope_lookup`.
    pub fn scope_lookup(&self, scope_context_id: String, name: String) -> Result<String, ScpError> {
        validate_context_id(&scope_context_id)?;

        let guard =
            self.inner
                .core
                .scope_registries()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("scope registry lock poisoned: {e}"),
                    code: codes::VALID_7130.to_owned(),
                })?;

        let result = match guard.get(&scope_context_id) {
            Some(registry) => registry
                .lookup(&scp_core::discovery::ScopeLookupParams { name })
                .map_err(|e| ScpError::Validation {
                    msg: format!("scope lookup failed: {e}"),
                    code: codes::VALID_7133.to_owned(),
                })?,
            None => scp_core::discovery::ScopeLookupResult {
                results: Vec::new(),
            },
        };

        serde_json::to_string(&result).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize scope lookup result: {e}"),
            code: codes::VALID_7133.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `scope_deregister`.
    pub fn scope_deregister(
        &self,
        scope_context_id: String,
        name: String,
        did: String,
    ) -> Result<String, ScpError> {
        validate_context_id(&scope_context_id)?;
        validate_did(&did)?;

        let mut guard =
            self.inner
                .core
                .scope_registries()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("scope registry lock poisoned: {e}"),
                    code: codes::VALID_7130.to_owned(),
                })?;

        let result = match guard.get_mut(&scope_context_id) {
            Some(registry) => registry
                .deregister(&scp_core::discovery::ScopeDeregisterParams {
                    name,
                    did: scp_identity::DID::from(did.as_str()),
                })
                .map_err(|e| ScpError::Validation {
                    msg: format!("scope deregister failed: {e}"),
                    code: codes::VALID_7134.to_owned(),
                })?,
            None => scp_core::discovery::ScopeDeregisterResult { removed: false },
        };

        serde_json::to_string(&result).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize scope deregister result: {e}"),
            code: codes::VALID_7134.to_owned(),
        })
    }

    // ----- Address resolution -----

    /// Per-instance equivalent of the free-function `address_resolve`.
    pub fn address_resolve(
        &self,
        owner_did: String,
        address: String,
        known_contexts_json: Option<String>,
    ) -> Result<String, ScpError> {
        if owner_did.is_empty() {
            return Err(ScpError::Validation {
                msg: "owner_did must not be empty".to_owned(),
                code: codes::VALID_7110.to_owned(),
            });
        }

        let bi = &*self.inner;

        let mut known_contexts: std::collections::HashMap<String, String> =
            if let Some(ref json) = known_contexts_json {
                serde_json::from_str(json).map_err(|e| ScpError::Validation {
                    msg: format!("invalid known_contexts_json: {e}"),
                    code: codes::VALID_7090.to_owned(),
                })?
            } else {
                let guard =
                    bi.core
                        .handle_registries()
                        .lock()
                        .map_err(|e| ScpError::Validation {
                            msg: format!("handle registry lock poisoned: {e}"),
                            code: codes::VALID_7120.to_owned(),
                        })?;
                guard.keys().map(|k| (k.clone(), k.clone())).collect()
            };

        // Merge scope registry contexts for two-hop resolution (§22.3.5).
        let scope_contexts = petname_helpers::known_contexts_from_scope_registries(&bi.core);
        for (name, ctx_id) in scope_contexts {
            known_contexts.entry(name).or_insert(ctx_id);
        }

        let known_domains: Vec<&str> = Vec::new();
        let petname_map = {
            let guard = bi
                .core
                .petname_maps()
                .lock()
                .map_err(|e| ScpError::Validation {
                    msg: format!("petname lock poisoned: {e}"),
                    code: codes::VALID_7112.to_owned(),
                })?;
            guard.get(&owner_did).cloned().unwrap_or_default()
        };

        let handle = tokio::runtime::Handle::current();
        let results = tokio::task::block_in_place(|| {
            handle.block_on(async {
                let mut resolver = scp_core::discovery::AddressResolver::new();
                let querier = petname_helpers::LocalHandleQuerier::new(&bi.core);
                resolver
                    .resolve(
                        &address,
                        &petname_map,
                        &querier,
                        &known_contexts,
                        &known_domains,
                        &scp_primitives::SystemClock,
                    )
                    .await
                    .map_err(|e| ScpError::Validation {
                        msg: format!("address resolution failed: {e}"),
                        code: codes::VALID_7091.to_owned(),
                    })
            })
        })?;

        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(petname_helpers::address_resolution_to_json)
            .collect();
        serde_json::to_string(&json_results).map_err(|e| ScpError::Validation {
            msg: format!("failed to serialize address resolution results: {e}"),
            code: codes::VALID_7092.to_owned(),
        })
    }

    // ----- Economy budget methods -----

    /// Per-instance equivalent of the free-function `economy_budget_remaining`.
    pub fn economy_budget_remaining(
        &self,
        context_id: String,
        did: String,
    ) -> Result<u64, ScpError> {
        validate_did(&did)?;
        let member_did = scp_identity::DID::from(did.as_str());
        let remaining = self
            .inner
            .core
            .with_economy_budget(&context_id, |tracker| tracker.remaining(&member_did));
        Ok(remaining.value())
    }

    /// Per-instance equivalent of the free-function `economy_budget_grant`.
    pub fn economy_budget_grant(
        &self,
        context_id: String,
        did: String,
        amount: u64,
    ) -> Result<(), ScpError> {
        validate_did(&did)?;
        let member_did = scp_identity::DID::from(did.as_str());
        self.inner
            .core
            .with_economy_budget_mut(&context_id, |tracker| {
                tracker.grant(&member_did, scp_core::economy::Amount::new(amount));
            });
        Ok(())
    }

    /// Per-instance equivalent of the free-function `economy_budget_record_spend`.
    pub fn economy_budget_record_spend(
        &self,
        context_id: String,
        did: String,
        amount: u64,
    ) -> Result<(), ScpError> {
        validate_did(&did)?;
        let member_did = scp_identity::DID::from(did.as_str());
        self.inner
            .core
            .with_economy_budget_mut(&context_id, |tracker| {
                tracker
                    .record_spend(&member_did, scp_core::economy::Amount::new(amount))
                    .map_err(|e| ScpError::Validation {
                        msg: format!("{e}"),
                        code: codes::VALID_7052.to_owned(),
                    })
            })
    }

    // ----- Economy antispam methods -----

    /// Per-instance equivalent of the free-function `economy_antispam_record`.
    pub fn economy_antispam_record(
        &self,
        context_id: String,
        sender_did: String,
        timestamp: u64,
    ) -> Result<(), ScpError> {
        validate_did(&sender_did)?;
        let did = scp_identity::DID::from(sender_did.as_str());
        self.inner
            .core
            .with_economy_antispam(&context_id, |tracker| {
                tracker.record_message(&did, timestamp);
            });
        Ok(())
    }

    /// Per-instance equivalent of the free-function `economy_antispam_velocity`.
    pub fn economy_antispam_velocity(
        &self,
        context_id: String,
        sender_did: String,
        now: u64,
    ) -> Result<u64, ScpError> {
        validate_did(&sender_did)?;
        let did = scp_identity::DID::from(sender_did.as_str());
        let velocity = self
            .inner
            .core
            .with_economy_antispam(&context_id, |tracker| tracker.get_velocity(&did, now));
        Ok(velocity)
    }

    /// Per-instance equivalent of the free-function `economy_antispam_escalated_cost`.
    #[allow(clippy::too_many_arguments)]
    pub fn economy_antispam_escalated_cost(
        &self,
        context_id: String,
        sender_did: String,
        now: u64,
        base_cost: u64,
        thresholds_json: String,
        floor: Option<u64>,
        cap: Option<u64>,
    ) -> Result<u64, ScpError> {
        validate_did(&sender_did)?;
        let thresholds: Vec<(u64, u64)> =
            serde_json::from_str(&thresholds_json).map_err(|e| ScpError::Validation {
                msg: format!("invalid thresholds JSON: {e}"),
                code: codes::VALID_7050.to_owned(),
            })?;

        let config = scp_core::economy::EscalationConfig {
            thresholds: thresholds
                .into_iter()
                .map(|(vel, cost)| scp_core::economy::EscalationThreshold {
                    velocity_threshold: vel,
                    additional_cost: scp_core::economy::Amount::new(cost),
                })
                .collect(),
        };

        let did = scp_identity::DID::from(sender_did.as_str());
        let cost = self
            .inner
            .core
            .with_economy_antispam(&context_id, |tracker| {
                tracker.compute_escalated_cost(
                    &did,
                    now,
                    scp_core::economy::Amount::new(base_cost),
                    &config,
                    floor.map(scp_core::economy::Amount::new),
                    cap.map(scp_core::economy::Amount::new),
                )
            });
        Ok(cost.value())
    }

    /// Per-instance equivalent of the free-function `economy_verify_payment_receipts`.
    ///
    /// Deserializes a JSON array of [`scp_core::economy::PaymentReceipt`] and
    /// dispatches an [`EconomyCommand::VerifyPaymentReceipts`] to the
    /// supervisor, returning a JSON `{"all_valid": <bool>, "results": [...]}`
    /// document with one entry per receipt. Mirrors the `PyO3` reference bridge
    /// exactly. Maximum 10,000 receipts per call.
    ///
    /// `all_valid` is `true` iff every entry both reached the adapter (`ok ==
    /// true`) and the adapter reported the receipt valid (`result.valid ==
    /// true`); it is vacuously `true` for an empty batch. Each `results` entry
    /// is either `{"receipt_id": <hex>, "ok": true, "valid": <bool>, "result":
    /// <structured VerificationResult>}` on success or `{"ok": false, "error":
    /// "..."}` on failure. `ok` means the adapter *responded* — NOT that the
    /// payment is valid; callers scanning for failures must inspect
    /// `valid`/`all_valid`.
    pub async fn economy_verify_payment_receipts(
        &self,
        receipts_json: String,
    ) -> Result<String, ScpError> {
        // Validate input at the FFI boundary before touching supervisor state,
        // so a malformed payload fails fast with a `Validation` error.
        let receipts: Vec<scp_core::economy::PaymentReceipt> = serde_json::from_str(&receipts_json)
            .map_err(|e| ScpError::Validation {
                msg: format!("invalid receipts JSON: {e}"),
                code: codes::VALID_7050.to_owned(),
            })?;

        // Bound the per-call batch before dispatch: each receipt fans out to a
        // serial payment-adapter verification round-trip, so an unbounded batch
        // is a denial-of-service vector. See `MAX_RECEIPT_BATCH`.
        if receipts.len() > scp_core::economy::MAX_RECEIPT_BATCH {
            return Err(ScpError::Validation {
                msg: format!(
                    "receipt batch too large: {} (max {})",
                    receipts.len(),
                    scp_core::economy::MAX_RECEIPT_BATCH
                ),
                code: codes::VALID_7050.to_owned(),
            });
        }

        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                use scp_core::context::actor::commands::EconomyCommand;

                let sup = bi.context_manager_or_error()?;
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = EconomyCommand::VerifyPaymentReceipts {
                    receipts: Box::new(receipts),
                    reply: tx,
                };
                sup.dispatch_economy_command(cmd)
                    .await
                    .map_err(ScpError::from)?;
                let results = rx.await.map_err(|e| ScpError::Context {
                    msg: format!("verify_payment_receipts shim reply dropped: {e}"),
                    code: codes::ECON_12091.to_owned(),
                })?;

                // Serialize via the single canonical helper shared by all
                // bridges, so the JSON contract (string currency, numeric
                // amount, `ok` vs `valid`/`all_valid` semantics) cannot drift
                // across PyO3, napi, and UniFFI. See
                // `scp_runtime::economy::receipt::verification_results_to_json`.
                Ok(scp_core::economy::verification_results_to_json(results))
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during verify_payment_receipts: {e}"),
                code: codes::ECON_12091.to_owned(),
            })?
    }

    // ----- Economic policy methods -----

    /// Per-instance equivalent of the free-function `set_economic_policy`.
    ///
    /// Economic policy changes must go through governance — this method
    /// always returns an error to enforce that invariant.
    #[allow(clippy::needless_pass_by_value)] // UniFFI owned parameters
    pub fn set_economic_policy(
        &self,
        handle: Arc<ContextHandle>,
        policy_json: String,
    ) -> Result<(), ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let _ = (handle, policy_json);
        Err(ScpError::Permission {
            msg: "economic policy changes must go through governance \
                  (propose SetEconomicPolicy action). Direct mutation is \
                  not permitted — see spec §19.3"
                .to_owned(),
            code: codes::CTX_2013.to_owned(),
        })
    }

    /// Per-instance equivalent of the free-function `get_economic_policy`.
    pub fn get_economic_policy(
        &self,
        handle: Arc<ContextHandle>,
    ) -> Result<Option<String>, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let guard = handle
            .economic_policy
            .lock()
            .map_err(|_| ScpError::Context {
                msg: "economic_policy lock is poisoned".to_owned(),
                code: codes::CTX_2012.to_owned(),
            })?;
        Ok(guard.clone())
    }

    // ----- Context export/import methods -----

    /// Per-instance equivalent of the free-function `context_export`.
    pub async fn context_export(&self, handle: Arc<ContextHandle>) -> Result<Vec<u8>, ScpError> {
        self.inner
            .core
            .check_handle(handle.instance_id())
            .map_err(ScpError::from)?;
        let ctx_id = handle.context_id.clone();
        let creator_did = handle.creator_did.clone();
        let handle = Arc::clone(&handle);
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let manager = bi.context_manager_or_error()?;
                // Sign the §23.16.8 snapshot digest via the exporter identity's
                // `KeyCustody::sign` (callback OR in-memory custody) rather than
                // extracting a raw Ed25519 key. This lets a sign-only /
                // keychain / HSM-shaped callback custody — one that signs but
                // cannot export key bytes — produce a verifiable signed export.
                // Private key material never crosses the FFI boundary (ADR-006).
                //
                // `export_context`'s `sign` closure is synchronous, but custody
                // `sign` is async (a callback custody awaits a Swift/Kotlin
                // `KeyCustodyProvider`). Bridge the two with `block_in_place` +
                // `block_on` on the current multi-thread runtime — the same
                // pattern used by `member_dids`/`get_role_state` elsewhere in
                // this bridge. This task already runs on a `runtime()` worker
                // (`new_multi_thread`), so a runtime handle is always present
                // and `block_in_place` is legal here.
                let rt = tokio::runtime::Handle::current();
                let export = manager
                    .export_context(
                        &ctx_id,
                        scp_identity::DID::from(creator_did),
                        |hash: &[u8; 32]| {
                            tokio::task::block_in_place(|| {
                                rt.block_on(sign_export_snapshot_via_custody(&handle, hash))
                            })
                        },
                    )
                    .await
                    .map_err(ScpError::from)?;
                scp_core::context::export_import::serialize_export(&export).map_err(|e| {
                    ScpError::Context {
                        msg: format!("export serialization failed: {e}"),
                        code: codes::CTX_2030.to_owned(),
                    }
                })
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during context export: {e}"),
                code: codes::CTX_2031.to_owned(),
            })?
    }

    /// Per-instance equivalent of the free-function `context_import`.
    ///
    /// `importer_identity` supplies the §9.10.4 per-context pseudonym
    /// derivation material — the importing member derives their OWN routing ID
    /// rather than inheriting the exporter's local-instance pseudonym.
    pub async fn context_import(
        &self,
        data: Vec<u8>,
        importer_identity: Arc<Identity>,
    ) -> Result<String, ScpError> {
        self.inner
            .core
            .check_handle(importer_identity.instance_id())
            .map_err(ScpError::from)?;
        let bi = Arc::clone(&self.inner);
        runtime()
            .spawn(async move {
                let identity = importer_identity;
                validate_did(&identity.did)?;

                let export =
                    scp_core::context::export_import::deserialize_export(&data).map_err(|e| {
                        ScpError::Context {
                            msg: format!("invalid export data: {e}"),
                            code: codes::CTX_2032.to_owned(),
                        }
                    })?;
                let context_id = export.snapshot.context_id.clone();
                let imported_core_params = export.snapshot.context_params.clone();
                let imported_is_broadcast = matches!(
                    imported_core_params.mode,
                    scp_core::context::params::ContextMode::Broadcast
                );

                // Resolve the verification key for the snapshot's `creator_did`
                // (§23.16.8 step 1, ADR-050) — NOT the unauthenticated envelope
                // `exporter_did`. The runtime separately asserts
                // `exporter_did == creator_did` (§23.16.8 step 2). Fail-closed:
                // if no key resolves, the import is rejected — never imported
                // unverified.
                let creator_did = export.snapshot.role_state.creator_did.clone();
                validate_did(&creator_did)?;
                let verifying_key = resolve_uniffi_creator_verifying_key(&bi, &creator_did).await?;

                // Verify-before-init: validate the snapshot signature, signer
                // binding, version gate, and Merkle chain BEFORE touching the
                // bridge's ContextManager. `init_context_manager_with_did`
                // seeds the MLS provider's credential identity from
                // `creator_did`, and that OnceLock is first-call-wins. Seeding
                // it from an unverified snapshot would let an attacker-crafted
                // `creator_did` set the provider identity on a fresh bridge
                // whose first operation is an import. Running the full
                // verification here means the identity is only seeded from a
                // cryptographically authenticated `creator_did`.
                // `import_context` re-runs the same validation (authoritative
                // path); the duplicate work is acceptable to keep the security
                // ordering correct.
                scp_core::context::export_import::validate_export_for_import(
                    &export,
                    &verifying_key,
                )
                .map_err(ScpError::from)?;

                // §9.10.4 misuse-resistance: the importer MUST be a member of
                // the now-verified snapshot, else its derived pseudonym routes
                // to an ID no peer expects and the member is silently
                // unaddressable. Reject loudly (SCP-CTX-2092). The creator is a
                // member, so a creator re-homing its own context passes.
                scp_core::context::export_import::ensure_importer_is_member(
                    &export.snapshot,
                    &identity.did,
                )
                .map_err(ScpError::from)?;

                // Ensure the ContextManager is initialized — context_import is
                // a valid first operation. `init_context_manager_with_did` is
                // idempotent (`OnceLock`). Seeding from the now-verified
                // `creator_did` is safe per the verify-before-init step above.
                bi.init_context_manager_with_did(&creator_did);

                // §9.10.4: derive the importer's OWN per-context pseudonym
                // before the runtime import. The importer is DISTINCT from the
                // snapshot `creator_did`. The runtime import path is
                // encrypted-only (broadcast-mode exports are rejected upstream
                // with SCP-CTX-2092), so a real pseudonym is ALWAYS required —
                // derive it UNCONDITIONALLY, exactly like the PyO3 reference
                // bridge. Custody / derivation failure is a hard error carrying
                // granular codes (missing material → 1054, derivation failure →
                // 1055, wrong length → 1057), never a silent zero-pseudonym
                // fallback and never a `[0u8; 32]` sentinel for broadcast (which
                // would make the member permanently unaddressable).
                let local_pseudonym: [u8; 32] =
                    derive_member_pseudonym_required(&identity, &context_id).await?;

                // Dispatch the import carrying BOTH the creator verifying key
                // (verify-before-init, §23.16.8) and the importer's derived
                // pseudonym (§9.10.4). `import_context` re-runs the
                // authoritative verification and surfaces the typed
                // `ContextError` (signature/version forgery + §9.10.4 codes)
                // through `ScpError`.
                let sup = bi.context_manager_or_error()?;
                sup.import_context(export, &verifying_key, Some(local_pseudonym))
                    .await
                    .map_err(ScpError::from)?;

                // §9.10.4: emit a PseudonymAnnouncement so existing members
                // learn this importer's per-context routing ID. Encrypted
                // contexts only — broadcast contexts use the shared
                // `broadcast_routing_id` and carry no pseudonym registry.
                // Best-effort: a missing signing key just skips the
                // announcement, which peers recover on the importer's first
                // send via lazy re-announcement.
                if !imported_is_broadcast {
                    let sk_opt: Option<ed25519_dalek::SigningKey> =
                        if let Some(ref ik) = identity.core_id {
                            if let Some(ref cb) = identity.callback_custody {
                                cb.export_ed25519_signing_key(&ik.active_signing_key)
                                    .await
                                    .ok()
                            } else {
                                #[cfg(feature = "allow_in_memory_custody")]
                                {
                                    if let Some(ref custody) = identity.in_memory_custody {
                                        custody
                                            .0
                                            .export_ed25519_signing_key(&ik.active_signing_key)
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
                            }
                        } else {
                            None
                        };
                    if let Some(sk) = sk_opt {
                        use scp_core::context::actor::commands::{
                            MessagingCommand, SendPseudonymAnnouncementPayload, SigningKeyBytes,
                        };
                        let sender_did = scp_identity::DID(identity.did.clone());
                        let (atx, arx) = tokio::sync::oneshot::channel();
                        let ann_cmd = MessagingCommand::SendPseudonymAnnouncement {
                            payload: Box::new(SendPseudonymAnnouncementPayload {
                                context_id: context_id.clone(),
                                params: imported_core_params,
                                sender_did,
                                signing_key: SigningKeyBytes::from_signing_key(&sk),
                            }),
                            reply: atx,
                        };
                        if sup.dispatch_command(&context_id, ann_cmd).await.is_ok() {
                            let _ = arx.await;
                        }
                    }
                }

                Ok(context_id)
            })
            .await
            .map_err(|e| ScpError::Context {
                msg: format!("tokio task join error during context import: {e}"),
                code: codes::CTX_2033.to_owned(),
            })?
    }

    // ----- Invitation evaluation -----

    /// Per-instance equivalent of the free-function `evaluate_invitation`.
    pub fn evaluate_invitation(
        &self,
        params_json: String,
        inviter_did: String,
        identity_did: String,
        policy_json: Option<String>,
        spending_json: Option<String>,
        trusted_dids: Vec<String>,
    ) -> Result<String, ScpError> {
        use scp_core::context::invitation::{
            EvaluationDecision, SpendingContext, evaluate_invitation as core_evaluate,
        };
        use scp_core::context::policy::AutoAcceptPolicy;

        validate_did(&inviter_did)?;
        validate_did(&identity_did)?;

        let params: scp_core::context::params::ContextParams =
            serde_json::from_str(&params_json).map_err(|e| ScpError::Validation {
                msg: format!("failed to parse context params JSON: {e}"),
                code: codes::VALID_7010.to_owned(),
            })?;

        let policy: Option<AutoAcceptPolicy> = match policy_json {
            Some(ref json) => {
                Some(
                    serde_json::from_str(json).map_err(|e| ScpError::Validation {
                        msg: format!("failed to parse auto-accept policy JSON: {e}"),
                        code: codes::VALID_7010.to_owned(),
                    })?,
                )
            }
            None => None,
        };

        let spending: Option<SpendingContext> = match spending_json {
            Some(ref json) => {
                Some(
                    serde_json::from_str(json).map_err(|e| ScpError::Validation {
                        msg: format!("failed to parse spending context JSON: {e}"),
                        code: codes::VALID_7010.to_owned(),
                    })?,
                )
            }
            None => None,
        };

        let oracle_dids: Vec<scp_identity::DID> = trusted_dids
            .into_iter()
            .map(scp_identity::DID::from)
            .collect();
        let oracle = UniffiBridgeTrustOracle {
            trusted_dids: oracle_dids,
        };
        let inviter = scp_identity::DID::from(inviter_did.as_str());

        let decision = self
            .inner
            .with_rate_limit_tracker(&identity_did, |tracker| {
                core_evaluate(
                    &params,
                    &inviter,
                    policy.as_ref(),
                    spending.as_ref(),
                    &oracle,
                    tracker,
                    &scp_core::time::SystemClock,
                )
            });

        match decision {
            Ok(EvaluationDecision::AutoAccept) => Ok("auto_accept".to_owned()),
            Ok(EvaluationDecision::PromptAgent) => Ok("prompt_agent".to_owned()),
            Err(e) => Err(ScpError::Context {
                msg: format!("invitation evaluation failed: {e}"),
                code: codes::CTX_2060.to_owned(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Returns a fresh `Scp` instance for tests. Phase 4 PR 4 demolition
    /// (#1549) deleted the free-function façade; tests now drive bridge
    /// logic through an owned `Scp` instance.
    fn scp_test() -> Arc<crate::scp::Scp> {
        crate::scp::Scp::new_in_memory_for_test()
    }

    /// Builds a synthetic `ContextHandle` stamped with `scp`'s own
    /// `instance_id` so the per-instance handle-affinity check accepts
    /// it. Phase D (#1695): replaces the old `UNSET_INSTANCE_ID` stamp
    /// which only worked against the deleted process-wide default.
    fn test_handle_for(scp: &Arc<crate::scp::Scp>) -> Arc<ContextHandle> {
        let instance_id = scp.instance_id();
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
            core_context_params: scp_core::context::ContextParams::default(),
            instance_id,
        })
    }

    /// Builds a synthetic `Identity` stamped with `scp`'s own
    /// `instance_id`. Phase D (#1695): see `test_handle_for`.
    fn test_identity_for(scp: &Arc<crate::scp::Scp>) -> Arc<Identity> {
        let instance_id = scp.instance_id();
        // Synthetic pre-rotation custody — never inspected by callers that
        // only exercise non-migration paths, but the field is non-optional
        // so the test handle has to provide something.
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        Arc::new(Identity {
            did: "did:dht:z6MkTestUser".to_owned(),
            custody_type: CustodyMethod::InMemory,
            core_id: None,
            core_document: None,
            #[cfg(feature = "allow_in_memory_custody")]
            in_memory_custody: None,
            callback_custody: None,
            verifying_key_hex: None,
            instance_id,
            rotation_event_json: None,
            pre_rotation_handle: scp_platform::PreRotationKeyHandle::new(0),
            pre_rotation_custody,
        })
    }

    // ----- Context export signing via sign-only custody (§23.16.8) -----

    /// A deliberately **sign-only** `KeyCustodyProvider`: it signs and exposes a
    /// public key, but does NOT override `export_signing_key_bytes`, so the
    /// trait default (CTX-2050 "not implemented") applies. This models a
    /// keychain / Secure-Enclave / HSM-shaped custody whose raw private key is
    /// non-exportable — the exact case the prior raw-key export path could not
    /// sign a context export for. Backed by a fixed Ed25519 key so the produced
    /// signature is independently verifiable against the public key.
    struct SignOnlyCustody {
        signing_key: ed25519_dalek::SigningKey,
    }

    impl SignOnlyCustody {
        fn new() -> Self {
            // Deterministic seed of all 9s — independent of any production key.
            Self {
                signing_key: ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::KeyCustodyProvider for SignOnlyCustody {
        async fn sign(&self, _key_id: String, message: Vec<u8>) -> Result<Vec<u8>, ScpError> {
            use ed25519_dalek::Signer;
            Ok(self.signing_key.sign(&message).to_bytes().to_vec())
        }

        async fn get_public_key(&self, _key_id: String) -> Result<Vec<u8>, ScpError> {
            Ok(self.signing_key.verifying_key().to_bytes().to_vec())
        }

        async fn destroy_key(&self, _key_id: String) -> Result<(), ScpError> {
            Ok(())
        }

        async fn generate_keypair(&self, _key_type: String) -> Result<String, ScpError> {
            // Single fixed key; handle id `1` is what the test wires.
            Ok("1".to_owned())
        }

        async fn dh_agree(
            &self,
            _key_id: String,
            _peer_public: Vec<u8>,
        ) -> Result<Vec<u8>, ScpError> {
            Err(ScpError::Context {
                msg: "dh_agree not supported by SignOnlyCustody".to_owned(),
                code: codes::CTX_2050.to_owned(),
            })
        }

        async fn derive_pseudonym(
            &self,
            _key_id: String,
            _context_id: Vec<u8>,
        ) -> Result<Vec<u8>, ScpError> {
            Err(ScpError::Context {
                msg: "derive_pseudonym not supported by SignOnlyCustody".to_owned(),
                code: codes::CTX_2050.to_owned(),
            })
        }

        // NOTE: `export_signing_key_bytes` is intentionally NOT overridden —
        // the trait default returns CTX-2050, which is what makes this custody
        // "sign-only". `CallbackKeyCustody::export_ed25519_signing_key` (the old
        // export-signing path) therefore fails for this custody.

        fn custody_type(&self, _key_id: String) -> String {
            "hardware".to_owned()
        }
    }

    /// A sign-only custody (whose raw key cannot be exported) must still be able
    /// to sign a context-export snapshot digest via `KeyCustody::sign`
    /// (§23.16.8), producing a 64-byte Ed25519 signature that verifies against
    /// the custody's public key. This is the `UniFFI` parity fix for the `NAPI`
    /// callback-custody export path: the prior raw-key export path
    /// (`export_ed25519_signing_key`) cannot serve this custody.
    #[tokio::test]
    async fn sign_only_custody_signs_export_snapshot_and_verifies() {
        use ed25519_dalek::Verifier;

        let scp = scp_test();
        let provider = SignOnlyCustody::new();
        let verifying_key = provider.signing_key.verifying_key();

        let callback_custody = Arc::new(CallbackKeyCustody::new(Box::new(provider)));
        let key_handle = KeyHandle::new(1);

        // Sanity: the old raw-key export path must FAIL for a sign-only custody,
        // proving the new `custody.sign` path is load-bearing (not redundant
        // with the still-extant governance raw-key path).
        let export_attempt = callback_custody
            .export_ed25519_signing_key(&key_handle)
            .await;
        assert!(
            export_attempt.is_err(),
            "sign-only custody must not be able to export raw key bytes"
        );

        // Build a context handle carrying the sign-only callback custody and the
        // `#active` key handle, exactly as `context_create` would for a
        // platform-custody identity.
        let handle = Arc::new(ContextHandle {
            context_id: "ctx-sign-only".to_owned(),
            state: tokio::sync::Mutex::new(ContextState::Active),
            creator_did: "did:dht:z6MkSignOnly".to_owned(),
            #[cfg(feature = "allow_in_memory_custody")]
            in_memory_custody: None,
            callback_custody: Some(callback_custody),
            signing_key: Some(key_handle),
            ceiling_strings: Vec::new(),
            tool_registry: tokio::sync::Mutex::new(scp_core::context::tools::ToolRegistry::new()),
            tool_handlers: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            session_store: tokio::sync::Mutex::new(scp_core::context::tools::SessionStore::new()),
            economic_policy: std::sync::Mutex::new(None),
            core_context_params: scp_core::context::ContextParams::default(),
            instance_id: scp.instance_id(),
        });

        // The §23.16.8 digest is opaque to the signer — any 32-byte hash works
        // to prove the signing path.
        let hash = [0x42u8; 32];
        let signature = super::sign_export_snapshot_via_custody(&handle, &hash)
            .await
            .expect("sign-only custody must produce a context-export signature");

        // Exactly 64 bytes (length validation in the helper) and verifiable
        // against the custody's public key.
        assert_eq!(signature.len(), 64, "Ed25519 signature must be 64 bytes");
        let sig = ed25519_dalek::Signature::from_bytes(&signature);
        verifying_key
            .verify(&hash, &sig)
            .expect("signature must verify against the sign-only custody public key");
    }

    /// `sign_export_snapshot_via_custody` must fail closed when the handle
    /// carries no signing-key handle — never returning a bogus signature.
    #[tokio::test]
    async fn export_snapshot_signing_fails_closed_without_signing_key() {
        let scp = scp_test();
        let handle = test_handle_for(&scp); // signing_key: None, no custody
        let hash = [0u8; 32];
        let result = super::sign_export_snapshot_via_custody(&handle, &hash).await;
        let err = result.expect_err("missing signing key must be rejected");
        match err {
            ScpError::Context { ref code, .. } => assert_eq!(code, codes::CTX_2040),
            other => panic!("expected ScpError::Context CTX-2040, got {other:?}"),
        }
    }

    /// `UniFFI` `tool_invoke` must reject `None` `ucan_token` with a
    /// `Permission` error. Matches `PyO3`/NAPI behavior where the token
    /// is a required non-optional parameter. See issue #423.
    #[tokio::test]
    async fn tool_invoke_rejects_none_ucan_token() {
        let scp = scp_test();
        let result = scp
            .tool_invoke(
                test_handle_for(&scp),
                "test-tool".to_owned(),
                "{}".to_owned(),
                test_identity_for(&scp),
                None, // No UCAN token
                None,
                None, // spending_ucan_jwt
            )
            .await;

        let err = result.expect_err("None ucan_token must be rejected");
        match err {
            ScpError::Permission { ref code, .. } => {
                assert_eq!(code, codes::PERM_3001);
            }
            other => panic!("expected ScpError::Permission, got {other:?}"),
        }
    }

    /// Direct `set_economic_policy` always rejects — must use governance (#728).
    #[test]
    fn set_economic_policy_always_rejects_requires_governance() {
        // Phase D (#1695): use a fresh SCP instance and stamp the handle
        // with its instance_id so the per-instance affinity check accepts it.
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let handle = test_handle_for(&scp);

        // Initially None.
        let result = scp.get_economic_policy(Arc::clone(&handle)).unwrap();
        assert!(result.is_none());

        // Direct set always rejects.
        let json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":null,"per_tool_invoke":100,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkTest"}"#;
        let result = scp.set_economic_policy(Arc::clone(&handle), json.to_owned());
        assert!(
            result.is_err(),
            "direct set must be rejected — use governance"
        );

        // Policy should remain None.
        let result = scp.get_economic_policy(handle).unwrap();
        assert!(result.is_none());
    }

    /// `configure_local_transport` with a valid DID attaches a
    /// `ContextManager` to this instance (loopback transport, no network I/O).
    #[test]
    fn configure_local_transport_attaches_manager_for_valid_did() {
        let scp = scp_test();
        assert!(
            !scp.inner.core.has_supervisor(),
            "fresh instance must not have a ContextManager attached"
        );
        let result =
            scp.configure_local_transport("did:key:z6MkfreshLocalTransportTest".to_owned());
        assert!(result.is_ok(), "valid DID should configure local transport");
        assert!(
            scp.inner.core.has_supervisor(),
            "configure_local_transport must attach a ContextManager"
        );
    }

    /// `configure_local_transport` rejects a malformed DID at the FFI boundary
    /// with `ScpError::Validation` and leaves no `ContextManager` attached.
    #[test]
    fn configure_local_transport_rejects_invalid_did() {
        let scp = scp_test();
        let result = scp.configure_local_transport("not-a-valid-did".to_owned());
        let err = result.expect_err("invalid DID must be rejected");
        assert!(
            matches!(err, ScpError::Validation { .. }),
            "expected ScpError::Validation, got {err:?}"
        );
        assert!(
            !scp.inner.core.has_supervisor(),
            "a rejected DID must not leave a ContextManager attached"
        );
    }

    /// `economy_verify_payment_receipts` with an empty receipt array and an
    /// attached supervisor returns the empty
    /// `{"all_valid":true,"results":[]}` document — `all_valid` is vacuously
    /// `true` for an empty batch.
    #[tokio::test]
    async fn economy_verify_payment_receipts_empty_array_returns_empty_results() {
        let scp = scp_test();
        // Attach a supervisor (loopback transport, no network I/O).
        scp.configure_local_transport("did:key:z6MkVerifyReceiptsEmptyTest".to_owned())
            .expect("valid DID should configure local transport");

        let out = scp
            .economy_verify_payment_receipts("[]".to_owned())
            .await
            .expect("empty receipt array must verify successfully");
        assert_eq!(out, r#"{"all_valid":true,"results":[]}"#);
    }

    /// `economy_verify_payment_receipts` rejects a malformed payload with a
    /// `ScpError::Validation` before any supervisor lookup (no supervisor
    /// required to reach the validation path).
    #[tokio::test]
    async fn economy_verify_payment_receipts_rejects_malformed_json() {
        let scp = scp_test();
        let err = scp
            .economy_verify_payment_receipts("not json".to_owned())
            .await
            .expect_err("malformed JSON must be rejected");
        assert!(
            matches!(err, ScpError::Validation { .. }),
            "expected ScpError::Validation, got {err:?}"
        );
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
            discovery_method: scp_core::provenance::DiscoveryMethod::OutOfBand,
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
        assert!(matches!(ffi.discovery_method, DiscoveryMethod::OutOfBand));
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
            age: std::time::Duration::from_mins(10),
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
            discovery_method: DiscoveryMethod::OutOfBand,
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
            ScpError::Validation { code, msg } => {
                assert_eq!(code, codes::VALID_7080);
                assert!(
                    msg.contains("32 bytes"),
                    "expected '32 bytes' in message, got: {msg}"
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

        let json = discovery_result_to_json(&result).unwrap();
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
            discovery_source: scp_core::discovery::ContextDiscoverySource::HandleRegistry {
                context_id: "disc-ctx-1".to_owned(),
            },
            mode: None,
            metadata_summary: None,
        };

        let json = discovery_result_to_json(&result).unwrap();
        assert_eq!(json["trust_level"]["kind"], "HandleRegistryVerified");
        assert_eq!(json["resolution_path"]["layer"], "HandleRegistry");
        assert_eq!(json["resolution_path"]["source"], "handle_registry");
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

        let json = discovery_result_to_json(&result).unwrap();
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

        let json = discovery_result_to_json(&result).unwrap();
        assert_eq!(json["trust_level"]["kind"], "DomainVerified");
        assert_eq!(json["resolution_path"]["layer"], "Domain");
        assert_eq!(json["resolution_path"]["source"], "well-known");
        assert!(json["resolution_path"]["source_id"].is_null());
    }

    // -- tool_register validation: json_value_type_name via shared helper ------

    #[test]
    fn json_value_type_name_covers_all_variants() {
        assert_eq!(json_value_type_name(&serde_json::Value::Null), "null");
        assert_eq!(
            json_value_type_name(&serde_json::Value::Bool(false)),
            "boolean"
        );
        assert_eq!(json_value_type_name(&serde_json::json!(42)), "number");
        assert_eq!(json_value_type_name(&serde_json::json!("hi")), "string");
        assert_eq!(json_value_type_name(&serde_json::json!([])), "array");
        assert_eq!(json_value_type_name(&serde_json::json!({})), "object");
    }

    // -- tool_register validation: schema parse errors -------------------------

    #[tokio::test]
    async fn tool_register_rejects_invalid_input_schema_json() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let def = ToolDefinition {
            name: "test-tool".to_owned(),
            description: "desc".to_owned(),
            input_schema_json: "not valid json{{{".to_owned(),
            output_schema_json: r#"{"type": "object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let err = scp
            .tool_register(handle, def)
            .await
            .expect_err("invalid input_schema_json must be rejected");
        match err {
            ScpError::Validation { ref code, ref msg } => {
                assert_eq!(code, codes::VALID_7035);
                assert!(
                    msg.contains("invalid input_schema_json"),
                    "error should reference field name, got: {msg}"
                );
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_register_rejects_invalid_output_schema_json() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let def = ToolDefinition {
            name: "test-tool".to_owned(),
            description: "desc".to_owned(),
            input_schema_json: r#"{"type": "object"}"#.to_owned(),
            output_schema_json: "{broken".to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let err = scp
            .tool_register(handle, def)
            .await
            .expect_err("invalid output_schema_json must be rejected");
        match err {
            ScpError::Validation { ref code, ref msg } => {
                assert_eq!(code, codes::VALID_7036);
                assert!(
                    msg.contains("invalid output_schema_json"),
                    "error should reference field name, got: {msg}"
                );
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    // -- tool_register validation: schema type (non-object) --------------------

    #[tokio::test]
    async fn tool_register_rejects_non_object_input_schema() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let def = ToolDefinition {
            name: "test-tool".to_owned(),
            description: "desc".to_owned(),
            input_schema_json: r#""a string""#.to_owned(),
            output_schema_json: r#"{"type": "object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let err = scp
            .tool_register(handle, def)
            .await
            .expect_err("non-object input_schema must be rejected");
        match err {
            ScpError::Validation { ref code, ref msg } => {
                assert_eq!(code, codes::VALID_7035);
                assert!(
                    msg.contains("expected a JSON object"),
                    "error should mention expected type, got: {msg}"
                );
                assert!(
                    msg.contains("string"),
                    "error should mention actual type, got: {msg}"
                );
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_register_rejects_non_object_output_schema() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let def = ToolDefinition {
            name: "test-tool".to_owned(),
            description: "desc".to_owned(),
            input_schema_json: r#"{"type": "object"}"#.to_owned(),
            output_schema_json: "[1, 2, 3]".to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let err = scp
            .tool_register(handle, def)
            .await
            .expect_err("non-object output_schema must be rejected");
        match err {
            ScpError::Validation { ref code, ref msg } => {
                assert_eq!(code, codes::VALID_7036);
                assert!(
                    msg.contains("expected a JSON object"),
                    "error should mention expected type, got: {msg}"
                );
                assert!(
                    msg.contains("array"),
                    "error should mention actual type, got: {msg}"
                );
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    // -- tool_register validation: test vectors --------------------------------

    #[tokio::test]
    async fn tool_register_rejects_invalid_test_vectors_json() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let def = ToolDefinition {
            name: "test-tool".to_owned(),
            description: "desc".to_owned(),
            input_schema_json: r#"{"type": "object"}"#.to_owned(),
            output_schema_json: r#"{"type": "object"}"#.to_owned(),
            test_vectors_json: Some(r#"{"not": "an array"}"#.to_owned()),
            implementation_hash: None,
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let err = scp
            .tool_register(handle, def)
            .await
            .expect_err("non-array test_vectors_json must be rejected");
        match err {
            ScpError::Validation { ref code, ref msg } => {
                assert_eq!(code, codes::VALID_7037);
                assert!(
                    msg.contains("invalid test_vectors_json"),
                    "error should reference field name, got: {msg}"
                );
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_register_rejects_test_vectors_missing_fields() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        // Array of objects missing required fields for TestVector deserialization.
        let def = ToolDefinition {
            name: "test-tool".to_owned(),
            description: "desc".to_owned(),
            input_schema_json: r#"{"type": "object"}"#.to_owned(),
            output_schema_json: r#"{"type": "object"}"#.to_owned(),
            test_vectors_json: Some(r#"[{"bad": "entry"}]"#.to_owned()),
            implementation_hash: None,
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let err = scp
            .tool_register(handle, def)
            .await
            .expect_err("test vectors with missing fields must be rejected");
        match err {
            ScpError::Validation { ref code, .. } => {
                assert_eq!(code, codes::VALID_7037);
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    // -- tool_register validation: implementation hash -------------------------

    #[tokio::test]
    async fn tool_register_rejects_implementation_hash_wrong_length() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let def = ToolDefinition {
            name: "test-tool".to_owned(),
            description: "desc".to_owned(),
            input_schema_json: r#"{"type": "object"}"#.to_owned(),
            output_schema_json: r#"{"type": "object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: Some(vec![0u8; 16]), // 16 bytes, not 32
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let err = scp
            .tool_register(handle, def)
            .await
            .expect_err("implementation_hash with wrong length must be rejected");
        match err {
            ScpError::Validation { ref code, ref msg } => {
                assert_eq!(code, codes::VALID_7038);
                assert!(
                    msg.contains("32 bytes"),
                    "error should mention expected length, got: {msg}"
                );
                assert!(
                    msg.contains("16"),
                    "error should report actual length, got: {msg}"
                );
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tool_register_rejects_implementation_hash_too_long() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let def = ToolDefinition {
            name: "test-tool".to_owned(),
            description: "desc".to_owned(),
            input_schema_json: r#"{"type": "object"}"#.to_owned(),
            output_schema_json: r#"{"type": "object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: Some(vec![0u8; 64]), // 64 bytes, not 32
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let err = scp
            .tool_register(handle, def)
            .await
            .expect_err("implementation_hash with wrong length must be rejected");
        match err {
            ScpError::Validation { ref code, ref msg } => {
                assert_eq!(code, codes::VALID_7038);
                assert!(
                    msg.contains("32 bytes"),
                    "error should mention expected length, got: {msg}"
                );
                assert!(
                    msg.contains("64"),
                    "error should report actual length, got: {msg}"
                );
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    // -- bridge_register: format and self-approval tests -----------------------

    #[test]
    fn bridge_register_returns_active_with_valid_bridge_id() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:governance".to_owned(),
            "discord".to_owned(),
            "relay".to_owned(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(result.status, "active");
        assert_eq!(result.platform, "discord");
        // bridge_id must be a 64-char hex string (SHA-256 output per §12.2.1)
        assert_eq!(result.bridge_id.len(), 64);
        assert!(result.bridge_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn bridge_register_rejects_self_approval() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:operator".to_owned(),
            "discord".to_owned(),
            "relay".to_owned(),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ScpError::Context { ref msg, .. } => {
                assert!(
                    msg.contains("approver cannot be the same"),
                    "expected self-approval error, got: {err:?}"
                );
            }
            other => panic!("expected ScpError::Context, got {other:?}"),
        }
    }

    #[test]
    fn bridge_register_with_optional_fields() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:governance".to_owned(),
            "discord".to_owned(),
            "cooperative".to_owned(),
            Some("https://example.com/webhook".to_owned()),
            Some(vec![42u8; 32]),
            Some(500),
            Some("My Discord Bridge".to_owned()),
            Some("Bridges #general channel".to_owned()),
            Some("admin@example.com".to_owned()),
        )
        .unwrap();
        assert_eq!(result.status, "active");
    }

    #[test]
    fn bridge_register_rejects_invalid_platform_key_length() {
        let result = bridge_register(
            "ctx-test".to_owned(),
            "did:key:operator".to_owned(),
            "did:key:governance".to_owned(),
            "discord".to_owned(),
            "cooperative".to_owned(),
            None,
            Some(vec![42u8; 16]), // wrong length
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ScpError::Validation { ref code, .. } => {
                assert_eq!(code, codes::VALID_7052);
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    /// `registered_at` on a tool registered via the `UniFFI` bridge must be a
    /// seconds-epoch timestamp, not milliseconds or hardcoded 0.
    /// Calls the actual `tool_register` bridge function and inspects the
    /// stored `ToolRegistration`. Catches the original bug from issue #871.
    #[tokio::test]
    async fn registered_at_is_seconds_epoch() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let def = ToolDefinition {
            name: "timestamp-probe".to_owned(),
            description: "probes registered_at value".to_owned(),
            input_schema_json:
                r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"number"}}}"#
                    .to_owned(),
            output_schema_json: r#"{"type":"object"}"#.to_owned(),
            test_vectors_json: None,
            implementation_hash: None,
            operator_did: "did:dht:z6MkTestUser".to_owned(),
            cost: None,
        };

        let tool_id = scp
            .tool_register(handle.clone(), def)
            .await
            .expect("tool_register should succeed");

        let registry = handle.tool_registry.lock().await;
        let reg = registry
            .get(&tool_id)
            .expect("tool should exist in registry after registration");
        assert!(
            reg.registered_at > 1_700_000_000 && reg.registered_at < 2_000_000_000,
            "registered_at should be seconds-epoch (got {}); \
             milliseconds would be ~1.7 trillion, hardcoded 0 would fail lower bound",
            reg.registered_at
        );
    }

    // -----------------------------------------------------------------------
    // SCPID authentication (§3.11)
    // -----------------------------------------------------------------------

    #[test]
    fn scpid_challenge_returns_valid_json() {
        let json = scpid_challenge("https://example.com".to_owned(), 60)
            .expect("scpid_challenge should succeed");
        let v: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");
        assert_eq!(v["protocol"], "scpid/1.0");
        assert_eq!(v["audience"], "https://example.com");
        assert!(v["nonce"].is_string());
        assert!(v["issued_at"].is_u64());
        assert!(v["expires_at"].is_u64());
    }

    #[test]
    fn scpid_challenge_rejects_zero_ttl() {
        let result = scpid_challenge("https://example.com".to_owned(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn scpid_challenge_rejects_excessive_ttl() {
        let result = scpid_challenge("https://example.com".to_owned(), 301);
        assert!(result.is_err());
    }

    #[test]
    fn scpid_challenge_rejects_empty_audience() {
        let result = scpid_challenge(String::new(), 60);
        assert!(result.is_err());
    }

    #[test]
    fn parse_scpid_signing_key_id_valid() {
        assert_eq!(
            parse_scpid_signing_key_id("#active").unwrap(),
            scp_identity::SigningKeyId::Active
        );
        assert_eq!(
            parse_scpid_signing_key_id("#agent").unwrap(),
            scp_identity::SigningKeyId::Agent
        );
    }

    #[test]
    fn parse_scpid_signing_key_id_invalid() {
        assert!(parse_scpid_signing_key_id("active").is_err());
        assert!(parse_scpid_signing_key_id("#owner").is_err());
        assert!(parse_scpid_signing_key_id("").is_err());
    }

    #[test]
    fn scpid_error_code_maps_all_variants() {
        use scp_core::identity::ScpIdError;

        assert_eq!(
            scpid_error_code(&ScpIdError::ChallengeExpired),
            codes::IDENT_1030
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::AudienceMismatch),
            codes::IDENT_1031
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::TimestampInvalid),
            codes::IDENT_1032
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::DidResolutionFailed("test".to_owned())),
            codes::IDENT_1033
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::KeyNotAuthorized),
            codes::IDENT_1034
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::SignatureInvalid),
            codes::IDENT_1035
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::DidDocumentStale),
            codes::IDENT_1036
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::SigningFailed("test".to_owned())),
            codes::IDENT_1037
        );
        assert_eq!(
            scpid_error_code(&ScpIdError::InvalidInput("test".to_owned())),
            codes::IDENT_1038
        );
    }

    /// Bridge `scpid_verify` rejects malformed response JSON with the
    /// correct error code before attempting DID resolution.
    #[test]
    fn scpid_verify_rejects_malformed_response_json() {
        let result = scp_test().scpid_verify("not valid json".to_owned(), "{}".to_owned());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1038),
            "expected SCP-IDENT-1038, got: {err_str}"
        );
    }

    /// Bridge `scpid_verify` rejects malformed challenge JSON with the
    /// correct error code (response JSON parses, challenge does not).
    #[test]
    fn scpid_verify_rejects_malformed_challenge_json() {
        let response_json = serde_json::json!({
            "protocol": "scpid/1.0",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "audience": "https://example.com",
            "did": "did:dht:ztest",
            "signing_key_id": "Active",
            "signature": "AAAA",
            "issued_at": 1_000_000_000_u64,
            "expires_at": 2_000_000_000_u64,
        });
        let result = scp_test().scpid_verify(
            serde_json::to_string(&response_json).unwrap(),
            "not valid json".to_owned(),
        );
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1038),
            "expected SCP-IDENT-1038, got: {err_str}"
        );
    }

    /// Sign→verify roundtrip using `IdentityBackedDidResolver` — the same
    /// type used by the bridge function via the global `DID_RESOLVER`. Uses a
    /// shared `InMemoryDhtClient` so the DID published during identity
    /// creation is visible to the verify resolver.
    #[tokio::test]
    async fn scpid_sign_verify_roundtrip_via_identity_backed_resolver() {
        use scp_core::identity::{
            scpid_challenge as core_challenge, scpid_sign as core_sign, scpid_verify as core_verify,
        };
        use scp_identity::DidMethod;
        use std::time::Duration;

        let dht_client = Arc::new(InMemoryDhtClient::new());
        let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());

        // Create a DidDht with a signer so we can publish the DID document.
        let sign_fn =
            scp_identity::DidDht::<InMemoryDhtClient, scp_identity::cache::SystemClock>::make_sign_fn(
                Arc::clone(&custody),
            );
        let dht = scp_identity::DidDht::with_client_and_signer(
            Arc::clone(&dht_client),
            Arc::new(DidCache::new()),
            sign_fn,
        );
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, doc, _pre_rotation_handle) = dht
            .create(custody.as_ref(), pre_rotation_custody.as_ref())
            .await
            .unwrap();

        // Publish the document to the shared DHT so the resolver can find it.
        dht.publish(&identity, &doc).await.unwrap();

        // Challenge.
        let challenge = core_challenge("https://example.com", Duration::from_mins(2)).unwrap();

        // Sign.
        let response = core_sign(
            custody.as_ref(),
            &identity.active_signing_key,
            &identity.did,
            scp_identity::SigningKeyId::Active,
            &challenge,
            None,
        )
        .await
        .unwrap();

        // Verify using IdentityBackedDidResolver — the same type the bridge
        // function uses via the BridgeInstance DID resolver.
        let dual = DualLayerResolver::new(
            Arc::new(NoOpRelayQuerier),
            dht_client,
            Arc::new(DidCache::new()),
            Vec::new(),
        );
        let resolver = scp_ffi_common::IdentityBackedDidResolver::new(
            Arc::new(dual),
            tokio::runtime::Handle::current(),
        );
        let auth = core_verify(&resolver, &response, &challenge).await.unwrap();

        assert_eq!(auth.did, identity.did);
        assert_eq!(auth.signing_key_id, scp_identity::SigningKeyId::Active);
    }

    // -----------------------------------------------------------------------
    // Pre-rotation invariant — cross-bridge parity
    //
    // Mirrors the SHA-256(revealed_key) == commitment assertions in the
    // PyO3, NAPI, and WASM bridges. Spec §9.7.4.1 §6 / ADR-003 §4b
    // require that every `DidRotationEvent` carry a `PreRotationProof`
    // whose `revealed_key` hashes to the previous identity's
    // `pre_rotation_commitment`. Failing this invariant breaks
    // `verify_migration` for every downstream consumer.
    // -----------------------------------------------------------------------

    /// Verifies that `identity_migrate` on the in-memory custody path
    /// produces a `DidRotationEvent` whose `PreRotationProof` satisfies
    /// `SHA-256(revealed_key) == commitment`. Cross-bridge parity with
    /// the corresponding `PyO3`, NAPI, and WASM tests.
    #[tokio::test]
    #[cfg(feature = "allow_in_memory_custody")]
    async fn identity_migrate_pre_rotation_proof_satisfies_sha256_invariant() {
        use sha2::{Digest, Sha256};

        let scp = scp_test();
        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create");
        let migrated = scp
            .identity_migrate(Arc::clone(&identity))
            .await
            .expect("identity_migrate");

        let event_json = migrated
            .rotation_event_json()
            .expect("rotationEventJson must be Some on migrated handles");
        let event: scp_identity::DidRotationEvent =
            serde_json::from_str(&event_json).expect("rotation_event_json deserialises");
        let pre_rot = event
            .pre_rotation_proof
            .as_ref()
            .expect("PreRotationProof MUST be present on a migrate event");

        let recomputed: [u8; 32] = Sha256::digest(pre_rot.revealed_key).into();
        assert_eq!(
            recomputed, pre_rot.commitment,
            "PreRotationProof MUST satisfy SHA-256(revealed_key) == commitment"
        );
    }

    // MCP bridge tests (issue #591)
    // -----------------------------------------------------------------------

    /// `mcp_server_create` must reject empty `context_ids`.
    #[tokio::test]
    async fn mcp_server_create_rejects_empty_context_ids() {
        let config = McpServerConfig {
            identity_did: "did:dht:z6MkTestUser".to_owned(),
            context_ids: vec![],
            transport: "stdio".to_owned(),
            ucan_token: None,
            proof_tokens: None,
        };

        let result = scp_test().mcp_server_create(config).await;
        let err = result.expect_err("empty context_ids must be rejected");
        match err {
            ScpError::Transport { ref code, .. } => {
                assert_eq!(code, codes::TRANS_5011);
            }
            other => panic!("expected ScpError::Transport, got {other:?}"),
        }
    }

    /// `mcp_server_create` must reject invalid transport mode.
    #[tokio::test]
    async fn mcp_server_create_rejects_invalid_transport() {
        let config = McpServerConfig {
            identity_did: "did:dht:z6MkTestUser".to_owned(),
            context_ids: vec!["ctx-1".to_owned()],
            transport: "websocket".to_owned(),
            ucan_token: None,
            proof_tokens: None,
        };

        let result = scp_test().mcp_server_create(config).await;
        assert!(result.is_err(), "invalid transport mode should be rejected");
    }

    /// `mcp_client_connect_stdio` must reject empty command list.
    #[tokio::test]
    async fn mcp_client_connect_stdio_rejects_empty_command() {
        let result = scp_test().mcp_client_connect_stdio(vec![]).await;
        let err = result.expect_err("empty command must be rejected");
        match err {
            ScpError::Validation { ref code, .. } => {
                assert_eq!(code, codes::VALID_7034);
            }
            other => panic!("expected ScpError::Validation, got {other:?}"),
        }
    }

    /// `mcp_client_disconnect` must reject unknown handle.
    #[tokio::test]
    async fn mcp_client_disconnect_rejects_unknown_handle() {
        let result = scp_test()
            .mcp_client_disconnect("mcp-client-nonexistent".to_owned())
            .await;
        let err = result.expect_err("unknown handle must be rejected");
        match err {
            ScpError::Transport { ref code, .. } => {
                assert_eq!(code, codes::TRANS_5019);
            }
            other => panic!("expected ScpError::Transport, got {other:?}"),
        }
    }

    /// `mcp_client_list_tools` must reject unknown handle.
    #[tokio::test]
    async fn mcp_client_list_tools_rejects_unknown_handle() {
        let result = scp_test()
            .mcp_client_list_tools("mcp-client-nonexistent".to_owned())
            .await;
        let err = result.expect_err("unknown handle must be rejected");
        match err {
            ScpError::Transport { ref code, .. } => {
                assert_eq!(code, codes::TRANS_5020);
            }
            other => panic!("expected ScpError::Transport, got {other:?}"),
        }
    }

    /// `mcp_client_invoke` must reject invalid input JSON.
    #[tokio::test]
    async fn mcp_client_invoke_rejects_unknown_handle() {
        let result = scp_test()
            .mcp_client_invoke(
                "mcp-client-nonexistent".to_owned(),
                "test-tool".to_owned(),
                "{}".to_owned(),
                "ctx-test".to_owned(),
                "did:dht:z6MkTestUser".to_owned(),
            )
            .await;
        let err = result.expect_err("unknown handle must be rejected");
        match err {
            ScpError::Transport { ref code, .. } => {
                assert_eq!(code, codes::TRANS_5023);
            }
            other => panic!("expected ScpError::Transport, got {other:?}"),
        }
    }

    /// `mcp_server_stop` must reject unknown handle.
    #[tokio::test]
    async fn mcp_server_stop_rejects_unknown_handle() {
        let result = scp_test()
            .mcp_server_stop("mcp-server-nonexistent".to_owned())
            .await;
        let err = result.expect_err("unknown handle must be rejected");
        match err {
            ScpError::Transport { ref code, .. } => {
                assert_eq!(code, codes::TRANS_5012);
            }
            other => panic!("expected ScpError::Transport, got {other:?}"),
        }
    }

    /// Stdio allowlist: `get_state` on a fresh instance returns defaults.
    #[test]
    fn mcp_allowlist_get_state_returns_defaults() {
        let scp = scp_test();

        let state = scp
            .mcp_get_stdio_allowlist()
            .expect("get_state should succeed");
        assert!(!state.unrestricted, "should not be unrestricted by default");
        assert!(
            !state.allowed.is_empty(),
            "default allowlist should have entries"
        );
        // Verify some expected defaults.
        assert!(
            state.allowed.contains(&"uvx".to_owned()),
            "default allowlist should contain 'uvx'"
        );
        assert!(
            state.allowed.contains(&"node".to_owned()),
            "default allowlist should contain 'node'"
        );
    }

    /// Stdio allowlist: configure adds entries on this instance.
    #[test]
    fn mcp_allowlist_configure_adds_entries() {
        let scp = scp_test();

        scp.mcp_configure_stdio_allowlist(vec!["my-custom-server".to_owned()])
            .expect("configure should succeed");

        let state = scp
            .mcp_get_stdio_allowlist()
            .expect("get_state should succeed");
        assert!(
            state.allowed.contains(&"my-custom-server".to_owned()),
            "allowlist should contain newly added entry"
        );
    }

    /// Stdio allowlist: configure rejects entries containing paths.
    #[test]
    fn mcp_allowlist_configure_rejects_path_entries() {
        let scp = scp_test();
        let result = scp.mcp_configure_stdio_allowlist(vec!["/usr/bin/evil".to_owned()]);
        assert!(result.is_err(), "path entries must be rejected");
    }

    /// Stdio allowlist: disable enters unrestricted mode for this instance.
    #[test]
    fn mcp_allowlist_disable_enters_unrestricted() {
        let scp = scp_test();

        scp.mcp_disable_stdio_allowlist()
            .expect("disable should succeed");
        let state = scp
            .mcp_get_stdio_allowlist()
            .expect("get_state should succeed");
        assert!(state.unrestricted, "should be unrestricted after disable");
    }

    /// Stdio allowlist: reset restores defaults and re-enables enforcement.
    #[test]
    fn mcp_allowlist_reset_restores_defaults() {
        let scp = scp_test();

        // Start by disabling and adding a custom entry.
        scp.mcp_disable_stdio_allowlist()
            .expect("disable should succeed");
        scp.mcp_configure_stdio_allowlist(vec!["custom-thing".to_owned()])
            .expect("configure should succeed");

        // Reset.
        scp.mcp_reset_stdio_allowlist()
            .expect("reset should succeed");
        let state = scp
            .mcp_get_stdio_allowlist()
            .expect("get_state should succeed");

        assert!(
            !state.unrestricted,
            "should not be unrestricted after reset"
        );
        assert!(
            !state.allowed.contains(&"custom-thing".to_owned()),
            "custom entry should be gone after reset"
        );
    }

    /// WU6: Two-instance regression test — disabling enforcement on one
    /// `Scp` MUST NOT leak into another. Drives the public per-instance
    /// methods that SDKs call.
    #[test]
    fn allowlist_disable_does_not_leak_across_instances_uniffi() {
        let a = scp_test();
        let b = scp_test();

        a.mcp_disable_stdio_allowlist()
            .expect("disable on a should succeed");

        // `b` is unaffected.
        let b_state = b
            .mcp_get_stdio_allowlist()
            .expect("get_state on b should succeed");
        assert!(
            !b_state.unrestricted,
            "instance b must remain restricted after a is disabled"
        );

        // And `a` reports unrestricted.
        let a_state = a
            .mcp_get_stdio_allowlist()
            .expect("get_state on a should succeed");
        assert!(a_state.unrestricted);
    }

    /// WU6 supplement: configure on one instance does not leak.
    #[test]
    fn allowlist_configure_does_not_leak_across_instances_uniffi() {
        let a = scp_test();
        let b = scp_test();

        a.mcp_configure_stdio_allowlist(vec!["custom-a".to_owned()])
            .expect("configure on a");

        let a_state = a.mcp_get_stdio_allowlist().expect("snapshot a");
        assert!(a_state.allowed.contains(&"custom-a".to_owned()));

        let b_state = b.mcp_get_stdio_allowlist().expect("snapshot b");
        assert!(!b_state.allowed.contains(&"custom-a".to_owned()));
    }

    // -- Media bridge tests --------------------------------------------------

    #[test]
    fn media_check_capability_valid() {
        let result = media_check_capability(
            vec!["media:voice".to_owned(), "messages:read".to_owned()],
            "voice".to_owned(),
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn media_check_capability_missing() {
        let result = media_check_capability(vec!["messages:read".to_owned()], "voice".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn media_verify_sender_attribution_match() {
        let (_, msg) =
            scp_media::signaling::create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let json =
            String::from_utf8(scp_media::signaling::serialize_signaling(&msg).unwrap()).unwrap();
        let result = media_verify_sender_attribution(json, "did:dht:zAlice".to_owned());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn media_send_signaling_from_offer() {
        // Create an offer via media_create_offer
        let offer_json = media_create_offer(
            "session-1".to_owned(),
            "v=0\r\n".to_owned(),
            "did:dht:z6MkSender".to_owned(),
        )
        .unwrap();

        // Extract the signaling message JSON from the offer result
        let offer: serde_json::Value = serde_json::from_str(&offer_json).unwrap();
        let signaling_json = offer["message"].as_str().unwrap().to_owned();

        // Pass the signaling JSON through media_send_signaling
        let result_json = media_send_signaling(signaling_json).unwrap();
        let result: serde_json::Value = serde_json::from_str(&result_json).unwrap();

        // Verify output contains "payload" (base64 string) and "message_type"
        let payload = result["payload"]
            .as_str()
            .expect("payload must be a string");
        assert!(
            !payload.is_empty(),
            "payload must be a non-empty base64 string"
        );
        // Verify it is valid base64
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(payload)
            .expect("payload must be valid base64");

        let message_type = result["message_type"]
            .as_str()
            .expect("message_type must be a string");
        assert!(
            !message_type.is_empty(),
            "message_type must be a non-empty string"
        );
    }

    // -- provenance privacy functions (#585) ---------------------------------

    #[test]
    fn provenance_redact_counterparties_removes_dids() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": ["did:dht:z6MkAlice", "did:dht:z6MkBob"],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        let result = provenance_redact_counterparties(prov_json.to_string()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["counterparties"], serde_json::json!([]));
        assert_eq!(parsed["source_context"], "ctx-test");
    }

    #[test]
    fn provenance_pseudonymize_counterparties_deterministic() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": ["did:dht:z6MkAlice"],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        let key_hex = hex::encode(b"test-key");
        let result1 =
            provenance_pseudonymize_counterparties(prov_json.to_string(), key_hex.clone()).unwrap();
        let result2 =
            provenance_pseudonymize_counterparties(prov_json.to_string(), key_hex).unwrap();
        assert_eq!(result1, result2);

        let parsed: serde_json::Value = serde_json::from_str(&result1).unwrap();
        let parties = parsed["counterparties"].as_array().unwrap();
        assert_eq!(parties.len(), 1);
        assert!(parties[0].as_str().unwrap().starts_with("did:pseudo:"));
    }

    #[test]
    fn provenance_update_source_type_changes_type() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": [],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        let result =
            provenance_update_source_type(prov_json.to_string(), "closed_ephemeral".to_owned())
                .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["source_type"], "Ephemeral");
    }

    #[test]
    fn provenance_redact_counterparties_invalid_json_fails() {
        assert!(provenance_redact_counterparties("not json".to_owned()).is_err());
    }

    #[test]
    fn provenance_pseudonymize_counterparties_invalid_hex_fails() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": ["did:dht:z6MkAlice"],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        assert!(
            provenance_pseudonymize_counterparties(prov_json.to_string(), "not-hex-zz".to_owned())
                .is_err()
        );
    }

    #[test]
    fn media_verify_sender_attribution_mismatch() {
        let (_, msg) =
            scp_media::signaling::create_offer("s1", "v=0\r\n".into(), "did:dht:zAlice".into());
        let json =
            String::from_utf8(scp_media::signaling::serialize_signaling(&msg).unwrap()).unwrap();
        let result = media_verify_sender_attribution(json, "did:dht:zEve".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn provenance_update_source_type_invalid_state_fails() {
        let prov_json = serde_json::json!({
            "source_context": "ctx-test",
            "source_type": "Persistent",
            "counterparties": [],
            "purpose": null,
            "discovery_method": "OutOfBand",
            "age": { "secs": 0, "nanos": 0 },
            "memory_scope": "Full",
            "chain_depth": 0,
            "chain_path": null,
            "payment_amount": null,
            "payment_adapter": null,
            "payment_receipt_id": null
        });
        assert!(
            provenance_update_source_type(prov_json.to_string(), "invalid".to_owned()).is_err()
        );
    }

    // -------------------------------------------------------------------
    // Consequence event format tests (#1531, #1593, #1594)
    // -------------------------------------------------------------------

    #[test]
    fn format_consequence_triggered_event() {
        use scp_core::context::membership::ContextEvent;

        let event = ContextEvent::ConsequenceTriggered {
            context_id: "ctx-uniffi-123".to_owned(),
            member_did: scp_identity::DID("did:dht:z6MkBob".to_owned()),
            rule_index: 3,
            trigger_type: "tool_rate".to_owned(),
            action_type: "capability_suspension".to_owned(),
        };

        let formatted = super::format_context_event(&event);
        assert!(
            formatted.contains("consequence_triggered:"),
            "must contain consequence_triggered prefix"
        );
        assert!(
            formatted.contains("member=did:dht:z6MkBob"),
            "must contain member DID"
        );
        assert!(formatted.contains("rule=3"), "must contain rule index");
        assert!(
            formatted.contains("trigger=tool_rate"),
            "must contain trigger type"
        );
        assert!(
            formatted.contains("action=capability_suspension"),
            "must contain action type"
        );
        assert!(
            formatted.contains("context=ctx-uniffi-123"),
            "must contain context ID"
        );
    }

    #[test]
    fn format_consequence_enforced_event() {
        use scp_core::context::membership::ContextEvent;

        let event = ContextEvent::ConsequenceEnforced {
            context_id: "ctx-uniffi-456".to_owned(),
            member_did: scp_identity::DID("did:dht:z6MkAlice".to_owned()),
            action_type: "access_revocation".to_owned(),
            success: true,
        };

        let formatted = super::format_context_event(&event);
        assert!(
            formatted.contains("consequence_enforced:"),
            "must contain consequence_enforced prefix"
        );
        assert!(
            formatted.contains("member=did:dht:z6MkAlice"),
            "must contain member DID"
        );
        assert!(
            formatted.contains("action=access_revocation"),
            "must contain action type"
        );
        assert!(
            formatted.contains("success=true"),
            "must contain success=true"
        );
    }

    /// Verifies that `ContextParams` correctly accepts `consequence_rules`
    /// when parsed from JSON (mirrors the `UniFFI` bridge param flow).
    #[test]
    fn consequence_rules_in_context_params_via_json() {
        let json = r#"[{"trigger":"MessageVelocity","action":{"Enforcement":"SuspendAccess"},"threshold":10,"window":{"secs":3600,"nanos":0}}]"#;
        let rules: Vec<scp_core::trust::ConsequenceRule> = serde_json::from_str(json).unwrap();

        let params = scp_core::context::ContextParams {
            consequence_rules: rules,
            ..scp_core::context::ContextParams::default()
        };

        assert_eq!(
            params.consequence_rules.len(),
            1,
            "consequence_rules should carry 1 rule"
        );
    }

    // -------------------------------------------------------------------
    // Spending UCAN parameter acceptance tests (#1537, #1593)
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_invitation_accepts_spending_json() {
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();
        let spending_json =
            r#"{"has_spending_ucan":true,"configured_adapters":["x402"],"available_balance":10000}"#
                .to_owned();

        let result = scp_test().evaluate_invitation(
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            Some(spending_json),
            vec![],
        );

        assert!(
            result.is_ok(),
            "spending_json should be accepted: {result:?}"
        );
        assert_eq!(result.unwrap(), "prompt_agent");
    }

    #[test]
    fn evaluate_invitation_rejects_invalid_spending_json() {
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();

        let result = scp_test().evaluate_invitation(
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            Some("not valid json".to_owned()),
            vec![],
        );

        assert!(result.is_err(), "invalid spending JSON should be rejected");
    }

    #[test]
    fn evaluate_invitation_none_spending_accepted() {
        let params = scp_core::context::ContextParams::default();
        let params_json = serde_json::to_string(&params).unwrap();

        let result = scp_test().evaluate_invitation(
            params_json,
            "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo".to_owned(),
            "did:dht:z6MkLocalLocalLocalLocalLocalLocalLocal".to_owned(),
            None,
            None,
            vec![],
        );

        assert!(
            result.is_ok(),
            "None spending should be accepted: {result:?}"
        );
        assert_eq!(result.unwrap(), "prompt_agent");
    }

    // -----------------------------------------------------------------------
    // #1549 round-2 regression: UniFFI MCP provider + suppression task
    // must hold `Weak<UniffiBridgeInstance>`, not `Arc`, so the spawned
    // server task cannot pin the instance alive past the caller's last
    // `Arc` drop.
    // -----------------------------------------------------------------------

    /// Struct-level proof: `McpUniFfiBridgeProvider.bi` is `Weak`.
    /// If someone reverts the type to `Arc`, this test stops compiling.
    #[test]
    fn mcp_uniffi_provider_field_is_weak_not_arc() {
        let bi = Arc::new(crate::runtime::UniffiBridgeInstance::new_uniffi());
        let provider = McpUniFfiBridgeProvider {
            bi: Arc::downgrade(&bi),
            agent_did: "did:dht:z6MkTypeProof".to_owned(),
            context_ids: vec![],
            tool_timeout_ms: UNIFFI_TOOL_TIMEOUT_MS,
            agent_ucan_token: None,
            agent_proof_tokens: None,
        };
        let _opt: Option<Arc<crate::runtime::UniffiBridgeInstance>> = provider.bi.upgrade();
    }

    /// The `UniFFI` MCP provider's methods that degrade gracefully return
    /// safe defaults when the bridge instance has been dropped.
    #[test]
    fn mcp_uniffi_provider_returns_safe_defaults_when_bridge_dropped() {
        use scp_mcp::server::ContextProvider;

        let provider = {
            let bi = Arc::new(crate::runtime::UniffiBridgeInstance::new_uniffi());
            let p = McpUniFfiBridgeProvider {
                bi: Arc::downgrade(&bi),
                agent_did: "did:dht:z6MkDropped".to_owned(),
                context_ids: vec!["ctx-dropped".to_owned()],
                tool_timeout_ms: UNIFFI_TOOL_TIMEOUT_MS,
                agent_ucan_token: None,
                agent_proof_tokens: None,
            };
            drop(bi);
            p
        };

        // upgrade_bi itself returns Err.
        assert!(
            provider.upgrade_bi().is_err(),
            "upgrade_bi must fail when the bridge has been dropped"
        );

        // context_tools: returns empty (no panic, no upgrade attempt leak).
        assert!(provider.context_tools("ctx-dropped").is_empty());

        // context_members: returns empty.
        assert!(provider.context_members("ctx-dropped").is_empty());

        // context_events: returns zero-count JSON fallback.
        assert_eq!(
            provider.context_events("ctx-dropped"),
            serde_json::json!({ "event_count": 0 })
        );

        // validate_capability with no UCAN: returns the UCAN-required error
        // (it short-circuits before the bridge upgrade).
        assert!(provider.validate_capability("ctx-dropped", "t").is_err());

        // subscribe_resource is a no-op — still Ok.
        assert!(provider.subscribe_resource("scp://x").is_ok());

        // active_context_ids & agent_did don't touch the Weak at all.
        assert_eq!(
            provider.active_context_ids(),
            vec!["ctx-dropped".to_owned()]
        );
        assert_eq!(provider.agent_did(), "did:dht:z6MkDropped");
    }

    /// Suppression task must not hold a strong `Arc<UniffiBridgeInstance>`
    /// while parked on `recv()`. Proven by observing `Arc::strong_count`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn suppression_scoring_task_does_not_pin_uniffi_bridge_instance() {
        use std::time::Duration;

        let bi = Arc::new(crate::runtime::UniffiBridgeInstance::new_uniffi());
        let (_tx, rx) = tokio::sync::mpsc::channel(1);

        super::spawn_suppression_scoring_task(
            Arc::downgrade(&bi),
            bi.core.cancel_token(),
            rx,
            "ws://test-uniffi-suppression".to_owned(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            Arc::strong_count(&bi),
            1,
            "UniFFI suppression task must not hold a strong \
             Arc<UniffiBridgeInstance> while parked on recv() — holding \
             one would prevent Drop from ever running when the caller \
             releases their last strong ref (#1549 round-2)"
        );
    }

    /// Dropping the caller's `Arc<UniffiBridgeInstance>` triggers
    /// `emergency_cancel_tasks`, which fires `cancel_token`, which wakes
    /// the suppression task so it exits and the instance is fully dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_uniffi_bridge_instance_terminates_suppression_scoring_task() {
        use std::time::Duration;

        let bi = Arc::new(crate::runtime::UniffiBridgeInstance::new_uniffi());
        let weak_observer = Arc::downgrade(&bi);
        let (_tx, rx) = tokio::sync::mpsc::channel(1);

        super::spawn_suppression_scoring_task(
            Arc::downgrade(&bi),
            bi.core.cancel_token(),
            rx,
            "ws://test-uniffi-drop".to_owned(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(Arc::strong_count(&bi), 1);

        drop(bi);

        for _ in 0..50 {
            if weak_observer.strong_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(
            weak_observer.strong_count(),
            0,
            "after dropping the caller's Arc, UniffiBridgeInstance must \
             be fully released — if this fails, the suppression task is \
             still holding a strong reference (regressed Arc cycle)"
        );
        assert!(weak_observer.upgrade().is_none());
    }

    // -----------------------------------------------------------------------
    // PreRotationCustodyError typed-code mapping
    //
    // Regression tests pinning each `PreRotationCustodyError` variant to
    // its typed error code on the UniFFI bridge. Mirrors the PyO3 tests in
    // `crates/scp-ffi/src/error.rs` (same function names, same semantics)
    // so any future re-ordering or accidental swap of match arms in the
    // `From<scp_identity::IdentityError>` impl breaks here, not at the
    // Swift/Kotlin SDK boundary where it would be harder to diagnose.
    // -----------------------------------------------------------------------

    fn pre_rotation_code_of(e: ScpError) -> String {
        match e {
            ScpError::Identity { code, .. } => code,
            other => panic!("expected ScpError::Identity, got {other:?}"),
        }
    }

    #[test]
    fn pre_rotation_handle_not_found_surfaces_typed_code() {
        let err: ScpError = scp_identity::IdentityError::PreRotation(
            scp_platform::PreRotationCustodyError::HandleNotFound,
        )
        .into();
        assert_eq!(pre_rotation_code_of(err), codes::IDENT_1047);
    }

    #[test]
    fn pre_rotation_unavailable_surfaces_typed_code() {
        let err: ScpError = scp_identity::IdentityError::PreRotation(
            scp_platform::PreRotationCustodyError::Unavailable("hardware key not connected".into()),
        )
        .into();
        assert_eq!(pre_rotation_code_of(err), codes::IDENT_1048);
    }

    #[test]
    fn pre_rotation_user_declined_surfaces_typed_code() {
        let err: ScpError = scp_identity::IdentityError::PreRotation(
            scp_platform::PreRotationCustodyError::UserDeclined,
        )
        .into();
        assert_eq!(pre_rotation_code_of(err), codes::IDENT_1049);
    }

    #[test]
    fn pre_rotation_storage_surfaces_typed_code() {
        let err: ScpError = scp_identity::IdentityError::PreRotation(
            scp_platform::PreRotationCustodyError::Storage("disk full".into()),
        )
        .into();
        assert_eq!(pre_rotation_code_of(err), codes::IDENT_1050);
    }

    #[test]
    fn pre_rotation_invalid_callback_response_surfaces_typed_code() {
        let err: ScpError = scp_identity::IdentityError::PreRotation(
            scp_platform::PreRotationCustodyError::InvalidCallbackResponse(
                "handle is empty".into(),
            ),
        )
        .into();
        assert_eq!(pre_rotation_code_of(err), codes::IDENT_1051);
    }

    #[test]
    fn pre_rotation_commitment_mismatch_surfaces_typed_code() {
        let err: ScpError = scp_identity::IdentityError::PreRotation(
            scp_platform::PreRotationCustodyError::CommitmentMismatch,
        )
        .into();
        assert_eq!(pre_rotation_code_of(err), codes::IDENT_1052);
    }

    #[test]
    fn non_pre_rotation_identity_errors_keep_generic_envelope() {
        let err: ScpError = scp_identity::IdentityError::InvalidDidFormat("bad".into()).into();
        assert_eq!(pre_rotation_code_of(err), codes::IDENT_1001);
    }

    // -----------------------------------------------------------------------
    // Selector routing — connect sites must go through the instance selector
    // (cross-SDK QUIC selection). The in-memory relay serves no
    // `.well-known/scp`, so the selector's discovering connect fails open to
    // WebSocket and still succeeds. These tests prove each uniffi connect site
    // routes through `self.inner.core.transport_selector()` rather than dialing
    // `NativeRelayAdapter::connect_sourced` directly.
    //
    // Driven via `runtime().block_on(...)` from sync `#[test]` fns because the
    // bridge methods spawn / block on the bridge's own static runtime; a
    // `#[tokio::test]` would nest runtimes and panic.
    // -----------------------------------------------------------------------

    /// `Scp::transport_connect` must route through the instance selector and
    /// connect via WebSocket fallback against a relay that advertises no QUIC.
    #[cfg(feature = "server")]
    #[test]
    fn transport_connect_routes_through_selector_ws_fallback() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        // An in-memory relay serves no `.well-known/scp`; QUIC is never
        // advertised, so a selector-routed connect must fail open to WS.
        let relay = runtime()
            .block_on(scp.relay_start_in_memory())
            .expect("in-memory relay must start");
        let relay_url = relay.relay_url();

        let handle = runtime()
            .block_on(scp.transport_connect(relay_url))
            .expect("selector-routed connect to a no-QUIC relay must succeed via WS fallback");

        assert!(
            handle.is_connected(),
            "handle must report connected after selector-routed connect"
        );
        assert_eq!(handle.adapter_count(), 1);

        relay.shutdown();
    }

    /// `TransportManager::add_relay` must route through the instance selector
    /// and add a second WS-fallback adapter to the manager.
    #[cfg(feature = "server")]
    #[test]
    fn add_relay_routes_through_selector_ws_fallback() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let relay = runtime()
            .block_on(scp.relay_start_in_memory())
            .expect("in-memory relay must start");
        let relay_url = relay.relay_url();

        let handle = runtime()
            .block_on(scp.transport_connect(relay_url.clone()))
            .expect("initial selector-routed connect must succeed");
        assert_eq!(handle.adapter_count(), 1);

        // Invoke `add_relay` exactly as production does: it is a SYNC
        // `#[uniffi::export]` method, which UniFFI runs on the foreign caller
        // thread with NO ambient tokio runtime entered. Call it from a plain
        // `std::thread` that never enters/spawns on a runtime, so this test
        // genuinely exercises the sync production path. `add_relay` drives its
        // own connect via the bridge's static `runtime().block_on(...)` and
        // then spawns the suppression-scoring task on that same runtime handle.
        //
        // This is the regression guard for the suppression task's spawn: if it
        // reverts to a bare `tokio::spawn(...)`, that spawn runs after
        // `block_on` returns (when the runtime context is gone) and panics
        // ("there is no reactor running"), failing this test. The prior
        // `spawn_blocking` wrapper hid that panic by providing a runtime
        // context the real sync export never has.
        let add_handle = Arc::clone(&handle);
        let count = std::thread::spawn(move || add_handle.add_relay(relay_url))
            .join()
            .expect("add_relay thread must not panic — a panic here means the suppression task spawned without a runtime context")
            .expect("selector-routed add_relay to a no-QUIC relay must succeed via WS fallback");
        assert_eq!(
            count, 2,
            "second selector-routed adapter must be registered in the manager"
        );

        relay.shutdown();
    }

    /// `Scp::configure_relay_transport` must route through the instance selector
    /// and install a `RelayTransportProvider` over the WS-fallback adapter.
    #[cfg(feature = "server")]
    #[test]
    fn configure_relay_transport_routes_through_selector_ws_fallback() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let relay = runtime()
            .block_on(scp.relay_start_in_memory())
            .expect("in-memory relay must start");
        let relay_url = relay.relay_url();

        runtime()
            .block_on(
                scp.configure_relay_transport(
                    relay_url,
                    "did:dht:z6MkTestConfigureRelay".to_owned(),
                ),
            )
            .expect(
                "selector-routed configure_relay_transport to a no-QUIC relay must succeed via \
                 WS fallback and install a ContextManager",
            );

        assert!(
            scp.inner.core.has_supervisor(),
            "ContextManager must be attached after configure_relay_transport routes through \
             the selector"
        );

        relay.shutdown();
    }

    // -------------------------------------------------------------------
    // Bridge credential store lifecycle (§12.11)
    // -------------------------------------------------------------------

    #[test]
    fn parse_credential_type_variants() {
        assert!(matches!(
            parse_credential_type("ApiKey").unwrap(),
            CredentialType::ApiKey
        ));
        assert_eq!(
            parse_credential_type("Custom:discord").unwrap(),
            CredentialType::Custom("discord".to_owned())
        );
        assert!(parse_credential_type("Nope").is_err());
    }

    #[test]
    fn parse_credential_key_bytes_rejects_wrong_length() {
        assert!(parse_credential_key_bytes(&[0u8; 16]).is_err());
        assert!(parse_credential_key_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn credential_provision_retrieve_rotate_revoke_lifecycle() {
        let scp = scp_test();
        let bridge_id = "bridge-cred-uniffi-001".to_owned();
        let key = vec![9u8; 32];

        let provisioned = scp
            .bridge_credential_provision(
                bridge_id.clone(),
                "ApiKey".to_owned(),
                b"first-secret".to_vec(),
                key.clone(),
            )
            .unwrap();
        assert_eq!(provisioned.bridge_id, bridge_id);
        assert_eq!(provisioned.credential_type, "ApiKey");

        let retrieved = scp
            .bridge_credential_retrieve(bridge_id.clone(), "ApiKey".to_owned(), key.clone())
            .unwrap();
        assert_eq!(retrieved, b"first-secret");

        scp.bridge_credential_rotate(
            bridge_id.clone(),
            "ApiKey".to_owned(),
            b"second-secret".to_vec(),
            key.clone(),
        )
        .unwrap();
        let rotated = scp
            .bridge_credential_retrieve(bridge_id.clone(), "ApiKey".to_owned(), key.clone())
            .unwrap();
        assert_eq!(rotated, b"second-secret");

        let types = scp.bridge_credential_list(bridge_id.clone()).unwrap();
        assert_eq!(types, vec!["ApiKey".to_owned()]);

        scp.bridge_credential_revoke(bridge_id.clone()).unwrap();
        assert!(
            scp.bridge_credential_retrieve(bridge_id, "ApiKey".to_owned(), key)
                .is_err()
        );
    }

    #[test]
    fn credential_key_store_get_delete_lifecycle() {
        let scp = scp_test();
        let bridge_id = "bridge-cred-uniffi-002".to_owned();
        let key = vec![3u8; 32];

        scp.bridge_credential_store_key(bridge_id.clone(), key.clone())
            .unwrap();
        let got = scp.bridge_credential_get_key(bridge_id.clone()).unwrap();
        assert_eq!(got, key);

        scp.bridge_credential_delete_key(bridge_id.clone()).unwrap();
        assert!(scp.bridge_credential_get_key(bridge_id).is_err());
    }

    #[test]
    fn credential_store_is_per_instance() {
        let scp_a = scp_test();
        let scp_b = scp_test();
        let bridge_id = "bridge-cred-uniffi-003".to_owned();
        let key = vec![1u8; 32];

        scp_a
            .bridge_credential_provision(
                bridge_id.clone(),
                "ApiKey".to_owned(),
                b"only-in-a".to_vec(),
                key.clone(),
            )
            .unwrap();

        assert!(
            scp_b
                .bridge_credential_retrieve(bridge_id, "ApiKey".to_owned(), key)
                .is_err(),
            "credential provisioned on instance A must not be visible on instance B"
        );
    }

    #[test]
    fn petname_apply_event_and_counts_uniffi() {
        let scp = scp_test();
        let owner = "did:dht:zUniffiApply".to_owned();
        scp.petname_apply_event(
            owner.clone(),
            r#"{"SetPetname": {"did": "did:dht:zAlice", "name": "alice"}}"#.to_owned(),
        )
        .unwrap();
        assert_eq!(scp.petname_did_count(owner.clone()).unwrap(), 1);

        let json = scp
            .petname_resolve_did(owner.clone(), "alice".to_owned())
            .unwrap();
        let dids: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(dids, vec!["did:dht:zAlice".to_owned()]);

        scp.petname_apply_event(
            owner.clone(),
            r#"{"SetContextPetname": {"context_id": "ctx-1", "name": "work"}}"#.to_owned(),
        )
        .unwrap();
        assert_eq!(scp.petname_context_count(owner.clone()).unwrap(), 1);

        scp.petname_apply_event(
            owner.clone(),
            r#"{"RemovePetname": {"did": "did:dht:zAlice"}}"#.to_owned(),
        )
        .unwrap();
        assert_eq!(scp.petname_did_count(owner).unwrap(), 0);
    }

    #[test]
    fn petname_apply_event_rejects_malformed_uniffi() {
        let scp = scp_test();
        assert!(
            scp.petname_apply_event("did:dht:zOwner".to_owned(), "nope".to_owned())
                .is_err()
        );
    }

    #[test]
    fn petname_counts_empty_owner_errors_uniffi() {
        let scp = scp_test();
        assert!(scp.petname_did_count(String::new()).is_err());
        assert!(scp.petname_context_count(String::new()).is_err());
    }

    #[test]
    fn petname_malformed_owner_rejected_uniffi() {
        // Non-empty but syntactically invalid owner DIDs must be rejected by
        // the pre-existing petname ops, matching the strict `validate_did`
        // gate already enforced by the WASM bridge and the §4.7 ops.
        let scp = scp_test();
        let bad = "not-a-did".to_owned();
        assert!(
            scp.petname_set(bad.clone(), "did:dht:z1".to_owned(), "test".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_remove(bad.clone(), "did:dht:z1".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_set_context(bad.clone(), "ctx-1".to_owned(), "work".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_remove_context(bad.clone(), "ctx-1".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_resolve_did(bad.clone(), "alice".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_resolve_context(bad.clone(), "work".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_get_for_did(bad.clone(), "did:dht:z1".to_owned())
                .is_err()
        );
        assert!(
            scp.petname_get_for_context(bad, "ctx-1".to_owned())
                .is_err()
        );
    }

    /// `identity_remove` / `identity_remove_if_present` must reject a
    /// non-empty but syntactically invalid DID via the shared `validate_did`
    /// gate — matching the `PyO3` reference bridge — before touching the
    /// registry. A syntactically valid but absent DID is accepted as an
    /// idempotent no-op. Mirrors `petname_malformed_owner_rejected_uniffi`.
    #[cfg(feature = "allow_in_memory_custody")]
    #[test]
    fn identity_remove_malformed_did_rejected_uniffi() {
        let scp = scp_test();
        let bad = "not-a-did".to_owned();
        assert!(
            scp.identity_remove(bad.clone()).is_err(),
            "identity_remove must reject a malformed DID"
        );
        assert!(
            scp.identity_remove_if_present(bad).is_err(),
            "identity_remove_if_present must reject a malformed DID"
        );

        // Accept side: a valid but unregistered DID is a no-op success.
        let valid_absent = "did:dht:z6MkNeverRegisteredIdentityForRemoveTest".to_owned();
        scp.identity_remove(valid_absent.clone())
            .expect("valid DID must not be rejected by identity_remove");
        assert!(
            !scp.identity_remove_if_present(valid_absent)
                .expect("valid DID must not be rejected by identity_remove_if_present"),
            "removing an unregistered DID must report false"
        );
    }

    /// A freshly created in-memory identity must be present in the custody
    /// registry so `identity_remove_if_present` reports `true` on first
    /// removal and `false` on the second — matching the NAPI bridge whose
    /// `identity_create` registers a bundled entry. Pins the §4.1 port-gap
    /// fix: before it, `identity_create` never populated the registry, so a
    /// created identity reported `false`. Also exercises the unconditional
    /// `identity_remove` on a separately created identity.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(feature = "allow_in_memory_custody")]
    async fn identity_remove_if_present_reports_presence() {
        let scp = scp_test();

        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create");
        let did = identity.did();

        // First removal of a freshly created identity must report presence.
        assert!(
            scp.identity_remove_if_present(did.clone())
                .expect("identity_remove_if_present must accept a valid DID"),
            "a freshly created in-memory identity must be present in the \
             custody registry and report true on first removal"
        );

        // Second removal must report absence (idempotent).
        assert!(
            !scp.identity_remove_if_present(did)
                .expect("identity_remove_if_present must accept a valid DID"),
            "removing an already-removed identity must report false"
        );

        // The unconditional `identity_remove` must succeed on a fresh,
        // separately created identity.
        let other = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create (second identity)");
        scp.identity_remove(other.did())
            .expect("identity_remove must succeed on a registered identity");
    }

    // -----------------------------------------------------------------------
    // Checkpoint sender_did ↔ signing-identity binding
    //
    // The UniFFI bridge has no DID-keyed identity registry, so the recorded
    // `sender_did` is bound to the signing `Identity` explicitly inside
    // `event_log_checkpoint_by_did_impl` (the `did != identity.did` guard).
    // Without it a caller could record a checkpoint as signed by an arbitrary
    // DID while signing with an unrelated identity's key — a provenance
    // forgery. These tests pin that guard so a future re-order or removal of
    // the binding check breaks here rather than at the Swift/Kotlin boundary.
    // -----------------------------------------------------------------------

    /// A `did` that differs from the signing identity's own DID must be
    /// rejected with `SCP-VALID-7000`, and the matching `did` must succeed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(feature = "allow_in_memory_custody")]
    async fn checkpoint_by_did_binds_recorded_sender_to_signing_identity() {
        let scp = scp_test();
        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create");
        let handle = test_handle_for(&scp);

        // Mismatch: a different, syntactically valid DID is rejected because it
        // does not match the signing identity's DID.
        let foreign_did = "did:dht:z6MkForeignSignerThatIsNotTheIdentity".to_owned();
        assert_ne!(foreign_did, identity.did);
        let mismatch = scp
            .event_log_checkpoint_by_did(Arc::clone(&handle), Arc::clone(&identity), foreign_did, 0)
            .await;
        match mismatch {
            Err(ScpError::Validation { code, .. }) => {
                assert_eq!(
                    code,
                    codes::VALID_7000,
                    "sender_did != identity.did must surface SCP-VALID-7000"
                );
            }
            other => panic!("expected ScpError::Validation (VALID_7000), got {other:?}"),
        }

        // Happy path: did == identity.did succeeds and the produced checkpoint
        // is attributed to (and signed by) that same identity.
        let own_did = identity.did();
        let checkpoint = scp
            .event_log_checkpoint_by_did(handle, Arc::clone(&identity), own_did.clone(), 0)
            .await
            .expect("checkpoint with matching did must succeed");
        assert_eq!(
            checkpoint.sender_did, own_did,
            "the checkpoint must be attributed to the signing identity's DID"
        );
        assert!(
            !checkpoint.signature.is_empty(),
            "a successful checkpoint must carry a signature"
        );
    }

    // ----- Missing-signing-custody → SCP-IDENT-1017 -----
    //
    // A context handle / identity that retains no custody (externally loaded:
    // `in_memory_custody`, `signing_key`, `callback_custody` all `None`) must
    // reject UCAN mint, UCAN delegate, and event-log checkpoint with the
    // canonical missing-signing-custody code — not an overloaded
    // permission/nonce code.

    #[tokio::test]
    async fn ucan_mint_without_retained_custody_returns_ident_1017() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);

        let result = ucan_mint_impl(
            handle,
            "did:dht:z6MkMember".to_owned(),
            vec!["messages:write".to_owned()],
            None,
        )
        .await;
        let Err(err) = result else {
            panic!("mint without retained custody must fail")
        };
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1017),
            "expected SCP-IDENT-1017, got: {err_str}"
        );
    }

    #[tokio::test]
    async fn ucan_delegate_without_retained_custody_returns_ident_1017() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);

        // The handle-borne custody check fires before any parent-token parsing.
        let result = ucan_delegate_impl(
            handle,
            "did:dht:z6MkDelegator".to_owned(),
            "did:dht:z6MkDelegatee".to_owned(),
            "header.payload.signature".to_owned(),
            vec!["messages:write".to_owned()],
        )
        .await;
        let Err(err) = result else {
            panic!("delegate without retained custody must fail")
        };
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1017),
            "expected SCP-IDENT-1017, got: {err_str}"
        );
    }

    #[tokio::test]
    async fn event_log_checkpoint_without_retained_custody_returns_ident_1017() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        let identity = test_identity_for(&scp);

        let result =
            event_log_checkpoint_impl(Arc::clone(&scp.inner), handle, identity, 1u64).await;
        let Err(err) = result else {
            panic!("checkpoint without retained custody must fail")
        };
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1017),
            "expected SCP-IDENT-1017, got: {err_str}"
        );
    }

    #[tokio::test]
    async fn broadcast_publish_without_retained_custody_returns_ident_1017() {
        let scp = scp_test();
        let handle = test_handle_for(&scp);
        // `test_identity_for` builds an externally-loaded identity
        // (`core_id: None`), so broadcast publish trips the missing
        // signing-custody gate before reaching the relay.
        let identity = test_identity_for(&scp);

        let result = scp
            .broadcast_publish(handle, identity, b"hello".to_vec())
            .await;
        let Err(err) = result else {
            panic!("broadcast publish without retained custody must fail")
        };
        let err_str = err.to_string();
        assert!(
            err_str.contains(codes::IDENT_1017),
            "expected SCP-IDENT-1017, got: {err_str}"
        );
    }
}
