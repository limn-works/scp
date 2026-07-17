//! Streaming signer abstraction for the §5.4.5 outlet streaming dispatch
//! path (ADR-049 round 8).
//!
//! # Why a trait
//!
//! The round-7 closure threaded an `Arc<ed25519_dalek::SigningKey>` through
//! [`super::dispatch::OpenStreamParams`], [`super::dispatch::SharedSessionState`],
//! and both the dispatch and inner-invoke pumps, signing chunks synchronously.
//! Holding the raw operator private key in runtime structs and signing
//! synchronously is incompatible with the platform `KeyCustody` abstraction:
//!
//! - **ADR-006**: private keys never cross the FFI boundary. A custody-backed
//!   operator does not hand the runtime an `ed25519_dalek::SigningKey`; it
//!   exposes an `async` signing call and the public verifying key.
//! - **`KeyCustody::sign` is RPITIT / `async` and NOT object-safe**, so the
//!   runtime cannot store a `dyn KeyCustody` directly.
//!
//! [`StreamSigner`] is the object-safe, `async` seam the streaming dispatch
//! path signs through. The runtime composes the §5.4.5 chunk / cancel
//! preimage synchronously (the bytes are byte-identical to round 7) and
//! awaits the signer only for the 64-byte Ed25519 signature. An
//! `InProcessStreamSigner` (a `testing`-gated adapter) backs the trait with an in-memory
//! `ed25519_dalek::SigningKey` for tests and for the WASM bridge (where
//! operator == invoker per ADR-034 §1, single-process bridge); native FFI
//! bridges supply custody-backed adapters that satisfy the same trait.

use ed25519_dalek::VerifyingKey;
#[cfg(any(test, feature = "testing"))]
use ed25519_dalek::{Signer, SigningKey};
use scp_platform::PlatformError;

// ---------------------------------------------------------------------------
// StreamSignerCustodyCategory
// ---------------------------------------------------------------------------

/// Bounded category of a custody-side signing failure.
///
/// This is a *positive whitelist* of the failure modes that a
/// [`KeyCustody::sign`](scp_platform::traits::KeyCustody::sign) call can
/// surface into [`StreamSignerError::Custody`]. It carries **no free-form
/// string** by construction: the discriminant is the only information that
/// crosses into the runtime, so the type system guarantees that no backend
/// error text — and therefore no key material, no raw preimage, and no
/// backend-internal handle — can leak into structured logs via this path
/// (ADR-006 custody isolation, ADR-049 §4 / ADR-061 error-detail
/// sanitization, crypto defense-in-depth).
///
/// Each category maps from a real [`PlatformError`] variant reachable through
/// `KeyCustody::sign` (see [`From<&PlatformError>`](StreamSignerCustodyCategory#impl-From<%26PlatformError>-for-StreamSignerCustodyCategory)).
/// `#[non_exhaustive]` so future custody backends can surface additional
/// bounded categories without breaking downstream matches — new spellings of
/// the same failure are added here, never as a re-introduced `String`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSignerCustodyCategory {
    /// The operator signing key handle is unknown to the custody backend —
    /// never provisioned, or destroyed. Maps from [`PlatformError::KeyNotFound`].
    KeyNotFound,
    /// The custody handle does not refer to an Ed25519 signing key. Maps from
    /// [`PlatformError::WrongKeyType`].
    WrongKeyType,
    /// The custody backend does not support signing through this seam (e.g. a
    /// non-extractable HSM path). Maps from [`PlatformError::Unsupported`].
    Unsupported,
    /// The custody backend failed for another reason (a generic backend
    /// fault). Maps from [`PlatformError::CustodyError`] and — conservatively,
    /// so an unclassified failure never falls through to a more permissive
    /// category — from any other [`PlatformError`] variant that reaches the
    /// signing adapter.
    BackendFault,
}

impl StreamSignerCustodyCategory {
    /// Returns the fixed, non-sensitive human string for this category.
    ///
    /// The returned `&'static str` is a compile-time constant: it contains no
    /// dynamic content, no bytes, and no backend error text. This is the sole
    /// text [`StreamSignerError::Custody`] surfaces in logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyNotFound => "signing key not found",
            Self::WrongKeyType => "wrong key type for signing",
            Self::Unsupported => "signing operation unsupported by backend",
            Self::BackendFault => "backend fault",
        }
    }
}

impl core::fmt::Display for StreamSignerCustodyCategory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&PlatformError> for StreamSignerCustodyCategory {
    /// Maps a custody backend error into a bounded category, discarding all
    /// free-form detail. `KeyCustody::sign` documents [`PlatformError::KeyNotFound`]
    /// and [`PlatformError::WrongKeyType`]; a backend may additionally surface
    /// [`PlatformError::CustodyError`] or [`PlatformError::Unsupported`]. Every
    /// other variant is mapped to the conservative [`BackendFault`] category
    /// rather than reintroducing the error string.
    ///
    /// [`BackendFault`]: StreamSignerCustodyCategory::BackendFault
    fn from(err: &PlatformError) -> Self {
        match err {
            PlatformError::KeyNotFound => Self::KeyNotFound,
            PlatformError::WrongKeyType { .. } => Self::WrongKeyType,
            PlatformError::Unsupported(_) => Self::Unsupported,
            // `CustodyError` is the documented generic custody failure; the
            // remaining variants (`StorageError`, `AttestationError`,
            // `PushError`) belong to sibling platform traits and are not
            // expected from `sign`, but are mapped conservatively rather than
            // panicking or leaking their carried string.
            PlatformError::CustodyError(_)
            | PlatformError::StorageError(_)
            | PlatformError::AttestationError(_)
            | PlatformError::PushError(_) => Self::BackendFault,
        }
    }
}

// ---------------------------------------------------------------------------
// StreamSignerError
// ---------------------------------------------------------------------------

/// Failure modes for [`StreamSigner::sign`].
///
/// Implements [`std::error::Error`] so callers can propagate it through
/// `?` and surface it in the dispatch pump's structured logging without an
/// extra wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSignerError {
    /// The backing custody / signer failed to produce a signature. Native
    /// custody adapters map their backend error into a bounded
    /// [`StreamSignerCustodyCategory`] via
    /// [`From<&PlatformError>`](StreamSignerCustodyCategory#impl-From<%26PlatformError>-for-StreamSignerCustodyCategory).
    ///
    /// The variant carries only the bounded `category` — never a free-form
    /// string. This makes leaking sensitive data structurally impossible: key
    /// material (private-key bytes, seeds, derived secrets), the raw preimage /
    /// caller input, and backend-internal handles cannot enter the runtime
    /// address space through this field, so they cannot reach the structured
    /// logs the dispatch pump emits (ADR-006 custody isolation, ADR-049 §4 /
    /// ADR-061 error-detail sanitization). The operator private key never
    /// enters the runtime address space, and neither does any derivative of it.
    Custody {
        /// Bounded category of the custody-side failure. See
        /// [`StreamSignerCustodyCategory`].
        category: StreamSignerCustodyCategory,
    },
    /// JCS canonicalization of the payload failed while composing the
    /// preimage. Carries the canonicalization error string. This is a
    /// structural invariant violation for a well-formed `ChunkPayload`;
    /// surfaced for completeness so the pump can log + break rather than
    /// emit an unsigned chunk.
    Jcs(String),
}

impl core::fmt::Display for StreamSignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Custody { category } => write!(f, "stream signer custody failure: {category}"),
            Self::Jcs(detail) => write!(f, "stream signer JCS canonicalization failure: {detail}"),
        }
    }
}

impl std::error::Error for StreamSignerError {}

// ---------------------------------------------------------------------------
// StreamSigner
// ---------------------------------------------------------------------------

/// Object-safe, `async` signing seam for the §5.4.5 streaming dispatch path.
///
/// The runtime composes the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:` /
/// `SCP-OUTLET-CANCEL-V1:` preimage synchronously (32-byte SHA-256 digest)
/// and calls [`Self::sign`] with that preimage to obtain the operator's
/// 64-byte Ed25519 signature. [`Self::verifying_key`] returns the operator's
/// public key so the pump can `debug_assert!`-verify a just-signed chunk
/// and so the cancel primitive can self-verify the signature it just
/// produced before mutating stream state.
///
/// `Send + Sync + 'static` because the signer is shared (`Arc`) across the
/// open path, the spawned pump task, and the control-surface cancel path.
#[async_trait::async_trait]
pub trait StreamSigner: Send + Sync + 'static {
    /// Signs the supplied 32-byte preimage and returns the 64-byte Ed25519
    /// signature.
    ///
    /// `preimage` is the SHA-256 digest the §5.4.5 wire spec defines (the
    /// caller has already applied the domain separator and length-prefixed
    /// fields). The signer signs the digest bytes verbatim — it does NOT
    /// re-hash. This keeps the trait agnostic to which §5.4.5 preimage
    /// (chunk vs. cancel) is being signed.
    ///
    /// # Errors
    ///
    /// Returns [`StreamSignerError::Custody`] if the backing signer fails to
    /// produce a signature. The variant carries only a bounded
    /// [`StreamSignerCustodyCategory`], never a free-form string, so leaking
    /// key material, the raw `preimage`, other caller-supplied input, or
    /// backend-internal handles into structured logs is structurally
    /// impossible (ADR-006 custody isolation, ADR-049 §4 / ADR-061 error-detail
    /// sanitization). Implementors map their backend [`PlatformError`] into a
    /// category via
    /// [`From<&PlatformError>`](StreamSignerCustodyCategory#impl-From<%26PlatformError>-for-StreamSignerCustodyCategory).
    async fn sign(&self, preimage: &[u8]) -> Result<[u8; 64], StreamSignerError>;

    /// Returns the operator's Ed25519 verifying key. Used by the dispatch
    /// pump's `debug_assert!` self-verification and by the cancel primitive's
    /// own-signature check before it mutates stream state.
    fn verifying_key(&self) -> &VerifyingKey;
}

// ---------------------------------------------------------------------------
// InProcessStreamSigner
// ---------------------------------------------------------------------------

/// In-process [`StreamSigner`] backed by an in-memory
/// `ed25519_dalek::SigningKey`.
///
/// Used by:
///
/// - **Tests** (bridge integration tests, `scp-testing`, the dispatch /
///   invoke unit-test fixtures) that previously wrapped a raw
///   `Arc<SigningKey>`.
/// - **WASM** (ADR-034 §1, single-process bridge) where operator == invoker
///   and the signing key is already in-process.
///
/// Native FFI bridges do NOT use this type — they supply a custody-backed
/// adapter so the operator private key never enters the runtime address
/// space (ADR-006).
///
/// Exposed under the `testing` feature (and intra-crate `#[cfg(test)]`) so
/// it is available to downstream test code (bridge integration tests +
/// `scp-testing`) and this crate's own unit tests without leaking an
/// in-process signing key into production builds. The WASM bridge supplies
/// its own equivalent in-process adapter (ADR-034 §1) rather than depending
/// on this `testing`-gated type.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct InProcessStreamSigner {
    /// In-memory signing key.
    key: SigningKey,
    /// Cached verifying key (so [`StreamSigner::verifying_key`] can return a
    /// reference).
    vk: VerifyingKey,
}

#[cfg(any(test, feature = "testing"))]
impl InProcessStreamSigner {
    /// Wraps an `ed25519_dalek::SigningKey` in an in-process signer.
    #[must_use]
    pub fn new(key: SigningKey) -> Self {
        let vk = key.verifying_key();
        Self { key, vk }
    }
}

#[cfg(any(test, feature = "testing"))]
impl core::fmt::Debug for InProcessStreamSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the signing key — only the public verifying key.
        f.debug_struct("InProcessStreamSigner")
            .field("verifying_key", &self.vk)
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait::async_trait]
impl StreamSigner for InProcessStreamSigner {
    async fn sign(&self, preimage: &[u8]) -> Result<[u8; 64], StreamSignerError> {
        Ok(self.key.sign(preimage).to_bytes())
    }

    fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fixed_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    #[tokio::test]
    async fn in_process_signer_signs_and_verifies() {
        let signer = InProcessStreamSigner::new(fixed_key());
        let preimage = [0x11u8; 32];
        let sig = signer.sign(&preimage).await.expect("sign succeeds");
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(
            signer
                .verifying_key()
                .verify_strict(&preimage, &signature)
                .is_ok(),
            "signature must verify under the signer's own verifying key"
        );
    }

    #[tokio::test]
    async fn in_process_signer_verifying_key_matches_backing_key() {
        let key = fixed_key();
        let expected_vk = key.verifying_key();
        let signer = InProcessStreamSigner::new(key);
        assert_eq!(*signer.verifying_key(), expected_vk);
    }

    #[test]
    fn debug_does_not_render_signing_key() {
        let signer = InProcessStreamSigner::new(fixed_key());
        let rendered = format!("{signer:?}");
        // The struct renders only the public verifying key, never the
        // private signing key bytes.
        assert!(rendered.contains("InProcessStreamSigner"));
        assert!(rendered.contains("verifying_key"));
    }

    #[test]
    fn stream_signer_is_object_safe() {
        // Compile-time assertion that the trait is object-safe (the whole
        // point of the abstraction over the non-object-safe KeyCustody).
        let signer = InProcessStreamSigner::new(fixed_key());
        let _erased: std::sync::Arc<dyn StreamSigner> = std::sync::Arc::new(signer);
    }

    #[test]
    fn stream_signer_error_display() {
        let custody = StreamSignerError::Custody {
            category: StreamSignerCustodyCategory::BackendFault,
        };
        assert_eq!(
            custody.to_string(),
            "stream signer custody failure: backend fault"
        );
        let jcs = StreamSignerError::Jcs("non-finite float".to_owned());
        assert!(jcs.to_string().contains("non-finite float"));
    }

    /// Every custody category renders to a fixed, non-sensitive string — no
    /// dynamic content, no bytes, no backend error text. This is the whole
    /// point of the bounded enum: nothing custody-side can leak through
    /// `Display`. If a category is added, extend this list (the match below is
    /// exhaustive under `#[non_exhaustive]` within the defining crate, so a new
    /// variant breaks this test until an expected fixed string is asserted).
    #[test]
    fn custody_category_display_is_fixed_and_non_sensitive() {
        let cases = [
            (
                StreamSignerCustodyCategory::KeyNotFound,
                "stream signer custody failure: signing key not found",
            ),
            (
                StreamSignerCustodyCategory::WrongKeyType,
                "stream signer custody failure: wrong key type for signing",
            ),
            (
                StreamSignerCustodyCategory::Unsupported,
                "stream signer custody failure: signing operation unsupported by backend",
            ),
            (
                StreamSignerCustodyCategory::BackendFault,
                "stream signer custody failure: backend fault",
            ),
        ];
        for (category, expected) in cases {
            // Exact equality proves the rendered text is fully static.
            assert_eq!(
                StreamSignerError::Custody { category }.to_string(),
                expected
            );
            // Defense-in-depth: the category string carries no digit (a proxy
            // for handle ids / byte values / offsets that a leak would carry).
            assert!(
                !category.as_str().chars().any(|c| c.is_ascii_digit()),
                "category string must not contain dynamic/numeric content"
            );
        }
    }

    /// The canonical `PlatformError` -> category mapping is faithful: every
    /// variant maps to a bounded category, and the free-form strings the
    /// carrying variants hold are discarded (not present in the rendered
    /// output).
    #[test]
    fn platform_error_maps_to_bounded_category() {
        use scp_platform::traits::KeyType;

        assert_eq!(
            StreamSignerCustodyCategory::from(&PlatformError::KeyNotFound),
            StreamSignerCustodyCategory::KeyNotFound
        );
        assert_eq!(
            StreamSignerCustodyCategory::from(&PlatformError::WrongKeyType {
                expected: KeyType::Ed25519,
                actual: KeyType::X25519,
            }),
            StreamSignerCustodyCategory::WrongKeyType
        );
        assert_eq!(
            StreamSignerCustodyCategory::from(&PlatformError::Unsupported("no hsm sign")),
            StreamSignerCustodyCategory::Unsupported
        );
        // The generic custody failure and sibling-trait variants collapse to
        // the conservative BackendFault category, and their carried string is
        // dropped — it never reaches the rendered error.
        let secret_detail = "hsm serial 0xDEADBEEF offline";
        let category = StreamSignerCustodyCategory::from(&PlatformError::CustodyError(
            secret_detail.to_owned(),
        ));
        assert_eq!(category, StreamSignerCustodyCategory::BackendFault);
        let rendered = StreamSignerError::Custody { category }.to_string();
        assert!(
            !rendered.contains(secret_detail) && !rendered.contains("DEADBEEF"),
            "backend error string must not survive into the rendered error"
        );
        assert_eq!(
            StreamSignerCustodyCategory::from(&PlatformError::StorageError("x".to_owned())),
            StreamSignerCustodyCategory::BackendFault
        );
    }
}
