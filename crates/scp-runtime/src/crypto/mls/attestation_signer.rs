//! The two custody-backed ports the `KeyPackage`-attestation paths need.
//!
//! [`KeyPackageAttestationSigner`] serves the mint side and
//! [`DidDocumentResolver`] serves the verify side (§9.7.1; ADR-057 Amendment
//! 2026-08-01).
//!
//! Both traits exist for the same reason: the concrete capability behind each
//! one is **not** `dyn`-compatible, so the runtime cannot store it directly.
//! `scp_platform::KeyCustody::sign` and `scp_identity::resolver::DidResolver::resolve`
//! both return `impl Future` (RPITIT), which forbids `Arc<dyn KeyCustody>` and
//! `Arc<dyn DidResolver>`. The runtime holds an `Arc` of the erasing trait
//! instead, and each FFI bridge implements it over the custody or resolver it
//! already owns — the same construction
//! [`StreamSigner`](crate::context::outlets::signer::StreamSigner) uses for
//! §5.4.5 outlet-stream chunks.
//!
//! # Why the signer binds its identity at construction
//!
//! One [`KeyPackageAttestationSigner`] signs for exactly one identity acting as
//! exactly one verification method. `KeyPackageStoreActor` owns one pool per
//! local identity, so a per-identity signer matches the actor's scope, and
//! [`KeyPackageAttestationSigner::signing_key_id`] is the value the actor
//! stamps into the leaf's `ScpCredential`. §9.7.1 check 10 requires the
//! credential and the attestation to name the **same** verification method;
//! reading both from this one port makes them agree by construction rather
//! than by convention.
//!
//! # Custody never crosses the actor mailbox
//!
//! `Supervisor` documents why a `KeyCustody` value cannot travel through an
//! actor command. These ports do not change that: the supervisor registers an
//! `Arc<dyn KeyPackageAttestationSigner>` per identity **before** spawning the
//! `KeyPackage` actor, the actor holds the `Arc`, and each mint awaits
//! [`sign_attestation`](KeyPackageAttestationSigner::sign_attestation) inside
//! its own handler.

use scp_did::{DidDocument, SigningKeyId};

/// Why a [`KeyPackageAttestationSigner`] could not produce a signature.
///
/// The variants carry no key material and no custody-internal detail, because
/// the value reaches an SDK caller through `MlsError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationSignerError {
    /// The custody backend refused or failed the signing operation.
    #[error("attestation signing failed: {0}")]
    SigningFailed(String),

    /// The custody backend holds no key at the verification method this signer
    /// names, so the attestation cannot be signed by it.
    #[error("no custody key for verification method {0}")]
    KeyUnavailable(SigningKeyId),
}

/// Signs a `KeyPackage` attestation with one identity's `#active`/`#agent`
/// custody key (§9.7.1; §9.5.2).
///
/// Implementors bind the DID and the verification method at construction, so a
/// single value signs for one identity acting as one persona.
#[async_trait::async_trait]
pub trait KeyPackageAttestationSigner: Send + Sync + 'static {
    /// Which verification method this signer acts as — `#active` for a
    /// human-initiated join, `#agent` for an agent-initiated one (ADR-039).
    /// `#0` is never used for an attestation: §9.7.1 classes attestation
    /// issuance as a Category-B operational action.
    fn signing_key_id(&self) -> SigningKeyId;

    /// Returns the Ed25519 signature over the 32-byte §9.5.1 signing hash.
    ///
    /// The signature covers **these 32 bytes** and nothing else — not the
    /// canonical preimage, and not the `0xFF03` extension body (§9.5.2).
    ///
    /// # Errors
    ///
    /// Returns [`AttestationSignerError`] when custody refuses the operation or
    /// holds no key at [`signing_key_id`](Self::signing_key_id).
    async fn sign_attestation(
        &self,
        signing_hash: &[u8; 32],
    ) -> Result<[u8; 64], AttestationSignerError>;
}

/// Why a [`DidDocumentResolver`] could not return a document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidDocumentResolveError {
    /// Resolution ran and failed — a DHT timeout, an unreachable `did:web`
    /// authority, a TLS failure, or any other transport-level error.
    #[error("DID resolution failed: {0}")]
    Failed(String),
}

/// Resolves a DID to its current document for the §9.7.1 attestation
/// current-key check (checks 1–2).
///
/// This is the `dyn`-safe face of `scp_identity::resolver::DidResolver`, whose
/// own `resolve` returns `impl Future` and therefore cannot be stored as a
/// trait object. Each FFI bridge implements this over the canonical resolver it
/// already owns (§3.10.4 dual-layer resolution), and the runtime stores the
/// result as `Arc<dyn DidDocumentResolver>`.
///
/// An implementor MUST return a **freshly resolved** document: §9.7.1 check 2
/// bounds the resolving document's age at
/// [`MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`](scp_mls::MAX_ATTESTATION_KEY_RESOLUTION_STALENESS)
/// (300 seconds), and §9.7.1's "Resolution failure policy" forbids serving a
/// stale or pre-rotation cached document in place of a failed resolution.
#[async_trait::async_trait]
pub trait DidDocumentResolver: Send + Sync + 'static {
    /// Resolves `did` to its current document.
    ///
    /// Returns `Ok(None)` when resolution succeeded and no document exists,
    /// which the Add path treats as a reject exactly like an error (§9.7.1
    /// "New member (Add) — fail-closed, no stale fallback").
    ///
    /// # Errors
    ///
    /// Returns [`DidDocumentResolveError`] when resolution itself fails.
    async fn resolve_document(
        &self,
        did: &str,
    ) -> Result<Option<DidDocument>, DidDocumentResolveError>;
}

// ---------------------------------------------------------------------------
// Testing-only signer
// ---------------------------------------------------------------------------

/// A [`KeyPackageAttestationSigner`] backed by a caller-held Ed25519 key.
///
/// A test needs a real signature over the §9.5.1 signing hash so the minted
/// leaf carries a well-formed `0xFF03` extension, and it has no custody
/// backend to produce one. This signs with a key the test generated, which
/// makes the resulting attestation verifiable against a DID document the test
/// also controls.
///
/// This is not a stand-in for [`CustodyAttestationSigner`]. It is gated on
/// `testing`, so no shipped artifact carries it, and no production path can
/// name it: a production caller reaches the identity key through
/// `KeyCustody::sign` by way of the FFI bridge's own implementor, and a
/// production path with no signer fails closed rather than reaching for this.
///
/// [`CustodyAttestationSigner`]: https://docs.rs/scp-ffi-common
#[cfg(any(test, feature = "testing"))]
pub struct TestAttestationSigner {
    signing_key: ed25519_dalek::SigningKey,
    signing_key_id: SigningKeyId,
}

#[cfg(any(test, feature = "testing"))]
impl TestAttestationSigner {
    /// Builds a signer that acts as `signing_key_id` and signs with
    /// `signing_key`.
    #[must_use]
    pub const fn new(signing_key: ed25519_dalek::SigningKey, signing_key_id: SigningKeyId) -> Self {
        Self {
            signing_key,
            signing_key_id,
        }
    }

    /// Builds a signer over a freshly generated key, acting as `#active`.
    ///
    /// Returns the signer and its verifying key, so a test can put that key
    /// into the DID document the §9.7.1 current-key check resolves.
    #[must_use]
    pub fn generate() -> (Self, ed25519_dalek::VerifyingKey) {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public = key.verifying_key();
        (Self::new(key, SigningKeyId::Active), public)
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait::async_trait]
impl KeyPackageAttestationSigner for TestAttestationSigner {
    fn signing_key_id(&self) -> SigningKeyId {
        self.signing_key_id
    }

    async fn sign_attestation(
        &self,
        signing_hash: &[u8; 32],
    ) -> Result<[u8; 64], AttestationSignerError> {
        use ed25519_dalek::Signer as _;
        Ok(self.signing_key.sign(signing_hash).to_bytes())
    }
}

/// A [`DidDocumentResolver`] that answers every DID with one document naming
/// `active_key` as its `#active` verification method.
///
/// §9.7.1 checks 1 and 2 resolve the signer's document to learn the key the
/// attestation must verify against, and the Add path fails closed when no
/// resolver is wired. A test that mints through [`TestAttestationSigner`] pairs
/// that signer's verifying key with this resolver, so the check reads the key
/// the test actually signed with.
///
/// It answers every DID with the same document, which is what makes it a test
/// double rather than a resolver: it performs no resolution, verifies no BEP44
/// signature, and enforces no staleness bound. It is gated on `testing`, so no
/// shipped artifact carries it, and the production Add path reaches the real
/// resolver each FFI bridge owns.
#[cfg(any(test, feature = "testing"))]
pub struct TestDidDocumentResolver {
    active_key: [u8; 32],
}

#[cfg(any(test, feature = "testing"))]
impl TestDidDocumentResolver {
    /// Builds a resolver whose document names `active_key` as `#active`.
    #[must_use]
    pub const fn new(active_key: [u8; 32]) -> Self {
        Self { active_key }
    }

    /// Builds a signer and a resolver that agree on one freshly generated key.
    ///
    /// Pairing the two at construction is what keeps §9.7.1 check 1 satisfied:
    /// the key the signer signs with is the key the resolved document names.
    #[must_use]
    pub fn paired_with_signer() -> (TestAttestationSigner, Self) {
        let (signer, public) = TestAttestationSigner::generate();
        let resolver = Self::new(public.to_bytes());
        (signer, resolver)
    }
}

#[cfg(any(test, feature = "testing"))]
#[async_trait::async_trait]
impl DidDocumentResolver for TestDidDocumentResolver {
    async fn resolve_document(
        &self,
        did: &str,
    ) -> Result<Option<DidDocument>, DidDocumentResolveError> {
        // The identity key and the pre-rotation commitment take fixed values:
        // §9.7.1 checks 1 and 2 read the `#active` entry, and no check this
        // resolver serves reads either of the other two.
        let identity_key = [0x11_u8; 32];
        let commitment = [0u8; 32];
        Ok(Some(DidDocument::new(
            did,
            &identity_key,
            &self.active_key,
            &commitment,
        )))
    }
}
