//! On-device identity for the participant driver.
//!
//! The [`Signer`] trait abstracts the participant's DID identity — the DID
//! string and which verification-method key ([`SigningKeyId`]) it acts as. The
//! driver uses it to construct the [`ScpCredential`](scp_mls::ScpCredential)
//! embedded in MLS leaf nodes, so every MLS leaf (and every event-log leaf the
//! driver appends) traces to the on-device human/agent DID.
//!
//! For the Slice-2 MVP the concrete impl is [`LocalSigner`], a plain struct
//! holding the DID and key id. It is a trait — not a concrete type — precisely
//! so a later slice can slot in a WebCrypto-callback custody backend (the key
//! stays in JS/WebCrypto and never enters wasm memory, per ADR-057 component 3)
//! without changing the driver.
//!
//! # Scope note (ADR-057)
//!
//! The ed25519 MLS signing key pair used for the MLS protocol itself is
//! generated and held inside `scp-mls` (`generate_key_package` /
//! `create_group`). This [`Signer`] models the *SCP DID* identity layer above
//! it; the two are bridged through the `ScpCredential`. A future custody slice
//! unifies them behind one on-device key boundary.

use scp_did::SigningKeyId;

/// The participant's on-device DID identity.
///
/// Implementations supply the DID string and the verification-method key id
/// the participant acts as. They are cheap to clone-by-reference and are
/// expected to be held behind an `Arc<dyn Signer>` in the driver.
pub trait Signer: Send + Sync {
    /// The participant's DID string (e.g. `did:dht:z6Mk…`).
    fn did(&self) -> &str;

    /// Which verification-method key this signer acts as.
    fn signing_key_id(&self) -> SigningKeyId;

    /// Signs the 32-byte §9.5.1 signing hash of a `KeyPackage` attestation with
    /// this identity's `#active`/`#agent` key.
    ///
    /// §9.7.1 binds an MLS leaf to its DID through a `0xFF03`
    /// `scp_keypackage_attestation` extension carrying this signature, and
    /// every `Add` verifier rejects a leaf that carries none. This is the
    /// on-device signing boundary ADR-057's 2026-08-01 amendment names when it
    /// says a browser client "joins with an attestation minted by a
    /// custody-capable surface".
    ///
    /// Returns `None` when this backend holds no such key. The driver then
    /// refuses to mint a `KeyPackage` at all rather than publishing an
    /// unattested leaf, so a backend that cannot sign costs the participant the
    /// ability to join and never costs a verifier its guarantee.
    ///
    /// The signature covers **these 32 bytes** and nothing else — not the
    /// canonical preimage, and not the `0xFF03` extension body (§9.5.2).
    fn sign_key_package_attestation(&self, signing_hash: &[u8; 32]) -> Option<[u8; 64]>;
}

/// In-memory [`Signer`] for the MVP driver.
///
/// Holds the DID string and [`SigningKeyId`] directly. This is the
/// development/test identity backend; a production browser client supplies a
/// WebCrypto-callback custody backend instead (ADR-057 component 3).
#[derive(Clone)]
pub struct LocalSigner {
    did: String,
    signing_key_id: SigningKeyId,
    /// The Ed25519 key that signs this identity's `KeyPackage` attestations.
    ///
    /// `None` on a signer built by [`LocalSigner::new`] or
    /// [`LocalSigner::active`], because neither is given key material. A driver
    /// holding such a signer cannot mint a `KeyPackage` and refuses to try.
    attestation_key: Option<ed25519_dalek::SigningKey>,
}

impl core::fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The attestation key is private key material, so this reports whether
        // one is present and never its bytes.
        f.debug_struct("LocalSigner")
            .field("did", &self.did)
            .field("signing_key_id", &self.signing_key_id)
            .field("attestation_key", &self.attestation_key.is_some())
            .finish()
    }
}

impl LocalSigner {
    /// Creates a new local signer for the given DID, acting as the given key.
    #[must_use]
    pub fn new(did: impl Into<String>, signing_key_id: SigningKeyId) -> Self {
        Self {
            did: did.into(),
            signing_key_id,
            attestation_key: None,
        }
    }

    /// Creates a signer that also holds the Ed25519 key signing this identity's
    /// `KeyPackage` attestations (§9.7.1).
    ///
    /// A driver built on a signer from [`LocalSigner::new`] or
    /// [`LocalSigner::active`] cannot mint a `KeyPackage`, because neither
    /// carries key material. This constructor is what gives a driver the
    /// ability to join a context.
    #[must_use]
    pub fn with_attestation_key(
        did: impl Into<String>,
        signing_key_id: SigningKeyId,
        attestation_key: ed25519_dalek::SigningKey,
    ) -> Self {
        Self {
            did: did.into(),
            signing_key_id,
            attestation_key: Some(attestation_key),
        }
    }

    /// Creates a signer acting as `#active` over a freshly generated
    /// attestation key.
    ///
    /// A test needs a driver that can actually join a context, which §9.7.1
    /// makes conditional on holding a key that signs the leaf attestation.
    /// This is gated on `testing`, so no shipped artifact carries it, and a
    /// production browser client supplies a custody-backed [`Signer`] instead
    /// (ADR-057 component 3). It is not a stand-in for that custody: it holds a
    /// key generated in process memory, which no verifier can tie to a
    /// published DID document unless the test also serves a matching one.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn active_for_testing(did: impl Into<String>) -> Self {
        Self::with_attestation_key(
            did,
            SigningKeyId::Active,
            ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        )
    }

    /// Creates a new local signer for the given DID acting as the human's
    /// active key ([`SigningKeyId::Active`]) — the common case.
    #[must_use]
    pub fn active(did: impl Into<String>) -> Self {
        Self::new(did, SigningKeyId::Active)
    }
}

impl Signer for LocalSigner {
    fn did(&self) -> &str {
        &self.did
    }

    fn signing_key_id(&self) -> SigningKeyId {
        self.signing_key_id
    }

    fn sign_key_package_attestation(&self, signing_hash: &[u8; 32]) -> Option<[u8; 64]> {
        use ed25519_dalek::Signer as _;
        self.attestation_key
            .as_ref()
            .map(|key| key.sign(signing_hash).to_bytes())
    }
}
