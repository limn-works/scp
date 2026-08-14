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
}

/// In-memory [`Signer`] for the MVP driver.
///
/// Holds the DID string and [`SigningKeyId`] directly. This is the
/// development/test identity backend; a production browser client supplies a
/// WebCrypto-callback custody backend instead (ADR-057 component 3).
#[derive(Debug, Clone)]
pub struct LocalSigner {
    did: String,
    signing_key_id: SigningKeyId,
}

impl LocalSigner {
    /// Creates a new local signer for the given DID, acting as the given key.
    #[must_use]
    pub fn new(did: impl Into<String>, signing_key_id: SigningKeyId) -> Self {
        Self {
            did: did.into(),
            signing_key_id,
        }
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
}
