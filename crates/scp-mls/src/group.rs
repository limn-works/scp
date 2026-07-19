//! MLS group lifecycle operations for SCP.
//!
//! This module implements the core group management wrapper around `OpenMLS`'s
//! `MlsGroup`. Every SCP context maps to one MLS group. The wrapper exposes
//! SCP-specific operations and hides `OpenMLS` internals behind a clean interface.
//!
//! # Operations
//!
//! - [`create_group`] — Create a new MLS group with the creator as the sole member.
//! - [`add_member`] — Add a member via their pre-published `KeyPackage`.
//! - [`remove_member`] — Remove a member by their leaf index.
//! - [`destroy_group`] — Destroy all MLS group state.
//!
//! # Ciphersuite
//!
//! All groups use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — no
//! ciphersuite negotiation. See ADR-001 for the rationale.

use std::ops::Deref;

use crate::InMemoryMlsProvider;
use crate::convergent_timestamp::encode_convergent_timestamp_aad;
use crate::credential::ScpCredential;
use crate::error::MlsError;
use crate::lifetime::{key_package_lifetime, validate_key_package_lifetime};
use openmls::group::GroupContext;
use openmls::messages::group_info::GroupInfo;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use scp_clock::Clock;
use scp_protocol::context::ScpContextExtension;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

/// The single ciphersuite used by all SCP MLS groups.
///
/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` provides:
/// - X25519 for key exchange (DHKEM)
/// - AES-128-GCM for authenticated encryption
/// - SHA-256 for hashing
/// - Ed25519 for digital signatures
///
/// No ciphersuite negotiation is supported. This eliminates downgrade attacks
/// and simplifies the implementation. See ADR-001 for the rationale.
pub const SCP_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// ---------------------------------------------------------------------------
// EagerDropSigner — defense-in-depth wrapper for upstream SignatureKeyPair
// ---------------------------------------------------------------------------

/// Wrapper around `openmls_basic_credential::SignatureKeyPair` that documents
/// the zeroization gap and ensures eager drop semantics.
///
/// `SignatureKeyPair` stores its Ed25519 private key in a plain `Vec<u8>` and
/// does not implement `Zeroize` or `ZeroizeOnDrop`. The `private` field is not
/// publicly accessible (only available behind the `test-utils` feature), so
/// we cannot zeroize it from outside the crate without `unsafe` code.
///
/// Using `unsafe` to reach into the struct's private field was considered and
/// rejected: `#[repr(Rust)]` provides no field ordering guarantee, so
/// calculating field offsets is undefined behavior. Writing through a shared
/// reference also violates aliasing rules under Stacked/Tree Borrows.
/// See issue #601 and the security review on PR #764.
///
/// This wrapper provides:
/// 1. **Documentation of the gap** — future upstream support for `Zeroize` on
///    `SignatureKeyPair` would close this.
/// 2. **Eager drop via [`EagerDropSigner::take`]** — `destroy_group` uses
///    `take()` to drop the key material as early as possible.
/// 3. **Centralized ownership** — all `SignatureKeyPair` storage in
///    `ScpMlsGroup` goes through this type.
///
/// **Upstream limitation:** Full zeroization requires `openmls_basic_credential`
/// to implement `Zeroize` on `SignatureKeyPair`. See issue #82.
pub struct EagerDropSigner(Option<SignatureKeyPair>);

impl EagerDropSigner {
    /// Wraps a `SignatureKeyPair` in an eager-drop wrapper.
    #[must_use]
    pub const fn new(inner: SignatureKeyPair) -> Self {
        Self(Some(inner))
    }

    /// Returns a reference to the inner `SignatureKeyPair`, or `None` after
    /// destruction.
    #[must_use]
    pub const fn as_ref(&self) -> Option<&SignatureKeyPair> {
        self.0.as_ref()
    }

    /// Takes the inner `SignatureKeyPair` out, leaving `None`. Used by
    /// `destroy_group` for eager cleanup, and by the runtime's persistent
    /// provider when consuming a pending-join signer (ADR-057).
    #[must_use = "the taken signing key should be used or explicitly dropped"]
    pub const fn take(&mut self) -> Option<SignatureKeyPair> {
        self.0.take()
    }
}

impl Deref for EagerDropSigner {
    type Target = Option<SignatureKeyPair>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Recovers the 32-byte Ed25519 private **seed** from an MLS `SignatureKeyPair`
/// (ADR-057 Option A pseudonym derivation).
///
/// `openmls_basic_credential::SignatureKeyPair` stores the ED25519 private key as
/// `ed25519_dalek::SigningKey::to_bytes()` — the 32-byte RFC-8032 seed (see its
/// `SignatureKeyPair::new` ED25519 arm), exactly the form
/// [`ed25519_dalek::SigningKey::from_bytes`] consumes. Its `private()` accessor
/// is `test-utils`-gated (unavailable in a shipped build), so this production
/// path recovers the seed through the type's own `serde` derive — the identical
/// name-tagged `MessagePack` form `ProviderSignerDump` already serializes the
/// signer with (see `snapshot.rs`) — reading back only the `private` field.
/// (A dedicated `scp-mls` unit test cross-checks this against the `test-utils`
/// `private()` accessor, so a future upstream serde-shape change fails loudly.)
///
/// The intermediate serialized bytes and the extracted seed `Vec` are zeroized;
/// the returned seed rides home in [`Zeroizing`](zeroize::Zeroizing). Fails
/// closed if the seed is not exactly 32 bytes, so a non-Ed25519 or malformed
/// signer can never be silently truncated into a derivation.
fn extract_ed25519_seed(
    signer: &SignatureKeyPair,
) -> Result<zeroize::Zeroizing<[u8; 32]>, MlsError> {
    use zeroize::Zeroize as _;

    // Only the private seed is read back; `public` / `signature_scheme` are
    // ignored (serde skips unknown fields for a struct by default). `private` is
    // a plain `Vec<u8>` on the upstream type (no `serde_bytes`), so it round-trips
    // through `rmp_serde` as a positional u8 sequence into this `Vec<u8>` — match
    // that shape exactly.
    #[derive(serde::Deserialize)]
    struct Ed25519SeedExtract {
        private: Vec<u8>,
    }

    // Defense-in-depth (C1): confirm the signer is Ed25519 BEFORE interpreting its
    // private bytes as a 32-byte Ed25519 seed. A different scheme could carry a
    // 32-byte key of another kind that would pass the length guard below but derive
    // a meaningless pseudonym. SCP groups are Ed25519-only ([`SCP_CIPHERSUITE`]), so
    // this can only fail on a corrupt/foreign signer — fail closed. Uses the public
    // `signature_scheme()` accessor (no `test-utils` gate).
    let expected_scheme = SCP_CIPHERSUITE.signature_algorithm();
    if signer.signature_scheme() != expected_scheme {
        return Err(MlsError::PseudonymDerivationFailed(format!(
            "MLS signer signature scheme is {:?}, expected the SCP ciphersuite scheme {:?} (Ed25519)",
            signer.signature_scheme(),
            expected_scheme
        )));
    }

    let mut serialized = rmp_serde::to_vec_named(signer)
        .map_err(|e| MlsError::PseudonymDerivationFailed(format!("serializing MLS signer: {e}")))?;
    let extract: Result<Ed25519SeedExtract, _> = rmp_serde::from_slice(&serialized);
    serialized.zeroize();
    let mut extract = extract.map_err(|e| {
        MlsError::PseudonymDerivationFailed(format!("recovering MLS signer private seed: {e}"))
    })?;

    let outcome = if extract.private.len() == 32 {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&extract.private);
        Ok(seed)
    } else {
        Err(MlsError::PseudonymDerivationFailed(format!(
            "MLS signer private key is {} bytes, expected a 32-byte Ed25519 seed",
            extract.private.len()
        )))
    };
    extract.private.zeroize();
    outcome
}

/// Wrapper around an `OpenMLS` `MlsGroup` that enforces SCP conventions.
///
/// `ScpMlsGroup` holds the MLS group state, the provider (crypto + storage),
/// and the local member's signing key. It exposes SCP-specific lifecycle
/// operations: create, add member, remove member, destroy.
///
/// # Ownership
///
/// Each `ScpMlsGroup` owns its provider and signer. The provider contains
/// the in-memory storage for this group's MLS state. The signer is the local
/// member's Ed25519 signing key used for MLS commits and proposals.
///
/// See ADR-001 for the MLS wrapper design.
pub struct ScpMlsGroup {
    /// The underlying `OpenMLS` group. `None` after [`destroy_group`]
    /// drops the MLS state (tree secrets, epoch keys, etc.).
    pub(crate) group: Option<MlsGroup>,
    /// The MLS provider (crypto + storage) for this group.
    pub(crate) provider: InMemoryMlsProvider,
    /// The local member's Ed25519 signing key pair, wrapped in
    /// [`EagerDropSigner`] for best-effort zeroization on drop.
    /// Inner `Option` is `None` after [`destroy_group`] drops the
    /// private key material.
    pub(crate) signer: EagerDropSigner,
    /// Whether the group has been destroyed.
    pub(crate) destroyed: bool,
}

impl ScpMlsGroup {
    /// Returns a reference to the underlying `OpenMLS` `MlsGroup`.
    ///
    /// Use this for read-only inspection of group state (members, epoch, etc.).
    /// Mutable operations should go through the wrapper methods.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn inner(&self) -> Result<&MlsGroup, MlsError> {
        self.group.as_ref().ok_or(MlsError::GroupDestroyed)
    }

    /// Returns a reference to the provider for this group.
    #[must_use]
    pub const fn provider(&self) -> &InMemoryMlsProvider {
        &self.provider
    }

    /// Returns a reference to the local member's `SignatureKeyPair`.
    ///
    /// Exposed for the native runtime's persistent provider, which serializes
    /// the signer into the durable MLS crypto snapshot (ADR-057). The signing
    /// key never leaves the device; this is an in-process read for the snapshot
    /// path only.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed
    /// (the signer is taken on destruction for eager zeroization).
    pub fn signer_key_pair(&self) -> Result<&SignatureKeyPair, MlsError> {
        self.signer.as_ref().ok_or(MlsError::GroupDestroyed)
    }

    /// Derives this member's per-context **pseudonym public key** (32 bytes) over
    /// the wasm-held MLS `SignatureKeyPair` (ADR-057 Option A, §9.10.4.A interim
    /// deviation).
    ///
    /// The browser has no identity key inside wasm; the only wasm-held Ed25519 key
    /// is this per-context MLS signing keypair. So — per the Alec 2026-07-16
    /// ruling (ADR-057 planning-session-10, Option A) — the browser derives its
    /// pseudonym over the MLS key via the single shared
    /// [`scp_crypto::pseudonym::derive_pseudonym_keypair`] recipe. This is
    /// **MLS-keyed, not identity-keyed**: it does NOT byte-match a native member's
    /// identity-keyed pseudonym for the same human. That is acceptable under the
    /// device-local-pseudonym model (each member announces its own address; peers
    /// record it) and is a documented, human-ruled deviation from §9.10.4.A,
    /// pending the #1980 key-to-WebCrypto move that unifies the key boundary.
    ///
    /// The private seed NEVER leaves this method: it is extracted, fed to the
    /// derivation, and dropped (zeroized) here. Only the resulting public
    /// pseudonym (a routing address, not a secret) is returned.
    ///
    /// `context_id` is the raw context-id bytes. This derives the **v1 (static)**
    /// pseudonym — the only form the transport slice wires today; v2 epoch-scoped
    /// (rotatable) derivation (§9.10.4.1) is not yet driven, so the epoch is fixed
    /// to `None` internally (see the body note) rather than exposed as an
    /// always-`None` parameter.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group (and thus the signer) has
    /// been destroyed, or [`MlsError::PseudonymDerivationFailed`] if the signer's
    /// private seed cannot be recovered or is not the expected 32-byte Ed25519
    /// seed (a fail-closed guard against a non-Ed25519 or malformed signer — SCP
    /// groups are Ed25519-only per [`SCP_CIPHERSUITE`]).
    pub fn derive_pseudonym(&self, context_id: &[u8]) -> Result<[u8; 32], MlsError> {
        let signer = self.signer_key_pair()?;
        let seed = extract_ed25519_seed(signer)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        // v1 (static) derivation. The epoch is fixed to `None` internally rather
        // than exposed as an always-`None` parameter — v2 epoch-scoped (rotatable)
        // pseudonyms (§9.10.4.1) are not yet driven by the transport slice, and the
        // shared recipe gains the epoch when rotation is wired.
        let pseudonym =
            scp_crypto::pseudonym::derive_pseudonym_keypair(&signing_key, context_id, None);
        Ok(pseudonym.verifying_key().to_bytes())
    }

    /// Reconstructs an `ScpMlsGroup` from its constituent parts.
    ///
    /// Used by the native runtime's persistent provider to rebuild a live group
    /// from a durable MLS crypto snapshot (the inverse of reading
    /// [`inner`](Self::inner) / [`provider`](Self::provider) /
    /// [`signer_key_pair`](Self::signer_key_pair)) after a restart (ADR-057).
    /// The resulting group is active (`destroyed = false`).
    #[must_use]
    pub const fn from_parts(
        group: MlsGroup,
        provider: InMemoryMlsProvider,
        signer: SignatureKeyPair,
    ) -> Self {
        Self {
            group: Some(group),
            provider,
            signer: EagerDropSigner::new(signer),
            destroyed: false,
        }
    }

    /// Returns the group's current epoch number.
    ///
    /// The epoch advances with each Commit (add member, remove member, update).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn epoch(&self) -> Result<u64, MlsError> {
        let g = self.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(g.epoch().as_u64())
    }

    /// Returns the group ID as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn group_id(&self) -> Result<&[u8], MlsError> {
        let g = self.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(g.group_id().as_slice())
    }

    /// Returns the list of group members.
    ///
    /// Each member includes their leaf index, credential, and public keys.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn members(&self) -> Result<Vec<Member>, MlsError> {
        let g = self.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(g.members().collect())
    }

    /// Returns the local member's own leaf index in the group tree.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn own_leaf_index(&self) -> Result<LeafNodeIndex, MlsError> {
        let g = self.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(g.own_leaf_index())
    }

    /// Signs data using the local member's MLS signing key.
    ///
    /// This is the key that `open_envelope` resolves from the MLS group tree
    /// when verifying inner envelope signatures (SCP-177). Inner envelopes
    /// must be signed with this key for `open_envelope` verification to pass.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    /// Returns [`MlsError::EncryptionFailed`] if signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, MlsError> {
        let signer = self.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
        openmls_traits::signatures::Signer::sign(signer, data)
            .map_err(|e| MlsError::EncryptionFailed(format!("signing failed: {e:?}")))
    }

    /// Returns the local member's MLS signing public key bytes.
    ///
    /// This is the Ed25519 public key stored in the member's leaf node in the
    /// MLS tree. `open_envelope` resolves this key from the sender's leaf node
    /// to verify inner envelope signatures (SCP-177).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn signer_public_key(&self) -> Result<Vec<u8>, MlsError> {
        let signer = self.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(signer.to_public_vec())
    }
}

/// Creates a new MLS group with the creator as the sole member.
///
/// The group uses [`SCP_CIPHERSUITE`]
/// (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) and starts at epoch 0.
/// The creator's identity is embedded in the group via an [`ScpCredential`]
/// containing their DID and optional UCAN token.
///
/// # Arguments
///
/// * `credential` - The creator's SCP credential (DID + optional UCAN).
/// * `clock` - The injected hardened [`Clock`] used to stamp the creator's own
///   `LeafNode` `Lifetime`, so the group leaf's freshness bounds come from the
///   SCP-layer clock rather than openmls's internal (wasm: unhardened) one
///   (ADR-057 §Prereq-1).
///
/// # Returns
///
/// An [`ScpMlsGroup`] wrapping the newly created `OpenMLS` group. The group
/// has exactly one member: the creator.
///
/// # Errors
///
/// Returns [`MlsError::CredentialSerializationFailed`] if the credential
/// cannot be serialized. Returns [`MlsError::GroupCreationFailed`] if
/// `OpenMLS` group creation fails.
///
/// See ADR-001 acceptance criterion 1.
pub fn create_group(
    credential: &ScpCredential,
    clock: &dyn Clock,
) -> Result<ScpMlsGroup, MlsError> {
    create_group_with_wrapping_key(credential, None, clock)
}

/// Creates a new MLS group with the creator as the sole member, optionally
/// including an `scp_wrapping_key` `LeafNode` extension.
///
/// When `wrapping_pubkey` is `Some`, the creator's `LeafNode` includes the
/// `scp_wrapping_key` extension with the given 32-byte X25519 public key.
/// This allows other members to read the wrapping key from the MLS tree
/// for sender key distribution (§9.16.1).
///
/// # Arguments
///
/// * `credential` - The creator's SCP credential (DID + optional UCAN).
/// * `wrapping_pubkey` - Optional 32-byte X25519 public key for the
///   `scp_wrapping_key` `LeafNode` extension.
/// * `clock` - The injected hardened [`Clock`] used to stamp the creator's own
///   `LeafNode` `Lifetime` (ADR-057 §Prereq-1).
///
/// # Errors
///
/// Returns [`MlsError::CredentialSerializationFailed`] if the credential
/// cannot be serialized. Returns [`MlsError::GroupCreationFailed`] if
/// `OpenMLS` group creation fails.
///
/// See ADR-001 acceptance criterion 1, spec §9.16.1.
pub fn create_group_with_wrapping_key(
    credential: &ScpCredential,
    wrapping_pubkey: Option<&[u8; 32]>,
    clock: &dyn Clock,
) -> Result<ScpMlsGroup, MlsError> {
    // If a wrapping key is provided, declare the extension type in capabilities
    // and include the wrapping key in the LeafNode extensions. No group_context
    // extension for the wrapping-key-only path.
    let (capabilities, leaf_extensions) = match wrapping_pubkey {
        Some(pubkey) => {
            let caps = crate::wrapping_extension::scp_capabilities_with_wrapping_key();
            let ext = crate::wrapping_extension::make_wrapping_key_extension(pubkey);
            let leaf_extensions = Extensions::<LeafNode>::single(ext).map_err(|e| {
                MlsError::GroupCreationFailed(format!("wrapping key extension: {e}"))
            })?;
            (Some(caps), Some(leaf_extensions))
        }
        None => (None, None),
    };

    create_group_inner(credential, capabilities, None, leaf_extensions, clock)
}

/// Creates a new MLS group whose `group_context` binds the SCP context
/// parameters, with the creator as the sole member.
///
/// The group carries **both** SCP extensions:
/// - the `scp_wrapping_key` `LeafNode` extension (`0xFF01`) with the creator's
///   32-byte X25519 wrapping public key, for sender key distribution (§9.16.1);
/// - the `scp_context_params` `group_context` extension (`0xFF02`) binding
///   `context_extension` into the group identity so the parameters are folded
///   into the MLS key schedule and read back identically by every member
///   (spec §5.13.3, finding FFI-02).
///
/// Members' [`Capabilities`](openmls::prelude::Capabilities) declare both
/// extension types via
/// [`scp_capabilities_with_context_params`](crate::context_extension::scp_capabilities_with_context_params).
/// A joiner must present a `KeyPackage` from
/// [`generate_key_package_with_context_params`] (which declares `0xFF02`):
/// `OpenMLS` rejects an Add whose leaf does not support every `group_context`
/// extension (`valn0502`). See the module docs on
/// [`context_extension`](crate::context_extension).
///
/// A context group always has a wrapping key, so `wrapping_pubkey` is required
/// (unlike [`create_group_with_wrapping_key`], which accepts `None` for the
/// wrapping-key-only path).
///
/// # Arguments
///
/// * `credential` - The creator's SCP credential (DID + optional UCAN).
/// * `wrapping_pubkey` - The creator's 32-byte X25519 wrapping public key.
/// * `context_extension` - The context parameters to commit into `group_context`.
/// * `clock` - The injected hardened [`Clock`] used to stamp the creator's own
///   `LeafNode` `Lifetime` (ADR-057 §Prereq-1).
///
/// # Errors
///
/// Returns [`MlsError::CredentialSerializationFailed`] if the credential cannot
/// be serialized, [`MlsError::ExtensionError`] if the context extension cannot
/// be canonically encoded, or [`MlsError::GroupCreationFailed`] if `OpenMLS`
/// group creation fails.
///
/// See ADR-001 acceptance criterion 1, spec §5.13.3, §9.16.1.
pub fn create_group_with_context(
    credential: &ScpCredential,
    wrapping_pubkey: &[u8; 32],
    context_extension: &ScpContextExtension,
    clock: &dyn Clock,
) -> Result<ScpMlsGroup, MlsError> {
    let capabilities = crate::context_extension::scp_capabilities_with_context_params();
    let group_context_extensions =
        crate::context_extension::group_context_extensions(context_extension)?;

    let leaf_ext = crate::wrapping_extension::make_wrapping_key_extension(wrapping_pubkey);
    let leaf_extensions = Extensions::<LeafNode>::single(leaf_ext)
        .map_err(|e| MlsError::GroupCreationFailed(format!("wrapping key extension: {e}")))?;

    create_group_inner(
        credential,
        Some(capabilities),
        Some(group_context_extensions),
        Some(leaf_extensions),
        clock,
    )
}

/// Shared single-member group-creation core for
/// [`create_group_with_wrapping_key`] and [`create_group_with_context`].
///
/// Builds a fresh in-memory provider and signer, embeds `credential` in the MLS
/// `BasicCredential`, and creates a one-member group under [`SCP_CIPHERSUITE`].
/// The optional `capabilities`, `group_context_extensions`, and
/// `leaf_node_extensions` are attached to the create config. Capabilities are
/// applied **before** the leaf-node extensions because
/// `with_leaf_node_extensions` validates each leaf extension type against the
/// configured capabilities (`OpenMLS` `valn0107`).
fn create_group_inner(
    credential: &ScpCredential,
    capabilities: Option<Capabilities>,
    group_context_extensions: Option<Extensions<GroupContext>>,
    leaf_node_extensions: Option<Extensions<LeafNode>>,
    clock: &dyn Clock,
) -> Result<ScpMlsGroup, MlsError> {
    let provider = InMemoryMlsProvider::default();

    // Generate an Ed25519 signing key pair for the creator.
    let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::GroupCreationFailed(format!("signature key generation: {e}")))?;

    // Store the signer's keys in the provider's key store so OpenMLS can
    // look them up during group operations.
    signer
        .store(provider.storage())
        .map_err(|e| MlsError::StorageError(format!("storing signature key: {e}")))?;

    // Serialize the SCP credential into the MLS BasicCredential identity field.
    let credential_bytes = credential.to_bytes()?;
    let basic_credential = BasicCredential::new(credential_bytes);
    let credential_with_key = CredentialWithKey {
        credential: basic_credential.into(),
        signature_key: signer.to_public_vec().into(),
    };

    // Configure the group with the SCP ciphersuite. The ratchet tree
    // extension is enabled so that Welcome messages include the full tree,
    // allowing new members to join without out-of-band tree distribution.
    // max_past_epochs(2) retains message secrets for the 2 most recent past
    // epochs in OpenMLS's MessageSecretsStore. This aligns with the 30-second
    // sender key grace window (§9.16.2, §9.7, ADR-001 criterion 6): during
    // epoch transitions, in-flight messages encrypted under a previous epoch
    // can still be decrypted. Without this, merge_staged_commit() /
    // merge_pending_commit() delete previous epoch key material immediately
    // (default max_past_epochs=0), making grace-window messages undecryptable.
    // Value 2 covers the common case of one in-flight epoch plus one safety
    // margin. The EpochGraceStore enforces the 30-second time bound at the SCP
    // layer, so retention is bounded by both count (2) and time (30s).
    // See issue #324.
    // SECURITY (ADR-057 §Prereq-1): the creator's own `LeafNode` `Lifetime` is
    // stamped from the injected hardened `Clock` — NOT openmls's internal (wasm:
    // unhardened `Date.now()`) clock. `MlsGroupCreateConfigBuilder::lifetime`
    // routes our `Lifetime::init(now - margin, now + lifetime)` (built from the
    // injected clock) into `MlsGroup::new`, so the creator's leaf freshness
    // bounds are governed by the same clock as the rest of the client. Without
    // this call the leaf would fall back to `Lifetime::default()`, which reads
    // openmls's internal clock. See `crate::lifetime`.
    let mut builder = MlsGroupCreateConfig::builder()
        .ciphersuite(SCP_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .lifetime(key_package_lifetime(clock))
        .max_past_epochs(2);

    // Capabilities must be set before the leaf-node extensions: OpenMLS's
    // with_leaf_node_extensions validates each leaf extension type against the
    // configured capabilities (valn0107).
    if let Some(caps) = capabilities {
        builder = builder.capabilities(caps);
    }
    if let Some(gc_extensions) = group_context_extensions {
        builder = builder.with_group_context_extensions(gc_extensions);
    }
    if let Some(leaf_extensions) = leaf_node_extensions {
        builder = builder
            .with_leaf_node_extensions(leaf_extensions)
            .map_err(|e| MlsError::GroupCreationFailed(format!("leaf node extensions: {e}")))?;
    }

    let group_create_config = builder.build();

    // Create the MLS group with the creator as the sole member. The creator's
    // own `LeafNode` `Lifetime` was routed through the injected `Clock` via the
    // `.lifetime(...)` call on the create-config builder above (ADR-057
    // §Prereq-1). The residual openmls-internal-clock exposure is confined to
    // the *receive* side (Welcome tree-leaf validation), which openmls does not
    // expose for bracketing — see the module docs in `crate::lifetime`.
    let group = MlsGroup::new(
        &provider,
        &signer,
        &group_create_config,
        credential_with_key,
    )
    .map_err(|e| MlsError::GroupCreationFailed(e.to_string()))?;

    Ok(ScpMlsGroup {
        group: Some(group),
        provider,
        signer: EagerDropSigner::new(signer),
        destroyed: false,
    })
}

/// The result of adding a member to an MLS group.
///
/// Contains the MLS messages that must be distributed to complete the
/// add operation: a Welcome message for the new member and a Commit
/// message for existing members.
pub struct AddMemberResult {
    /// The MLS Commit message that advances the group epoch.
    /// Must be sent to all existing group members.
    pub commit: MlsMessageOut,
    /// The MLS Welcome message, HPKE-encrypted to the new member's
    /// `KeyPackage`. Contains all group state the new member needs to
    /// decrypt future messages.
    pub welcome: MlsMessageOut,
    /// Optional group info that may be needed by external parties.
    pub group_info: Option<GroupInfo>,
}

/// Adds a member to the group using their pre-published `KeyPackage`.
///
/// The operation produces a Commit (epoch advance) and a Welcome message.
/// The Welcome is HPKE-encrypted to the new member's `KeyPackage` and contains
/// all group state they need to participate. After this call returns
/// successfully, the pending commit has been merged and the group epoch has
/// advanced.
///
/// # Arguments
///
/// * `group` - The MLS group to add the member to. Must be active.
/// * `key_package` - The new member's pre-published `KeyPackage`, signed by
///   their Ed25519 key and containing their SCP credential.
/// * `clock` - The injected hardened [`Clock`]. After openmls validates the
///   key package (which runs its own un-injectable internal `Lifetime::is_valid`
///   against openmls's clock), the accepted `Lifetime` is *additionally*
///   re-validated against this hardened clock — and checked for the RFC 9420
///   maximum-range bound openmls never applies (ADR-057 §Prereq-1).
///
/// # Returns
///
/// An [`AddMemberResult`] containing the Commit and Welcome messages.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::AddMemberFailed`] if `OpenMLS` rejects the add operation.
/// Returns [`MlsError::KeyPackageLifetimeInvalid`] if the accepted key package's
/// `Lifetime` fails validation against the injected clock (expired, not yet
/// valid, or over-long range).
/// Returns [`MlsError::MergePendingCommitFailed`] if committing fails.
///
/// See ADR-001 acceptance criterion 2.
pub fn add_member(
    group: &mut ScpMlsGroup,
    key_package: KeyPackageIn,
    clock: &dyn Clock,
) -> Result<AddMemberResult, MlsError> {
    // Validate the key package.
    let verified_key_package = key_package
        .validate(group.provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| MlsError::AddMemberFailed(format!("key package validation: {e}")))?;

    // SECURITY (ADR-057 §Prereq-1): openmls's `validate` above runs its own
    // internal `Lifetime::is_valid` against openmls's (wasm: unhardened) clock.
    // Re-validate the accepted `Lifetime` against the injected hardened clock,
    // and enforce the RFC 9420 maximum-range bound openmls's `validate` never
    // applies. This is additive hardening — it never replaces openmls's check.
    validate_key_package_lifetime(verified_key_package.life_time(), clock)?;

    let signer = group.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;

    // Add the member to the group. Returns (commit, welcome, group_info).
    // Both commit and welcome are MlsMessageOut.
    let (commit, welcome, group_info) = g
        .add_members(
            &group.provider,
            signer,
            core::slice::from_ref(&verified_key_package),
        )
        .map_err(|e| MlsError::AddMemberFailed(e.to_string()))?;

    // Merge the pending commit to advance the group epoch locally.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    g.merge_pending_commit(&group.provider)
        .map_err(|e| MlsError::MergePendingCommitFailed(e.to_string()))?;

    Ok(AddMemberResult {
        commit,
        welcome,
        group_info,
    })
}

/// Adds a member, binding a **convergent committer timestamp** into the Commit's
/// MLS AAD so existing members recover it authenticated (ADR-057).
///
/// Identical to [`add_member`] except it sets the group's ephemeral AAD to the
/// 13-byte convergent-timestamp blob
/// ([`encode_convergent_timestamp_aad`](crate::convergent_timestamp::encode_convergent_timestamp_aad))
/// immediately before delegating. openmls folds that AAD into the Commit's
/// `FramedContent.authenticated_data`, which is covered by the committer's leaf
/// signature (and, under the `PURE_CIPHERTEXT` policy, the AEAD tag), so an
/// existing member reading the value back from [`decrypt_with_membership_changes`]
/// gets it authenticated — not trusted on the wire. The added member does not
/// need the AAD: its copy of the timestamp already rides inside the replayed
/// event log.
///
/// # AAD lifecycle
///
/// openmls's `set_aad` is ephemeral — it is reset automatically only on an API
/// call that *successfully* returns an `MlsMessageOut`. This function therefore
/// **clears the AAD on error** so a failed add cannot leak the timestamp into a
/// subsequent unrelated send/commit on the same group.
///
/// The existing [`add_member`] is left untouched: the native runtime is a
/// consumer of it and does not use the AAD-binding path (its convergent timestamp
/// rides inside a signed SCP envelope).
///
/// # Arguments
///
/// * `group` - The MLS group to add the member to. Must be active.
/// * `key_package` - The new member's pre-published `KeyPackage`.
/// * `clock` - The injected hardened [`Clock`] for the `Lifetime` re-validation
///   [`add_member`] performs (ADR-057 §Prereq-1).
/// * `timestamp_secs` - The convergent committer timestamp (Unix seconds) to bind
///   into the Commit AAD. The committer stamps the same value on its own
///   `MemberJoined` leaf.
///
/// # Errors
///
/// Same as [`add_member`]. On any error the ephemeral AAD is cleared before the
/// error is returned.
pub fn add_member_with_convergent_timestamp(
    group: &mut ScpMlsGroup,
    key_package: KeyPackageIn,
    clock: &dyn Clock,
    timestamp_secs: u64,
) -> Result<AddMemberResult, MlsError> {
    let aad = encode_convergent_timestamp_aad(timestamp_secs);
    {
        let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
        g.set_aad(aad.to_vec());
    }
    let result = add_member(group, key_package, clock);
    if result.is_err() {
        // openmls resets the ephemeral AAD only on a successful MlsMessageOut;
        // on error it persists, so clear it to prevent leaking the timestamp
        // into the next op. (If the group was destroyed, there is nothing to
        // clear.)
        if let Some(g) = group.group.as_mut() {
            g.set_aad(Vec::new());
        }
    }
    result
}

/// Extracts the SCP DID embedded in a fully-validated `KeyPackage`'s leaf
/// credential.
///
/// Runs `OpenMLS`'s full [`KeyPackageIn::validate`] — which verifies the leaf
/// node signature, the key package signature, the protocol version, and the
/// `Lifetime` — and only then reads the `BasicCredential` from the verified
/// leaf node and parses it as an [`ScpCredential`] to recover the DID. The
/// returned DID is therefore cryptographically authenticated: it is bound to a
/// leaf node whose signature has been checked against the key package's own
/// signature key, not merely deserialized from untrusted bytes. This lets a
/// driver name the member a key package belongs to *before* consuming the
/// package in [`add_member`], so the membership record and the MLS leaf cannot
/// disagree.
///
/// This is the standalone counterpart of the credential extraction
/// `add_member` and `decrypt_with_sender_did` already perform internally; it
/// exists so an in-browser participant driver (ADR-057) can read the joiner's
/// DID off the wire-delivered key package without trusting a separately
/// supplied DID. Because validation is identical to the one `add_member`
/// performs, a key package this function accepts is one `add_member` will also
/// accept (and vice versa) — there is no weaker "advisory" window.
///
/// # Arguments
///
/// * `key_package` - The wire-delivered key package to authenticate and read.
/// * `protocol_version` - The MLS protocol version to validate against.
/// * `clock` - The injected hardened [`Clock`]. The accepted `Lifetime` is
///   re-validated against it (and the RFC 9420 max-range bound enforced) after
///   openmls's own validation, so this function accepts exactly the key packages
///   [`add_member`] accepts — preserving the "no weaker advisory window"
///   equivalence documented above (ADR-057 §Prereq-1).
///
/// # Errors
///
/// Returns [`MlsError::AddMemberFailed`] if the key package fails validation
/// (bad signature, wrong protocol version, or an invalid/expired `Lifetime`),
/// [`MlsError::KeyPackageLifetimeInvalid`] if the accepted `Lifetime` fails
/// validation against the injected clock, or
/// [`MlsError::CredentialSerializationFailed`] if the validated leaf
/// credential is not a parseable SCP `BasicCredential`.
pub fn key_package_in_did(
    key_package: &KeyPackageIn,
    protocol_version: ProtocolVersion,
    clock: &dyn Clock,
) -> Result<String, MlsError> {
    // A fresh in-memory provider supplies the crypto backend for validation;
    // it holds no group state and is discarded.
    let provider = InMemoryMlsProvider::default();
    let verified = key_package
        .clone()
        .validate(provider.crypto(), protocol_version)
        .map_err(|e| MlsError::AddMemberFailed(format!("key package validation: {e}")))?;

    // SECURITY (ADR-057 §Prereq-1): mirror the hardened-clock re-validation
    // `add_member` performs, so the DID this function authenticates belongs to a
    // key package `add_member` will also accept (and vice versa).
    validate_key_package_lifetime(verified.life_time(), clock)?;

    let credential = verified.leaf_node().credential().clone();
    let basic = BasicCredential::try_from(credential).map_err(|e| {
        MlsError::CredentialSerializationFailed(format!("extracting BasicCredential: {e}"))
    })?;
    let scp_cred = ScpCredential::from_bytes(basic.identity())?;
    Ok(scp_cred.did)
}

/// Extracts the `scp_wrapping_key` X25519 public key published in a
/// fully-validated `KeyPackage`'s leaf extension (§9.16.1).
///
/// This is the adder-side counterpart of the recovery
/// [`decrypt_with_membership_changes`](crate::encrypt::decrypt_with_membership_changes)
/// performs for bystanders: it lets the member creating an add read the joiner's
/// stable wrapping public key straight off the wire-delivered `KeyPackage`, so it
/// can HPKE-seal its own sender key to the new member (ADR-057 sender-key
/// distribution). Validation is identical to [`key_package_in_did`] — the leaf
/// signature, key-package signature, protocol version, and (hardened) `Lifetime`
/// are all checked — so a key package this function reads a wrapping key from is
/// one [`add_member`] will also accept.
///
/// FAIL-CLOSED (ADR-057 INVARIANT 3): a `KeyPackage` whose leaf carries no
/// `scp_wrapping_key` extension is rejected with [`MlsError::ExtensionError`],
/// mirroring the pre-merge fail-closed in `decrypt_with_membership_changes`. A
/// member no peer can HPKE-seal a sender key to must not be admitted.
///
/// # Arguments
///
/// * `key_package` - The wire-delivered key package to authenticate and read.
/// * `protocol_version` - The MLS protocol version to validate against.
/// * `clock` - The injected hardened [`Clock`] the accepted `Lifetime` is
///   re-validated against (ADR-057 §Prereq-1).
///
/// # Errors
///
/// Returns [`MlsError::AddMemberFailed`] if the key package fails validation,
/// [`MlsError::KeyPackageLifetimeInvalid`] if the accepted `Lifetime` fails the
/// hardened-clock re-validation, or [`MlsError::ExtensionError`] if the leaf
/// carries no (or a malformed) `scp_wrapping_key` extension.
pub fn key_package_in_wrapping_key(
    key_package: &KeyPackageIn,
    protocol_version: ProtocolVersion,
    clock: &dyn Clock,
) -> Result<[u8; 32], MlsError> {
    let provider = InMemoryMlsProvider::default();
    let verified = key_package
        .clone()
        .validate(provider.crypto(), protocol_version)
        .map_err(|e| MlsError::AddMemberFailed(format!("key package validation: {e}")))?;

    // SECURITY (ADR-057 §Prereq-1): mirror the hardened-clock re-validation
    // `add_member` / `key_package_in_did` perform, so this accepts exactly the
    // key packages the add path accepts.
    validate_key_package_lifetime(verified.life_time(), clock)?;

    crate::wrapping_extension::extract_wrapping_key(verified.leaf_node().extensions())?.ok_or_else(
        || {
            MlsError::ExtensionError(
                "KeyPackage leaf carries no scp_wrapping_key extension; a member no peer \
                 can HPKE-seal a sender key to must not be admitted (§9.16.1, ADR-057 \
                 sender-key distribution INVARIANT 3)"
                    .to_owned(),
            )
        },
    )
}

/// The result of removing a member from an MLS group.
///
/// Contains the Commit message that must be distributed to remaining members
/// to advance the epoch and ratchet to new key material.
pub struct RemoveMemberResult {
    /// The MLS Commit message that advances the group epoch.
    /// Must be sent to all remaining group members. The removed member
    /// cannot derive new epoch keys from this Commit.
    pub commit: MlsMessageOut,
    /// Optional group info.
    pub group_info: Option<GroupInfo>,
}

/// Removes a member from the group by their leaf index.
///
/// The operation produces a Commit that advances the epoch. All remaining
/// members ratchet to new key material. The removed member cannot derive
/// new epoch keys. Cost is O(log n) via MLS tree structure.
///
/// After this call returns successfully, the pending commit has been merged
/// and the group epoch has advanced.
///
/// # Arguments
///
/// * `group` - The MLS group to remove the member from. Must be active.
/// * `leaf_index` - The leaf index of the member to remove. Obtain this from
///   the group's member list via [`ScpMlsGroup::members`].
///
/// # Returns
///
/// A [`RemoveMemberResult`] containing the Commit message.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::RemoveMemberFailed`] if `OpenMLS` rejects the remove
/// operation (e.g., invalid leaf index, removing self).
/// Returns [`MlsError::MergePendingCommitFailed`] if committing fails.
///
/// See ADR-001 acceptance criterion 3.
pub fn remove_member(
    group: &mut ScpMlsGroup,
    leaf_index: LeafNodeIndex,
) -> Result<RemoveMemberResult, MlsError> {
    let signer = group.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;

    // Remove the member. Returns (commit, optional_welcome, group_info).
    let (commit, _welcome, group_info) = g
        .remove_members(&group.provider, signer, core::slice::from_ref(&leaf_index))
        .map_err(|e| MlsError::RemoveMemberFailed(e.to_string()))?;

    // Merge the pending commit to advance the group epoch locally.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    g.merge_pending_commit(&group.provider)
        .map_err(|e| MlsError::MergePendingCommitFailed(e.to_string()))?;

    Ok(RemoveMemberResult { commit, group_info })
}

/// Destroys all MLS group state.
///
/// After destruction, the group cannot be used for any operation. All tree
/// secrets, epoch key schedules, and application key material are released.
/// Historical messages encrypted under this group become physically unreadable
/// once the in-memory state is dropped.
///
/// This is the operation triggered by ephemeral context closure (spec
/// section 9.7.2).
///
/// # Arguments
///
/// * `group` - The MLS group to destroy.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has already been
/// destroyed.
///
/// See ADR-001 acceptance criterion 9.
pub fn destroy_group(group: &mut ScpMlsGroup) -> Result<(), MlsError> {
    if group.destroyed {
        return Err(MlsError::GroupDestroyed);
    }

    // Eagerly drop cryptographic state. `Option::take` moves the value out,
    // leaving `None`, and the taken value is dropped at the end of the
    // statement. This releases:
    //   - MlsGroup: tree secrets, epoch key schedules, ratchet state
    //   - SignatureKeyPair: Ed25519 private key (Vec<u8>)
    drop(group.group.take());
    drop(group.signer.take());

    // Replace the provider with a fresh empty instance. The old provider's
    // MemoryStorage contains encryption key pairs, key packages, and other
    // MLS artifacts — dropping it releases all of that key material.
    group.provider = InMemoryMlsProvider::default();

    // Mark the group as destroyed so all future operations are rejected.
    group.destroyed = true;

    Ok(())
}

/// Generates a `KeyPackage` for a participant, suitable for offline member
/// addition.
///
/// The `KeyPackage` is signed by the participant's Ed25519 key and contains
/// their SCP credential. It uses [`SCP_CIPHERSUITE`].
///
/// # Arguments
///
/// * `credential` - The participant's SCP credential (DID + optional UCAN).
/// * `clock` - The injected hardened [`Clock`] used to stamp the key package's
///   `Lifetime` (ADR-057 §Prereq-1), so the published freshness bounds come
///   from the SCP-layer clock rather than openmls's internal one.
///
/// # Returns
///
/// A tuple of (`KeyPackageBundle`, `SignatureKeyPair`, `InMemoryMlsProvider`).
/// The `KeyPackageBundle` contains the public `KeyPackage` that should be
/// published, plus private keys stored in the provider. The provider and
/// signer must be retained by the participant to later join a group via a
/// Welcome message.
///
/// # Errors
///
/// Returns [`MlsError::CredentialSerializationFailed`] if the credential
/// cannot be serialized.
/// Returns [`MlsError::KeyPackageGenerationFailed`] if key package
/// generation fails.
pub fn generate_key_package(
    credential: &ScpCredential,
    clock: &dyn Clock,
) -> Result<(KeyPackageBundle, SignatureKeyPair, InMemoryMlsProvider), MlsError> {
    generate_key_package_with_wrapping_key(credential, None, clock)
}

/// Generates a `KeyPackage` with an optional `scp_wrapping_key` `LeafNode`
/// extension.
///
/// When `wrapping_pubkey` is `Some`, the generated `KeyPackage`'s `LeafNode`
/// includes the `scp_wrapping_key` extension with the given 32-byte X25519
/// public key. This publishes the wrapping key so that other members can
/// read it from the MLS tree for sender key distribution (§9.16.1).
///
/// # Arguments
///
/// * `credential` - The participant's SCP credential (DID + optional UCAN).
/// * `wrapping_pubkey` - Optional 32-byte X25519 public key for the
///   `scp_wrapping_key` `LeafNode` extension.
/// * `clock` - The injected hardened [`Clock`] used to stamp the key package's
///   `Lifetime` (ADR-057 §Prereq-1).
///
/// # Errors
///
/// Returns [`MlsError::CredentialSerializationFailed`] if the credential
/// cannot be serialized.
/// Returns [`MlsError::KeyPackageGenerationFailed`] if key package
/// generation fails.
pub fn generate_key_package_with_wrapping_key(
    credential: &ScpCredential,
    wrapping_pubkey: Option<&[u8; 32]>,
    clock: &dyn Clock,
) -> Result<(KeyPackageBundle, SignatureKeyPair, InMemoryMlsProvider), MlsError> {
    // Wrapping-key-only path: declare only the 0xFF01 extension type and carry
    // the wrapping key in the LeafNode when a key is provided.
    let (capabilities, leaf_extensions) = match wrapping_pubkey {
        Some(pubkey) => {
            let caps = crate::wrapping_extension::scp_capabilities_with_wrapping_key();
            let ext = crate::wrapping_extension::make_wrapping_key_extension(pubkey);
            let leaf_extensions = Extensions::<LeafNode>::single(ext).map_err(|e| {
                MlsError::KeyPackageGenerationFailed(format!("wrapping key extension: {e}"))
            })?;
            (Some(caps), Some(leaf_extensions))
        }
        None => (None, None),
    };

    generate_key_package_inner(credential, capabilities, leaf_extensions, clock)
}

/// Generates a `KeyPackage` for joining an SCP **context** group (one whose
/// `group_context` carries the `scp_context_params` extension, `0xFF02`).
///
/// The generated `KeyPackage`'s `LeafNode` **unconditionally** declares support
/// for **both** SCP extension types (`0xFF01` + `0xFF02`) via
/// [`scp_capabilities_with_context_params`](crate::context_extension::scp_capabilities_with_context_params).
/// It carries the `scp_wrapping_key` (`0xFF01`) `LeafNode` extension with the
/// participant's wrapping public key **only when `wrapping_pubkey` is `Some`**.
///
/// The `0xFF02` capability declaration is **required** to join a context group:
/// `OpenMLS` rejects an Add proposal (RFC 9420 §12.1.8.2, `valn0502`) unless the
/// joiner's leaf supports every extension present in the group's `group_context`
/// — including the `scp_context_params` extension. A `KeyPackage` produced by
/// [`generate_key_package_with_wrapping_key`] (which declares only `0xFF01`, or
/// nothing at all when no key is given) therefore cannot be added to a context
/// group; use this function instead for **any** `KeyPackage` destined for an
/// encrypted (`0xFF02`) context.
///
/// # Capability vs. leaf extension
///
/// The `0xFF02` *capability* — a support declaration in the leaf's
/// [`Capabilities`] — is what `valn0502` checks, and it requires **no** key
/// material. The `0xFF01` *leaf extension* — the actual 32-byte wrapping public
/// key — is a separate, optional §9.16.1 enhancement that lets other members
/// HPKE-seal sender keys to this member (`add_member` reads it from the leaf via
/// `extract_wrapping_key`; distribution to a member with no published wrapping
/// key is simply skipped). A member with `wrapping_pubkey == None` is therefore
/// still fully **context-joinable** — it just receives no sender keys until it
/// publishes a wrapping key. Declaring the `0xFF01` capability while omitting the
/// `0xFF01` leaf extension is valid: `valn0107` only constrains the reverse
/// (a present leaf extension must be declared in capabilities).
///
/// # Arguments
///
/// * `credential` - The participant's SCP credential (DID + optional UCAN).
/// * `wrapping_pubkey` - The participant's 32-byte X25519 wrapping public key,
///   or `None` when the identity has not published one. In both cases the KP is
///   context-joinable (declares `0xFF02`); the leaf wrapping-key extension is
///   attached only in the `Some` case.
/// * `clock` - The injected hardened [`Clock`] used to stamp the `KeyPackage`
///   `Lifetime` (ADR-057 §Prereq-1).
///
/// # Errors
///
/// Returns [`MlsError::CredentialSerializationFailed`] if the credential cannot
/// be serialized, or [`MlsError::KeyPackageGenerationFailed`] if key package
/// generation fails.
///
/// See spec §5.13.3, §9.16.1.
pub fn generate_key_package_with_context_params(
    credential: &ScpCredential,
    wrapping_pubkey: Option<&[u8; 32]>,
    clock: &dyn Clock,
) -> Result<(KeyPackageBundle, SignatureKeyPair, InMemoryMlsProvider), MlsError> {
    // Always declare BOTH 0xFF01 + 0xFF02 capabilities: this KP is
    // context-joinable by construction, satisfying valn0502 regardless of
    // whether a wrapping key is available.
    let capabilities = crate::context_extension::scp_capabilities_with_context_params();
    // Carry the 0xFF01 wrapping-key LEAF extension only when a key is present.
    let leaf_extensions = match wrapping_pubkey {
        Some(pubkey) => {
            let ext = crate::wrapping_extension::make_wrapping_key_extension(pubkey);
            Some(Extensions::<LeafNode>::single(ext).map_err(|e| {
                MlsError::KeyPackageGenerationFailed(format!("wrapping key extension: {e}"))
            })?)
        }
        None => None,
    };

    generate_key_package_inner(credential, Some(capabilities), leaf_extensions, clock)
}

/// Shared `KeyPackage` generation core for
/// [`generate_key_package_with_wrapping_key`] and
/// [`generate_key_package_with_context_params`].
///
/// Builds a fresh in-memory provider and signer, embeds `credential`, and
/// generates a single-use `KeyPackage` under [`SCP_CIPHERSUITE`] with the given
/// optional leaf capabilities and leaf-node extensions.
fn generate_key_package_inner(
    credential: &ScpCredential,
    capabilities: Option<Capabilities>,
    leaf_node_extensions: Option<Extensions<LeafNode>>,
    clock: &dyn Clock,
) -> Result<(KeyPackageBundle, SignatureKeyPair, InMemoryMlsProvider), MlsError> {
    let provider = InMemoryMlsProvider::default();

    let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::KeyPackageGenerationFailed(format!("signer generation: {e}")))?;

    signer
        .store(provider.storage())
        .map_err(|e| MlsError::StorageError(format!("storing signature key: {e}")))?;

    let credential_bytes = credential.to_bytes()?;
    let basic_credential = BasicCredential::new(credential_bytes);
    let credential_with_key = CredentialWithKey {
        credential: basic_credential.into(),
        signature_key: signer.to_public_vec().into(),
    };

    let mut builder = KeyPackage::builder();

    if let Some(caps) = capabilities {
        builder = builder.leaf_node_capabilities(caps);
    }
    if let Some(leaf_extensions) = leaf_node_extensions {
        builder = builder.leaf_node_extensions(leaf_extensions);
    }

    // SECURITY (ADR-057 §Prereq-1): the KeyPackage `Lifetime`
    // (`not_before`/`not_after`) is stamped from the injected hardened `Clock`,
    // NOT openmls's internal clock. `KeyPackageBuilder::key_package_lifetime`
    // routes our `Lifetime::init(now - margin, now + lifetime)` (built from the
    // injected clock via `crate::lifetime::key_package_lifetime`) into
    // `build()`, so the published freshness bounds are governed by the same
    // clock as the rest of the client. Without this call `build()` falls back to
    // `Lifetime::default()` → `Lifetime::new()`, which reads openmls's INTERNAL
    // clock — under the wasm `js` feature `fluvio_wasm_timer::SystemTime`, an
    // attacker-overridable `Date.now()`. Generation is now fully routed; the
    // only residual openmls-internal-clock read is the *receive* side
    // (`Lifetime::is_valid` on Welcome tree-leaf validation), which openmls does
    // not expose for bracketing. add_member / key_package_in_did / the
    // staged-commit Add paths re-validate accepted `Lifetime`s against the
    // injected clock; the Welcome-leaf residual is tracked upstream (see
    // `crate::lifetime` module docs).
    let key_package_bundle = builder
        .key_package_lifetime(key_package_lifetime(clock))
        .build(SCP_CIPHERSUITE, &provider, &signer, credential_with_key)
        .map_err(|e| MlsError::KeyPackageGenerationFailed(e.to_string()))?;

    Ok((key_package_bundle, signer, provider))
}

/// Joins a group from a Welcome message received after being added.
///
/// The new member processes the Welcome message to reconstruct the group
/// state and become an active participant. The Welcome contains all group
/// state the new member needs to decrypt future messages.
///
/// # Arguments
///
/// * `welcome` - A reference to the Welcome message (as `MlsMessageOut`)
///   from the add operation's [`AddMemberResult`].
/// * `provider` - The MLS provider that holds the new member's key material
///   (from [`generate_key_package`]).
/// * `signer` - The new member's signing key pair (from [`generate_key_package`]).
///
/// # Returns
///
/// An [`ScpMlsGroup`] wrapping the joined group.
///
/// # Errors
///
/// Returns [`MlsError::WelcomeProcessingFailed`] if the Welcome message
/// cannot be processed.
pub fn join_group(
    welcome: &MlsMessageOut,
    provider: InMemoryMlsProvider,
    signer: SignatureKeyPair,
) -> Result<ScpMlsGroup, MlsError> {
    let serialized = welcome
        .tls_serialize_detached()
        .map_err(|e| MlsError::WelcomeProcessingFailed(format!("serializing welcome: {e}")))?;
    join_group_from_bytes(&serialized, provider, signer)
}

/// Joins a group from TLS-serialized Welcome bytes.
///
/// This is the cross-process variant of [`join_group`]: the Welcome message
/// arrives as raw bytes (e.g., from a relay or FFI boundary) rather than as
/// an `MlsMessageOut` reference.
///
/// # Arguments
///
/// * `welcome_bytes` - TLS-serialized MLS Welcome message.
/// * `provider` - The MLS provider holding the key package's private state
///   (from [`generate_key_package`]).
/// * `signer` - The new member's signing key pair (from [`generate_key_package`]).
///
/// # Returns
///
/// An [`ScpMlsGroup`] wrapping the joined group.
///
/// # Errors
///
/// Returns [`MlsError::WelcomeProcessingFailed`] if the Welcome message
/// cannot be deserialized or processed.
pub fn join_group_from_bytes(
    welcome_bytes: &[u8],
    provider: InMemoryMlsProvider,
    signer: SignatureKeyPair,
) -> Result<ScpMlsGroup, MlsError> {
    let welcome_in = MlsMessageIn::tls_deserialize(&mut &*welcome_bytes)
        .map_err(|e| MlsError::WelcomeProcessingFailed(format!("deserializing welcome: {e}")))?;

    // Extract the Welcome from the MlsMessageIn body.
    let welcome_body = welcome_in.extract();
    let MlsMessageBodyIn::Welcome(welcome) = welcome_body else {
        return Err(MlsError::WelcomeProcessingFailed(
            "message is not a Welcome".to_string(),
        ));
    };

    // The join config must MIRROR create_group's MlsGroupCreateConfig, or a
    // member that joined via Welcome would build subtly different group state
    // from the creator's:
    // - `max_past_epochs(2)` — retain past-epoch message secrets during the
    //   30-second grace window (mirrors create_group);
    // - `use_ratchet_tree_extension(true)` — embed the ratchet tree in every
    //   Welcome THIS member later produces when it adds a member. Without it a
    //   joined member's Welcome omits the tree and the new joiner fails with
    //   "No ratchet tree available to build initial tree" (openmls does not
    //   inherit this flag from the group a Welcome was joined from; it is a
    //   property of the local join config). The creator sets it in
    //   create_group, so mirroring it here keeps every member — creator or
    //   Welcome-joined — able to add further members (§9.16.1 in-tab
    //   distribution requires every member to be an eligible adder/bystander).
    let join_config = MlsGroupJoinConfig::builder()
        .max_past_epochs(2)
        .use_ratchet_tree_extension(true)
        .build();

    let staged_welcome = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
        .map_err(|e| MlsError::WelcomeProcessingFailed(e.to_string()))?;

    let group = staged_welcome
        .into_group(&provider)
        .map_err(|e| MlsError::WelcomeProcessingFailed(e.to_string()))?;

    Ok(ScpMlsGroup {
        group: Some(group),
        provider,
        signer: EagerDropSigner::new(signer),
        destroyed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scp_clock::SystemClock;

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap()
    }

    /// The `test-utils` `private()` accessor is the ground-truth private seed.
    /// `derive_pseudonym` recovers that SAME seed via the production serde path
    /// (`extract_ed25519_seed`) and feeds it to the shared derivation, so the two
    /// must agree byte-for-byte. This pins the serde-extraction step against the
    /// upstream `SignatureKeyPair` shape: an upstream serde change (or a wrong
    /// seed length) breaks this test loudly rather than silently deriving a
    /// different pseudonym. (ADR-057 Option A, §9.10.4.A.)
    #[test]
    #[allow(clippy::unwrap_used)]
    fn derive_pseudonym_matches_direct_private_seed_derivation() {
        let cred = test_credential("alice");
        let group = create_group(&cred, &SystemClock).unwrap();

        let context_id = b"ctx-derive-pseudonym-crosscheck";
        let via_method = group.derive_pseudonym(context_id).unwrap();

        // Ground truth: read the seed directly through the test-utils accessor and
        // derive independently via the shared recipe.
        let signer = group.signer_key_pair().unwrap();
        // SCP MLS signer is Ed25519 → a 32-byte seed.
        let seed: [u8; 32] = signer.private().try_into().unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let expected = scp_crypto::pseudonym::derive_pseudonym_keypair(&sk, context_id, None)
            .verifying_key()
            .to_bytes();

        assert_eq!(
            via_method, expected,
            "derive_pseudonym must recover the exact MLS private seed and derive the same pseudonym"
        );
        // (v2 epoch-scoped derivation is not exposed by `derive_pseudonym` yet — the
        // epoch is fixed to `None` internally; the v1-vs-v2 domain separation is
        // covered by `scp_crypto::pseudonym`'s own KAT.)
    }

    /// The pseudonym is a deterministic function of the MLS signing key, so it
    /// survives a state serialize/restore round-trip unchanged (the persisted MLS
    /// signer is byte-identical after `serialize_state` / `deserialize_state`).
    /// This is the property the browser relies on: a reopened tab re-derives the
    /// SAME pseudonym from its restored MLS key (ADR-057 T2).
    #[test]
    #[allow(clippy::unwrap_used)]
    fn derive_pseudonym_is_stable_across_serialize_restore() {
        let cred = test_credential("alice");
        let group = create_group(&cred, &SystemClock).unwrap();
        let context_id = b"ctx-derive-pseudonym-restore";
        let before = group.derive_pseudonym(context_id).unwrap();

        let blob = group.serialize_state().unwrap();
        let restored = ScpMlsGroup::deserialize_state(&blob).unwrap();
        let after = restored.derive_pseudonym(context_id).unwrap();

        assert_eq!(
            before, after,
            "the same MLS key must re-derive the same pseudonym after restore"
        );
    }

    /// Two independently-created groups (distinct MLS keys) derive distinct
    /// pseudonyms for the same context — the pseudonym is keyed on the private
    /// seed, so it is per-member, not per-context-only.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn derive_pseudonym_distinct_per_group() {
        let context_id = b"ctx-derive-pseudonym-distinct";
        let a = create_group(&test_credential("alice"), &SystemClock)
            .unwrap()
            .derive_pseudonym(context_id)
            .unwrap();
        let b = create_group(&test_credential("bob"), &SystemClock)
            .unwrap()
            .derive_pseudonym(context_id)
            .unwrap();
        assert_ne!(a, b, "distinct MLS keys derive distinct pseudonyms");
    }

    /// A destroyed group has no signer, so pseudonym derivation fails closed
    /// rather than deriving from absent key material.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn derive_pseudonym_on_destroyed_group_fails_closed() {
        let mut group = create_group(&test_credential("alice"), &SystemClock).unwrap();
        destroy_group(&mut group).unwrap();
        assert!(matches!(
            group.derive_pseudonym(b"ctx"),
            Err(MlsError::GroupDestroyed)
        ));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_group_returns_group_with_one_member() {
        let cred = test_credential("alice");
        let group = create_group(&cred, &SystemClock).unwrap();

        let members = group.members().unwrap();
        assert_eq!(members.len(), 1, "group should have exactly one member");

        let epoch = group.epoch().unwrap();
        assert_eq!(epoch, 0, "new group should be at epoch 0");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_group_uses_scp_ciphersuite() {
        let cred = test_credential("alice");
        let group = create_group(&cred, &SystemClock).unwrap();

        let inner = group.inner().unwrap();
        assert_eq!(
            inner.ciphersuite(),
            SCP_CIPHERSUITE,
            "group must use SCP ciphersuite"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_group_embeds_scp_credential() {
        let cred = test_credential("alice");
        let group = create_group(&cred, &SystemClock).unwrap();

        let members = group.members().unwrap();
        assert_eq!(members.len(), 1);

        let member = &members[0];
        let basic_cred = BasicCredential::try_from(member.credential.clone()).unwrap();
        let decoded = ScpCredential::from_bytes(basic_cred.identity()).unwrap();
        assert_eq!(decoded.did, cred.did);
        assert_eq!(decoded.ucan_token, cred.ucan_token);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_member_returns_welcome_and_commit() {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();

        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
        let result = add_member(&mut alice_group, bob_kp, &SystemClock).unwrap();

        // Verify we got both messages.
        assert!(
            !result.commit.tls_serialize_detached().unwrap().is_empty(),
            "commit message should not be empty"
        );
        assert!(
            !result.welcome.tls_serialize_detached().unwrap().is_empty(),
            "welcome message should not be empty"
        );

        // Verify epoch advanced.
        let epoch = alice_group.epoch().unwrap();
        assert_eq!(epoch, 1, "epoch should advance to 1 after add");

        // Verify member count increased.
        let members = alice_group.members().unwrap();
        assert_eq!(members.len(), 2, "group should have two members after add");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_member_welcome_allows_joining() {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();

        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
        let result = add_member(&mut alice_group, bob_kp, &SystemClock).unwrap();

        // Bob joins using the Welcome message.
        let bob_group = join_group(&result.welcome, bob_provider, bob_signer).unwrap();

        // Both Alice and Bob should see 2 members.
        let alice_members = alice_group.members().unwrap();
        let bob_members = bob_group.members().unwrap();
        assert_eq!(alice_members.len(), 2);
        assert_eq!(bob_members.len(), 2);

        // Both should be at epoch 1.
        assert_eq!(alice_group.epoch().unwrap(), 1);
        assert_eq!(bob_group.epoch().unwrap(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn remove_member_advances_epoch() {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        // Add Bob.
        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, _bob_signer, _bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
        let _add_result = add_member(&mut alice_group, bob_kp, &SystemClock).unwrap();

        // Epoch should be 1 after add.
        assert_eq!(alice_group.epoch().unwrap(), 1);

        // Find Bob's leaf index (not Alice's own).
        let alice_own_index = alice_group.own_leaf_index().unwrap();
        let members = alice_group.members().unwrap();
        let bob_member = members.iter().find(|m| m.index != alice_own_index).unwrap();

        // Remove Bob.
        let remove_result = remove_member(&mut alice_group, bob_member.index).unwrap();

        // Verify epoch advanced to 2.
        assert_eq!(alice_group.epoch().unwrap(), 2);

        // Verify only Alice remains.
        let members = alice_group.members().unwrap();
        assert_eq!(members.len(), 1, "only alice should remain");

        // Verify commit is non-empty.
        assert!(
            !remove_result
                .commit
                .tls_serialize_detached()
                .unwrap()
                .is_empty(),
            "commit should not be empty"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_group_prevents_further_operations() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred, &SystemClock).unwrap();

        destroy_group(&mut group).unwrap();

        // All operations should return GroupDestroyed.
        assert!(group.epoch().is_err());
        assert!(group.members().is_err());
        assert!(group.group_id().is_err());
        assert!(group.inner().is_err());
        assert!(group.own_leaf_index().is_err());

        // Double destroy should also error.
        assert!(destroy_group(&mut group).is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_group_releases_crypto_state() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred, &SystemClock).unwrap();

        // Before destroy: group and signer are Some.
        assert!(group.group.is_some());
        assert!(group.signer.is_some());

        destroy_group(&mut group).unwrap();

        // After destroy: group and signer are None, provider is fresh.
        assert!(
            group.group.is_none(),
            "MLS group must be dropped on destroy"
        );
        assert!(
            group.signer.is_none(),
            "signing key must be dropped on destroy"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_group_then_add_member_fails() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred, &SystemClock).unwrap();
        destroy_group(&mut group).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, _signer, _provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let result = add_member(&mut group, bob_kp, &SystemClock);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_key_package_produces_valid_package() {
        let cred = test_credential("bob");
        let (kp_bundle, _signer, _provider) = generate_key_package(&cred, &SystemClock).unwrap();

        // The key package should use the SCP ciphersuite.
        assert_eq!(
            kp_bundle.key_package().ciphersuite(),
            SCP_CIPHERSUITE,
            "key package must use SCP ciphersuite"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn key_package_in_did_recovers_embedded_did() {
        // The DID a `key_package_in_did` reads must equal the DID the key
        // package was generated for — proving a driver can name the joiner from
        // the wire-delivered package without a separately supplied DID.
        let cred = ScpCredential::new(
            "did:dht:z6MkKeyPackageDidExtractFixture".to_string(),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap();
        let (kp_bundle, _signer, _provider) = generate_key_package(&cred, &SystemClock).unwrap();
        let kp_in: KeyPackageIn = kp_bundle.key_package().clone().into();

        let did = key_package_in_did(&kp_in, ProtocolVersion::Mls10, &SystemClock).unwrap();
        assert_eq!(did, "did:dht:z6MkKeyPackageDidExtractFixture");
    }

    // -----------------------------------------------------------------------
    // ADR-057 §Prereq-1: KeyPackage Lifetime routed through the injected Clock
    // -----------------------------------------------------------------------
    //
    // Test-clock realism: openmls's un-injectable internal `is_valid`/`Lifetime::new`
    // still run against the REAL system clock at every openmls generation/validation
    // site, so injected TestClocks must sit within the real-clock acceptance window.
    // We seed from `SystemClock.now_secs()` and apply small relative offsets.

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_key_package_lifetime_pins_bounds_to_injected_clock() {
        use crate::lifetime::{KEY_PACKAGE_LIFETIME_MARGIN_SECS, KEY_PACKAGE_LIFETIME_SECS};
        // Seed the injected clock at real-now so openmls's own internal checks
        // (which run against the real clock) also pass.
        let now = SystemClock.now_secs();
        let clock = scp_clock::TestClock::new(now);
        let cred = test_credential("alice");
        let (bundle, _s, _p) = generate_key_package(&cred, &clock).unwrap();
        let lt = bundle.key_package().life_time();
        assert_eq!(
            lt.not_before(),
            now - KEY_PACKAGE_LIFETIME_MARGIN_SECS,
            "not_before must be injected-now minus the 1h margin"
        );
        assert_eq!(
            lt.not_after(),
            now + KEY_PACKAGE_LIFETIME_SECS,
            "not_after must be injected-now plus the ~84d lifetime"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_key_package_lifetime_follows_injected_clock_not_openmls_clock() {
        use crate::lifetime::{KEY_PACKAGE_LIFETIME_MARGIN_SECS, KEY_PACKAGE_LIFETIME_SECS};
        // Inject a clock 900s ahead of the real clock. If generation read
        // openmls's internal clock the bounds would be pinned to real-now; they
        // must instead be pinned to the injected (real-now + 900) value. 900s is
        // well within openmls's real-clock acceptance window.
        let real_now = SystemClock.now_secs();
        let injected = real_now + 900;
        let clock = scp_clock::TestClock::new(injected);
        let (bundle, _s, _p) = generate_key_package(&test_credential("bob"), &clock).unwrap();
        let lt = bundle.key_package().life_time();
        assert_eq!(lt.not_before(), injected - KEY_PACKAGE_LIFETIME_MARGIN_SECS);
        assert_eq!(lt.not_after(), injected + KEY_PACKAGE_LIFETIME_SECS);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_group_routes_own_leaf_lifetime_through_injected_clock() {
        // The creator's own-leaf `Lifetime` is in fact publicly reachable
        // (`MlsGroup::own_leaf_node()` is public, and `leaf_node_source()` — also
        // public — exposes the `Lifetime` via `LeafNodeSource::KeyPackage`; only
        // `LeafNode::life_time()` is `pub(crate)`). This test deliberately pins
        // the observable contract instead — create_group accepts an injected
        // clock and builds a usable group — because the leaf-bound routing shares
        // the exact `key_package_lifetime` helper already asserted directly in
        // the two generate_key_package tests above and in the `crate::lifetime`
        // unit tests, so re-reading the own leaf here would only duplicate that.
        // (The un-bracketable residual is the *joining peers'* leaves, which — un-
        // like the own leaf — a joined `MlsGroup` exposes no public way to reach.)
        let now = SystemClock.now_secs();
        let clock = scp_clock::TestClock::new(now);
        let group = create_group(&test_credential("carol"), &clock).unwrap();
        assert_eq!(group.members().unwrap().len(), 1);
        assert_eq!(group.epoch().unwrap(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn add_member_rejects_lifetime_expired_against_injected_clock() {
        // A KeyPackage minted at real-now (not_after ~ real-now + 84d) must be
        // rejected by add_member when the injected clock is 100 days ahead —
        // even though openmls's own internal validate (real clock) accepts it.
        // The SCP-layer check is authoritative and the group epoch is unchanged.
        let real_now = SystemClock.now_secs();
        let mut alice = create_group(&test_credential("alice"), &SystemClock).unwrap();
        let epoch_before = alice.epoch().unwrap();

        let (bob_bundle, _s, _p) =
            generate_key_package(&test_credential("bob"), &SystemClock).unwrap();
        let bob_kp: KeyPackageIn = bob_bundle.key_package().clone().into();

        let hundred_days = 100 * 24 * 60 * 60;
        let future = scp_clock::TestClock::new(real_now + hundred_days);
        // `.err()` avoids requiring `AddMemberResult: Debug` for `unwrap_err`.
        let err = add_member(&mut alice, bob_kp, &future)
            .err()
            .expect("add_member must reject an expired-lifetime KP");
        assert!(
            matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }),
            "expected KeyPackageLifetimeInvalid, got {err:?}"
        );
        assert_eq!(
            alice.epoch().unwrap(),
            epoch_before,
            "a rejected add must NOT advance the epoch"
        );

        // With the clock at real-now, an equivalent fresh KP is accepted.
        let (carol_bundle, _cs, _cp) =
            generate_key_package(&test_credential("carol"), &SystemClock).unwrap();
        let carol_kp: KeyPackageIn = carol_bundle.key_package().clone().into();
        add_member(&mut alice, carol_kp, &SystemClock).unwrap();
        assert_eq!(
            alice.epoch().unwrap(),
            epoch_before + 1,
            "an accepted add advances the epoch"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn key_package_in_did_rejects_expired_against_injected_clock() {
        let real_now = SystemClock.now_secs();
        let (bundle, _s, _p) =
            generate_key_package(&test_credential("carol"), &SystemClock).unwrap();
        let kp_in: KeyPackageIn = bundle.key_package().clone().into();

        let hundred_days = 100 * 24 * 60 * 60;
        let future = scp_clock::TestClock::new(real_now + hundred_days);
        let err = key_package_in_did(&kp_in, ProtocolVersion::Mls10, &future).unwrap_err();
        assert!(
            matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }),
            "expected KeyPackageLifetimeInvalid, got {err:?}"
        );

        // Accepted with the clock at real-now.
        let did = key_package_in_did(&kp_in, ProtocolVersion::Mls10, &SystemClock).unwrap();
        assert_eq!(did, "did:dht:z6Mkcarol");
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn add_member_rejects_over_long_lifetime_that_openmls_would_accept() {
        use crate::lifetime::KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS;
        // Build a legitimately-signed KeyPackage whose Lifetime is temporally
        // valid (not_before < now < not_after) but whose total range exceeds the
        // RFC 9420 maximum. openmls's own `validate` would accept it (it never
        // calls `has_acceptable_range`); our add_member rejects it on range.
        let real_now = SystemClock.now_secs();
        let cred = test_credential("dave");
        let provider = InMemoryMlsProvider::default();
        let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(cred.to_bytes().unwrap()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let over_long = Lifetime::init(
            real_now - 10,
            real_now + KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS + 10,
        );
        let bundle = KeyPackage::builder()
            .key_package_lifetime(over_long)
            .build(SCP_CIPHERSUITE, &provider, &signer, cwk)
            .unwrap();
        let kp_in: KeyPackageIn = bundle.key_package().clone().into();

        // Sanity: openmls's own validation accepts this over-long KP.
        assert!(
            kp_in
                .clone()
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .is_ok(),
            "openmls validate should accept the over-long-but-temporally-valid KP"
        );

        let mut alice = create_group(&test_credential("alice"), &SystemClock).unwrap();
        let err = add_member(&mut alice, kp_in, &SystemClock)
            .err()
            .expect("add_member must reject an over-long-range KP");
        assert!(
            matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }),
            "add_member must reject an over-long-range KP openmls would accept, got {err:?}"
        );
    }
}
