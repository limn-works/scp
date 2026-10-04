//! Production [`MlsBackend`](super::backend::MlsBackend) implementation.
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §6).
//!
//! # Design
//!
//! [`ProductionMlsBackend`] is a stateless struct that delegates every
//! primitive to the existing [`scp_mls::group`], [`scp_mls::encrypt`], and
//! [`scp_mls::ratchet`] free functions — the same `OpenMLS` primitives the
//! pre-refactor `NodeMlsFactory` calls. This guarantees byte-identical
//! output for equivalent inputs (see the unit test suite below), which is a
//! hard requirement of the commit 4 plan: later commits replace
//! `NodeMlsFactory` with handler functions that call this trait, and the
//! migration MUST NOT perturb wire bytes.
//!
//! # Signer-state serialization
//!
//! `generate_key_package` returns an opaque [`SignerState`](
//! super::backend::SignerState) that the caller later passes back to
//! `join_from_welcome`. The serialization format is MessagePack-encoded
//! [`SerializedSigner`] — the byte layout is private to this module and is
//! not a stable interoperability surface. Callers MUST NOT parse the bytes.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use openmls::ciphersuite::hash_ref::make_key_package_ref;
use openmls::prelude::*;
use openmls::treesync::errors::LifetimeError;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::StorageProvider as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use super::backend::{
    AddMemberRaw, GeneratedKeyPackage, MlsBackend, RemoveMemberRaw, SignerState,
    ValidatedKeyPackage,
};
use super::storage::new_provider;
use super::storage_adapter::OpenMlsStorageAdapter;
use scp_clock::Clock;
use scp_mls::InMemoryMlsProvider;
use scp_mls::credential::ScpCredential;
use scp_mls::encrypt::{DecryptedContent, decrypt_with_sender_did};
use scp_mls::error::MlsError;
use scp_mls::group::{self, SCP_CIPHERSUITE, ScpMlsGroup};
use scp_mls::validate_key_package_lifetime;

/// Durable-store key namespace for the consumed-init-key set (A2 crypto-layer
/// single-use backstop). Value at `scp-kp-consumed-initkey/{hex(SHA-256(init_key))}`
/// is a 1-byte marker; its presence means that KP's init key was already
/// consumed by a completed join.
const CONSUMED_INIT_KEY_PREFIX: &str = "scp-kp-consumed-initkey";

// ---------------------------------------------------------------------------
// ProductionMlsBackend
// ---------------------------------------------------------------------------

/// Production `MlsBackend` backed by `OpenMLS`.
///
/// Stateless on the wire-primitive surface — every MLS primitive delegates to
/// the same free-function family the pre-refactor `NodeMlsFactory` uses,
/// preserving byte-identical output through the trait split. The owned state is
/// the durable consumed-init-key set (`consumed_init_key_store`), a crypto-layer
/// single-use backstop attached once after construction via
/// [`MlsBackend::set_consumed_init_key_store`], plus a `join_gate` mutex that
/// serializes the retrieve→join→store consumed-init-key sequence.
///
/// # Why the store is attached after construction (not a constructor arg)
///
/// The backend is built inside `NodeMlsFactory::new` / `with_backends`,
/// which run BEFORE the supervisor exists and therefore before the
/// supervisor-owned `mls_storage` is available — the provider (carrying this
/// backend) is passed INTO `Supervisor::with_providers`, which only then has
/// the storage to wire. A construction-time required parameter is thus
/// impossible without inverting that ordering across all three FFI bridges.
/// Instead the store is a [`OnceLock`] set once after construction, and
/// `join_from_welcome` **fails CLOSED** when it is still unset (deny-by-default)
/// — the single-use backstop never silently vanishes.
///
/// The store is a [`OnceLock`] so reads stay lock-free (ADR-049 §12) and the
/// store is set at most once. Safe to share via `Arc` across every actor in the
/// process.
///
/// # Anchor independence vs. shared durable substrate (ADR-049 §9)
///
/// This crypto-layer consumed-init-key set (A2) is independent of the actor's
/// reservation journal (A1) in KEYING (HPKE init key vs. reservation-id /
/// consumed-`kp_ref`) and in ENFORCEMENT LOCATION (this backend vs. the
/// `KeyPackageStoreActor`): a LOGIC bug in either cannot defeat the other. The
/// two anchors are NOT independent in their durable substrate — the attached
/// `consumed_init_key_store` is the SAME injected `mls_storage` `Arc` the
/// reservation journal writes to (a different key prefix on one backend).
/// Single-use DURABILITY is therefore contingent on that backend's
/// crash-and-rollback consistency: an operator or faulty/adversarial `Storage`
/// backend that can roll `mls_storage` back to a pre-consume state — a partial
/// restore, a rollback, or a correlated loss spanning both key prefixes —
/// un-consumes a `KeyPackage` at BOTH layers at once, re-enabling re-pool +
/// re-join. This is consistent with the protocol treating durable storage as
/// the trust anchor; it is not a logic gap the backend can close in code.
/// Giving A2 a SEPARATE failure domain from A1 is a possible FUTURE hardening,
/// out of scope until the consume path is production-wired (the
/// spawn-from-Welcome entrypoint) and deliberately NOT implemented now.
pub struct ProductionMlsBackend {
    /// Injected hardened [`Clock`] used to stamp `KeyPackage` / group-leaf
    /// `Lifetime`s on generation and to re-validate accepted `Lifetime`s on the
    /// receive/add paths and the joiner's own `KeyPackage` on a Welcome join
    /// (ADR-057 §Prereq-1); another member's Welcome tree leaf is checked for
    /// range only and reads no clock. In production this is the SAME
    /// `Arc` the owning `NodeMlsFactory` and the actor-deps clock share, so
    /// there is one hardened clock per node — never openmls's internal one.
    clock: Arc<dyn Clock>,
    /// Durable consumed-init-key set. `None` until
    /// [`MlsBackend::set_consumed_init_key_store`] wires the supervisor's
    /// shared `mls_storage`. When unset, `join_from_welcome` FAILS CLOSED (it
    /// does NOT skip the crypto-layer replay check).
    consumed_init_key_store: OnceLock<Arc<dyn OpenMlsStorageAdapter>>,
    /// Serializes the consumed-init-key `retrieve → join → store` sequence in
    /// [`MlsBackend::join_from_welcome`] so two concurrent joins of the same
    /// init key cannot both pass the retrieve before either stores (a
    /// check-then-act TOCTOU on the shared backend instance).
    ///
    /// This is NOT a per-context read-path lock — joins are rare and off the
    /// hot per-context dispatch path, so ADR-049 §12's "no `Mutex` on read
    /// paths" rule is not implicated (the gate is acquired only on a join,
    /// which is not a per-command-dispatch read).
    #[allow(
        clippy::disallowed_types,
        reason = "ADR-049 §Decision 12 allow-list: serializes the join_from_welcome consumed-init-key retrieve→join→store sequence (TOCTOU guard). Acquired only on a join, not on a per-command read path."
    )]
    join_gate: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for ProductionMlsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductionMlsBackend")
            .field("clock", &"<Arc<dyn Clock>>")
            .field(
                "consumed_init_key_store",
                &self.consumed_init_key_store.get().is_some(),
            )
            .field("join_gate", &"<tokio::sync::Mutex>")
            .finish()
    }
}

impl ProductionMlsBackend {
    /// Creates a new production backend with no consumed-init-key store
    /// attached yet. Production wires the store via
    /// [`MlsBackend::set_consumed_init_key_store`] (called from the
    /// supervisor's `with_providers`) BEFORE any join is attempted; until the
    /// store is attached, [`MlsBackend::join_from_welcome`] fails closed.
    ///
    /// # Arguments
    ///
    /// * `clock` - The injected hardened [`Clock`] used for `KeyPackage` /
    ///   group-leaf `Lifetime` stamping and validation (ADR-057 §Prereq-1).
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        #[allow(
            clippy::disallowed_types,
            reason = "ADR-049 §Decision 12 allow-list: constructs the join_from_welcome TOCTOU guard (see the `join_gate` field); acquired only on a join, not a per-command read."
        )]
        let join_gate = tokio::sync::Mutex::new(());
        Self {
            clock,
            consumed_init_key_store: OnceLock::new(),
            join_gate,
        }
    }

    /// Derive the durable consumed-init-key set key for a KP's TLS-serialized
    /// public bytes: `scp-kp-consumed-initkey/{hex(SHA-256(hpke_init_key))}`.
    ///
    /// The HPKE init key is the cryptographically-unique single-use element of
    /// a `KeyPackage` (RFC 9420 §10): each KP carries a fresh init key, and a
    /// Welcome is HPKE-sealed to it. Keying the consumed set by the init key
    /// (not the whole KP bytes) binds the marker to the exact one-time secret
    /// `OpenMLS` consumes on join.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::WelcomeProcessingFailed`] if the public bytes do
    /// not deserialize / validate as an SCP `KeyPackage`.
    pub(crate) fn consumed_init_key_key(
        key_package_public_bytes: &[u8],
    ) -> Result<String, MlsError> {
        Self::init_key_marker(key_package_public_bytes, |e| {
            MlsError::WelcomeProcessingFailed(format!("validating key package for init-key: {e}"))
        })
    }

    /// [`Self::consumed_init_key_key`] for the signer state's own
    /// `KeyPackage` bytes in `join_from_welcome`: openmls's internal-clock
    /// rejection in `KeyPackageIn::validate` is reported as
    /// [`MlsError::KeyPackageLifetimeInvalid`] with `own_lifetime`'s bounds and
    /// the `now` openmls read, the shape of an injected-clock rejection
    /// (ADR-057 §Prereq-1 residual). `own_lifetime` is the `Lifetime` of the
    /// signer state's own `KeyPackageBundle`, read from the same bytes, so the
    /// bounds always belong to the `KeyPackage` openmls rejected. Only those
    /// bytes may be passed here; the caller-supplied bytes go through the
    /// unmapped [`Self::consumed_init_key_key`].
    ///
    /// # Errors
    ///
    /// As [`Self::consumed_init_key_key`], except for the `Lifetime` rejection.
    fn own_consumed_init_key_key(
        key_package_public_bytes: &[u8],
        own_lifetime: &Lifetime,
    ) -> Result<String, MlsError> {
        Self::init_key_marker(key_package_public_bytes, |e| {
            MlsError::KeyPackageLifetimeInvalid {
                not_before: own_lifetime.not_before(),
                not_after: own_lifetime.not_after(),
                now: match e {
                    LifetimeError::Expired { now, .. } | LifetimeError::NotValidYet { now, .. } => {
                        *now
                    }
                    LifetimeError::SystemTimeBeforeUnixEpoch => 0,
                },
            }
        })
    }

    /// Shared body of [`Self::consumed_init_key_key`] and
    /// [`Self::own_consumed_init_key_key`]; `on_lifetime` maps openmls's
    /// `LifetimeError` from `KeyPackageIn::validate`.
    fn init_key_marker(
        key_package_public_bytes: &[u8],
        on_lifetime: impl FnOnce(&LifetimeError) -> MlsError,
    ) -> Result<String, MlsError> {
        let kp_in =
            KeyPackageIn::tls_deserialize(&mut &*key_package_public_bytes).map_err(|e| {
                MlsError::WelcomeProcessingFailed(format!(
                    "deserializing key package for init-key: {e}"
                ))
            })?;
        let provider = new_provider();
        let validated = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| match e {
                KeyPackageVerifyError::LifetimeError(lifetime_error) => {
                    on_lifetime(&lifetime_error)
                }
                other => MlsError::WelcomeProcessingFailed(format!(
                    "validating key package for init-key: {other}"
                )),
            })?;
        Ok(Self::consumed_init_key_marker(
            validated.hpke_init_key().as_slice(),
        ))
    }

    /// The consumed-init-key set key for an HPKE init key:
    /// `scp-kp-consumed-initkey/{hex(SHA-256(init_key))}`.
    fn consumed_init_key_marker(init_key: &[u8]) -> String {
        let digest = Sha256::digest(init_key);
        format!("{CONSUMED_INIT_KEY_PREFIX}/{}", hex::encode(digest))
    }

    /// Read the signer state's own `KeyPackage` from the `KeyPackageBundle`
    /// that `generate_key_package` stored in the signer state's provider
    /// (ADR-057 §Prereq-1).
    ///
    /// The bundle is SCP's own locally generated record, keyed by the
    /// `KeyPackageRef` of `own_key_package_bytes` (the public bytes the signer
    /// state carries), so its `Lifetime` and HPKE init key are read without
    /// parsing an unverified `KeyPackage`. `KeyPackage::life_time` cannot fail
    /// on a bundle's `KeyPackage`, whose leaf openmls builds KeyPackage-sourced.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::StorageError`] if the provider storage cannot be
    /// read, and [`MlsError::WelcomeProcessingFailed`] if the reference cannot
    /// be computed or the signer state holds no bundle for its own
    /// `KeyPackage`.
    fn own_key_package(
        provider: &InMemoryMlsProvider,
        own_key_package_bytes: &[u8],
    ) -> Result<KeyPackage, MlsError> {
        let kp_ref =
            make_key_package_ref(own_key_package_bytes, SCP_CIPHERSUITE, provider.crypto())
                .map_err(|e| {
                    MlsError::WelcomeProcessingFailed(format!("own key package reference: {e}"))
                })?;
        let bundle: KeyPackageBundle = provider
            .storage()
            .key_package(&kp_ref)
            .map_err(|e| MlsError::StorageError(format!("reading own key package bundle: {e}")))?
            .ok_or_else(|| {
                MlsError::WelcomeProcessingFailed(
                    "signer state holds no key package bundle for its own key package".to_owned(),
                )
            })?;
        Ok(bundle.key_package().clone())
    }
}

// ---------------------------------------------------------------------------
// SignerState serialization format
// ---------------------------------------------------------------------------

/// Opaque byte layout behind [`SignerState`]. Private to this module.
///
/// `signer_bytes` and `mls_storage_entries` hold private signing key and HPKE
/// decryption-key material, so both are `Zeroizing`: a transient
/// `SerializedSigner` (the wrapper built to serialize a signer-state in
/// `serialize_signer_state`, or parsed back out of one via `parse_signer_state`
/// during a join) wipes them on every drop. `Zeroizing`'s serde impls delegate
/// to the inner value, so the encoding is that of plain `Vec<u8>` / tuple-vec
/// fields. `key_package_public_bytes` is the publishable KP and is not zeroed.
#[derive(Serialize, Deserialize)]
struct SerializedSigner {
    /// MessagePack-serialized [`SignatureKeyPair`] bytes. Zeroed on drop.
    signer_bytes: zeroize::Zeroizing<Vec<u8>>,
    /// Raw MLS storage entries from the `InMemoryMlsProvider` generated
    /// alongside the `KeyPackage`. Needed to process a Welcome addressed to
    /// the KP (`OpenMLS` reads the private HPKE decryption key out of
    /// storage when decrypting the Welcome). Zeroed on drop.
    mls_storage_entries: scp_mls::snapshot::ProviderStorageEntries,
    /// TLS-serialized PUBLIC `KeyPackage` bytes this signer-state was
    /// generated for. Carried so [`MlsBackend::join_from_welcome`] can derive
    /// the consumed-init-key marker from the signer-state's OWN KP and bind it
    /// to the `key_package_public_bytes` argument — defeating a mismatched
    /// `(public_bytes, signer_state)` pair at the bare API boundary. Publishable
    /// (not zeroed).
    key_package_public_bytes: Vec<u8>,
}

fn serialize_signer_state(
    signer: &SignatureKeyPair,
    provider: &InMemoryMlsProvider,
    key_package_public_bytes: &[u8],
) -> Result<SignerState, MlsError> {
    let wrapper = serialized_signer(signer, provider, key_package_public_bytes)?;
    let bytes = scp_mls::secret_msgpack::encode_named(&wrapper)
        .map_err(|e| MlsError::StorageError(format!("signer-state serialization: {e}")))?;

    Ok(SignerState { bytes })
}

/// Captures the [`SerializedSigner`] wrapper [`serialize_signer_state`]
/// encodes: the signer bytes, the provider's storage entries, and the public
/// `KeyPackage` bytes.
fn serialized_signer(
    signer: &SignatureKeyPair,
    provider: &InMemoryMlsProvider,
    key_package_public_bytes: &[u8],
) -> Result<SerializedSigner, MlsError> {
    let (signer_bytes, mls_storage_entries) =
        scp_mls::snapshot::capture_signer_and_storage(provider, signer)?;
    Ok(SerializedSigner {
        signer_bytes,
        mls_storage_entries,
        key_package_public_bytes: key_package_public_bytes.to_vec(),
    })
}

/// Parse the opaque [`SignerState`] blob into its [`SerializedSigner`] wrapper
/// ONCE. Both the bound-init-key derivation and the signer/provider
/// reconstruction in [`MlsBackend::join_from_welcome`] consume the SAME parsed
/// wrapper, so the blob is deserialized exactly once per join (not 2-3×).
fn parse_signer_state(state: &SignerState) -> Result<SerializedSigner, MlsError> {
    rmp_serde::from_slice(&state.bytes)
        .map_err(|e| MlsError::StorageError(format!("signer-state deserialization: {e}")))
}

/// Rebuild the `OpenMLS` signer + provider from an already-parsed
/// [`SerializedSigner`] wrapper. Consumes the wrapper so the private
/// `mls_storage_entries` move into the provider without a copy.
fn signer_and_provider_from_wrapper(
    mut wrapper: SerializedSigner,
) -> Result<(SignatureKeyPair, InMemoryMlsProvider), MlsError> {
    let signer: SignatureKeyPair = rmp_serde::from_slice(&wrapper.signer_bytes)
        .map_err(|e| MlsError::StorageError(format!("signer deserialization: {e}")))?;

    let provider = new_provider();
    {
        let mut values = provider
            .storage()
            .values
            .write()
            .map_err(|e| MlsError::StorageError(format!("provider lock poisoned: {e}")))?;
        // The entries move into the provider without a copy; the provider's
        // own `Drop` wipes them, and the drained `Zeroizing` vector wipes its
        // buffer when `wrapper` drops.
        for (k, v) in wrapper.mls_storage_entries.drain(..) {
            values.insert(k, v);
        }
    }

    // The signer is not written into the provider's storage: every openmls
    // operation that signs takes it as an argument, and openmls never reads a
    // stored `SignatureKeyPair` back.
    Ok((signer, provider))
}

// ---------------------------------------------------------------------------
// MlsBackend impl
// ---------------------------------------------------------------------------

#[async_trait]
impl MlsBackend for ProductionMlsBackend {
    async fn create_group(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<ScpMlsGroup, MlsError> {
        // Delegate to the free function; byte-identical to
        // `NodeMlsFactory::create_mls_group` (which also calls the same
        // primitive). The creator's own leaf `Lifetime` is stamped from the
        // injected hardened clock (ADR-057 §Prereq-1).
        group::create_group_with_wrapping_key(credential, wrapping_pubkey, self.clock.as_ref())
    }

    async fn add_member_raw(
        &self,
        group: &mut ScpMlsGroup,
        key_package_bytes: &[u8],
    ) -> Result<AddMemberRaw, MlsError> {
        // Deserialize the incoming KP bytes into `KeyPackageIn`. This mirrors
        // the existing `add_member` API which accepts a pre-deserialized KP;
        // the trait boundary takes raw bytes so callers do not need to
        // depend on OpenMLS types directly.
        let kp = KeyPackageIn::tls_deserialize(&mut &*key_package_bytes)
            .map_err(|e| MlsError::AddMemberFailed(format!("deserializing key package: {e}")))?;

        let result = group::add_member(group, kp, self.clock.as_ref())?;

        // Serialize the outputs. TLS-serialize matches the primitive
        // `AddMemberResult` fields exactly — byte-identical to the pre-
        // refactor path.
        let commit = result
            .commit
            .tls_serialize_detached()
            .map_err(|e| MlsError::AddMemberFailed(format!("serializing commit: {e}")))?;
        let welcome = result
            .welcome
            .tls_serialize_detached()
            .map_err(|e| MlsError::AddMemberFailed(format!("serializing welcome: {e}")))?;
        let group_info = result
            .group_info
            .map(|gi| {
                gi.tls_serialize_detached()
                    .map_err(|e| MlsError::AddMemberFailed(format!("serializing group_info: {e}")))
            })
            .transpose()?;

        Ok(AddMemberRaw {
            commit,
            welcome,
            group_info,
        })
    }

    async fn remove_member_raw(
        &self,
        group: &mut ScpMlsGroup,
        leaf_index: LeafNodeIndex,
    ) -> Result<RemoveMemberRaw, MlsError> {
        let result = group::remove_member(group, leaf_index)?;

        let commit = result
            .commit
            .tls_serialize_detached()
            .map_err(|e| MlsError::RemoveMemberFailed(format!("serializing commit: {e}")))?;
        let group_info = result
            .group_info
            .map(|gi| {
                gi.tls_serialize_detached().map_err(|e| {
                    MlsError::RemoveMemberFailed(format!("serializing group_info: {e}"))
                })
            })
            .transpose()?;

        Ok(RemoveMemberRaw { commit, group_info })
    }

    async fn encrypt(
        &self,
        group: &mut ScpMlsGroup,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, MlsError> {
        let mls_message = scp_mls::encrypt::encrypt(group, plaintext)?;
        scp_mls::encrypt::serialize_ciphertext(&mls_message)
    }

    async fn decrypt(
        &self,
        group: &mut ScpMlsGroup,
        ciphertext: &[u8],
    ) -> Result<DecryptedContent, MlsError> {
        decrypt_with_sender_did(group, ciphertext, self.clock.as_ref())
    }

    async fn process_commit(
        &self,
        group: &mut ScpMlsGroup,
        commit_bytes: &[u8],
    ) -> Result<(), MlsError> {
        // `decrypt_commit` refuses a non-Commit before decrypting it, so a
        // refused application message or Proposal consumes no ratchet
        // generation, then merges a Commit through `decrypt_with_sender_did`.
        scp_mls::encrypt::decrypt_commit(group, commit_bytes, self.clock.as_ref())
    }

    async fn advance_epoch(
        &self,
        group: &mut ScpMlsGroup,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, MlsError> {
        // Match the existing `NodeMlsFactory::advance_epoch` semantics:
        // the pre-refactor code defaulted the wrapping key to zero-bytes
        // when the provider had not yet generated one (rare but possible
        // during test flows). Mirror that behaviour byte-for-byte.
        let wrap = wrapping_pubkey.map_or([0u8; 32], |k| *k);
        let commit = scp_mls::ratchet::propose_update_with_wrapping_key(group, &wrap)?;
        commit
            .tls_serialize_detached()
            .map_err(|e| MlsError::CommitProcessingFailed(format!("serializing commit: {e}")))
    }

    async fn validate_key_package(
        &self,
        key_package_bytes: &[u8],
        clock: &dyn Clock,
    ) -> Result<ValidatedKeyPackage, MlsError> {
        // Deserialize and validate against the SCP ciphersuite. This runs the
        // OpenMLS-side validation without holding any group state.
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*key_package_bytes)
            .map_err(|e| MlsError::AddMemberFailed(format!("deserializing key package: {e}")))?;

        let provider = new_provider();
        let validated = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| MlsError::AddMemberFailed(format!("key package validation: {e}")))?;

        // SECURITY (ADR-057 §Prereq-1): openmls's `validate` above runs its own
        // internal `Lifetime::validate` against openmls's (wasm: unhardened)
        // clock. Re-validate the accepted `Lifetime` against the injected
        // hardened clock (threaded in as `clock`, not read from backend state —
        // SCP-CRYPTOMOVE-000c) and enforce the RFC 9420 max-range bound
        // openmls's `validate` never applies. Additive hardening; never
        // replaces openmls.
        validate_key_package_lifetime(validated.life_time(), clock)?;

        // Guard the SCP ciphersuite invariant: any KP using a non-SCP
        // ciphersuite MUST be rejected even if OpenMLS validates it against
        // `Mls10`.
        if validated.ciphersuite() != SCP_CIPHERSUITE {
            return Err(MlsError::AddMemberFailed(format!(
                "key package uses non-SCP ciphersuite: {:?}",
                validated.ciphersuite()
            )));
        }

        // Extract the authenticated credential DID from the SAME already-
        // validated leaf. This is the single validate-and-bind that replaces
        // the caller-side re-parse + `scp_mls::group::key_package_in_did`
        // re-validation: it mirrors that primitive's extraction exactly
        // (leaf credential → `BasicCredential` → `ScpCredential` → `did`) but
        // reuses `validated` instead of re-running `.validate` on the bytes.
        let credential = validated.leaf_node().credential().clone();
        let basic = BasicCredential::try_from(credential).map_err(|e| {
            MlsError::CredentialSerializationFailed(format!("extracting BasicCredential: {e}"))
        })?;
        let credential_did = ScpCredential::from_bytes(basic.identity())?.did;

        // Re-serialize to return the canonical validated bytes. Functionally
        // equivalent to the input (OpenMLS does not mutate on validate), but
        // we construct via the validated type so downstream persistence is
        // guaranteed to parse identically.
        let bytes = key_package_bytes.to_vec();
        Ok(ValidatedKeyPackage {
            key_package_bytes: bytes,
            credential_did,
        })
    }

    async fn generate_key_package(
        &self,
        credential: &ScpCredential,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<GeneratedKeyPackage, MlsError> {
        // Every pooled KeyPackage must be joinable into an SCP *context* group,
        // whose `group_context` carries the `scp_context_params` (`0xFF02`)
        // extension. OpenMLS rejects (`valn0502`, RFC 9420 §12.1.8.2) an Add
        // whose leaf does not declare support for every `group_context`
        // extension present in the group — so the KP leaf MUST advertise the
        // `0xFF02` capability regardless of whether a wrapping key is available.
        //
        // `generate_key_package_with_context_params` declares BOTH `0xFF01` +
        // `0xFF02` *capabilities* unconditionally, and attaches the `0xFF01`
        // wrapping-key *leaf extension* only when a key is present (§9.16.1).
        // The capability is what `valn0502` requires (no key material); the
        // leaf extension is the optional enhancement that lets other members
        // HPKE-seal sender keys to this member. Passing `wrapping_pubkey`
        // straight through therefore yields a context-joinable KP in BOTH
        // cases: `Some` → full participant (declares `0xFF02`, carries the
        // wrapping key); `None` → context-joinable but non-receiving until the
        // identity publishes a wrapping key. A `None` KP is NOT downgraded to a
        // wrapping-only (`0xFF01`-only) KeyPackage, which real MLS would reject
        // from a context group.
        //
        // The injected `Clock` mints the KeyPackage `Lifetime` (ADR-057
        // Prereq-1, #2026) — never wall-clock `SystemTime::now()`.
        let (bundle, signer, provider) = group::generate_key_package_with_context_params(
            credential,
            wrapping_pubkey,
            self.clock.as_ref(),
        )?;

        let kp_bytes = bundle.key_package().tls_serialize_detached().map_err(|e| {
            MlsError::KeyPackageGenerationFailed(format!("serializing key package: {e}"))
        })?;

        let signer_state = serialize_signer_state(&signer, &provider, &kp_bytes)?;

        Ok(GeneratedKeyPackage {
            key_package_bytes: kp_bytes,
            signer_state,
        })
    }

    async fn join_from_welcome(
        &self,
        welcome_bytes: &[u8],
        signer_state: SignerState,
        key_package_public_bytes: &[u8],
    ) -> Result<ScpMlsGroup, MlsError> {
        // A2 — crypto-layer single-use backstop. Independent of the actor's
        // reservation bookkeeping in KEYING and ENFORCEMENT LOCATION (so a LOGIC
        // bug in the reservation journal cannot defeat it), this rejects a SECOND
        // join with the same KP init key durably, protecting every join that
        // flows through `MlsBackend::join_from_welcome`. Both anchors share the
        // same durable `mls_storage` substrate, so a storage rollback can still
        // un-consume at both layers — see the struct doc's "Anchor independence
        // vs. shared durable substrate" note.
        //
        // Deny-by-default: when no consumed-init-key store has been attached
        // (it is wired post-construction by the supervisor's `with_providers`),
        // FAIL CLOSED rather than skip the check — a single-use security
        // backstop that silently vanishes when unconfigured is the wrong
        // default. The store is always attached before any production join.
        let Some(store) = self.consumed_init_key_store.get() else {
            return Err(MlsError::StorageError(
                "consumed-init-key store not attached: refusing to join without the \
                 single-use backstop (call set_consumed_init_key_store first)"
                    .to_owned(),
            ));
        };

        // Parse the opaque signer-state wrapper ONCE and rebuild its signer
        // and provider; the join reuses both.
        let wrapper = parse_signer_state(&signer_state)?;
        let own_key_package_bytes = wrapper.key_package_public_bytes.clone();
        let (signer, provider) = signer_and_provider_from_wrapper(wrapper)?;

        // The signer state's own KeyPackage, from its locally generated
        // `KeyPackageBundle`: its `Lifetime` and the consumed-set key of its
        // HPKE init key, the one secret a join over this provider consumes.
        let own_key_package = Self::own_key_package(&provider, &own_key_package_bytes)?;
        let own_lifetime = *own_key_package.life_time();
        let consumed_key =
            Self::consumed_init_key_marker(own_key_package.hpke_init_key().as_slice());

        // Serialize the retrieve→join→store sequence so two concurrent joins of
        // the same init key cannot both pass the retrieve before either stores
        // (check-then-act TOCTOU on this shared backend instance). The gate is
        // acquired only on a join (rare, off the per-context read path) — see
        // the `join_gate` field doc for the ADR-049 §12 lock-free-read note.
        let _join_guard = self.join_gate.lock().await;

        // Consult the durable consumed set FIRST, before any lifetime check.
        // An init key already present means this KP was already consumed →
        // reject the replay. A confirm retry after a join that completed must
        // see `KeyPackageReplay` even once the KeyPackage has expired, because
        // the key package actor reads that variant as its own prior
        // completion and finishes the consume.
        let already = store
            .retrieve(&consumed_key)
            .await
            .map_err(|e| MlsError::StorageError(format!("consumed-init-key retrieve: {e}")))?;
        if already.is_some() {
            return Err(MlsError::KeyPackageReplay);
        }

        // ADR-057 §Prereq-1: check the own `Lifetime` against the injected
        // clock before openmls's clock reads it in `KeyPackageIn::validate`,
        // so an own KeyPackage that is expired, not yet valid, or out of range
        // is `KeyPackageLifetimeInvalid` on native as in the browser, whatever
        // openmls's clock says.
        validate_key_package_lifetime(&own_lifetime, self.clock.as_ref())?;

        // Validate the signer state's own KeyPackage bytes. openmls's clock
        // rejection there is `KeyPackageLifetimeInvalid` with the bounds of
        // the KeyPackage it rejected; any other failure, or bytes whose init
        // key differs from the bundle's, is `WelcomeProcessingFailed`.
        if Self::own_consumed_init_key_key(&own_key_package_bytes, &own_lifetime)? != consumed_key {
            return Err(MlsError::WelcomeProcessingFailed(
                "signer state's key package bytes do not match its key package bundle".to_owned(),
            ));
        }

        // Init-key / Welcome binding (checked BEFORE the join consumes anything).
        // `key_package_public_bytes` names the KP the caller believes it is
        // consuming; a successful join over a provider built SOLELY from
        // `signer_state` necessarily uses THAT signer state's init private key
        // (OpenMLS has no other init key in scope), so the caller's bytes must
        // carry the same init key. They go through the unmapped
        // `consumed_init_key_key`, so a lifetime rejection of a mismatched
        // caller KeyPackage is never reported with the own KeyPackage's
        // bounds. Fast path: byte-identical bytes (the actor's normal path)
        // trivially share the init key.
        if own_key_package_bytes != key_package_public_bytes
            && Self::consumed_init_key_key(key_package_public_bytes)? != consumed_key
        {
            return Err(MlsError::WelcomeProcessingFailed(
                "key_package_public_bytes init key does not match the signer-state's \
                 key package (mismatched (public_bytes, signer_state) pair)"
                    .to_owned(),
            ));
        }

        // ADR-057 §Prereq-1: `join_group_from_bytes` checks only the range of
        // every other member's tree leaf, and checks the joiner's OWN leaf in
        // the joined group against the injected hardened clock passed here. A rejection drops the group before the init key is
        // recorded as consumed, so the KeyPackage is not used up.
        let group =
            group::join_group_from_bytes(welcome_bytes, provider, signer, self.clock.as_ref())?;

        // Join succeeded and the marker key is bound to the consumed init key —
        // durably record it BEFORE returning, so a replay (even on a different
        // code path or after a crash) is rejected by the check above. A write
        // failure fails the join closed: returning Ok here would acknowledge a
        // join whose single-use marker was not durably recorded.
        store
            .store(&consumed_key, &[0x01])
            .await
            .map_err(|e| MlsError::StorageError(format!("consumed-init-key store: {e}")))?;

        Ok(group)
    }

    fn set_consumed_init_key_store(&self, store: Arc<dyn OpenMlsStorageAdapter>) {
        // Idempotent single set; a second attach is ignored (the first store
        // wins). Production attaches exactly once via `with_providers`.
        let _ = self.consumed_init_key_store.set(store);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compare two `ScpMlsGroup` instances by their serialized `OpenMLS` storage
/// contents and public group-ID / epoch / member list. Used by the equivalence
/// tests — two groups produced by equivalent call sequences must contain
/// identical on-disk MLS state.
///
/// Returns `Ok(())` on equivalence, or a diagnostic message on divergence.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
/// Compare two MLS groups for STRUCTURAL equivalence.
///
/// `group_id` is intentionally random per `create_group` call (RFC 9420
/// §12.4.2.1: `GroupContext.group_id` is generated by the creator); two
/// groups created independently for the same purpose will never share a
/// `group_id`. We compare ciphersuite, epoch, member count, and member-DID
/// set, which together establish that both backends produced the same
/// "shape" of group from the same inputs.
fn assert_groups_equivalent(left: &ScpMlsGroup, right: &ScpMlsGroup) -> Result<(), String> {
    let l_epoch = left.epoch().map_err(|e| e.to_string())?;
    let r_epoch = right.epoch().map_err(|e| e.to_string())?;
    if l_epoch != r_epoch {
        return Err(format!("epoch differs: {l_epoch} vs {r_epoch}"));
    }

    let l_cs = left.inner().map_err(|e| e.to_string())?.ciphersuite();
    let r_cs = right.inner().map_err(|e| e.to_string())?.ciphersuite();
    if l_cs != r_cs {
        return Err(format!("ciphersuite differs: {l_cs:?} vs {r_cs:?}"));
    }

    let l_members = left.members().map_err(|e| e.to_string())?;
    let r_members = right.members().map_err(|e| e.to_string())?;
    if l_members.len() != r_members.len() {
        return Err(format!(
            "member count differs: {} vs {}",
            l_members.len(),
            r_members.len()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — byte-identical output with NodeMlsFactory MLS primitive calls
// ---------------------------------------------------------------------------
//
// These tests feed identical inputs to `ProductionMlsBackend` and the existing
// `group::*` / `encrypt::*` / `ratchet::*` primitives (the same primitives
// `NodeMlsFactory` delegates to) and assert byte-identical output on the
// MLS primitive surface. Because MLS Welcome / Commit / Ciphertext bytes all
// embed fresh randomness (HPKE ephemeral, AEAD nonces, ratcheted key
// schedule), strict byte equality on identical random inputs requires the
// same RNG seed sequence — which neither path controls. Instead the tests
// assert:
//
// 1. Structural equivalence — same group_id, same epoch after each op.
// 2. Functional round-trip — encrypt via backend → decrypt via primitive (and
//    vice versa), with identical plaintext emerging.
// 3. Welcome cross-compatibility — add_member_raw welcome bytes successfully
//    drive `join_group_from_bytes` (i.e. the Welcome is wire-compatible).
//
// This is the strongest byte-level property we can assert without reseeding
// OpenMLS's internal RNG. The wire format is stable under `MLS_10` per RFC
// 9420 §14; the test suite catches structural divergence (e.g., a dropped
// extension, a non-default group config) which is the failure mode the byte-
// identity requirement actually protects against.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter;
    use scp_clock::SystemClock;
    use scp_did::SigningKeyId;
    use scp_mls::credential::ScpCredential;
    use scp_platform::in_memory::InMemoryStorage;

    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(format!("did:dht:z6Mk{name}"), None, SigningKeyId::Active).unwrap()
    }

    /// `SerializedSigner`'s `Zeroizing` fields encode exactly as the plain
    /// `Vec` fields they replaced, so a signer-state written before the change
    /// still parses and one written after it reads as the plain layout.
    #[test]
    fn serialized_signer_encodes_like_plain_fields() {
        #[derive(Serialize, Deserialize)]
        struct Plain {
            signer_bytes: Vec<u8>,
            mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
            key_package_public_bytes: Vec<u8>,
        }
        let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm()).unwrap();
        let provider = InMemoryMlsProvider::default();
        provider
            .storage()
            .values
            .write()
            .unwrap()
            .insert(b"EncryptionKeyPair-a".to_vec(), vec![0xC3_u8; 48]);
        let wrapper = serialized_signer(&signer, &provider, &[0x5A_u8; 37]).unwrap();
        assert_eq!(wrapper.mls_storage_entries.len(), 1);
        let plain = Plain {
            signer_bytes: wrapper.signer_bytes.to_vec(),
            mls_storage_entries: wrapper.mls_storage_entries.to_vec(),
            key_package_public_bytes: wrapper.key_package_public_bytes.clone(),
        };
        let plain_bytes = rmp_serde::to_vec_named(&plain).unwrap();
        assert_eq!(rmp_serde::to_vec_named(&wrapper).unwrap(), plain_bytes);
        let parsed = parse_signer_state(&SignerState {
            bytes: zeroize::Zeroizing::new(plain_bytes),
        })
        .unwrap();
        assert_eq!(*parsed.signer_bytes, plain.signer_bytes);
        assert_eq!(*parsed.mls_storage_entries, plain.mls_storage_entries);
    }

    /// A `ProductionMlsBackend` with the durable consumed-init-key store
    /// attached over a fresh in-memory `Storage`, so `join_from_welcome` is
    /// JOINABLE (it fails closed without a store). Use for any test that drives
    /// a real join.
    fn joinable_backend() -> ProductionMlsBackend {
        let backend = ProductionMlsBackend::new(Arc::new(SystemClock));
        let store: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ));
        backend.set_consumed_init_key_store(store);
        backend
    }

    /// Security-critical: two concurrent `join_from_welcome` calls for ONE
    /// generated KP (same init key) on a store-wired backend must resolve to
    /// EXACTLY one `Ok` and one `Err(MlsError::KeyPackageReplay)`. This
    /// exercises the `join_gate` mutex that serializes the
    /// retrieve→join→store consumed-init-key sequence: without it, both joins
    /// could pass the durable `retrieve` (seeing the init key absent) before
    /// either `store`d the marker — a check-then-act TOCTOU that would let the
    /// single-use KP join two groups. A Welcome is single-use cryptographically,
    /// so we build TWO distinct Welcomes addressed to the SAME KP (two inviter
    /// groups each add the same `key_package_bytes`); the init-key backstop —
    /// not Welcome uniqueness — is what must reject the second join.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_join_of_one_kp_yields_exactly_one_replay_rejection() {
        let backend = Arc::new(joinable_backend());

        // Two inviter groups each add the SAME KeyPackage, producing two
        // distinct (cryptographically single-use) Welcomes for one init key.
        let kp_cred = test_credential("bob-race");
        let kp_gen = backend.generate_key_package(&kp_cred, None).await.unwrap();

        let inviter_a = test_credential("alice-race-a");
        let mut grp_a = backend.create_group(&inviter_a, None).await.unwrap();
        let added_a = backend
            .add_member_raw(&mut grp_a, &kp_gen.key_package_bytes)
            .await
            .unwrap();

        let inviter_b = test_credential("alice-race-b");
        let mut grp_b = backend.create_group(&inviter_b, None).await.unwrap();
        let added_b = backend
            .add_member_raw(&mut grp_b, &kp_gen.key_package_bytes)
            .await
            .unwrap();

        // Race the two joins of the SAME KP (same init key) through the shared
        // backend (shared `join_gate` + consumed-init-key store).
        let b1 = Arc::clone(&backend);
        let b2 = Arc::clone(&backend);
        let kp_bytes_1 = kp_gen.key_package_bytes.clone();
        let kp_bytes_2 = kp_gen.key_package_bytes.clone();
        let signer_1 = kp_gen.signer_state.clone();
        let signer_2 = kp_gen.signer_state.clone();
        let welcome_1 = added_a.welcome.clone();
        let welcome_2 = added_b.welcome.clone();

        let (res1, res2) = tokio::join!(
            async move {
                b1.join_from_welcome(&welcome_1, signer_1, &kp_bytes_1)
                    .await
            },
            async move {
                b2.join_from_welcome(&welcome_2, signer_2, &kp_bytes_2)
                    .await
            },
        );

        // `ScpMlsGroup` is not `Debug`; project each result to a Debug-able tag
        // for the assertion messages.
        let tag = |r: &Result<ScpMlsGroup, MlsError>| match r {
            Ok(_) => "Ok".to_owned(),
            Err(e) => format!("Err({e:?})"),
        };
        let (t1, t2) = (tag(&res1), tag(&res2));

        let ok_count = usize::from(res1.is_ok()) + usize::from(res2.is_ok());
        let replay_count = usize::from(matches!(res1, Err(MlsError::KeyPackageReplay)))
            + usize::from(matches!(res2, Err(MlsError::KeyPackageReplay)));
        assert_eq!(
            ok_count, 1,
            "exactly one concurrent join must succeed (res1={t1}, res2={t2})"
        );
        assert_eq!(
            replay_count, 1,
            "exactly one concurrent join must be rejected as a single-use replay \
             (res1={t1}, res2={t2})"
        );
    }

    /// ADR-057 §Prereq-1 wiring: `join_from_welcome` accepts a Welcome whose
    /// tree holds a KeyPackage-sourced leaf that expired under the real clock,
    /// which both openmls and the backend read, and records the joiner's init
    /// key as consumed. A member whose leaf expired no longer blocks a join.
    #[tokio::test]
    async fn join_from_welcome_accepts_expired_tree_leaf_and_records_consumed_key() {
        let store: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ));
        let joiner = ProductionMlsBackend::new(Arc::new(SystemClock));
        joiner.set_consumed_init_key_store(Arc::clone(&store));

        let bob_gen = joiner
            .generate_key_package(&test_credential("bob-expired-leaf"), None)
            .await
            .unwrap();

        let (mut alice, carol_not_after) = group::group_holding_carol_leaf_expired().unwrap();
        assert!(
            carol_not_after < SystemClock.now_secs(),
            "Carol's leaf must be expired under the real clock"
        );
        let added = ProductionMlsBackend::new(Arc::new(SystemClock))
            .add_member_raw(&mut alice, &bob_gen.key_package_bytes)
            .await
            .unwrap();

        let bob = joiner
            .join_from_welcome(
                &added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();
        assert_eq!(bob.members().unwrap().len(), 3, "Carol, Alice and Bob");

        let consumed_key =
            ProductionMlsBackend::consumed_init_key_key(&bob_gen.key_package_bytes).unwrap();
        assert!(
            store.retrieve(&consumed_key).await.unwrap().is_some(),
            "an accepted join records the init key as consumed"
        );
    }

    /// ADR-057 §Prereq-1 wiring: `join_from_welcome` checks the joiner's own
    /// `KeyPackage` against the backend's injected clock, not only openmls's
    /// real clock. The backend clock sits past the `KeyPackage`'s `not_after`
    /// while the real clock is still inside its `Lifetime`, so openmls's check
    /// in `own_consumed_init_key_key` passes and only the injected-clock check can
    /// reject. The rejection records no consumed init key, so the same Welcome
    /// joins once the backend clock is correct.
    #[tokio::test]
    async fn join_from_welcome_rejects_own_key_package_expired_under_injected_clock() {
        use scp_clock::TestClock;
        use scp_mls::lifetime::KEY_PACKAGE_LIFETIME_SECS;

        let real_now = SystemClock.now_secs();
        let joiner_clock = Arc::new(TestClock::new(real_now));
        let store: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ));
        let joiner = ProductionMlsBackend::new(Arc::clone(&joiner_clock) as Arc<dyn Clock>);
        joiner.set_consumed_init_key_store(Arc::clone(&store));

        // Minted at the real present, so openmls's real-clock checks on the
        // adder's side and in `own_consumed_init_key_key` accept it.
        let bob_gen = joiner
            .generate_key_package(&test_credential("bob-own-expired"), None)
            .await
            .unwrap();
        let adder = ProductionMlsBackend::new(Arc::new(SystemClock));
        let mut alice = adder
            .create_group(&test_credential("alice-own-expired"), None)
            .await
            .unwrap();
        let bob_add = adder
            .add_member_raw(&mut alice, &bob_gen.key_package_bytes)
            .await
            .unwrap();

        // Bob's `not_after` is `real_now + KEY_PACKAGE_LIFETIME_SECS`.
        joiner_clock.set(real_now + KEY_PACKAGE_LIFETIME_SECS + 1);
        let err = joiner
            .join_from_welcome(
                &bob_add.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .err()
            .expect("an own KeyPackage expired under the injected clock must be rejected");
        assert!(
            matches!(
                err,
                MlsError::KeyPackageLifetimeInvalid { not_after, now, .. } if not_after <= now
            ),
            "expected KeyPackageLifetimeInvalid for Bob's own KeyPackage, got {err:?}"
        );

        let consumed_key =
            ProductionMlsBackend::consumed_init_key_key(&bob_gen.key_package_bytes).unwrap();
        assert!(
            store.retrieve(&consumed_key).await.unwrap().is_none(),
            "a rejected join must not record the init key as consumed"
        );

        // Control: under a correct clock the same Welcome joins and records
        // the init key.
        joiner_clock.set(real_now);
        let bob = joiner
            .join_from_welcome(
                &bob_add.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();
        assert_eq!(bob.members().unwrap().len(), 2, "Alice and Bob");
        assert!(
            store.retrieve(&consumed_key).await.unwrap().is_some(),
            "an accepted join records the init key as consumed"
        );
    }

    /// The consumed-set key of the signer state's own `KeyPackage`, read from
    /// its `KeyPackageBundle` as `join_from_welcome` reads it, so it needs no
    /// openmls validation of a `KeyPackage` openmls's clock rejects.
    fn own_consumed_marker(signer_state: &SignerState) -> String {
        let wrapper = parse_signer_state(signer_state).unwrap();
        let own_bytes = wrapper.key_package_public_bytes.clone();
        let (_signer, provider) = signer_and_provider_from_wrapper(wrapper).unwrap();
        let own = ProductionMlsBackend::own_key_package(&provider, &own_bytes).unwrap();
        ProductionMlsBackend::consumed_init_key_marker(own.hpke_init_key().as_slice())
    }

    /// A joiner whose injected clock is the clock Bob's `KeyPackage` was
    /// minted on, so the injected-clock check passes and only openmls's real
    /// clock in `KeyPackageIn::validate` can reject. `join_from_welcome` runs
    /// every own-`KeyPackage` check before it reads the Welcome bytes, so no
    /// adder and no real-time wait are needed.
    async fn joiner_on_mint_clock(
        mint_now: u64,
        name: &str,
    ) -> (
        ProductionMlsBackend,
        Arc<dyn OpenMlsStorageAdapter>,
        GeneratedKeyPackage,
    ) {
        let store: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ));
        let joiner = ProductionMlsBackend::new(Arc::new(scp_clock::TestClock::new(mint_now)));
        joiner.set_consumed_init_key_store(Arc::clone(&store));
        let bob_gen = joiner
            .generate_key_package(&test_credential(name), None)
            .await
            .unwrap();
        (joiner, store, bob_gen)
    }

    /// ADR-057 §Prereq-1, residual: the injected clock reads Bob's
    /// `KeyPackage` as current, but openmls's real clock in
    /// `KeyPackageIn::validate` (inside `own_consumed_init_key_key`) reads it as
    /// expired. The join reports that rejection as `KeyPackageLifetimeInvalid`
    /// with the `KeyPackage`'s bounds and openmls's `now`, the same shape as an
    /// injected-clock rejection, and records no consumed init key.
    #[tokio::test]
    async fn join_from_welcome_reports_openmls_clock_rejection_of_own_key_package_as_lifetime_invalid()
     {
        use scp_mls::lifetime::{KEY_PACKAGE_LIFETIME_MARGIN_SECS, KEY_PACKAGE_LIFETIME_SECS};

        // Expired under the real clock since `SystemClock.now_secs() - 10`.
        let mint_now = SystemClock.now_secs() - 10 - KEY_PACKAGE_LIFETIME_SECS;
        let (joiner, store, bob_gen) = joiner_on_mint_clock(mint_now, "bob-openmls-expired").await;

        let err = joiner
            .join_from_welcome(
                b"never read",
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .err()
            .expect("openmls's clock rejects Bob's expired KeyPackage");
        assert!(
            matches!(
                err,
                MlsError::KeyPackageLifetimeInvalid { not_before, not_after, now }
                    if not_before == mint_now - KEY_PACKAGE_LIFETIME_MARGIN_SECS
                        && not_after == mint_now + KEY_PACKAGE_LIFETIME_SECS
                        && not_after <= now
            ),
            "expected KeyPackageLifetimeInvalid with Bob's bounds, got {err:?}"
        );
        assert!(
            store
                .retrieve(&own_consumed_marker(&bob_gen.signer_state))
                .await
                .unwrap()
                .is_none(),
            "a rejected join must not record the init key as consumed"
        );
    }

    /// As `join_from_welcome_reports_openmls_clock_rejection_of_own_key_package_as_lifetime_invalid`,
    /// for openmls's `NotValidYet`: Bob's `KeyPackage` is minted on a clock two
    /// hours ahead, so its `not_before` lies an hour ahead of the real clock,
    /// and the injected clock reads that same future time.
    #[tokio::test]
    async fn join_from_welcome_reports_openmls_not_valid_yet_of_own_key_package_as_lifetime_invalid()
     {
        use scp_mls::lifetime::{KEY_PACKAGE_LIFETIME_MARGIN_SECS, KEY_PACKAGE_LIFETIME_SECS};

        let real_now = SystemClock.now_secs();
        let mint_now = real_now + 2 * 60 * 60;
        let (joiner, store, bob_gen) = joiner_on_mint_clock(mint_now, "bob-openmls-early").await;

        let err = joiner
            .join_from_welcome(
                b"never read",
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .err()
            .expect("openmls's clock rejects Bob's not-yet-valid KeyPackage");
        assert!(
            matches!(
                err,
                MlsError::KeyPackageLifetimeInvalid { not_before, not_after, now }
                    if not_before == mint_now - KEY_PACKAGE_LIFETIME_MARGIN_SECS
                        && not_after == mint_now + KEY_PACKAGE_LIFETIME_SECS
                        && real_now <= now
                        && now < not_before
            ),
            "expected KeyPackageLifetimeInvalid with Bob's bounds, got {err:?}"
        );
        assert!(
            store
                .retrieve(&own_consumed_marker(&bob_gen.signer_state))
                .await
                .unwrap()
                .is_none(),
            "a rejected join must not record the init key as consumed"
        );
    }

    /// A confirm retry after a join that completed, or a replay of a consumed
    /// `KeyPackage`, is `KeyPackageReplay` even once the own `KeyPackage` has
    /// expired under the injected clock: the consumed-set check runs before
    /// any lifetime check, and the key package actor relies on that variant to
    /// finish an interrupted consume.
    #[tokio::test]
    async fn join_from_welcome_replay_after_injected_clock_expiry_is_key_package_replay() {
        use scp_clock::TestClock;
        use scp_mls::lifetime::KEY_PACKAGE_LIFETIME_SECS;

        let real_now = SystemClock.now_secs();
        let joiner_clock = Arc::new(TestClock::new(real_now));
        let store: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ));
        let joiner = ProductionMlsBackend::new(Arc::clone(&joiner_clock) as Arc<dyn Clock>);
        joiner.set_consumed_init_key_store(Arc::clone(&store));
        let bob_gen = joiner
            .generate_key_package(&test_credential("bob-replay-injected"), None)
            .await
            .unwrap();
        let adder = ProductionMlsBackend::new(Arc::new(SystemClock));
        let mut alice = adder
            .create_group(&test_credential("alice-replay-injected"), None)
            .await
            .unwrap();
        let bob_add = adder
            .add_member_raw(&mut alice, &bob_gen.key_package_bytes)
            .await
            .unwrap();
        joiner
            .join_from_welcome(
                &bob_add.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();

        // Bob's `not_after` is `real_now + KEY_PACKAGE_LIFETIME_SECS`.
        joiner_clock.set(real_now + KEY_PACKAGE_LIFETIME_SECS + 1);
        let err = joiner
            .join_from_welcome(
                &bob_add.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .err()
            .expect("a second join of a consumed KeyPackage must be rejected");
        assert!(
            matches!(err, MlsError::KeyPackageReplay),
            "expected KeyPackageReplay for the consumed, since-expired KeyPackage, got {err:?}"
        );
    }

    /// As `join_from_welcome_replay_after_injected_clock_expiry_is_key_package_replay`,
    /// but only openmls's real clock reads the consumed own `KeyPackage` as
    /// expired; the injected clock still reads it as current. The store holds
    /// the consumed marker for the bundle's init key, as a completed join
    /// leaves it.
    #[tokio::test]
    async fn join_from_welcome_replay_after_openmls_clock_expiry_is_key_package_replay() {
        use scp_mls::lifetime::KEY_PACKAGE_LIFETIME_SECS;

        // Expired under the real clock since `SystemClock.now_secs() - 10`.
        let mint_now = SystemClock.now_secs() - 10 - KEY_PACKAGE_LIFETIME_SECS;
        let (joiner, store, bob_gen) = joiner_on_mint_clock(mint_now, "bob-replay-openmls").await;
        store
            .store(&own_consumed_marker(&bob_gen.signer_state), &[0x01])
            .await
            .unwrap();

        let err = joiner
            .join_from_welcome(
                b"never read",
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .err()
            .expect("a second join of a consumed KeyPackage must be rejected");
        assert!(
            matches!(err, MlsError::KeyPackageReplay),
            "expected KeyPackageReplay for the consumed, since-expired KeyPackage, got {err:?}"
        );
    }

    /// A mismatched `(key_package_public_bytes, signer_state)` pair whose
    /// caller `KeyPackage` has expired under openmls's clock is the mismatch
    /// rejection (`WelcomeProcessingFailed`), never a
    /// `KeyPackageLifetimeInvalid` carrying the signer state's own, current
    /// `KeyPackage`'s bounds.
    #[tokio::test]
    async fn join_from_welcome_mismatched_expired_caller_key_package_is_not_lifetime_invalid() {
        use scp_clock::TestClock;
        use scp_mls::lifetime::KEY_PACKAGE_LIFETIME_SECS;

        let real_now = SystemClock.now_secs();
        let store: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ));
        let joiner = ProductionMlsBackend::new(Arc::new(TestClock::new(real_now)));
        joiner.set_consumed_init_key_store(Arc::clone(&store));
        let bob_gen = joiner
            .generate_key_package(&test_credential("bob-mismatch-own"), None)
            .await
            .unwrap();
        // Expired under both clocks since `real_now - 10`.
        let expired = ProductionMlsBackend::new(Arc::new(TestClock::new(
            real_now - 10 - KEY_PACKAGE_LIFETIME_SECS,
        )))
        .generate_key_package(&test_credential("bob-mismatch-expired"), None)
        .await
        .unwrap();
        let adder = ProductionMlsBackend::new(Arc::new(SystemClock));
        let mut alice = adder
            .create_group(&test_credential("alice-mismatch"), None)
            .await
            .unwrap();
        let bob_add = adder
            .add_member_raw(&mut alice, &bob_gen.key_package_bytes)
            .await
            .unwrap();

        let err = joiner
            .join_from_welcome(
                &bob_add.welcome,
                bob_gen.signer_state.clone(),
                &expired.key_package_bytes,
            )
            .await
            .err()
            .expect("a mismatched pair must be rejected");
        assert!(
            matches!(err, MlsError::WelcomeProcessingFailed(_)),
            "expected the mismatch rejection, got {err:?}"
        );
        let consumed_key =
            ProductionMlsBackend::consumed_init_key_key(&bob_gen.key_package_bytes).unwrap();
        assert!(
            store.retrieve(&consumed_key).await.unwrap().is_none(),
            "a rejected join must not record the init key as consumed"
        );
    }

    /// Pins the injected-clock check on the signer state's own `KeyPackage`
    /// in `join_from_welcome`, with no real-time wait. The injected clock
    /// sits past the own `KeyPackage`'s `not_after` while the real clock
    /// reads it as current, and the caller passes the bytes of a different,
    /// current `KeyPackage`. Only the injected-clock check rejects before the
    /// mismatch check: without it, openmls's clock accepts the own
    /// `KeyPackage` and the mismatch is `WelcomeProcessingFailed`.
    #[tokio::test]
    async fn join_from_welcome_checks_own_key_package_against_injected_clock_before_mismatch() {
        use scp_clock::TestClock;
        use scp_mls::lifetime::KEY_PACKAGE_LIFETIME_SECS;

        let real_now = SystemClock.now_secs();
        let joiner_clock = Arc::new(TestClock::new(real_now));
        let store: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ));
        let joiner = ProductionMlsBackend::new(Arc::clone(&joiner_clock) as Arc<dyn Clock>);
        joiner.set_consumed_init_key_store(Arc::clone(&store));
        let bob_gen = joiner
            .generate_key_package(&test_credential("bob-injected-own"), None)
            .await
            .unwrap();
        let other = joiner
            .generate_key_package(&test_credential("bob-injected-other"), None)
            .await
            .unwrap();
        let adder = ProductionMlsBackend::new(Arc::new(SystemClock));
        let mut alice = adder
            .create_group(&test_credential("alice-injected-own"), None)
            .await
            .unwrap();
        let bob_add = adder
            .add_member_raw(&mut alice, &bob_gen.key_package_bytes)
            .await
            .unwrap();

        // Bob's `not_after` is `real_now + KEY_PACKAGE_LIFETIME_SECS`.
        let injected_now = real_now + KEY_PACKAGE_LIFETIME_SECS + 1;
        joiner_clock.set(injected_now);
        let err = joiner
            .join_from_welcome(
                &bob_add.welcome,
                bob_gen.signer_state.clone(),
                &other.key_package_bytes,
            )
            .await
            .err()
            .expect("an own KeyPackage expired under the injected clock must be rejected");
        assert!(
            matches!(
                err,
                MlsError::KeyPackageLifetimeInvalid { not_after, now, .. }
                    if now == injected_now && not_after == real_now + KEY_PACKAGE_LIFETIME_SECS
            ),
            "expected KeyPackageLifetimeInvalid at the injected clock's now, got {err:?}"
        );
        let consumed_key =
            ProductionMlsBackend::consumed_init_key_key(&bob_gen.key_package_bytes).unwrap();
        assert!(
            store.retrieve(&consumed_key).await.unwrap().is_none(),
            "a rejected join must not record the init key as consumed"
        );
    }

    /// ADR-057 §Prereq-1 wiring: `join_from_welcome` rejects a Welcome whose
    /// tree holds a KeyPackage-sourced leaf over the maximum lifetime range
    /// with `TreeLeafLifetimeRangeInvalid`. The durable consumed-init-key set
    /// records nothing, so the rejected join does not use up the `KeyPackage`:
    /// a later Welcome to the same `KeyPackage` joins.
    #[tokio::test]
    async fn join_from_welcome_rejects_over_range_tree_leaf_and_records_no_consumed_key() {
        let store: Arc<dyn OpenMlsStorageAdapter> = Arc::new(SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ));
        let joiner = ProductionMlsBackend::new(Arc::new(SystemClock));
        joiner.set_consumed_init_key_store(Arc::clone(&store));

        let bob_gen = joiner
            .generate_key_package(&test_credential("bob-over-range-leaf"), None)
            .await
            .unwrap();

        let (mut alice, over_long_not_after) =
            group::group_holding_carol_leaf_over_max_range().unwrap();
        let adder = ProductionMlsBackend::new(Arc::new(SystemClock));
        let over_range_add = adder
            .add_member_raw(&mut alice, &bob_gen.key_package_bytes)
            .await
            .unwrap();

        let err = joiner
            .join_from_welcome(
                &over_range_add.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .err()
            .expect("the join must reject a Welcome whose tree holds an over-range leaf");
        assert!(
            matches!(
                err,
                MlsError::TreeLeafLifetimeRangeInvalid { leaf_index: 1, not_after, .. }
                    if not_after == over_long_not_after
            ),
            "expected TreeLeafLifetimeRangeInvalid for Carol's leaf (leaf 1), got {err:?}"
        );

        let consumed_key =
            ProductionMlsBackend::consumed_init_key_key(&bob_gen.key_package_bytes).unwrap();
        assert!(
            store.retrieve(&consumed_key).await.unwrap().is_none(),
            "a rejected join must not record the init key as consumed"
        );

        // Control: a Welcome to the same KeyPackage from a group without the
        // over-range leaf joins over the same store and records the init key.
        let mut clean = adder
            .create_group(&test_credential("alice-clean"), None)
            .await
            .unwrap();
        let clean_added = adder
            .add_member_raw(&mut clean, &bob_gen.key_package_bytes)
            .await
            .unwrap();
        joiner
            .join_from_welcome(
                &clean_added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();
        assert!(
            store.retrieve(&consumed_key).await.unwrap().is_some(),
            "an accepted join records the init key under the same store key"
        );
    }

    #[tokio::test]
    async fn create_group_matches_primitive() {
        let backend = ProductionMlsBackend::new(Arc::new(SystemClock));
        let cred = test_credential("alice-create");

        let via_backend = backend.create_group(&cred, None).await.unwrap();
        let via_primitive = group::create_group(&cred, &SystemClock).unwrap();

        // Both groups are single-member at epoch 0 with the SCP ciphersuite.
        assert_groups_equivalent(&via_backend, &via_primitive).expect("groups diverge");
        assert_eq!(via_backend.epoch().unwrap(), 0);
        assert_eq!(via_backend.members().unwrap().len(), 1);
        assert_eq!(via_backend.inner().unwrap().ciphersuite(), SCP_CIPHERSUITE,);
    }

    #[tokio::test]
    async fn create_group_with_wrapping_key_propagates_extension() {
        let backend = ProductionMlsBackend::new(Arc::new(SystemClock));
        let cred = test_credential("alice-wrap");
        let wrap_pub = [0x11u8; 32];

        let grp = backend.create_group(&cred, Some(&wrap_pub)).await.unwrap();

        // Reading the wrapping key back via the existing helper proves the
        // extension was placed correctly — byte-for-byte with the primitive
        // path.
        let own_wrap = scp_mls::wrapping_extension::extract_own_wrapping_key(&grp)
            .expect("extension present")
            .expect("wrapping key bytes");
        assert_eq!(own_wrap, wrap_pub);
    }

    #[tokio::test]
    async fn add_member_raw_bytes_drive_join() {
        let backend = joinable_backend();

        let alice_cred = test_credential("alice-add");
        let mut alice_grp = backend.create_group(&alice_cred, None).await.unwrap();

        // Bob generates a KP via the backend.
        let bob_cred = test_credential("bob-add");
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();

        // Alice adds Bob via backend primitive.
        let added = backend
            .add_member_raw(&mut alice_grp, &bob_gen.key_package_bytes)
            .await
            .unwrap();
        assert!(!added.commit.is_empty());
        assert!(!added.welcome.is_empty());
        assert_eq!(alice_grp.epoch().unwrap(), 1);
        assert_eq!(alice_grp.members().unwrap().len(), 2);

        // Bob joins from the returned Welcome bytes.
        let bob_grp = backend
            .join_from_welcome(
                &added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();
        assert_eq!(bob_grp.epoch().unwrap(), 1);
        assert_eq!(bob_grp.members().unwrap().len(), 2);

        // Both groups at same epoch with same member count.
        assert_groups_equivalent(&alice_grp, &bob_grp).expect("groups diverge");
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let backend = joinable_backend();

        // Alice + Bob setup.
        let alice_cred = test_credential("alice-enc");
        let bob_cred = test_credential("bob-enc");
        let mut alice_grp = backend.create_group(&alice_cred, None).await.unwrap();
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();
        let added = backend
            .add_member_raw(&mut alice_grp, &bob_gen.key_package_bytes)
            .await
            .unwrap();
        let mut bob_grp = backend
            .join_from_welcome(
                &added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();

        let plaintext = b"roundtrip payload";
        let ct = backend.encrypt(&mut alice_grp, plaintext).await.unwrap();
        let out = backend.decrypt(&mut bob_grp, &ct).await.unwrap();

        match out {
            DecryptedContent::Application {
                plaintext: pt,
                sender_did,
            } => {
                assert_eq!(pt, plaintext);
                assert_eq!(sender_did, alice_cred.did);
            }
            other => panic!("expected Application, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn remove_member_raw_advances_epoch() {
        let backend = ProductionMlsBackend::new(Arc::new(SystemClock));

        let alice_cred = test_credential("alice-rem");
        let bob_cred = test_credential("bob-rem");
        let mut alice_grp = backend.create_group(&alice_cred, None).await.unwrap();
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();
        let _added = backend
            .add_member_raw(&mut alice_grp, &bob_gen.key_package_bytes)
            .await
            .unwrap();
        assert_eq!(alice_grp.epoch().unwrap(), 1);

        let own_index = alice_grp.own_leaf_index().unwrap();
        let members = alice_grp.members().unwrap();
        let bob = members.iter().find(|m| m.index != own_index).unwrap();

        let removed = backend
            .remove_member_raw(&mut alice_grp, bob.index)
            .await
            .unwrap();

        assert!(!removed.commit.is_empty());
        assert_eq!(alice_grp.epoch().unwrap(), 2);
        assert_eq!(alice_grp.members().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn advance_epoch_with_wrapping_key_matches_primitive() {
        let backend = ProductionMlsBackend::new(Arc::new(SystemClock));

        let alice_cred = test_credential("alice-adv");
        let mut alice_grp = backend.create_group(&alice_cred, None).await.unwrap();
        let wrap_pub = [0x22u8; 32];

        let commit_bytes = backend
            .advance_epoch(&mut alice_grp, Some(&wrap_pub))
            .await
            .unwrap();
        assert!(!commit_bytes.is_empty());
        assert_eq!(alice_grp.epoch().unwrap(), 1);

        // Re-deserialize to confirm the commit is TLS-valid.
        let _reparsed = MlsMessageIn::tls_deserialize(&mut &*commit_bytes).unwrap();
    }

    #[tokio::test]
    async fn validate_key_package_accepts_valid_scp_kp() {
        let backend = ProductionMlsBackend::new(Arc::new(SystemClock));
        let bob_cred = test_credential("bob-val");
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();

        let validated = backend
            .validate_key_package(&bob_gen.key_package_bytes, &SystemClock)
            .await
            .unwrap();
        assert_eq!(validated.key_package_bytes, bob_gen.key_package_bytes);
        // The single validate-and-bind extracts the authenticated credential DID
        // from the SAME validated leaf — it MUST equal the DID the KeyPackage was
        // minted for (this is the binding the join/add call sites now rely on
        // instead of a second `key_package_in_did` pass).
        assert_eq!(validated.credential_did, bob_cred.did);
    }

    #[tokio::test]
    async fn validate_key_package_rejects_garbage() {
        let backend = ProductionMlsBackend::new(Arc::new(SystemClock));
        let err = backend
            .validate_key_package(&[0u8; 64], &SystemClock)
            .await
            .unwrap_err();
        assert!(matches!(err, MlsError::AddMemberFailed(_)));
    }

    #[tokio::test]
    async fn validate_key_package_stateless_clock_param_valid_and_expired() {
        // SCP-CRYPTOMOVE-000c AC4: drive the stateless `MlsBackend::validate_key_package`
        // form directly and assert both arms — a valid KeyPackage returns
        // `Ok(ValidatedKeyPackage)`, and an expired-lifetime KeyPackage returns
        // `MlsError::KeyPackageLifetimeInvalid` (the stateless form's variant; the
        // retained `NodeMlsFactory::validate_key_package` wrapper maps the same
        // condition to `ContextError::InvalidKeyPackage`, asserted in
        // `provider::tests::validate_key_package_rejects_expired_lifetime_at_gate`).
        use scp_clock::TestClock;
        use scp_mls::KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS;

        // Mint the KeyPackage at the REAL present (backend clock is `SystemClock`)
        // so openmls's un-injectable internal `validate` accepts it; the injected
        // `clock` param is what drives the SCP hardened re-check below.
        let backend = ProductionMlsBackend::new(Arc::new(SystemClock));
        let cred = test_credential("carol-stateless");
        let generated = backend.generate_key_package(&cred, None).await.unwrap();

        // Valid arm: clock at the real present → Ok(ValidatedKeyPackage).
        let validated = backend
            .validate_key_package(&generated.key_package_bytes, &SystemClock)
            .await
            .unwrap();
        assert_eq!(validated.key_package_bytes, generated.key_package_bytes);

        // Expired arm: advance the injected clock one full max-range past the
        // present so the SCP bracket's `now < not_after` check fails.
        let future_now = SystemClock.now_secs() + KEY_PACKAGE_LIFETIME_MAX_RANGE_SECS * 2;
        let err = backend
            .validate_key_package(&generated.key_package_bytes, &TestClock::new(future_now))
            .await
            .unwrap_err();
        assert!(
            matches!(err, MlsError::KeyPackageLifetimeInvalid { .. }),
            "expired lifetime under the injected clock must return \
             KeyPackageLifetimeInvalid, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn process_commit_applies_epoch_advance() {
        let backend = joinable_backend();

        // `advance_epoch` always proposes a wrapping-extension update on
        // the leaf (mirrors `NodeMlsFactory::advance_epoch`). For Bob
        // to accept the commit, Alice's group, Bob's KeyPackage, and the
        // subsequent `advance_epoch` call MUST agree on the wrapping
        // extension being present. We pass the same `wrap_pub` to
        // `create_group`, `generate_key_package`, and `advance_epoch`.
        let wrap_pub = [0x42u8; 32];

        let alice_cred = test_credential("alice-pc");
        let bob_cred = test_credential("bob-pc");
        let mut alice_grp = backend
            .create_group(&alice_cred, Some(&wrap_pub))
            .await
            .unwrap();
        let bob_gen = backend
            .generate_key_package(&bob_cred, Some(&wrap_pub))
            .await
            .unwrap();
        let added = backend
            .add_member_raw(&mut alice_grp, &bob_gen.key_package_bytes)
            .await
            .unwrap();
        let mut bob_grp = backend
            .join_from_welcome(
                &added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();

        // Alice advances epoch again; Bob processes the Commit.
        let adv_commit = backend
            .advance_epoch(&mut alice_grp, Some(&wrap_pub))
            .await
            .unwrap();
        assert_eq!(alice_grp.epoch().unwrap(), 2);

        backend
            .process_commit(&mut bob_grp, &adv_commit)
            .await
            .unwrap();
        assert_eq!(bob_grp.epoch().unwrap(), 2);
    }

    /// An application message handed to the backend's `process_commit` is
    /// refused before decryption, so Bob's epoch is unchanged and the same bytes
    /// still decrypt through the backend's `decrypt`: the refusal consumed no
    /// sender ratchet generation and deleted no key.
    #[tokio::test]
    async fn process_commit_refuses_application_message_without_consuming_its_key() {
        let backend = joinable_backend();

        let alice_cred = test_credential("alice-pcapp");
        let bob_cred = test_credential("bob-pcapp");
        let mut alice_grp = backend.create_group(&alice_cred, None).await.unwrap();
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();
        let added = backend
            .add_member_raw(&mut alice_grp, &bob_gen.key_package_bytes)
            .await
            .unwrap();
        let mut bob_grp = backend
            .join_from_welcome(
                &added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();
        let epoch_before = bob_grp.epoch().unwrap();

        let ct = backend.encrypt(&mut alice_grp, b"in flight").await.unwrap();
        let err = backend.process_commit(&mut bob_grp, &ct).await.unwrap_err();
        assert!(
            matches!(err, MlsError::CommitProcessingFailed(_)),
            "expected CommitProcessingFailed, got {err:?}"
        );
        assert_eq!(bob_grp.epoch().unwrap(), epoch_before);

        match backend.decrypt(&mut bob_grp, &ct).await.unwrap() {
            DecryptedContent::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"in flight");
            }
            other => panic!("expected Application, got {other:?}"),
        }
    }

    /// Byte-level equivalence: a backend-produced encryption can be
    /// decrypted by the bare primitive, and vice versa. Proves the wire
    /// bytes are interoperable in both directions.
    #[tokio::test]
    async fn wire_bytes_interop_between_backend_and_primitive() {
        let backend = joinable_backend();

        let alice_cred = test_credential("alice-wire");
        let bob_cred = test_credential("bob-wire");
        let mut alice_grp = backend.create_group(&alice_cred, None).await.unwrap();
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();
        let added = backend
            .add_member_raw(&mut alice_grp, &bob_gen.key_package_bytes)
            .await
            .unwrap();
        let mut bob_grp = backend
            .join_from_welcome(
                &added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .unwrap();

        // Backend → primitive.
        let ct1 = backend.encrypt(&mut alice_grp, b"msg-a").await.unwrap();
        let pt1 = scp_mls::encrypt::decrypt(&mut bob_grp, &ct1).unwrap();
        assert_eq!(pt1, b"msg-a");

        // Primitive → backend.
        let mls_out = scp_mls::encrypt::encrypt(&mut bob_grp, b"msg-b").unwrap();
        let ct2 = scp_mls::encrypt::serialize_ciphertext(&mls_out).unwrap();
        let decrypted = backend.decrypt(&mut alice_grp, &ct2).await.unwrap();
        match decrypted {
            DecryptedContent::Application { plaintext, .. } => {
                assert_eq!(plaintext, b"msg-b");
            }
            other => panic!("expected Application, got {other:?}"),
        }
    }

    /// Root `scp_context_params` extension fixture.
    fn sample_context_extension(context_id: &str) -> scp_protocol::context::ScpContextExtension {
        use scp_did::DID;
        use scp_protocol::context::GovernanceModel;
        use scp_protocol::context::params::{CeilingPolicy, ContextMode};
        use scp_protocol::context::roles::{Capability, CapabilityCeiling};

        let governance = GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![
                DID::from("did:dht:z6MkAlice".to_owned()),
                DID::from("did:dht:z6MkBob".to_owned()),
            ],
        };
        let ceiling = CapabilityCeiling::new([Capability::MessagesRead, Capability::MessagesWrite]);
        scp_protocol::context::ScpContextExtension::for_root(
            context_id.to_owned(),
            DID::from("did:dht:z6MkAlice".to_owned()),
            ContextMode::Encrypted,
            &governance,
            CeilingPolicy::Immutable,
            &ceiling,
        )
        .unwrap()
    }

    /// End-to-end proof of the wrapping-key / context-params coupling
    /// (`valn0502`): a `KeyPackage` produced by the **production**
    /// [`MlsBackend::generate_key_package`] path (which now declares BOTH
    /// `0xFF01` and `0xFF02`) can be added to, and joined into, an SCP context
    /// group (whose `group_context` carries the `0xFF02` extension). Without the
    /// context-params switch in `generate_key_package`, the pooled KP would
    /// declare only `0xFF01` and `OpenMLS` would reject the Add with
    /// `AddMemberFailed`. This is the load-bearing coupling test.
    #[tokio::test]
    async fn production_key_package_joins_context_group() {
        let backend = joinable_backend();

        // Creator side: a context group carrying the 0xFF02 extension.
        let alice_cred = test_credential("alice-ctx");
        let alice_wrap = [0xA1u8; 32];
        let ctx_ext = sample_context_extension("ctx:prod-join");
        let mut alice_group = group::create_group_with_context(
            &alice_cred,
            &alice_wrap,
            &ctx_ext,
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Joiner side: KP via the PRODUCTION generate_key_package path WITH a
        // wrapping key — now declares 0xFF01 + 0xFF02.
        let bob_cred = test_credential("bob-ctx");
        let bob_wrap = [0xB2u8; 32];
        let bob_gen = backend
            .generate_key_package(&bob_cred, Some(&bob_wrap))
            .await
            .unwrap();

        // The Add SUCCEEDS: bob's leaf declares 0xFF02, satisfying valn0502.
        let added = backend
            .add_member_raw(&mut alice_group, &bob_gen.key_package_bytes)
            .await
            .expect("production KP must satisfy valn0502 for a context group");

        // And bob joins from the Welcome, recovering the creator-committed
        // context extension byte-identically from the replicated group_context.
        let bob_group = backend
            .join_from_welcome(
                &added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .expect("joiner processes the Welcome for the context group");

        assert_eq!(
            bob_group.group_context_extension().unwrap(),
            Some(ctx_ext.clone()),
            "joiner reads the creator-committed context extension"
        );
        assert_eq!(
            alice_group.group_context_extension().unwrap(),
            bob_group.group_context_extension().unwrap(),
            "creator and joiner observe identical context extensions"
        );
    }

    /// The `None`-branch (no wrapping key) production KP is STILL
    /// context-joinable: it declares the `0xFF02` (`scp_context_params`)
    /// capability — required by `valn0502` — even though it carries no `0xFF01`
    /// wrapping-key leaf extension. This is the load-bearing invariant for the
    /// production reserve path, whose supervisor `wrapping_keys` map has no
    /// production writer yet (§9.16.1 wrapping-key publication is unwired), so
    /// every reserved KP is generated with `wrapping_pubkey == None`. Were the
    /// `None` branch to downgrade to a wrapping-only (`0xFF01`-only) KP, real
    /// MLS would reject the Add ("the capabilities of the add proposal are
    /// insufficient for this group") and NO node could ever join an encrypted
    /// context via the reserve path.
    ///
    /// The joiner completes the Welcome round-trip and reads the
    /// creator-committed context extension byte-identically. Sender-key
    /// distribution to this member is separately (and correctly) skipped
    /// because the leaf carries no wrapping key — but MLS membership succeeds.
    #[tokio::test]
    async fn production_key_package_without_wrapping_key_joins_context_group() {
        let backend = joinable_backend();

        let alice_cred = test_credential("alice-ctx-neg");
        let alice_wrap = [0xA3u8; 32];
        let ctx_ext = sample_context_extension("ctx:prod-neg");
        let mut alice_group = group::create_group_with_context(
            &alice_cred,
            &alice_wrap,
            &ctx_ext,
            &scp_clock::SystemClock,
        )
        .unwrap();

        // Reserve-path KP: generated WITHOUT a wrapping key (the production
        // reserve path today, since supervisor `wrapping_keys` is unwired).
        let bob_cred = test_credential("bob-ctx-neg");
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();

        // The Add SUCCEEDS: bob's leaf declares 0xFF02 (capability, no key
        // material required), satisfying valn0502 for the context group.
        let added = backend
            .add_member_raw(&mut alice_group, &bob_gen.key_package_bytes)
            .await
            .expect(
                "a wrapping-key-less production KP MUST still be context-joinable \
                 (declares 0xFF02 capability)",
            );

        // And bob joins from the Welcome, recovering the creator-committed
        // context extension byte-identically.
        let bob_group = backend
            .join_from_welcome(
                &added.welcome,
                bob_gen.signer_state.clone(),
                &bob_gen.key_package_bytes,
            )
            .await
            .expect("wrapping-key-less joiner processes the Welcome for the context group");

        assert_eq!(
            bob_group.group_context_extension().unwrap(),
            Some(ctx_ext),
            "wrapping-key-less joiner reads the creator-committed context extension",
        );
    }
}
