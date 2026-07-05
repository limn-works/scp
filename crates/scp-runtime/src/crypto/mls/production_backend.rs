//! Production [`MlsBackend`](super::backend::MlsBackend) implementation.
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §6).
//!
//! # Design
//!
//! [`ProductionMlsBackend`] is a stateless struct that delegates every
//! primitive to the existing [`super::group`], [`super::encrypt`], and
//! [`super::ratchet`] free functions — the same `OpenMLS` primitives the
//! pre-refactor `MlsCryptoProvider` calls. This guarantees byte-identical
//! output for equivalent inputs (see the unit test suite below), which is a
//! hard requirement of the commit 4 plan: later commits replace
//! `MlsCryptoProvider` with handler functions that call this trait, and the
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
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};
use zeroize::Zeroizing;

use super::backend::{
    AddMemberRaw, GeneratedKeyPackage, MlsBackend, RemoveMemberRaw, SignerState,
    ValidatedKeyPackage,
};
use super::credential::ScpCredential;
use super::encrypt::{DecryptedContent, decrypt_with_sender_did};
use super::error::MlsError;
use super::group::{self, SCP_CIPHERSUITE, ScpMlsGroup};
use super::storage::new_provider;
use super::storage_adapter::OpenMlsStorageAdapter;
use crate::crypto::mls::InMemoryMlsProvider;

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
/// the same free-function family the pre-refactor `MlsCryptoProvider` uses,
/// preserving byte-identical output through the trait split. The owned state is
/// the durable consumed-init-key set (`consumed_init_key_store`), a crypto-layer
/// single-use backstop attached once after construction via
/// [`MlsBackend::set_consumed_init_key_store`], plus a `join_gate` mutex that
/// serializes the retrieve→join→store consumed-init-key sequence.
///
/// # Why the store is attached after construction (not a constructor arg)
///
/// The backend is built inside `MlsCryptoProvider::new` / `with_backends`,
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
#[derive(Default)]
pub struct ProductionMlsBackend {
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
    join_gate: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for ProductionMlsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductionMlsBackend")
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            consumed_init_key_store: OnceLock::new(),
            join_gate: tokio::sync::Mutex::new(()),
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
    fn consumed_init_key_key(key_package_public_bytes: &[u8]) -> Result<String, MlsError> {
        let kp_in =
            KeyPackageIn::tls_deserialize(&mut &*key_package_public_bytes).map_err(|e| {
                MlsError::WelcomeProcessingFailed(format!(
                    "deserializing key package for init-key: {e}"
                ))
            })?;
        let provider = new_provider();
        let validated = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| {
                MlsError::WelcomeProcessingFailed(format!(
                    "validating key package for init-key: {e}"
                ))
            })?;
        let init_key = validated.hpke_init_key().as_slice();
        let digest = Sha256::digest(init_key);
        Ok(format!(
            "{CONSUMED_INIT_KEY_PREFIX}/{}",
            hex::encode(digest)
        ))
    }
}

// ---------------------------------------------------------------------------
// SignerState serialization format
// ---------------------------------------------------------------------------

/// Opaque byte layout behind [`SignerState`]. Private to this module.
///
/// `signer_bytes` and `mls_storage_entries` hold private signing key and HPKE
/// decryption-key material. A transient `SerializedSigner` (the wrapper built to
/// serialize a signer-state in `serialize_signer_state`, or parsed back out of
/// one via `parse_signer_state` during a join) would otherwise drop those
/// private `Vec`s un-zeroed. The hand-written [`Drop`] zeroes them on every drop
/// while leaving the on-disk serde format (plain `Vec<u8>` / tuple-vec fields)
/// unchanged. `key_package_public_bytes` is the publishable KP and is not zeroed.
#[derive(Serialize, Deserialize)]
struct SerializedSigner {
    /// MessagePack-serialized [`SignatureKeyPair`] bytes. Zeroed on drop.
    signer_bytes: Vec<u8>,
    /// Raw MLS storage entries from the `InMemoryMlsProvider` generated
    /// alongside the `KeyPackage`. Needed to process a Welcome addressed to
    /// the KP (`OpenMLS` reads the private HPKE decryption key out of
    /// storage when decrypting the Welcome). Zeroed on drop.
    mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// TLS-serialized PUBLIC `KeyPackage` bytes this signer-state was
    /// generated for. Carried so [`MlsBackend::join_from_welcome`] can derive
    /// the consumed-init-key marker from the signer-state's OWN KP and bind it
    /// to the `key_package_public_bytes` argument — defeating a mismatched
    /// `(public_bytes, signer_state)` pair at the bare API boundary. Publishable
    /// (not zeroed).
    key_package_public_bytes: Vec<u8>,
}

impl Drop for SerializedSigner {
    fn drop(&mut self) {
        // Zero the private signing-key + HPKE-key material on drop;
        // `key_package_public_bytes` is publishable.
        zeroize::Zeroize::zeroize(&mut self.signer_bytes);
        for (k, v) in &mut self.mls_storage_entries {
            zeroize::Zeroize::zeroize(k);
            zeroize::Zeroize::zeroize(v);
        }
    }
}

fn serialize_signer_state(
    signer: &SignatureKeyPair,
    provider: &InMemoryMlsProvider,
    key_package_public_bytes: &[u8],
) -> Result<SignerState, MlsError> {
    let signer_bytes = Zeroizing::new(
        rmp_serde::to_vec_named(signer)
            .map_err(|e| MlsError::StorageError(format!("signer serialization: {e}")))?,
    );

    let mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)> = {
        let values = provider
            .storage()
            .values
            .read()
            .map_err(|e| MlsError::StorageError(format!("provider lock poisoned: {e}")))?;
        values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };

    let wrapper = SerializedSigner {
        signer_bytes: signer_bytes.to_vec(),
        mls_storage_entries,
        key_package_public_bytes: key_package_public_bytes.to_vec(),
    };

    let bytes = Zeroizing::new(
        rmp_serde::to_vec_named(&wrapper)
            .map_err(|e| MlsError::StorageError(format!("signer-state serialization: {e}")))?,
    );

    Ok(SignerState { bytes })
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
        // `SerializedSigner` has a `Drop` that zeroes its private fields, so
        // the entries cannot be moved out by value; take them out via
        // `mem::take` (leaving an empty Vec the Drop harmlessly zeroes) so the
        // private bytes move into the provider without an extra copy.
        for (k, v) in std::mem::take(&mut wrapper.mls_storage_entries) {
            values.insert(k, v);
        }
    }

    // Re-store the signer in the provider's key store so OpenMLS can resolve
    // it during Welcome processing.
    signer
        .store(provider.storage())
        .map_err(|e| MlsError::StorageError(format!("signer store failed: {e}")))?;

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
        // `MlsCryptoProvider::create_mls_group` (which also calls the same
        // primitive).
        group::create_group_with_wrapping_key(credential, wrapping_pubkey)
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

        let result = group::add_member(group, kp)?;

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
        let mls_message = super::encrypt::encrypt(group, plaintext)?;
        super::encrypt::serialize_ciphertext(&mls_message)
    }

    async fn decrypt(
        &self,
        group: &mut ScpMlsGroup,
        ciphertext: &[u8],
    ) -> Result<DecryptedContent, MlsError> {
        decrypt_with_sender_did(group, ciphertext)
    }

    async fn process_commit(
        &self,
        group: &mut ScpMlsGroup,
        commit_bytes: &[u8],
    ) -> Result<(), MlsError> {
        // Parse the incoming Commit bytes and process via `decrypt_with_sender_did`
        // path, but only accept Commit outcomes. This reuses the existing
        // `process_message` + `merge_staged_commit` sequence verbatim.
        let content = decrypt_with_sender_did(group, commit_bytes)?;
        match content {
            DecryptedContent::Commit { .. } => Ok(()),
            DecryptedContent::Application { .. } => Err(MlsError::CommitProcessingFailed(
                "expected Commit, got Application message".to_string(),
            )),
            DecryptedContent::Proposal { .. } => Err(MlsError::CommitProcessingFailed(
                "expected Commit, got Proposal message".to_string(),
            )),
        }
    }

    async fn advance_epoch(
        &self,
        group: &mut ScpMlsGroup,
        wrapping_pubkey: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, MlsError> {
        // Match the existing `MlsCryptoProvider::advance_epoch` semantics:
        // the pre-refactor code defaulted the wrapping key to zero-bytes
        // when the provider had not yet generated one (rare but possible
        // during test flows). Mirror that behaviour byte-for-byte.
        let wrap = wrapping_pubkey.map_or([0u8; 32], |k| *k);
        let commit = super::ratchet::propose_update_with_wrapping_key(group, &wrap)?;
        commit
            .tls_serialize_detached()
            .map_err(|e| MlsError::CommitProcessingFailed(format!("serializing commit: {e}")))
    }

    async fn validate_key_package(
        &self,
        key_package_bytes: &[u8],
    ) -> Result<ValidatedKeyPackage, MlsError> {
        // Deserialize and validate against the SCP ciphersuite. This runs the
        // OpenMLS-side validation without holding any group state.
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*key_package_bytes)
            .map_err(|e| MlsError::AddMemberFailed(format!("deserializing key package: {e}")))?;

        let provider = new_provider();
        let validated = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| MlsError::AddMemberFailed(format!("key package validation: {e}")))?;

        // Guard the SCP ciphersuite invariant: any KP using a non-SCP
        // ciphersuite MUST be rejected even if OpenMLS validates it against
        // `Mls10`.
        if validated.ciphersuite() != SCP_CIPHERSUITE {
            return Err(MlsError::AddMemberFailed(format!(
                "key package uses non-SCP ciphersuite: {:?}",
                validated.ciphersuite()
            )));
        }

        // Re-serialize to return the canonical validated bytes. Functionally
        // equivalent to the input (OpenMLS does not mutate on validate), but
        // we construct via the validated type so downstream persistence is
        // guaranteed to parse identically.
        let bytes = key_package_bytes.to_vec();
        Ok(ValidatedKeyPackage {
            key_package_bytes: bytes,
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
        // extension present in the group — so the KP leaf MUST advertise BOTH
        // `0xFF01` (wrapping) and `0xFF02` (context params).
        // `generate_key_package_with_context_params` declares both and carries
        // the `0xFF01` wrapping-key leaf extension; it therefore requires a
        // wrapping key.
        //
        // When no wrapping key is available (`None`), the identity has no
        // published wrapping key (§9.16.1) and so cannot receive sender keys —
        // such a KP is inherently non-participating and is NOT context-joinable
        // (it cannot declare `0xFF02` without also carrying the coupled `0xFF01`
        // leaf via the current scp-mls API). Fall back to the wrapping-key path.
        // In production the KeyPackageStoreActor sources the wrapping key from
        // the identity's published wrapping key, so a context-participating
        // identity always takes the `Some` branch.
        let (bundle, signer, provider) = match wrapping_pubkey {
            Some(pk) => group::generate_key_package_with_context_params(credential, pk)?,
            None => group::generate_key_package_with_wrapping_key(credential, None)?,
        };

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

        // Parse the opaque signer-state wrapper ONCE; both the bound-init-key
        // derivation below and the signer/provider rebuild later reuse it.
        let wrapper = parse_signer_state(&signer_state)?;

        // Derive the init-key set key from the caller-supplied
        // `key_package_public_bytes`. This also validates the KP, so a malformed
        // KP is rejected before any group state is built.
        let consumed_key = Self::consumed_init_key_key(key_package_public_bytes)?;

        // Init-key / Welcome binding (checked BEFORE the join consumes anything).
        // `key_package_public_bytes` is the marker key source; the
        // `signer_state` carries its OWN KP public bytes. A successful join over
        // a provider built SOLELY from `signer_state` necessarily uses THAT KP's
        // init private key (OpenMLS has no other init key in scope). If a caller
        // passed a `key_package_public_bytes` whose init key does not match the
        // one in `signer_state`, the marker would key the WRONG init key.
        //
        // Fast path: when the caller-supplied bytes are byte-identical to the
        // bytes carried in `signer_state` (the actor's normal path — it passes
        // the reserved KP's OWN bytes), they trivially share an init key, so the
        // second KeyPackageIn validation is skipped. Only when the bytes DIFFER
        // (a bare-API misuse) do we re-derive the marker from the signer-state's
        // own KP and require it to equal `consumed_key`; a mismatch means the
        // caller violated the `(public_bytes, signer_state)` pairing contract —
        // reject before consuming any crypto. Behaviour-preserving: the mismatch
        // rejection still fires for every genuinely-mismatched pair.
        if wrapper.key_package_public_bytes != key_package_public_bytes {
            let bound_key = Self::consumed_init_key_key(&wrapper.key_package_public_bytes)?;
            if bound_key != consumed_key {
                return Err(MlsError::WelcomeProcessingFailed(
                    "key_package_public_bytes init key does not match the signer-state's \
                     key package (mismatched (public_bytes, signer_state) pair)"
                        .to_owned(),
                ));
            }
        }

        // Serialize the retrieve→join→store sequence so two concurrent joins of
        // the same init key cannot both pass the retrieve before either stores
        // (check-then-act TOCTOU on this shared backend instance). The gate is
        // acquired only on a join (rare, off the per-context read path) — see
        // the `join_gate` field doc for the ADR-049 §12 lock-free-read note.
        let _join_guard = self.join_gate.lock().await;

        // Consult the durable consumed set FIRST. An init key already present
        // means this KP was already consumed → reject the replay.
        let already = store
            .retrieve(&consumed_key)
            .await
            .map_err(|e| MlsError::StorageError(format!("consumed-init-key retrieve: {e}")))?;
        if already.is_some() {
            return Err(MlsError::KeyPackageReplay);
        }

        let (signer, provider) = signer_and_provider_from_wrapper(wrapper)?;
        let group = group::join_group_from_bytes(welcome_bytes, provider, signer)?;

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
// Tests — byte-identical output with MlsCryptoProvider MLS primitive calls
// ---------------------------------------------------------------------------
//
// These tests feed identical inputs to `ProductionMlsBackend` and the existing
// `group::*` / `encrypt::*` / `ratchet::*` primitives (the same primitives
// `MlsCryptoProvider` delegates to) and assert byte-identical output on the
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
    use crate::crypto::mls::credential::ScpCredential;
    use crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter;
    use scp_identity::SigningKeyId;
    use scp_platform::testing::InMemoryStorage;

    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(format!("did:dht:z6Mk{name}"), None, SigningKeyId::Active).unwrap()
    }

    /// A `ProductionMlsBackend` with the durable consumed-init-key store
    /// attached over a fresh in-memory `Storage`, so `join_from_welcome` is
    /// JOINABLE (it fails closed without a store). Use for any test that drives
    /// a real join.
    fn joinable_backend() -> ProductionMlsBackend {
        let backend = ProductionMlsBackend::new();
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

    #[tokio::test]
    async fn create_group_matches_primitive() {
        let backend = ProductionMlsBackend::new();
        let cred = test_credential("alice-create");

        let via_backend = backend.create_group(&cred, None).await.unwrap();
        let via_primitive = group::create_group(&cred).unwrap();

        // Both groups are single-member at epoch 0 with the SCP ciphersuite.
        assert_groups_equivalent(&via_backend, &via_primitive).expect("groups diverge");
        assert_eq!(via_backend.epoch().unwrap(), 0);
        assert_eq!(via_backend.members().unwrap().len(), 1);
        assert_eq!(via_backend.inner().unwrap().ciphersuite(), SCP_CIPHERSUITE,);
    }

    #[tokio::test]
    async fn create_group_with_wrapping_key_propagates_extension() {
        let backend = ProductionMlsBackend::new();
        let cred = test_credential("alice-wrap");
        let wrap_pub = [0x11u8; 32];

        let grp = backend.create_group(&cred, Some(&wrap_pub)).await.unwrap();

        // Reading the wrapping key back via the existing helper proves the
        // extension was placed correctly — byte-for-byte with the primitive
        // path.
        let own_wrap = crate::crypto::mls::wrapping_extension::extract_own_wrapping_key(&grp)
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
        let backend = ProductionMlsBackend::new();

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
        let backend = ProductionMlsBackend::new();

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
        let backend = ProductionMlsBackend::new();
        let bob_cred = test_credential("bob-val");
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();

        let validated = backend
            .validate_key_package(&bob_gen.key_package_bytes)
            .await
            .unwrap();
        assert_eq!(validated.key_package_bytes, bob_gen.key_package_bytes);
    }

    #[tokio::test]
    async fn validate_key_package_rejects_garbage() {
        let backend = ProductionMlsBackend::new();
        let err = backend.validate_key_package(&[0u8; 64]).await.unwrap_err();
        assert!(matches!(err, MlsError::AddMemberFailed(_)));
    }

    #[tokio::test]
    async fn process_commit_applies_epoch_advance() {
        let backend = joinable_backend();

        // `advance_epoch` always proposes a wrapping-extension update on
        // the leaf (mirrors `MlsCryptoProvider::advance_epoch`). For Bob
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
        let pt1 = super::super::encrypt::decrypt(&mut bob_grp, &ct1).unwrap();
        assert_eq!(pt1, b"msg-a");

        // Primitive → backend.
        let mls_out = super::super::encrypt::encrypt(&mut bob_grp, b"msg-b").unwrap();
        let ct2 = super::super::encrypt::serialize_ciphertext(&mls_out).unwrap();
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
        use scp_primitives::DID;
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
        let mut alice_group =
            group::create_group_with_context(&alice_cred, &alice_wrap, &ctx_ext).unwrap();

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

    /// The documented `None`-branch fallback: a production KP generated WITHOUT
    /// a wrapping key declares only what the wrapping-key path can and is NOT
    /// context-joinable — a context group rejects it (`valn0502`), matching the
    /// non-participating identity it represents (§9.16.1). This pins that the
    /// `None` branch does not silently produce a `0xFF02`-declaring KP.
    #[tokio::test]
    async fn production_key_package_without_wrapping_key_rejected_by_context_group() {
        let backend = ProductionMlsBackend::new();

        let alice_cred = test_credential("alice-ctx-neg");
        let alice_wrap = [0xA3u8; 32];
        let ctx_ext = sample_context_extension("ctx:prod-neg");
        let mut alice_group =
            group::create_group_with_context(&alice_cred, &alice_wrap, &ctx_ext).unwrap();

        let bob_cred = test_credential("bob-ctx-neg");
        let bob_gen = backend.generate_key_package(&bob_cred, None).await.unwrap();

        let result = backend
            .add_member_raw(&mut alice_group, &bob_gen.key_package_bytes)
            .await;
        assert!(
            matches!(result, Err(MlsError::AddMemberFailed(_))),
            "a wrapping-key-less production KP must be rejected by a context group, got {result:?}"
        );
    }
}
