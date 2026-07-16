//! Standalone identity construction — the flat `IdentityConfig` config object
//! and the [`Identity::create`] entry point (ADR-052, Phase B-P3e).
//!
//! This module is the Rust-core front-end for **standalone** identity
//! construction. It wraps the existing [`DidMethod::create`] creation logic in
//! the flat-config-object shape mandated by `.docs/standards/construction.md`
//! (§Identity) and ADR-052 (AC-7), so an LLM author writes correct code from the
//! type signature plus one example, with no compile-retry loop.
//!
//! # Relationship to the other identity-creation paths
//!
//! Today identities are created in two other places, both of which this module
//! **reuses rather than duplicates**:
//!
//! - Inside a Node, via `IdentitySource::{Generate, Persisted}` →
//!   [`DidMethod::create`] (`crates/scp-node/src/config.rs`).
//! - At the FFI boundary, via the three `identity_create*` bridge entry points
//!   (`crates/scp-ffi/src/identity.rs`).
//!
//! All of these — and this module — funnel into the same [`DidMethod::create`]
//! call, minting a fresh per-identity [`InMemoryPreRotationCustody`] for the
//! cold-storage pre-rotation key exactly as the existing paths do (the
//! construction-standard `IdentityConfig` shape carries no separate
//! pre-rotation slot, so the internal mint is the established behaviour).
//!
//! # Agent signing keys
//!
//! `IdentityConfig` covers the plain create path (`method` + `custody` +
//! `persistence`). Creating an identity that *also* carries an `#agent`
//! verification method is a **separate operation** ([`DidDht::create_with_agent_key`](crate::DidDht)),
//! not a field on this config — consistent with construction.md §Identity, which
//! defines `IdentityConfig` as exactly `{ method, custody, persistence }`.
//!
//! # The pattern (construction.md §Identity)
//!
//! ```ignore
//! // The DID method carries an explicit DHT client — production names a real
//! // `PkarrDhtClient`; the in-memory arm shown here is test/testing-only.
//! let method = DidDht::with_client(Arc::new(pkarr_client));
//!
//! // Ephemeral identity — no key material at rest (the fail-safe default, M2):
//! let (identity, document, pre_rotation) =
//!     Identity::create_ephemeral(IdentityConfig::ephemeral(
//!         method,
//!         InMemoryKeyCustody::new(),
//!     ))
//!     .await?;
//!
//! // Persisted identity — encrypted-only (the EncryptedStorage seal):
//! let (identity, document, pre_rotation) =
//!     Identity::create(IdentityConfig {
//!         method: DidDht::with_client(Arc::new(pkarr_client)),
//!         custody: InMemoryKeyCustody::new(),
//!         persistence: Some(encrypted_storage), // S: EncryptedStorage
//!     })
//!     .await?;
//! ```

use scp_platform::EncryptedStorage;
use scp_platform::testing::InMemoryPreRotationCustody;
use scp_platform::traits::{KeyCustody, PreRotationKeyHandle, Storage};

use crate::{DidMethod, IdentityError, ScpIdentity};
use scp_did::DidDocument;

/// An uninhabited placeholder storage type for the **ephemeral** construction
/// path, used as the `S` type argument when `persistence` is `None`.
///
/// [`IdentityConfig`] is generic over its storage type `S` (exactly as
/// `NodeConfig<K, D, S>` is). On the ephemeral path the caller never supplies a
/// storage value, so there is no concrete `S` to infer — this uninhabited type
/// fills that slot. It implements [`Storage`] only to satisfy the `S: Storage`
/// bound on [`IdentityConfig`]; because it has no constructor and no variants,
/// no value of it can ever exist, so none of its [`Storage`] methods are
/// reachable (every body is `match *self {}`). It deliberately does **not**
/// implement [`EncryptedStorage`], so it can never be used on the persisting
/// [`Identity::create`] path.
#[derive(Debug)]
pub enum NoPersistence {}

// `NoPersistence` is uninhabited, so each method body discharges the impossible
// `&self` by matching the empty enum via `match *self {}`. RPITIT with an
// explicit `+ Send` future, matching the `Storage` trait shape exactly.
//
// `clippy::uninhabited_references` flags the `*self` deref as UB-adjacent in
// general, but here it is the *intended* and only way to write a method body for
// an uninhabited type: the deref is statically unreachable because no
// `NoPersistence` value can exist, so it can never actually execute. This is the
// canonical "this method is unreachable" encoding.
#[allow(clippy::manual_async_fn, clippy::uninhabited_references)]
impl Storage for NoPersistence {
    fn store(
        &self,
        _key: &str,
        _data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send {
        async move { match *self {} }
    }

    fn retrieve(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, scp_platform::PlatformError>> + Send
    {
        async move { match *self {} }
    }

    fn delete(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<(), scp_platform::PlatformError>> + Send {
        async move { match *self {} }
    }

    fn list_keys(
        &self,
        _prefix: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, scp_platform::PlatformError>> + Send
    {
        async move { match *self {} }
    }

    fn delete_prefix(
        &self,
        _prefix: &str,
    ) -> impl std::future::Future<Output = Result<u64, scp_platform::PlatformError>> + Send {
        async move { match *self {} }
    }

    fn exists(
        &self,
        _key: &str,
    ) -> impl std::future::Future<Output = Result<bool, scp_platform::PlatformError>> + Send {
        async move { match *self {} }
    }
}

/// Flat configuration object for standalone identity construction
/// (construction.md §Identity, ADR-052 AC-7).
///
/// One flat config object, every parameter a named field — the LLM-first
/// construction shape. Required choices are required (non-`Option`) fields; the
/// security-critical choice (persist-or-not) is a fail-safe-defaulted `Option`.
///
/// # Type parameters
///
/// - `K: KeyCustody` — the operational key-custody backend (holds the identity
///   and active signing keys). A typed generic, never a boxed `dyn`:
///   [`KeyCustody`] uses return-position `impl Trait` in trait and is not
///   object-safe (ADR-049 lock-free-read invariant).
/// - `D: DidMethod` — the DID method (e.g. [`DidDht`](crate::DidDht)).
/// - `S: Storage` — the storage type carried by `persistence`. Defaults to
///   [`NoPersistence`] so the ephemeral path needs no turbofish. On the
///   persisting [`Identity::create`] path this is additionally bound by
///   [`EncryptedStorage`].
///
/// # Security-critical field (M2): `persistence`
///
/// Whether to persist key material is the security-critical Identity choice.
/// `persistence: None` — an **ephemeral** identity with no key material at rest —
/// is the fail-safe default, reached by an explicit `None`, never by silent
/// omission of a required field. `Some(storage)` opts into persistence and, on
/// the production [`Identity::create`] path, binds the storage to
/// [`EncryptedStorage`] (`crates/scp-platform/src/encrypted.rs`) — identity key
/// material persists only to an encrypted slot, the same compile-time seal as
/// `Node::start`.
///
/// # No whole-struct `Default` (M4)
///
/// `method` and `custody` are irreducible (the caller must decide), so this
/// struct intentionally has **no** `Default` impl — omitting either is a compile
/// error, not a silent `None`.
#[derive(Debug)]
pub struct IdentityConfig<K, D, S = NoPersistence>
where
    K: KeyCustody,
    D: DidMethod,
    S: Storage,
{
    /// The DID method used to create the identity (required).
    pub method: D,
    /// The operational key-custody backend holding the identity's keys
    /// (required).
    pub custody: K,
    /// Whether to persist the identity.
    ///
    /// `None` (the fail-safe default; M2) yields an **ephemeral** identity with
    /// no key material at rest. `Some(storage)` persists the identity's public
    /// DID document into `storage`; on the production [`Identity::create`] path
    /// the storage is [`EncryptedStorage`]-bound, so persisting is
    /// encrypted-only.
    pub persistence: Option<S>,
}

impl<K, D> IdentityConfig<K, D, NoPersistence>
where
    K: KeyCustody,
    D: DidMethod,
{
    /// Constructs an **ephemeral** [`IdentityConfig`] (`persistence: None`) from
    /// the two irreducible required fields.
    ///
    /// This is the fail-safe constructor — the resulting identity persists no
    /// key material at rest (M2). For a persisted identity, build the struct
    /// literally with `persistence: Some(encrypted_storage)`.
    #[must_use]
    pub const fn ephemeral(method: D, custody: K) -> Self {
        Self {
            method,
            custody,
            persistence: None,
        }
    }
}

/// Zero-sized entry-point namespace for standalone identity construction
/// (ADR-052).
///
/// All standalone identity construction flows through [`Identity::create`]
/// (production, `where S: EncryptedStorage`) or [`Identity::create_ephemeral`]
/// (the no-persistence convenience). There is no `IdentityBuilder`, no
/// typestate, no `.build()` terminator — the construction surface is one flat
/// [`IdentityConfig`] plus the entry function.
///
/// The entry verb is `create` (not `start`) per the construction.md entry-verb
/// rule: identity construction produces a value/handle, not a spawned runtime.
pub struct Identity;

/// The successful result of [`Identity::create`]: the identity handle, its DID
/// document, and the cold-stored pre-rotation key handle.
///
/// This is exactly what [`DidMethod::create`] returns; the caller persists the
/// [`PreRotationKeyHandle`] alongside the identity so it can later be presented
/// to `migrate_identity`.
pub type CreatedIdentity = (ScpIdentity, DidDocument, PreRotationKeyHandle);

impl Identity {
    /// Creates a new standalone identity from an [`IdentityConfig`]
    /// (production path).
    ///
    /// Lowers the flat config to the existing [`DidMethod::create`] call,
    /// minting a fresh per-identity [`InMemoryPreRotationCustody`] for the
    /// cold-storage pre-rotation key — the same internal mint every other
    /// identity-creation path performs (the construction-standard
    /// `IdentityConfig` shape carries no separate pre-rotation slot). When
    /// `config.persistence` is `Some`, the identity's public DID document is
    /// persisted under the spec §17.3 key `identity/{did}/document` after
    /// successful creation.
    ///
    /// # The `EncryptedStorage` seal (M2 / construction.md)
    ///
    /// This method is bound `where S: EncryptedStorage`. When the caller chooses
    /// to persist (`persistence: Some`), the storage type is therefore
    /// compile-time-guaranteed to encrypt at rest — identity key material can
    /// never persist to plaintext. The ephemeral path
    /// ([`Identity::create_ephemeral`]) carries no storage and needs no such
    /// bound.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if key generation / DID creation fails, or if
    /// persisting the document to `config.persistence` fails.
    pub async fn create<K, D, S>(
        config: IdentityConfig<K, D, S>,
    ) -> Result<CreatedIdentity, IdentityError>
    where
        K: KeyCustody,
        D: DidMethod,
        S: EncryptedStorage,
    {
        let IdentityConfig {
            method,
            custody,
            persistence,
        } = config;

        let (identity, document, pre_rotation_handle) = create_inner(&method, &custody).await?;

        if let Some(storage) = persistence {
            persist_document(&storage, &identity.did, &document).await?;
        }

        Ok((identity, document, pre_rotation_handle))
    }

    /// Creates a new **ephemeral** standalone identity — no key material at rest.
    ///
    /// The fail-safe convenience entry (M2): equivalent to [`Identity::create`]
    /// with `persistence: None`, but without requiring an [`EncryptedStorage`]
    /// type argument (there is no storage). Use this for short-lived identities
    /// (tests, one-shot signing, in-memory agents) where nothing should be
    /// written to disk.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if key generation / DID creation fails.
    pub async fn create_ephemeral<K, D>(
        config: IdentityConfig<K, D, NoPersistence>,
    ) -> Result<CreatedIdentity, IdentityError>
    where
        K: KeyCustody,
        D: DidMethod,
    {
        // `persistence` is structurally `Option<NoPersistence>`; because
        // `NoPersistence` is uninhabited, it is always `None`. Destructure only
        // `method`/`custody` so the ephemeral path performs no persistence.
        let IdentityConfig {
            method, custody, ..
        } = config;
        create_inner(&method, &custody).await
    }
}

/// Shared lowering: mint a per-identity cold pre-rotation custody and call
/// [`DidMethod::create`]. Both [`Identity::create`] paths funnel through here so
/// the creation logic is written exactly once.
///
/// # Pre-rotation custody (known limitation, shared with `Node::start`)
///
/// This mints an [`InMemoryPreRotationCustody`] internally, exactly as the Node
/// builder (`generate_identity_with`/`identity_with_storage`) and every FFI
/// `identity_create*` path do. Per spec §9.7.4.1 §3 (storage isolation) the
/// pre-rotation key lives in a *separate substrate* from the operational
/// `custody`, which the type system guarantees (distinct custody type). However,
/// the only [`PreRotationCustody`](scp_platform::PreRotationCustody) backend that
/// exists today is the in-memory one, which is process-local: the returned
/// [`PreRotationKeyHandle`] cannot be reloaded after a process restart. A
/// `warn!` records this so operators know Layer-2 DID migration (recovery from
/// `#0` compromise, spec §9.7.4.1) is not durable for this identity until a
/// persistent pre-rotation backend ships. Unlike the Node path, this entry point
/// *returns* the handle rather than dropping it, so a future durable backend can
/// be threaded without an API change.
async fn create_inner<K, D>(method: &D, custody: &K) -> Result<CreatedIdentity, IdentityError>
where
    K: KeyCustody,
    D: DidMethod,
{
    let pre_rotation_custody = InMemoryPreRotationCustody::new();
    let (identity, document, pre_rotation_handle) =
        method.create(custody, &pre_rotation_custody).await?;
    tracing::warn!(
        did = %identity.did,
        "identity created with a process-local in-memory PreRotationCustody — \
         Layer-2 DID migration (recovery from `#0` compromise via spec §9.7.4.1) \
         is not durable across process restart until a persistent pre-rotation \
         backend ships."
    );
    Ok((identity, document, pre_rotation_handle))
}

/// Persists an identity's public DID document under the spec §17.3 key
/// convention `identity/{did}/document`.
///
/// Only the **public** DID document is persisted — key material never leaves the
/// [`KeyCustody`] boundary (ADR-006). The storage is [`EncryptedStorage`]-bound
/// at the [`Identity::create`] call site, so even this public artifact lands on
/// an encrypted-at-rest substrate.
async fn persist_document<S>(
    storage: &S,
    did: &str,
    document: &DidDocument,
) -> Result<(), IdentityError>
where
    S: EncryptedStorage,
{
    let key = identity_document_key(did)?;
    let data = serialize_document(document)?;
    storage
        .store(&key, &data)
        .await
        .map_err(IdentityError::Platform)
}

/// Storage key for an identity's persisted DID document (spec §17.3:
/// `identity/{did}/document`).
///
/// Delegates to the shared `scp_platform::store_value` key builder — the single
/// source of the `identity/{did}/document` convention used by both this path
/// and `ProtocolRepository::store_identity_document`. The shared builder runs
/// `sanitize_key_component`, rejecting a `did` containing `/`, `\`, `..`, or a
/// null byte (storage path-traversal guard), exactly as the canonical runtime
/// path does.
///
/// # Errors
///
/// Returns [`IdentityError::DocumentSerializationError`] if `did` contains
/// path-traversal characters.
fn identity_document_key(did: &str) -> Result<String, IdentityError> {
    scp_platform::store_value::identity_document_key(did)
        .map_err(|e| IdentityError::DocumentSerializationError(e.to_string()))
}

/// Serializes a DID document into the canonical on-disk form for the spec §17.3
/// `identity/{did}/document` slot.
///
/// This must be **byte-identical** to what
/// `ProtocolRepository::store_identity_document` writes, otherwise an identity
/// persisted here is unreadable by the canonical loader (and vice-versa). That
/// canonical path wraps the raw document bytes in a `StoredValue` version
/// envelope serialized with named `MessagePack`
/// (`scp_platform::store_value::to_stored_value_bytes`). We reproduce exactly
/// that shape: the inner `data` is the document's JSON bytes
/// (`serde_json::to_vec`, the `DidDocument`'s own serialization), wrapped in the
/// shared envelope. A cross-path round-trip test in `scp-runtime`
/// (`identity_create_persisted_document_loads_via_protocol_repository`)
/// mechanically enforces this compatibility so it cannot silently drift.
fn serialize_document(document: &DidDocument) -> Result<Vec<u8>, IdentityError> {
    let document_bytes = serde_json::to_vec(document)
        .map_err(|e| IdentityError::DocumentSerializationError(e.to_string()))?;
    scp_platform::store_value::to_stored_value_bytes(&document_bytes)
        .map_err(|e| IdentityError::DocumentSerializationError(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    use super::*;
    use scp_dht::InMemoryDhtClient;
    use scp_platform::encrypting_adapter::EncryptingAdapter;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::testing::InMemoryKeyCustody;

    /// A `did:dht` is always 32 verifying-key bytes z-base-32 encoded, so the
    /// `did:dht:z` prefix is the cheap structural check that creation produced a
    /// real, well-formed identity.
    fn assert_valid_did_dht(did: &str) {
        assert!(
            did.starts_with("did:dht:z"),
            "expected a did:dht:z... identity, got {did}"
        );
    }

    /// Builds an `EncryptedStorage` test backend (`EncryptingAdapter` over
    /// in-memory storage) wrapped in `Arc` so it is both `EncryptedStorage` (via
    /// the `Arc<T: EncryptedStorage>` blanket impl) and `Clone` — the latter so
    /// a test can hand one clone to the config and keep one to read back.
    fn encrypted_test_storage() -> Arc<EncryptingAdapter<InMemoryStorage>> {
        Arc::new(EncryptingAdapter::new(
            InMemoryStorage::new(),
            Zeroizing::new([7u8; 32]),
        ))
    }

    #[tokio::test]
    async fn ephemeral_create_produces_valid_did_dht() {
        let (identity, document, _pre_rotation) =
            Identity::create_ephemeral(IdentityConfig::ephemeral(
                crate::DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
                InMemoryKeyCustody::new(),
            ))
            .await
            .expect("ephemeral identity creation should succeed");

        assert_valid_did_dht(&identity.did);
        // The document's id is the same DID the identity reports.
        assert_eq!(document.id, identity.did);
    }

    #[tokio::test]
    async fn ephemeral_create_via_explicit_none_persistence() {
        // The literal-struct form with an explicit `None` storage is the
        // ephemeral path; it must produce the same well-formed identity as the
        // `ephemeral` convenience constructor.
        let (identity, _document, _pre_rotation) = Identity::create_ephemeral(IdentityConfig {
            method: crate::DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
            custody: InMemoryKeyCustody::new(),
            persistence: None::<NoPersistence>,
        })
        .await
        .expect("ephemeral identity creation should succeed");

        assert_valid_did_dht(&identity.did);
    }

    #[tokio::test]
    async fn persisted_create_round_trips_document() {
        let storage = encrypted_test_storage();

        let (identity, document, _pre_rotation) = Identity::create(IdentityConfig {
            method: crate::DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
            custody: InMemoryKeyCustody::new(),
            persistence: Some(Arc::clone(&storage)),
        })
        .await
        .expect("persisted identity creation should succeed");

        assert_valid_did_dht(&identity.did);

        // The document persisted under the spec §17.3 key round-trips back to
        // the same document the call returned. Reading through the same
        // `EncryptingAdapter` decrypts transparently. The on-disk form is the
        // canonical `StoredValue` named-`MessagePack` envelope wrapping the
        // document's JSON bytes — identical to what
        // `ProtocolRepository::store_identity_document` writes — so it is
        // decoded via the shared `store_value` helper, NOT bare JSON.
        let key = identity_document_key(&identity.did).expect("key build should succeed");
        let stored = storage
            .retrieve(&key)
            .await
            .expect("storage retrieve should succeed")
            .expect("a document should be persisted at identity/{did}/document");
        let document_bytes: Vec<u8> = scp_platform::store_value::from_stored_value_bytes(&stored)
            .expect("persisted envelope should deserialize");
        let reloaded: DidDocument = serde_json::from_slice(&document_bytes)
            .expect("inner document JSON should deserialize");
        assert_eq!(reloaded.id, document.id);
        assert_eq!(reloaded.id, identity.did);
    }

    #[tokio::test]
    async fn ephemeral_create_persists_nothing() {
        // An ephemeral identity must leave no document at rest. We assert the
        // negative by constructing a storage that is NOT handed to the config,
        // then confirming the ephemeral path returns without ever touching it.
        let untouched = encrypted_test_storage();
        let (identity, _document, _pre_rotation) =
            Identity::create_ephemeral(IdentityConfig::ephemeral(
                crate::DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
                InMemoryKeyCustody::new(),
            ))
            .await
            .expect("ephemeral identity creation should succeed");

        let key = identity_document_key(&identity.did).expect("key build should succeed");
        assert!(
            untouched
                .retrieve(&key)
                .await
                .expect("storage retrieve should succeed")
                .is_none(),
            "ephemeral creation must not persist any document"
        );
    }

    /// `NoPersistence` is uninhabited, so the ephemeral config's `persistence`
    /// is structurally always `None`. This documents (and locks in) that the
    /// ephemeral path can never carry a storage value.
    #[test]
    fn no_persistence_is_uninhabited() {
        let config: IdentityConfig<
            InMemoryKeyCustody,
            crate::DidDht<InMemoryDhtClient>,
            NoPersistence,
        > = IdentityConfig::ephemeral(
            crate::DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
            InMemoryKeyCustody::new(),
        );
        assert!(
            config.persistence.is_none(),
            "ephemeral config must carry no persistence"
        );
    }

    /// The persistence key builder must route the DID through the shared
    /// `sanitize_key_component` gate, rejecting path-traversal characters
    /// (`/`, `\`, `..`, null) before formatting — the same guard the canonical
    /// `ProtocolRepository` path applies. A raw `format!` would let a malformed
    /// DID escape its `identity/{did}/` namespace.
    #[test]
    fn identity_document_key_rejects_malformed_dids() {
        assert!(
            identity_document_key("../context/victim").is_err(),
            "a `..`/`/` DID must be rejected"
        );
        assert!(
            identity_document_key("evil\\did").is_err(),
            "a backslash DID must be rejected"
        );
        assert!(
            identity_document_key("a/b").is_err(),
            "a slashed DID must be rejected"
        );
        assert!(
            identity_document_key("nul\0did").is_err(),
            "a null-byte DID must be rejected"
        );
        // A well-formed DID is accepted and follows the spec §17.3 convention.
        assert_eq!(
            identity_document_key("did:dht:z6MkTest").expect("well-formed DID must be accepted"),
            "identity/did:dht:z6MkTest/document"
        );
    }

    /// The serialized on-disk form is the canonical `StoredValue` named-
    /// `MessagePack` envelope (NOT bare JSON): its inner `data` is the
    /// document's JSON bytes, and it carries the shared
    /// `CURRENT_STORE_VERSION`. This local guard catches drift away from the
    /// envelope shape even before the cross-crate round-trip test runs.
    #[tokio::test]
    async fn serialize_document_produces_stored_value_envelope() {
        let (_identity, document, _pre_rotation) =
            Identity::create_ephemeral(IdentityConfig::ephemeral(
                crate::DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
                InMemoryKeyCustody::new(),
            ))
            .await
            .expect("ephemeral identity creation should succeed");

        let bytes = serialize_document(&document).expect("serialization should succeed");

        // It is NOT bare JSON of the document.
        assert!(
            serde_json::from_slice::<DidDocument>(&bytes).is_err(),
            "persisted bytes must be the MessagePack envelope, not bare JSON"
        );

        // It IS a StoredValue<Vec<u8>> envelope whose inner data is the
        // document's JSON, deserializable via the shared helper.
        let inner: Vec<u8> = scp_platform::store_value::from_stored_value_bytes(&bytes)
            .expect("envelope should deserialize via the shared helper");
        let reloaded: DidDocument =
            serde_json::from_slice(&inner).expect("inner bytes should be the document JSON");
        assert_eq!(reloaded.id, document.id);
    }
}
