//! `did:dht` DID method implementation.
//!
//! Implements the [`DidMethod`] trait for `did:dht` identities. The `did:dht`
//! method uses the `BitTorrent` Mainline DHT for document publication and
//! resolution. The DID string is self-certifying: it is the z-base-32 encoding
//! of the Ed25519 Identity Key's public key.
//!
//! # DHT Publishing
//!
//! DID documents are published to the Mainline DHT as BEP44 signed mutable
//! items. The document is serialized to JSON, then signed with the identity's
//! Ed25519 key. The signature covers a BEP44-style payload that includes the
//! sequence number and value.
//!
//! # Resolution and Caching
//!
//! Resolved DID documents are cached with TTL-based staleness detection.
//! Active contacts use a 24-hour refresh interval; inactive contacts use a
//! 7-day interval. Stale results (not refreshed within the 2h30m republish
//! window) carry a staleness indicator.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full design.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyType, PreRotationCustody, PreRotationKeyHandle};

use super::cache::{Clock, DidCache, DidResolutionResult, Staleness, SystemClock};
use super::dht_client::{DhtClient, InMemoryDhtClient};
use super::document::{DidDocument, DidRotationEvent, MigrationProof, PreRotationProof};
use super::{DidMethod, IdentityError, ScpIdentity};

/// The `did:dht` DID method prefix.
const DID_DHT_PREFIX: &str = "did:dht:";

// ---------------------------------------------------------------------------
// BEP44 Sequence Persistence (issue #327)
// ---------------------------------------------------------------------------

/// Persistence trait for BEP44 sequence numbers.
///
/// DID document publications to the Mainline DHT use BEP44 signed mutable
/// items with a monotonically increasing sequence number. If the node restarts
/// and begins from 0, previously-published documents with higher sequence
/// numbers will be considered "newer" by DHT peers, enabling replay attacks.
///
/// Implementations persist the last-published sequence number so it can be
/// recovered on restart. The identity crate defines this trait (rather than
/// importing from `scp-core`) to preserve `scp-identity`'s self-contained
/// design.
///
/// See issue #327 and BEP44 §Mutable Items.
pub trait SequenceStore: Send + Sync {
    /// Loads the last-persisted sequence number for the given DID.
    ///
    /// Returns `Ok(None)` if no sequence has been stored (first run).
    fn load(
        &self,
        did: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, IdentityError>> + Send + '_>>;

    /// Persists the sequence number for the given DID.
    ///
    /// Called after every successful DID document publication.
    fn store(
        &self,
        did: &str,
        seq: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityError>> + Send + '_>>;
}

/// In-memory [`SequenceStore`] for testing.
///
/// Stores sequence numbers in a `HashMap` behind a `tokio::sync::Mutex`.
/// Not suitable for production (no persistence across restarts).
#[derive(Debug, Default)]
pub struct InMemorySequenceStore {
    sequences: tokio::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl InMemorySequenceStore {
    /// Creates a new empty in-memory sequence store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sequences: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl SequenceStore for InMemorySequenceStore {
    fn load(
        &self,
        did: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, IdentityError>> + Send + '_>> {
        let did = did.to_owned();
        Box::pin(async move {
            let map = self.sequences.lock().await;
            Ok(map.get(&did).copied())
        })
    }

    fn store(
        &self,
        did: &str,
        seq: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityError>> + Send + '_>> {
        let did = did.to_owned();
        Box::pin(async move {
            self.sequences.lock().await.insert(did, seq);
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Post-resolve hook (TOFU / certificate pinning integration point)
// ---------------------------------------------------------------------------

/// Hook called after every successful DID resolution.
///
/// This is the integration point for TOFU key tracking (spec §9.11) and
/// certificate pinning (spec §9.13). The `scp-core` crate provides an
/// implementation that calls `check_tofu` and persists records via
/// `ProtocolRepository`. The identity crate defines this trait (rather than
/// importing from `scp-core`) to preserve `scp-identity`'s self-contained
/// dependency graph.
///
/// # Rotation authorization on key change
///
/// When TOFU detects a key change (`TofuResult::Changed`), the implementation
/// should verify that the DID document update was properly authorized. For
/// `did:dht`, BEP44 signature verification during resolution already provides
/// this guarantee: the DHT record is signed by the Identity Key (`#0`), so
/// any document update — including key rotations — is cryptographically
/// authorized by the DID controller. The post-resolve hook does NOT need to
/// perform additional rotation authorization checks; it can focus on alerting
/// the user and refusing encrypted operations until the change is accepted.
pub trait PostResolveHook: Send + Sync {
    /// Called after a DID document is successfully resolved and verified.
    ///
    /// The hook receives the DID string and the resolved document. It may
    /// inspect verification method keys, compare against stored records,
    /// and report changes. Errors from this hook are logged but do not
    /// prevent the resolution result from being returned — TOFU is advisory,
    /// not a gate on resolution itself.
    fn on_resolve(
        &self,
        did: &str,
        document: &DidDocument,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityError>> + Send + '_>>;
}

/// Domain separator for migration proof hashes, preventing cross-protocol
/// signature confusion. See issue #78.
const DOMAIN_MIGRATION_V1: &[u8] = b"SCP-MIGRATION-V1:";

/// Maximum future-clock-skew tolerance (seconds) for a `migration_proof.rotated_at`
/// timestamp during verification. Mirrors the 5-minute tolerance spec §9.8.2(c)
/// applies to SCP envelope timestamps: enough headroom for legitimate clock skew
/// across federated nodes, tight enough that an attacker cannot trivially mint
/// a far-future migration claim.
const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Maximum past window (seconds) for a `migration_proof.rotated_at` timestamp
/// during verification. Migrations claimed to be older than this are rejected:
/// any reasonable offline-recovery flow will publish far sooner, so a deeply
/// past `rotated_at` is a strong signal of a forged proof. Set to 5 years.
const MAX_PAST_WINDOW_SECS: u64 = 5 * 365 * 24 * 3600;

/// Hard epoch floor (Unix seconds) for `migration_proof.rotated_at`. Even when
/// the verifier's clock is broken — `now < MAX_PAST_WINDOW_SECS` clamps the
/// `now.saturating_sub(...)` past-window bound to zero, accepting any
/// `rotated_at >= 0` — `rotated_at` strictly older than this floor is rejected.
///
/// Value: `1_700_000_000` Unix seconds — `2023-11-14T22:13:20Z UTC`. Chosen as
/// a fixed point well before any conceivable real SCP migration could have
/// taken place: the protocol's earliest source artifacts and ADRs post-date
/// this anchor, so no honest holder will ever produce a `rotated_at` below it.
/// Choosing a relative bound (e.g., "always reject the year 1970") would let a
/// faulty-clock verifier still accept absurd timestamps; this absolute anchor
/// makes the past-window bound robust to clock corruption.
const MIGRATION_EPOCH_FLOOR_UNIX_SECS: u64 = 1_700_000_000;

/// Type alias for the signing function stored in `DidDht`.
///
/// Takes a key handle ID and data to sign, returns the 64-byte Ed25519
/// signature. This abstraction allows `DidDht` to sign BEP44 payloads
/// without requiring a generic `KeyCustody` type parameter.
type SignFn = dyn Fn(u64, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, IdentityError>> + Send>>
    + Send
    + Sync;

/// `did:dht` implementation of the [`DidMethod`] trait.
///
/// Creates self-certifying DIDs where the identifier is the z-base-32 encoding
/// of the Ed25519 Identity Key's public key. Verification is a local operation
/// that decodes the DID suffix and compares to the provided public key.
///
/// # Type Parameters
///
/// * `D` — The DHT client implementation. Defaults to [`InMemoryDhtClient`]
///   for testing. Production code should use a pkarr-based client.
/// * `C` — The clock implementation for the cache. Defaults to [`SystemClock`].
///
/// # Construction
///
/// - [`DidDht::new()`] — Creates a default instance with `InMemoryDhtClient`
///   and no signing capability (for backward compatibility with SCP-006 tests).
/// - [`DidDht::with_client()`] — Creates an instance with a specific DHT client.
/// - `DidDht::with_client_and_custody()` — Creates a fully-configured instance
///   with DHT client and signing capability.
pub struct DidDht<D: DhtClient = InMemoryDhtClient, C: Clock = SystemClock> {
    /// The DHT client used for publish/resolve operations.
    dht_client: Arc<D>,
    /// Resolution cache for DID documents.
    cache: Arc<DidCache<C>>,
    /// Monotonically increasing BEP44 sequence number.
    sequence: AtomicU64,
    /// Optional signing function for BEP44 publish.
    sign_fn: Option<Arc<SignFn>>,
    /// Optional persistence for BEP44 sequence numbers (issue #327).
    ///
    /// When present, the sequence number is persisted after every successful
    /// DID document publication and loaded on startup via
    /// [`initialize_sequence`](Self::initialize_sequence).
    sequence_store: Option<Arc<dyn SequenceStore>>,
    /// Optional post-resolve hook for TOFU key tracking (spec §9.11).
    ///
    /// When present, called after every successful DID resolution. Errors
    /// from the hook are logged but do not prevent resolution from succeeding.
    post_resolve_hook: Option<Arc<dyn PostResolveHook>>,
}

// Manual Debug impl because SignFn and dyn SequenceStore can't derive Debug.
impl<D: DhtClient + std::fmt::Debug, C: Clock + std::fmt::Debug> std::fmt::Debug for DidDht<D, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DidDht")
            .field("dht_client", &self.dht_client)
            .field("cache", &self.cache)
            .field("sequence", &self.sequence)
            .field("sign_fn", &self.sign_fn.as_ref().map(|_| "<fn>"))
            .field(
                "sequence_store",
                &self.sequence_store.as_ref().map(|_| "<store>"),
            )
            .field(
                "post_resolve_hook",
                &self.post_resolve_hook.as_ref().map(|_| "<hook>"),
            )
            .finish()
    }
}

impl Default for DidDht<InMemoryDhtClient, SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl DidDht<InMemoryDhtClient, SystemClock> {
    /// Creates a new `DidDht` instance with an in-memory DHT client and no
    /// signing capability.
    ///
    /// This constructor is backward-compatible with SCP-006 tests. The
    /// `publish` method will return an error unless a signing function is
    /// configured via `DidDht::with_client_and_custody`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dht_client: Arc::new(InMemoryDhtClient::new()),
            cache: Arc::new(DidCache::new()),
            sequence: AtomicU64::new(0),
            sign_fn: None,
            sequence_store: None,
            post_resolve_hook: None,
        }
    }

    /// Creates a `DidDht` instance with in-memory DHT, cache, and a signing
    /// function derived from the provided [`KeyCustody`].
    ///
    /// This is the recommended constructor for tests and examples that need
    /// to create identities and publish DID documents. Equivalent to manually
    /// constructing an `InMemoryDhtClient`, `DidCache`, calling `make_sign_fn`,
    /// and wiring them together via `with_client_and_signer`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use scp_identity::dht::DidDht;
    /// use scp_identity::DidMethod;
    /// use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let custody = Arc::new(InMemoryKeyCustody::new());
    /// let pre_rotation_custody = Arc::new(InMemoryPreRotationCustody::new());
    /// let did_dht = DidDht::with_in_memory_custody(Arc::clone(&custody));
    /// let (identity, document, _pre_rotation_handle) = did_dht
    ///     .create(&*custody, &*pre_rotation_custody)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See issue #530.
    #[must_use]
    pub fn with_in_memory_custody<K: KeyCustody + 'static>(key_custody: Arc<K>) -> Self {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let sign_fn = Self::make_sign_fn(key_custody);
        Self {
            dht_client,
            cache,
            sequence: AtomicU64::new(0),
            sign_fn: Some(sign_fn),
            sequence_store: None,
            post_resolve_hook: None,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl DidDht<InMemoryDhtClient, SystemClock> {
    /// Creates an in-memory identity in a single call.
    ///
    /// Wires up [`InMemoryKeyCustody`](scp_platform::testing::InMemoryKeyCustody),
    /// `InMemoryDhtClient`, `DidCache`, and the signing function, then calls
    /// [`DidMethod::create`] to generate the identity. Returns all components
    /// the caller needs for subsequent operations.
    ///
    /// This replaces the 5-line boilerplate pattern:
    ///
    /// ```text
    /// // Before (5 lines):
    /// let custody = Arc::new(InMemoryKeyCustody::new());
    /// let dht_client = Arc::new(InMemoryDhtClient::new());
    /// let cache = Arc::new(DidCache::new());
    /// let sign_fn = DidDht::make_sign_fn(Arc::clone(&custody));
    /// let did_dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);
    /// let (identity, document) = did_dht.create(&*custody).await?;
    ///
    /// // After (1 line):
    /// let (identity, document, custody, did_dht) = DidDht::create_in_memory().await?;
    /// ```
    ///
    /// See issue #530.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] if key generation or identity creation fails
    /// (should not happen with in-memory backends).
    pub async fn create_in_memory() -> Result<
        (
            ScpIdentity,
            DidDocument,
            Arc<scp_platform::testing::InMemoryKeyCustody>,
            Self,
        ),
        IdentityError,
    > {
        use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

        let custody = Arc::new(InMemoryKeyCustody::new());
        let pre_rotation_custody = Arc::new(InMemoryPreRotationCustody::new());
        let did_dht = Self::with_in_memory_custody(Arc::clone(&custody));
        let (identity, document, _pre_rotation_handle) =
            did_dht.create(&*custody, &*pre_rotation_custody).await?;
        Ok((identity, document, custody, did_dht))
    }
}

impl<D: DhtClient> DidDht<D, SystemClock> {
    /// Creates a new `DidDht` instance with a specific DHT client and system
    /// clock.
    #[must_use]
    pub fn with_client(dht_client: Arc<D>) -> Self {
        Self {
            dht_client,
            cache: Arc::new(DidCache::new()),
            sequence: AtomicU64::new(0),
            sign_fn: None,
            sequence_store: None,
            post_resolve_hook: None,
        }
    }
}

/// Identifies which DHT publish step inside
/// [`DidDht::migrate_identity`] failed, and therefore which step a
/// resume attempt must re-run.
///
/// `migrate_identity` performs two DHT publishes:
///
/// - **Step 7** — publish the NEW DID document so verifiers following
///   `alsoKnownAs[new_did]` always find a published successor. Failure here
///   maps to [`MigrationResumePhase::PublishNew`]. Resume re-runs step 7,
///   step 7b (destroy OLD operational keys), and step 8 (republish OLD
///   document with `alsoKnownAs`).
/// - **Step 8** — republish the OLD DID document with
///   `alsoKnownAs = new_did` (with `#active`/`#agent` retired). Failure
///   here maps to [`MigrationResumePhase::RepublishOldAlsoKnownAs`]. Resume
///   re-runs only step 8 — the NEW document is already on the DHT, and
///   OLD operational keys are already destroyed.
///
/// Carried inside [`IdentityError::MigrationPublishFailed`] alongside a
/// [`MigrationPartialState`] that holds the byte-identical artifacts the
/// resume call must republish (spec §9.7.4.1 byte parity invariant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MigrationResumePhase {
    /// Step 7 — publish of the NEW DID document failed.
    ///
    /// At the moment of failure, the OLD pre-rotation handle is consumed
    /// (step 5), the NEW pre-rotation handle is registered in cold custody
    /// (step 4), the NEW `#0`/`#active` are present in operational custody
    /// (steps 5/3), and the OLD operational keys are still intact. Resume
    /// re-runs step 7 (publish NEW), step 7b (destroy OLD operational keys),
    /// and step 8 (publish OLD with `alsoKnownAs`).
    PublishNew,
    /// Step 8 — republish of the OLD DID document with `alsoKnownAs` failed.
    ///
    /// At the moment of failure, the NEW DID document is already published
    /// (step 7 succeeded), and the OLD `#active` / `#agent` keys are already
    /// destroyed (step 7b ran). The OLD `#0` is intentionally retained so
    /// step 8 can re-sign the republish. Resume re-runs only step 8.
    RepublishOldAlsoKnownAs,
}

/// Outcome returned by a successful [`DidDht::migrate_identity`] /
/// [`DidDht::resume_migration_publish`] call.
///
/// Carries the four byte-identical artifacts the caller needs to
/// continue operating under the new identity:
///
/// - `new_identity` — the new [`ScpIdentity`] (new DID and keys).
/// - `new_document` — the DID document for the new identity.
/// - `rotation_event` — the [`DidRotationEvent`] to distribute to all
///   active contexts (ADR-003 §4b).
/// - `new_pre_rotation_handle` — handle for the freshly-minted
///   pre-rotation key in `pre_rotation_custody` (per spec §9.7.4.1
///   item 6 "post-rotation key cycling"). Caller persists this for
///   the next migration.
///
/// Returned as a named struct rather than a tuple so future additions
/// (e.g. an audit-log digest, an attestation token) extend the type
/// without breaking destructuring callers — and so the four fields
/// are self-documenting at the call site.
#[derive(Debug, Clone)]
pub struct MigrationOutcome {
    /// The new [`ScpIdentity`] constructed by step 6 (its `#0` is the
    /// migrated OLD pre-rotation private key; its `#active` is a fresh
    /// keypair generated at step 3).
    pub new_identity: ScpIdentity,
    /// The NEW DID document constructed by step 6.
    pub new_document: DidDocument,
    /// The [`DidRotationEvent`] hoisted from step 9 — signed at step 2
    /// under the OLD `#0` and carrying the revealed pre-rotation public
    /// from step 1.
    pub rotation_event: DidRotationEvent,
    /// The NEW pre-rotation handle registered in cold custody by step 4
    /// (spec §9.7.4.1 item 6 "post-rotation key cycling"). Caller
    /// persists this for the next migration cycle.
    pub new_pre_rotation_handle: PreRotationKeyHandle,
}

/// Recovery handle for [`DidDht::migrate_identity`] DHT-publish failures.
///
/// `migrate_identity` performs two DHT publishes (step 7 publishes the NEW
/// DID document, step 8 republishes the OLD document with `alsoKnownAs`).
/// Both publishes happen AFTER the irreversible cold-custody mutation in
/// step 5 (`PreRotationCustody::destroy_after_migration`), which consumes
/// the OLD pre-rotation handle and surfaces its private bytes as the NEW
/// `#0`. By the time either publish runs, the caller cannot recover by
/// re-invoking `migrate_identity` (step 1's `reveal_public_key` would fail
/// against the now-missing handle). Instead, when either publish fails,
/// `migrate_identity` returns [`IdentityError::MigrationPublishFailed`]
/// carrying this state, and the caller passes it to
/// [`DidDht::resume_migration_publish`] to finish the migration.
///
/// # Byte-parity invariant
///
/// The carried [`Self::rotation_event`] holds the migration proof signed
/// at step 2 (under the OLD `#0`) and the pre-rotation proof carrying the
/// `revealed_key` bytes from step 1. Both are byte-identical to what a
/// successful first-pass `migrate_identity` would have returned —
/// `SHA-256(rotation_event.pre_rotation_proof.revealed_key) ==
/// new_document.pre_rotation_service().commitment` MUST hold both before
/// and after [`DidDht::resume_migration_publish`] succeeds (spec §9.7.4.1
/// byte parity invariant). Resume re-uses the carried artifacts
/// verbatim; it does NOT re-derive keys or re-sign proofs.
///
/// # OLD `#0` retention contract
///
/// Step 7b (`destroy_old_operational_keys`) destroys the OLD `#active`
/// and `#agent` keys but intentionally retains the OLD `#0`. Step 8 needs
/// `#0` to sign the BEP44 publish of the OLD document with `alsoKnownAs`,
/// and any later forwarding republish (recommended 90 days, ADR-003 §4b)
/// uses the same key. The OLD `#0` handle therefore continues to live in
/// operational custody even after step 7b runs; consumers of this struct
/// MUST NOT destroy it before resume completes.
///
/// # Idempotency
///
/// Calling [`DidDht::resume_migration_publish`] more than once with the
/// same `MigrationPartialState` is safe: the second call republishes
/// byte-identical documents under BEP44 sequence-number monotonicity (a
/// new `seq` is allocated each time and the DHT accepts higher
/// sequences), and step 7b's `destroy_key` is itself idempotent (it
/// surfaces `KeyNotFound` as a `warn!` and proceeds). The carried
/// artifacts are read-only.
///
/// # Persistence
///
/// `MigrationPartialState` derives `Serialize` + `Deserialize` so callers
/// can durably persist a recovery handle across process restarts (write
/// to disk after `MigrationPublishFailed`, reload, call
/// `resume_migration_publish`). All nested types (`ScpIdentity`,
/// `DidDocument`, `DidRotationEvent`, `PreRotationKeyHandle`) participate
/// in the serde tree — but note that `ScpIdentity`'s key fields are
/// [`scp_platform::traits::KeyHandle`] references (opaque numeric ids
/// into a custody), NOT private bytes. The handle is meaningless to a
/// process that does not have the matching custody substrate; persist
/// the substrate (file directory, keychain group, etc.) alongside the
/// handle.
///
/// # Field visibility
///
/// The fields are `pub(crate)` rather than `pub` so external callers
/// cannot swap nested artifacts (e.g. substitute a fresh
/// `new_pre_rotation_handle` whose hash drifts from
/// `new_document`'s commitment) and break the byte-parity invariant.
/// External access is via the read-only accessor methods on this struct;
/// the full state is consumed by value when passed into
/// [`DidDht::resume_migration_publish`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPartialState {
    /// Which step failed; dictates which steps a resume call must re-run.
    pub(crate) phase: MigrationResumePhase,
    /// The NEW [`ScpIdentity`] constructed by step 6 (its `#0` is the
    /// migrated OLD pre-rotation private key; its `#active` is a fresh
    /// keypair generated at step 3). Resume publishes its document.
    pub(crate) new_identity: ScpIdentity,
    /// The NEW DID document constructed by step 6. Carried byte-identical
    /// so resume re-publishes the same value the first pass would have.
    pub(crate) new_document: DidDocument,
    /// The [`DidRotationEvent`] hoisted from step 9 — signed at step 2
    /// under the OLD `#0` and carrying the revealed pre-rotation public
    /// from step 1. Returned verbatim by a successful resume so callers
    /// can distribute it to active contexts (ADR-003 §4b).
    pub(crate) rotation_event: DidRotationEvent,
    /// The NEW pre-rotation handle registered in cold custody by step 4.
    /// Caller persists this for the next migration cycle.
    pub(crate) new_pre_rotation_handle: PreRotationKeyHandle,
    /// The OLD [`ScpIdentity`] (the one passed into `migrate_identity`).
    /// Its `#0` is still present in operational custody — step 8 uses it
    /// to sign the republish — even after step 7b destroyed `#active`
    /// (and `#agent` if present).
    pub(crate) old_identity: ScpIdentity,
    /// The OLD DID document. Resume clones this, calls
    /// `set_also_known_as(new_identity.did)` +
    /// `retire_operational_keys_for_migration()`, and publishes the
    /// result under the OLD `#0`.
    pub(crate) old_document: DidDocument,
}

impl MigrationPartialState {
    /// Returns which `migrate_identity` step failed.
    ///
    /// Determines which steps a [`DidDht::resume_migration_publish`]
    /// call will re-run (see [`MigrationResumePhase`] for the per-phase
    /// contract).
    #[must_use]
    pub const fn phase(&self) -> MigrationResumePhase {
        self.phase
    }

    /// Returns the NEW DID string the failed migration was migrating to.
    ///
    /// Diagnostic helper — useful when logging or surfacing the
    /// in-flight migration target without exposing the full
    /// [`ScpIdentity`] (whose key handles are not safe to leak to logs).
    #[must_use]
    pub fn new_did(&self) -> &str {
        &self.new_identity.did
    }

    /// Returns the OLD DID string the failed migration was migrating away
    /// from.
    ///
    /// Diagnostic helper — pair with [`Self::new_did`] for log lines like
    /// `"resuming migration {old} → {new}"`.
    #[must_use]
    pub fn old_did(&self) -> &str {
        &self.old_identity.did
    }

    /// Returns the [`DidRotationEvent`] signed at step 2 of the failed
    /// `migrate_identity` call.
    ///
    /// Distributed to active contexts (ADR-003 §4b) after a successful
    /// resume so peers can promote the rotated identity. Returned verbatim
    /// by [`DidDht::resume_migration_publish`] on success, so most callers
    /// will consume it from the resume return value; this accessor is
    /// useful for inspecting the in-flight migration before deciding
    /// whether to resume.
    #[must_use]
    pub const fn rotation_event(&self) -> &DidRotationEvent {
        &self.rotation_event
    }

    /// Returns the NEW pre-rotation handle registered in cold custody by
    /// step 4 of the failed `migrate_identity` call.
    ///
    /// The handle was committed-to before any DHT publish: the NEW DID
    /// document's `PreRotationCommitment` service entry contains
    /// `SHA-256(reveal_public_key(handle))`. Resume re-uses this exact
    /// handle so the published commitment matches the (later-revealed)
    /// public key bit-for-bit (spec §9.7.4.1 byte parity invariant).
    #[must_use]
    pub const fn new_pre_rotation_handle(&self) -> &PreRotationKeyHandle {
        &self.new_pre_rotation_handle
    }
}

impl<D: DhtClient, C: Clock> DidDht<D, C> {
    /// Creates a new `DidDht` instance with a specific DHT client, cache, and
    /// signing function.
    ///
    /// The signing function takes a key handle ID and data bytes, returning the
    /// Ed25519 signature bytes. This is typically constructed from a
    /// [`KeyCustody`] implementation.
    #[must_use]
    pub fn with_client_and_signer(
        dht_client: Arc<D>,
        cache: Arc<DidCache<C>>,
        sign_fn: Arc<SignFn>,
    ) -> Self {
        Self {
            dht_client,
            cache,
            sequence: AtomicU64::new(0),
            sign_fn: Some(sign_fn),
            sequence_store: None,
            post_resolve_hook: None,
        }
    }

    /// Creates a new `DidDht` instance with DHT client, cache, signing
    /// function, and sequence persistence store (issue #327).
    ///
    /// After construction, call [`initialize_sequence`](Self::initialize_sequence)
    /// to bootstrap the sequence number from the store and/or DHT before
    /// publishing any documents.
    #[must_use]
    pub fn with_client_signer_and_store(
        dht_client: Arc<D>,
        cache: Arc<DidCache<C>>,
        sign_fn: Arc<SignFn>,
        sequence_store: Arc<dyn SequenceStore>,
    ) -> Self {
        Self {
            dht_client,
            cache,
            sequence: AtomicU64::new(0),
            sign_fn: Some(sign_fn),
            sequence_store: Some(sequence_store),
            post_resolve_hook: None,
        }
    }

    /// Creates a signing function from a [`KeyCustody`] implementation.
    ///
    /// The returned function captures the key custody in an `Arc` and delegates
    /// signing to `KeyCustody::sign`.
    pub fn make_sign_fn<K: KeyCustody + 'static>(key_custody: Arc<K>) -> Arc<SignFn> {
        Arc::new(move |key_id: u64, data: Vec<u8>| {
            let kc = Arc::clone(&key_custody);
            Box::pin(async move {
                let handle = scp_platform::traits::KeyHandle::new(key_id);
                let sig = kc
                    .sign(&handle, &data)
                    .await
                    .map_err(IdentityError::Platform)?;
                Ok(sig.into_bytes())
            })
        })
    }

    /// Returns a reference to the DHT client.
    #[must_use]
    pub const fn dht_client(&self) -> &Arc<D> {
        &self.dht_client
    }

    /// Returns a reference to the DID cache.
    #[must_use]
    pub const fn cache(&self) -> &Arc<DidCache<C>> {
        &self.cache
    }

    /// Returns the current sequence number.
    #[must_use]
    pub fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }

    /// Sets the sequence number (e.g., when loading from persistent storage).
    pub fn set_sequence(&self, seq: u64) {
        self.sequence.store(seq, Ordering::Release);
    }

    /// Returns a reference to the sequence store, if configured.
    #[must_use]
    pub fn sequence_store(&self) -> Option<&Arc<dyn SequenceStore>> {
        self.sequence_store.as_ref()
    }

    /// Sets a post-resolve hook for TOFU key tracking (spec §9.11).
    ///
    /// The hook is called after every successful DID resolution. Use this
    /// to integrate TOFU key tracking from `scp-core::crypto::tofu`.
    pub fn set_post_resolve_hook(&mut self, hook: Arc<dyn PostResolveHook>) {
        self.post_resolve_hook = Some(hook);
    }

    /// Returns a reference to the post-resolve hook, if configured.
    #[must_use]
    pub fn post_resolve_hook(&self) -> Option<&Arc<dyn PostResolveHook>> {
        self.post_resolve_hook.as_ref()
    }

    /// Bootstraps the BEP44 sequence number from persistent storage and/or
    /// the DHT (issue #327).
    ///
    /// This method MUST be called after construction and before publishing
    /// any DID documents. It ensures the node never publishes with a sequence
    /// number less than or equal to a previously-published value, even after
    /// restart.
    ///
    /// # Algorithm
    ///
    /// 1. Load the last-persisted sequence from the [`SequenceStore`] (if
    ///    configured).
    /// 2. Best-effort DHT query for the current sequence of the DID's BEP44
    ///    record. If the DHT is unreachable, initialization proceeds with the
    ///    locally-stored value and logs a warning.
    /// 3. Set the local sequence to `max(stored, remote)`. The next publish
    ///    will increment this to `max(stored, remote) + 1`.
    ///
    /// If no store is configured and no DHT record exists, the sequence
    /// remains at its current value (typically 0 for a new identity).
    ///
    /// # Errors
    ///
    /// Store load errors are propagated as-is. DHT query failures are
    /// logged but not propagated (best-effort).
    pub async fn initialize_sequence(&self, did: &str) -> Result<(), IdentityError> {
        // Step 1: Load from persistent store.
        let mut best_seq: u64 = if let Some(store) = &self.sequence_store
            && let Some(stored_seq) = store.load(did).await?
        {
            stored_seq
        } else {
            0
        };

        // Step 2: Best-effort DHT query for the current remote sequence.
        // If the DHT is unreachable we proceed with the locally-stored value
        // rather than failing the entire initialization.
        let public_key = extract_public_key(did)?;
        match self.dht_client.resolve(&public_key).await {
            Ok(Some(record)) => {
                best_seq = best_seq.max(record.seq);
            }
            Ok(None) => {} // No record on DHT — first publish or expired.
            Err(e) => {
                tracing::warn!(
                    did = %did,
                    error = %e,
                    "DHT query failed during sequence initialization, using local value"
                );
            }
        }

        // Step 3: Set to the maximum known sequence.
        // The next publish_document call will fetch_add(1), producing
        // max(stored, remote) + 1.
        if best_seq > 0 {
            self.sequence.store(best_seq, Ordering::Release);
        }

        Ok(())
    }

    /// Constructs the BEP44 signable payload for a value and sequence number.
    ///
    /// Delegates to the standalone [`bep44_signable`] function.
    #[must_use]
    pub fn bep44_signable(value: &[u8], seq: u64) -> Vec<u8> {
        bep44_signable(value, seq)
    }

    /// Verifies a BEP44 Ed25519 signature over the given value and sequence.
    ///
    /// Delegates to the standalone [`verify_bep44_signature`] function.
    fn verify_bep44_signature(
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> Result<(), IdentityError> {
        verify_bep44_signature(public_key, signature, value, seq)
    }

    /// Extracts the 32-byte public key from a `did:dht:z...` string.
    ///
    /// Delegates to the standalone [`extract_public_key`] function.
    fn extract_public_key(did_string: &str) -> Result<[u8; 32], IdentityError> {
        extract_public_key(did_string)
    }

    /// Publishes a DID document to the DHT with the given signing function.
    ///
    /// This is the internal publish implementation used by both
    /// `DidMethod::publish` and the `RepublishManager`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::DhtPublishFailed`] if the DHT publish fails,
    /// or [`IdentityError::DocumentSerializationError`] if the document cannot
    /// be serialized to JSON.
    pub async fn publish_document(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> Result<(), IdentityError> {
        let sign_fn = self.sign_fn.as_ref().ok_or_else(|| {
            IdentityError::DhtPublishFailed(
                "no signing function configured; use DidDht::with_client_and_signer".to_owned(),
            )
        })?;

        // Serialize the document to JSON.
        let doc_json = document
            .to_json()
            .map_err(|e| IdentityError::DocumentSerializationError(e.to_string()))?;
        let value = doc_json.as_bytes();

        // Increment the sequence number.
        let seq = self.sequence.fetch_add(1, Ordering::AcqRel) + 1;

        // Construct the BEP44 signable payload and sign it.
        let signable = Self::bep44_signable(value, seq);
        let sig_bytes = sign_fn(identity.identity_key.id(), signable).await?;

        // Convert signature to [u8; 64].
        let signature: [u8; 64] = sig_bytes.try_into().map_err(|v: Vec<u8>| {
            IdentityError::DhtPublishFailed(format!(
                "expected 64-byte signature, got {} bytes",
                v.len()
            ))
        })?;

        // Extract the public key from the DID.
        let public_key = Self::extract_public_key(&identity.did)?;

        // Publish to DHT.
        self.dht_client
            .publish(&public_key, &signature, value, seq)
            .await?;

        // Persist the sequence number after successful publish (issue #327).
        if let Some(store) = &self.sequence_store {
            store.store(&identity.did, seq).await?;
        }

        Ok(())
    }

    /// Publishes a DID document to the DHT with optional relay URLs.
    ///
    /// When `relay_urls` is non-empty, `SCPRelay` service entries are added to
    /// the document before signing and publishing. The BEP44 signature covers
    /// the complete document including relay entries (existing §9.6.3 property).
    ///
    /// This is used during identity creation when the caller knows their relay
    /// URLs upfront (§18.5 bootstrap flow).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidRelayUrl`] if any URL fails validation.
    /// Returns [`IdentityError::DhtPublishFailed`] if the DHT publish fails.
    pub async fn publish_with_relay_urls(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        relay_urls: &[&str],
    ) -> Result<DidDocument, IdentityError> {
        let mut doc = document.clone();
        doc.set_relay_services(relay_urls)?;
        self.publish_document(identity, &doc).await?;
        Ok(doc)
    }

    /// Updates the relay URL list for an already-published identity.
    ///
    /// Replaces all existing `SCPRelay` service entries in the document with the
    /// provided URLs, then publishes the updated document with an incremented
    /// BEP44 sequence number (§9.6.3 monotonicity). The BEP44 signature covers
    /// the complete updated document.
    ///
    /// Callers SHOULD use this method instead of manually modifying the document
    /// and calling `publish_document`, because this method ensures the relay
    /// entries are validated and the sequence number is incremented atomically.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidRelayUrl`] if any URL fails validation.
    /// Returns [`IdentityError::DhtPublishFailed`] if the DHT publish fails.
    pub async fn update_relay_urls(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        relay_urls: &[&str],
    ) -> Result<DidDocument, IdentityError> {
        let mut doc = document.clone();
        doc.set_relay_services(relay_urls)?;
        self.publish_document(identity, &doc).await?;
        Ok(doc)
    }

    /// Resolves a DID document from the DHT with cache and staleness detection.
    ///
    /// # Resolution Steps
    ///
    /// 1. Check the cache. If a fresh entry exists, return it.
    /// 2. Query the DHT for the BEP44 record.
    /// 3. Verify the BEP44 signature.
    /// 4. Deserialize the DID document.
    /// 5. Verify self-certification (z-base-32 decoded DID suffix matches
    ///    the identity key in the document).
    /// 6. Update the cache.
    ///
    /// # Errors
    ///
    /// Returns errors for DHT lookup failures, signature verification failures,
    /// deserialization failures, and self-certification failures.
    pub async fn resolve_did(
        &self,
        did_string: &str,
    ) -> Result<DidResolutionResult, IdentityError> {
        // Step 1: Check cache.
        if let Some(cached) = self.cache.get(did_string).await {
            // If the cache entry is stale, log a warning but still return it.
            // The caller can decide whether to attempt a fresh resolution.
            return Ok(cached);
        }

        // Step 2: Extract public key and query DHT.
        let public_key = Self::extract_public_key(did_string)?;

        let record = self
            .dht_client
            .resolve(&public_key)
            .await?
            .ok_or_else(|| IdentityError::DhtNotFound(did_string.to_owned()))?;

        // Step 3: Verify BEP44 signature.
        Self::verify_bep44_signature(&public_key, &record.signature, &record.value, record.seq)?;

        // Step 4: Deserialize the DID document.
        let doc_json = String::from_utf8(record.value).map_err(|e| {
            IdentityError::DocumentDeserializationError(format!("invalid UTF-8: {e}"))
        })?;
        let document = DidDocument::from_json(&doc_json)
            .map_err(|e| IdentityError::DocumentDeserializationError(e.to_string()))?;

        // Step 5: Verify self-certification.
        // The identity key (#0) in the document must match the public key
        // derived from the DID string.
        verify_self_certification(did_string, &document)?;

        // Step 6: Post-resolve hook (TOFU key tracking, spec §9.11).
        // Errors are logged but do not prevent resolution from succeeding.
        if let Some(hook) = &self.post_resolve_hook
            && let Err(e) = hook.on_resolve(did_string, &document).await
        {
            tracing::warn!(
                did = %did_string,
                error = %e,
                "post-resolve hook failed (TOFU key tracking may be unavailable)"
            );
        }

        // Step 7: Update cache.
        self.cache
            .insert(did_string, document.clone(), record.seq)
            .await;

        Ok(DidResolutionResult {
            document,
            staleness: Staleness::Fresh,
            sequence: record.seq,
        })
    }

    /// Rotates the active signing key for an identity (Layer 1).
    ///
    /// Generates a new Ed25519 keypair as the new Active Signing Key, updates
    /// the DID document (moves old active key to `#retired-{sequence}`, installs
    /// new key as `#active`), signs the document with the Identity Key, and
    /// publishes to the DHT.
    ///
    /// **The DID string does NOT change. The Identity Key does NOT change.**
    ///
    /// After rotation, the caller MUST issue MLS Update proposals in all active
    /// contexts and revoke/reissue UCAN tokens signed by the old active key.
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity (will be consumed to produce the
    ///   updated identity).
    /// * `document` - The current DID document (will be mutated in-place).
    /// * `key_custody` - The key custody for generating the new keypair.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Platform`] if key generation fails.
    /// Returns [`IdentityError::DhtPublishFailed`] if DHT publishing fails.
    ///
    /// See ADR-003 acceptance criterion 4a.
    pub async fn rotate_active_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> Result<(ScpIdentity, DidDocument), IdentityError> {
        // Step 1: Generate a new Ed25519 keypair for the new Active Signing Key.
        let new_active_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 2: Get the new key's public key.
        let new_active_public = key_custody
            .public_key(&new_active_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 3: Clone and update the document.
        let mut updated_doc = document.clone();
        let sequence = self.current_sequence().saturating_add(1);
        updated_doc.retire_active_key(new_active_public.as_bytes(), sequence);

        // Step 4: Publish the updated document. The publish_document method
        // signs with the Identity Key via the stored sign_fn.
        self.publish_document(identity, &updated_doc).await?;

        // Step 5: Build the updated identity. DID string and identity key
        // are preserved; only the active signing key changes.
        let updated_identity = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: new_active_key,
            agent_signing_key: identity.agent_signing_key,
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Creates a new identity with an agent signing key (ADR-039).
    ///
    /// Like [`DidMethod::create`] but generates a 4th Ed25519 keypair for the
    /// agent key. The agent key is included in the DID document as the `#agent`
    /// verification method and stored in `ScpIdentity::agent_signing_key`.
    ///
    /// # Arguments
    ///
    /// * `key_custody` - The key custody for generating Identity, Active,
    ///   and Agent keypairs (operational keys).
    /// * `pre_rotation_custody` - Cold-storage custody for the pre-rotation
    ///   key (spec §9.7.4.1 §3 — separate substrate from operational
    ///   custody). See [`DidMethod::create`] for the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Platform`] if operational key generation
    /// fails. Returns [`IdentityError::PreRotation`] if the pre-rotation
    /// key cannot be stored in cold custody.
    ///
    /// See ADR-039 acceptance criterion 4.
    pub async fn create_with_agent_key(
        &self,
        key_custody: &impl KeyCustody,
        pre_rotation_custody: &impl PreRotationCustody,
    ) -> Result<(ScpIdentity, DidDocument, PreRotationKeyHandle), IdentityError> {
        // Step 1: Operational keypairs (#0, #active, #agent).
        let identity_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        let active_signing_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 2: Ephemeral pre-rotation seed from the same RNG stream
        // (ADR-046 byte parity). Order matters: identity → active →
        // pre-rotation, MATCHING the seed-byte windows
        // [0..32]/[32..64]/[64..96] that cross-bridge tests pin. The
        // agent key follows after pre-rotation; no cross-bridge
        // byte-parity contract is currently asserted for the agent
        // slot ([96..128]), so adding a fifth seed-window consumer
        // before the agent slot would not break any existing test.
        let pre_rotation_seed = key_custody
            .generate_ephemeral_ed25519_seed()
            .await
            .map_err(IdentityError::Platform)?;
        let pre_rotation_signing = ed25519_dalek::SigningKey::from_bytes(&pre_rotation_seed);
        let pre_rotation_public_bytes = pre_rotation_signing.verifying_key().to_bytes();
        drop(pre_rotation_signing);

        // Step 3: Agent keypair (the fourth in the seed window).
        let agent_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 4: Get operational public keys.
        let identity_public = key_custody
            .public_key(&identity_key)
            .await
            .map_err(IdentityError::Platform)?;

        let active_public = key_custody
            .public_key(&active_signing_key)
            .await
            .map_err(IdentityError::Platform)?;

        let agent_public = key_custody
            .public_key(&agent_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 5: Derive the DID string.
        let did = format!(
            "{DID_DHT_PREFIX}z{}",
            zbase32::encode(identity_public.as_bytes())
        );

        // Step 6: Compute pre-rotation commitment.
        let mut hasher = Sha256::new();
        hasher.update(pre_rotation_public_bytes);
        let commitment_bytes = hasher.finalize();
        let mut pre_rotation_commitment = [0u8; 32];
        pre_rotation_commitment.copy_from_slice(&commitment_bytes);

        // Step 7: Hand the pre-rotation seed to cold custody. Operational
        // copy drops here (Zeroizing).
        let pre_rotation_handle = pre_rotation_custody
            .store_committed_pre_rotation_key(&pre_rotation_public_bytes, pre_rotation_seed)
            .await
            .map_err(IdentityError::PreRotation)?;

        // Step 8: Build the DID document with agent key.
        let document = DidDocument::new_with_agent_key(
            &did,
            identity_public.as_bytes(),
            active_public.as_bytes(),
            &pre_rotation_commitment,
            Some(agent_public.as_bytes()),
        );

        // Step 9: Return the identity, document, and pre-rotation handle.
        let identity = ScpIdentity {
            identity_key,
            active_signing_key,
            agent_signing_key: Some(agent_key),
            pre_rotation_commitment,
            did,
        };

        Ok((identity, document, pre_rotation_handle))
    }

    /// Adds an agent signing key to an existing identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair for the agent key, adds it to the DID
    /// document as the `#agent` verification method, signs the document with
    /// the Identity Key, and publishes to the DHT.
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity (must not already have an agent key).
    /// * `document` - The current DID document.
    /// * `key_custody` - The key custody for generating the agent keypair.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::AgentKeyAlreadyExists`] if `#agent` already exists.
    /// Returns [`IdentityError::Platform`] if key generation fails.
    /// Returns [`IdentityError::DhtPublishFailed`] if DHT publishing fails.
    ///
    /// See ADR-039 acceptance criterion 4.
    pub async fn add_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> Result<(ScpIdentity, DidDocument), IdentityError> {
        // Step 1: Check if the document already has an agent key.
        // This must happen BEFORE key generation to avoid leaking key material
        // in the custody provider on the error path.
        if document.has_agent_key() {
            return Err(IdentityError::AgentKeyAlreadyExists);
        }

        // Step 2: Generate a new Ed25519 keypair for the agent key.
        let agent_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 3: Get the agent key's public key.
        let agent_public = key_custody
            .public_key(&agent_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 4: Clone and update the document.
        let mut updated_doc = document.clone();
        updated_doc.add_agent_key(agent_public.as_bytes())?;

        // Step 5: Publish the updated document (signed with Identity Key).
        self.publish_document(identity, &updated_doc).await?;

        // Step 6: Build the updated identity.
        let updated_identity = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: identity.active_signing_key,
            agent_signing_key: Some(agent_key),
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Rotates the agent signing key for an identity (ADR-039).
    ///
    /// Generates a new Ed25519 keypair, updates the DID document (moves the old
    /// `#agent` key to `#retired-agent-{sequence}`, installs the new key as
    /// `#agent`), signs the document with the Identity Key, and publishes to
    /// the DHT.
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity (must have an existing agent key).
    /// * `document` - The current DID document.
    /// * `key_custody` - The key custody for generating the new agent keypair.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::AgentKeyNotFound`] if no `#agent` VM exists.
    /// Returns [`IdentityError::Platform`] if key generation fails.
    /// Returns [`IdentityError::DhtPublishFailed`] if DHT publishing fails.
    ///
    /// See ADR-039 acceptance criterion 4.
    pub async fn rotate_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> Result<(ScpIdentity, DidDocument), IdentityError> {
        // Step 0: Verify identity/document consistency — the identity must
        // track an agent key before we attempt rotation.
        if identity.agent_signing_key.is_none() {
            return Err(IdentityError::AgentKeyNotFound);
        }

        // Step 1: Generate a new Ed25519 keypair.
        let new_agent_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 2: Get the new key's public key.
        let new_agent_public = key_custody
            .public_key(&new_agent_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 3: Clone and update the document.
        let mut updated_doc = document.clone();
        let sequence = self.current_sequence().saturating_add(1);
        updated_doc.rotate_agent_key(new_agent_public.as_bytes(), sequence)?;

        // Step 4: Publish the updated document (signed with Identity Key).
        self.publish_document(identity, &updated_doc).await?;

        // Step 5: Build the updated identity. DID, identity key, active key,
        // and pre-rotation commitment are preserved.
        let updated_identity = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: identity.active_signing_key,
            agent_signing_key: Some(new_agent_key),
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Removes the agent signing key from an identity (ADR-039).
    ///
    /// Removes the `#agent` verification method from the DID document, signs
    /// the document with the Identity Key, and publishes to the DHT.
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity (must have an existing agent key).
    /// * `document` - The current DID document.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::AgentKeyNotFound`] if no `#agent` VM exists.
    /// Returns [`IdentityError::DhtPublishFailed`] if DHT publishing fails.
    ///
    /// See ADR-039 acceptance criterion 4.
    pub async fn remove_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> Result<(ScpIdentity, DidDocument), IdentityError> {
        // Step 0: Verify identity/document consistency — the identity must
        // track an agent key before we attempt removal.
        if identity.agent_signing_key.is_none() {
            return Err(IdentityError::AgentKeyNotFound);
        }

        // Step 1: Clone and update the document.
        let mut updated_doc = document.clone();
        updated_doc.remove_agent_key()?;

        // Step 2: Publish the updated document (signed with Identity Key).
        self.publish_document(identity, &updated_doc).await?;

        // Step 3: Build the updated identity with agent_signing_key: None.
        let updated_identity = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: identity.active_signing_key,
            agent_signing_key: None,
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        Ok((updated_identity, updated_doc))
    }

    /// Attaches a device attestation token to a DID document.
    ///
    /// Calls `DeviceAttestation::attest()` to generate a platform-specific
    /// attestation token, then stores it as an `ScpDeviceAttestation` service
    /// entry in the DID document (§9.3). The token is base64-encoded in the
    /// `serviceEndpoint` field. The service entry uses the ID format
    /// `{did}#device-attestation`.
    ///
    /// Device attestation is a Sybil resistance signal -- the protocol carries
    /// the proof but does not prescribe interpretation. Contexts MAY require
    /// device attestation for admission via `ContextParams`.
    ///
    /// When `DeviceAttestation` is not available (e.g., desktop platforms
    /// without hardware attestation), callers should skip this method. The
    /// absence of an `ScpDeviceAttestation` service entry is a valid state.
    ///
    /// # Arguments
    ///
    /// * `document` - The DID document to attach the attestation to.
    /// * `attestation` - A platform `DeviceAttestation` implementation.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Platform`] if the attestation service is
    /// unavailable or attestation generation fails.
    ///
    /// See §9.3, issue #362, BLACK-006.
    pub async fn attach_device_attestation(
        &self,
        document: &DidDocument,
        attestation: &impl scp_platform::traits::DeviceAttestation,
    ) -> Result<DidDocument, IdentityError> {
        let token = attestation
            .attest()
            .await
            .map_err(IdentityError::Platform)?;

        let mut updated_doc = document.clone();
        updated_doc.set_device_attestation_token(token.as_bytes());
        Ok(updated_doc)
    }

    /// Migrates an identity to a new DID (Layer 2).
    ///
    /// Creates a new DID using the pre-rotation key as the new Identity Key.
    /// Generates a new Active Signing Key and pre-rotation commitment for the
    /// new DID. Updates the old DID document with an `alsoKnownAs` pointing to
    /// the new DID and cryptographic linkage. Publishes both documents.
    ///
    /// **The DID string changes. All per-context references must be migrated
    /// via the returned [`DidRotationEvent`].**
    ///
    /// # Arguments
    ///
    /// * `identity` - The current identity being migrated.
    /// * `old_document` - The current DID document for the old identity.
    /// * `pre_rotation_handle` - Handle returned by [`PreRotationCustody::store_committed_pre_rotation_key`]
    ///   when the identity was created. Resolved against `pre_rotation_custody`
    ///   to recover the public bytes (for `revealed_key`) and consume the
    ///   private bytes (which become the new identity key, ADR-003 §4b).
    /// * `pre_rotation_custody` - The cold-storage custody holding the
    ///   pre-rotation key. Per spec §9.7.4.1 §6, the protocol immediately
    ///   stores a fresh pre-rotation key in this custody before returning.
    /// * `key_custody` - The operational custody for the new identity. The
    ///   migrated `#0` (the old pre-rotation key's private bytes) is
    ///   imported here; the new `#active` is generated here.
    /// * `rotated_at` - Unix timestamp for the migration event.
    ///
    /// # Returns
    ///
    /// A [`MigrationOutcome`] carrying:
    /// - `new_identity` — The new [`ScpIdentity`] with new DID and keys.
    /// - `new_document` — The DID document for the new identity.
    /// - `rotation_event` — The [`DidRotationEvent`] to distribute to all
    ///   active contexts (ADR-003 §4b).
    /// - `new_pre_rotation_handle` — Handle for the freshly-minted
    ///   pre-rotation key in `pre_rotation_custody` (per spec §9.7.4.1
    ///   item 6 "post-rotation key cycling"). Caller persists this for
    ///   the next migration.
    ///
    /// # Errors
    ///
    /// Returns errors if key generation, signing, or DHT publishing fails.
    ///
    /// See ADR-003 acceptance criterion 4b and spec §9.7.4.1 item 6, and
    /// [`Self::resume_migration_publish`] for the recovery path when one
    /// of the DHT publishes (step 7 or step 8) fails after the
    /// cold-custody consumption point.
    pub async fn migrate_identity(
        &self,
        identity: &ScpIdentity,
        old_document: &DidDocument,
        pre_rotation_handle: &PreRotationKeyHandle,
        pre_rotation_custody: &impl PreRotationCustody,
        key_custody: &impl KeyCustody,
        rotated_at: u64,
    ) -> Result<MigrationOutcome, IdentityError> {
        // Step 0: Pre-flight `import_ed25519_signing_key` capability on
        // the operational custody. Step 6 below imports the OLD
        // pre-rotation private bytes (returned by step 5's
        // `destroy_after_migration`) into operational custody as the
        // new `#0`. If `import_ed25519_signing_key` is unsupported on
        // this backend (e.g., HSM-bound `CallbackKeyCustody` today),
        // step 6 would fail BEFORE any DHT publish (steps 7 and 8) —
        // but only AFTER step 5 has already consumed the OLD
        // pre-rotation entry. Once consumed, the only key whose hash
        // satisfies `SHA-256(revealed_key) == commitment` is gone, so
        // the user cannot retry `migrate_identity`. The probe here
        // converts that pre-publish-yet-already-corrupting failure
        // into a clean fail-fast BEFORE any registry or cold-custody
        // mutation, leaving the source identity wholly intact.
        //
        // Probe seed is drawn from the OS CSPRNG, never a fixed pattern.
        // Content-addressed custody backends (e.g. `FileKeyCustody`'s
        // SHA-256-of-seed dedup) treat `import_ed25519_signing_key`
        // calls with identical seed bytes as references to the same
        // underlying entry. A fixed probe seed would alias any
        // pre-existing entry whose private bytes happen to match —
        // and the trailing `destroy_key` would then delete the user's
        // real key. CSPRNG-sourced bytes have negligible birthday
        // probability of colliding with any prior entry.
        let mut probe_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut probe_bytes);
        let probe_seed = zeroize::Zeroizing::new(probe_bytes);
        let probe_handle = key_custody
            .import_ed25519_signing_key(&probe_seed)
            .await
            .map_err(IdentityError::Platform)?;
        key_custody
            .destroy_key(&probe_handle)
            .await
            .map_err(IdentityError::Platform)?;

        // Step 1: Reveal the pre-rotation public key. This will become the
        // new identity public key (ADR-003 §4b). The custody verifies its
        // own commitment integrity if it stored one.
        let new_identity_public_bytes = pre_rotation_custody
            .reveal_public_key(pre_rotation_handle)
            .await
            .map_err(IdentityError::PreRotation)?;

        let new_did = format!(
            "{DID_DHT_PREFIX}z{}",
            zbase32::encode(&new_identity_public_bytes)
        );

        // Step 2: Build the migration_proof signed by the OLD identity key
        // and the pre_rotation_proof carrying the revealed public key.
        let migration_proof =
            Self::build_migration_proof(identity, &new_did, rotated_at, key_custody).await?;
        let pre_rotation_proof =
            Self::build_pre_rotation_proof_from_bytes(old_document, &new_identity_public_bytes)?;

        // Step 3: Generate the NEW pre-rotation seed using the operational
        // custody's RNG (ADR-046 byte parity). The new active key follows.
        // All mutations through step 6 are LOCAL — no externally-visible
        // state changes until the new DID document is published in
        // step 7. Publishing the OLD doc with `alsoKnownAs` is deferred
        // to step 8 (chain-forward order) so a failure in steps 4-7
        // leaves the OLD identity wholly intact and recoverable.
        //
        // Note: steps 3-4 allocate fresh `new_active_key` and
        // `new_pre_rotation_handle` BEFORE step 5's irreversible
        // `destroy_after_migration` runs. If steps 5-8 fail after
        // these allocations, the freshly-allocated handles remain in
        // operational and pre-rotation custody as orphaned entries
        // (storage leak with no security impact: the keys are fresh,
        // never published, and never bound to any DID). Storage cost
        // is bounded — a small, fixed-size set of unreferenced
        // entries per failed migration attempt — and recovery in
        // pathological cases is a user-driven custody wipe. A future
        // enhancement (Drop-with-rollback wrapper, or moving the
        // fallible publishes ahead of cold-custody allocations) would
        // close this gap without changing any externally-visible
        // semantic; deliberately deferred to keep this change
        // doc-only.
        let new_pre_rotation_seed = key_custody
            .generate_ephemeral_ed25519_seed()
            .await
            .map_err(IdentityError::Platform)?;
        let new_pre_rotation_signing =
            ed25519_dalek::SigningKey::from_bytes(&new_pre_rotation_seed);
        let new_pre_rotation_public_bytes = new_pre_rotation_signing.verifying_key().to_bytes();
        drop(new_pre_rotation_signing);

        let new_active_key = key_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .map_err(IdentityError::Platform)?;
        let new_active_public = key_custody
            .public_key(&new_active_key)
            .await
            .map_err(IdentityError::Platform)?;

        let mut hasher = Sha256::new();
        hasher.update(new_pre_rotation_public_bytes);
        let new_pre_rotation_commitment_bytes = hasher.finalize();
        let mut new_pre_rotation_commitment = [0u8; 32];
        new_pre_rotation_commitment.copy_from_slice(&new_pre_rotation_commitment_bytes);

        // Step 4: Hand the new pre-rotation seed to cold custody. If this
        // fails, the operational copy zeroizes on drop and we surface the
        // error WITHOUT having consumed the old pre-rotation key.
        let new_pre_rotation_handle = pre_rotation_custody
            .store_committed_pre_rotation_key(&new_pre_rotation_public_bytes, new_pre_rotation_seed)
            .await
            .map_err(IdentityError::PreRotation)?;

        // Step 5: Consume the OLD pre-rotation key from cold custody —
        // returning its private bytes — and import them into operational
        // custody as the new `#0`. Per spec §9.7.4.1 item 6
        // ("post-rotation key cycling"), the old pre-rotation key is
        // destroyed after migration completes; here we destroy-and-export
        // atomically (the trait method's documented contract). This is
        // the irreversible cold-custody mutation referenced as
        // "step 6" in spec §9.7.4.1 "Partial-publish recovery" — the
        // spec uses the §9.7.4.1 item numbering; the code uses its own
        // step sequence (steps 0-8) where this destroy-and-export is
        // code-step-5.
        let revealed_private = pre_rotation_custody
            .destroy_after_migration(*pre_rotation_handle)
            .await
            .map_err(IdentityError::PreRotation)?;

        let new_identity_key = key_custody
            .import_ed25519_signing_key(&revealed_private)
            .await
            .map_err(IdentityError::Platform)?;
        // `revealed_private` is `Zeroizing` — drops here.

        // Step 6: Build the new DID document and identity.
        let new_document = DidDocument::new(
            &new_did,
            &new_identity_public_bytes,
            new_active_public.as_bytes(),
            &new_pre_rotation_commitment,
        );

        let new_identity = ScpIdentity {
            identity_key: new_identity_key,
            active_signing_key: new_active_key,
            agent_signing_key: None,
            pre_rotation_commitment: new_pre_rotation_commitment,
            did: new_did.clone(),
        };

        // Hoisted step 9: build `rotation_event` BEFORE step 7 so a
        // partial-publish failure carries it back verbatim (spec
        // §9.7.4.1 byte parity invariant).
        let rotation_event = DidRotationEvent {
            old_did: identity.did.clone(),
            new_did: new_did.clone(),
            migration_proof,
            pre_rotation_proof,
            rotated_at,
        };

        // Steps 7 + 7b + 8: run the publish chain. On failure, the helper
        // wraps the partial state in `MigrationPublishFailed` so the
        // caller can finish via `resume_migration_publish`. A retry of
        // `migrate_identity` is impossible at this point — step 5
        // already consumed the OLD pre-rotation handle.
        self.run_migration_publish_chain(
            MigrationPartialState {
                phase: MigrationResumePhase::PublishNew,
                new_identity,
                new_document,
                rotation_event,
                new_pre_rotation_handle,
                old_identity: identity.clone(),
                old_document: old_document.clone(),
            },
            key_custody,
        )
        .await
    }

    /// Runs the publish chain (step 7 → step 7b → step 8) for a fresh or
    /// resumed migration. The supplied `state.phase` controls where the
    /// chain enters:
    ///
    /// - [`MigrationResumePhase::PublishNew`] — runs all three steps.
    /// - [`MigrationResumePhase::RepublishOldAlsoKnownAs`] — runs only
    ///   step 8 (step 7 already succeeded, step 7b already ran during
    ///   the original `migrate_identity` call).
    ///
    /// On success: returns the artifacts the caller would otherwise have
    /// received from a first-pass `migrate_identity`. On failure: returns
    /// [`IdentityError::MigrationPublishFailed`] with a
    /// [`MigrationPartialState`] reflecting the current phase the caller
    /// must resume from.
    async fn run_migration_publish_chain(
        &self,
        state: MigrationPartialState,
        key_custody: &impl KeyCustody,
    ) -> Result<MigrationOutcome, IdentityError> {
        let MigrationPartialState {
            phase,
            new_identity,
            new_document,
            rotation_event,
            new_pre_rotation_handle,
            old_identity,
            old_document,
        } = state;

        if phase == MigrationResumePhase::PublishNew {
            // Step 7: publish the NEW DID document FIRST so verifiers
            // following `alsoKnownAs[new_did]` always find a published
            // successor.
            if let Err(source) = self.publish_document(&new_identity, &new_document).await {
                return Err(IdentityError::MigrationPublishFailed {
                    phase: MigrationResumePhase::PublishNew,
                    partial: Box::new(MigrationPartialState {
                        phase: MigrationResumePhase::PublishNew,
                        new_identity,
                        new_document,
                        rotation_event,
                        new_pre_rotation_handle,
                        old_identity,
                        old_document,
                    }),
                    source: Box::new(source),
                });
            }

            // Step 7b (spec §9.12, "compromise recovery"): destroy the
            // OLD `#active` and (when present) `#agent` operational keys.
            // `destroy_old_operational_keys` is idempotent — re-invoking
            // after a `RepublishOldAlsoKnownAs`-phase resume is safe
            // (per-key `KeyNotFound` failures are swallowed as
            // `tracing::warn!`).
            destroy_old_operational_keys(key_custody, &old_identity).await;
        }

        // Step 8: republish OLD with `alsoKnownAs` + retire OLD operational
        // VMs (spec §9.12). On failure, surface a partial state at the
        // step-8-only phase — the caller's next resume runs only step 8.
        if let Err(source) = self
            .publish_old_doc_with_also_known_as(&old_identity, &old_document, &new_identity.did)
            .await
        {
            return Err(IdentityError::MigrationPublishFailed {
                phase: MigrationResumePhase::RepublishOldAlsoKnownAs,
                partial: Box::new(MigrationPartialState {
                    phase: MigrationResumePhase::RepublishOldAlsoKnownAs,
                    new_identity,
                    new_document,
                    rotation_event,
                    new_pre_rotation_handle,
                    old_identity,
                    old_document,
                }),
                source: Box::new(source),
            });
        }

        Ok(MigrationOutcome {
            new_identity,
            new_document,
            rotation_event,
            new_pre_rotation_handle,
        })
    }

    /// Step-8 helper shared by [`Self::migrate_identity`] and
    /// [`Self::resume_migration_publish`]: clone the OLD document, set
    /// `alsoKnownAs` to `new_did`, retire its operational verification
    /// methods (spec §9.12), and publish under the OLD `#0`.
    ///
    /// On failure: surfaces the underlying `publish_document` error so
    /// the caller can wrap it in
    /// [`IdentityError::MigrationPublishFailed`] with the correct
    /// `MigrationPartialState`. This helper does NOT wrap on its own —
    /// `migrate_identity` and `resume_migration_publish` own the partial
    /// state they want to surface.
    async fn publish_old_doc_with_also_known_as(
        &self,
        old_identity: &ScpIdentity,
        old_document: &DidDocument,
        new_did: &str,
    ) -> Result<(), IdentityError> {
        let mut updated_old_doc = old_document.clone();
        updated_old_doc.set_also_known_as(new_did);
        updated_old_doc.retire_operational_keys_for_migration();
        self.publish_document(old_identity, &updated_old_doc).await
    }

    /// Finish a [`Self::migrate_identity`] call that returned
    /// [`IdentityError::MigrationPublishFailed`].
    ///
    /// `migrate_identity` performs two DHT publishes (step 7 publishes the
    /// NEW DID document; step 8 republishes the OLD document with
    /// `alsoKnownAs`). Both publishes happen AFTER the irreversible
    /// cold-custody consumption point (step 5
    /// `destroy_after_migration`). When either publish fails, the caller
    /// cannot recover by re-invoking `migrate_identity`: the OLD
    /// pre-rotation handle is gone, the OLD `#active` is destroyed (if
    /// step 7 succeeded but step 8 failed), and the NEW operational
    /// keys are already minted. This function picks up exactly where
    /// `migrate_identity` left off using the carried
    /// [`MigrationPartialState`].
    ///
    /// # Behavior by phase
    ///
    /// - [`MigrationResumePhase::PublishNew`] — re-runs step 7 (publish
    ///   NEW), step 7b (destroy OLD `#active`/`#agent`), and step 8
    ///   (publish OLD with `alsoKnownAs`). If step 7 succeeds but step 8
    ///   fails, returns `MigrationPublishFailed { phase:
    ///   RepublishOldAlsoKnownAs, .. }` so the caller can resume from
    ///   the step-8-only checkpoint without re-running step 7b.
    /// - [`MigrationResumePhase::RepublishOldAlsoKnownAs`] — re-runs
    ///   only step 8. Step 7b is NOT re-run (it already ran during the
    ///   original `migrate_identity` call) — `destroy_key` is idempotent
    ///   in practice (subsequent calls surface `KeyNotFound` and are
    ///   logged as `warn!`), so re-running would be safe but is
    ///   skipped to keep the resume path minimal.
    ///
    /// # Idempotency
    ///
    /// BEP44 publishes use a monotonically increasing sequence number
    /// (see `publish_document`'s use of [`AtomicU64::fetch_add`]), so
    /// republishing byte-identical documents under fresh sequences is
    /// safe: peers accept the higher-`seq` record and the document
    /// value is unchanged. Calling `resume_migration_publish` more than
    /// once with the same state is therefore safe.
    ///
    /// # Byte parity (spec §9.7.4.1)
    ///
    /// The returned [`MigrationOutcome`] is byte-identical to what a
    /// successful first-pass `migrate_identity` would have returned —
    /// it is moved out of the supplied `MigrationPartialState` verbatim.
    /// In particular,
    /// `SHA-256(rotation_event.pre_rotation_proof.revealed_key) ==
    /// new_document.pre_rotation_service().commitment` holds without
    /// re-derivation: the proof was signed at step 2 (under the OLD
    /// `#0`, which is still in operational custody for step 8) and
    /// carried verbatim.
    ///
    /// # OLD `#0` retention
    ///
    /// Step 7b destroys OLD `#active` and `#agent` but intentionally
    /// retains OLD `#0`. Step 8 needs `#0` to sign the BEP44 publish.
    /// `key_custody` is the parameter that holds it — pass the SAME
    /// custody instance that was passed to the original `migrate_identity`
    /// call. Resume performs a pre-flight probe against the supplied
    /// custody (`public_key(&old_identity.identity_key)` plus
    /// `public_key(&new_identity.identity_key)`) so a mismatched substrate
    /// fails fast with [`IdentityError::Platform`] before any DHT publish
    /// runs — the diagnostic is then "your key handles don't match this
    /// custody" rather than the more opaque "publish failed at signing
    /// step."
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Platform`] if the supplied `key_custody`
    /// does not resolve either the OLD `#0` or the NEW `#0` handle
    /// (pre-flight substrate mismatch — see preceding paragraph).
    /// Returns [`IdentityError::MigrationPublishFailed`] if any publish
    /// in the resume path fails. The returned partial state may carry
    /// a different `phase` than the input — e.g. a `PublishNew`
    /// resume that succeeds step 7 but fails step 8 returns a
    /// `RepublishOldAlsoKnownAs` partial state.
    pub async fn resume_migration_publish(
        &self,
        state: MigrationPartialState,
        key_custody: &impl KeyCustody,
    ) -> Result<MigrationOutcome, IdentityError> {
        // Pre-flight custody substrate check. `resume_migration_publish`
        // re-uses the original `migrate_identity`'s key handles — handles
        // are numeric ids into a specific custody substrate (file
        // directory / keychain group / in-memory map). If the caller
        // serialized the partial state and reloaded it against a
        // *different* substrate, every later sign / public_key call
        // would surface `PlatformError::KeyNotFound` from inside the
        // publish chain — buried under a `MigrationPublishFailed`
        // wrapper whose source chain reads "publish failed at signing
        // step." The probe here surfaces the substrate mismatch as a
        // clean `IdentityError::Platform(KeyNotFound)` BEFORE any DHT
        // publish runs, so the SDK / operator gets the precise
        // diagnostic. Probes BOTH OLD `#0` (needed by step 8 to sign
        // the OLD-document republish) and NEW `#0` (needed by step 7's
        // BEP44 signature on the NEW document); we deliberately do
        // NOT probe OLD `#active` because the resume of a step-8
        // failure runs AFTER step 7b destroyed it — `KeyNotFound` for
        // OLD `#active` is the expected state, not an error.
        key_custody
            .public_key(&state.old_identity.identity_key)
            .await
            .map_err(IdentityError::Platform)?;
        key_custody
            .public_key(&state.new_identity.identity_key)
            .await
            .map_err(IdentityError::Platform)?;

        // Defer to the shared publish chain. `state.phase` selects the
        // entry point: `PublishNew` re-runs steps 7 + 7b + 8;
        // `RepublishOldAlsoKnownAs` runs only step 8.
        self.run_migration_publish_chain(state, key_custody).await
    }

    /// Builds a migration proof by signing
    /// `SHA-256(DOMAIN_MIGRATION_V1 || u32_be(len(old_did)) || old_did ||
    /// u32_be(len(new_did)) || new_did || u64_be(rotated_at))` with the old
    /// Identity Key. Length prefixes (u32 big-endian for the DID strings
    /// and the implicit u64 big-endian width of `rotated_at`) prevent
    /// concatenation ambiguity between variable-length DID strings.
    ///
    /// Note on digest scope: the signed digest covers
    /// `(DOMAIN_MIGRATION_V1, old_did, new_did, rotated_at)` only — it
    /// does NOT include the `(commitment, revealed_key)` pair carried in
    /// `pre_rotation_proof`. Layered verification provides equivalent
    /// binding for the current proof shape: `verify_migration` Step 2b
    /// binds `commitment` to the old document's `PreRotationCommitment`
    /// service entry (which itself is BEP44-signed under the old `#0`),
    /// and Step 2c binds `revealed_key` to `new_did` via self-cert
    /// derivation. Any future field added to `PreRotationProof` — for
    /// example an attestation timestamp or a substrate identifier —
    /// would NOT be automatically covered by the migration signature
    /// and MUST be wired into either the digest input or a dedicated
    /// `verify_migration` invariant.
    async fn build_migration_proof(
        identity: &ScpIdentity,
        new_did: &str,
        rotated_at: u64,
        key_custody: &impl KeyCustody,
    ) -> Result<MigrationProof, IdentityError> {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_MIGRATION_V1);
        let old_len = u32::try_from(identity.did.len()).map_err(|_| {
            IdentityError::InvalidDidFormat("DID too long for length prefix".into())
        })?;
        let new_len = u32::try_from(new_did.len()).map_err(|_| {
            IdentityError::InvalidDidFormat("DID too long for length prefix".into())
        })?;
        hasher.update(old_len.to_be_bytes());
        hasher.update(identity.did.as_bytes());
        hasher.update(new_len.to_be_bytes());
        hasher.update(new_did.as_bytes());
        hasher.update(rotated_at.to_be_bytes());
        let digest = hasher.finalize();

        let proof_sig = key_custody
            .sign(&identity.identity_key, &digest)
            .await
            .map_err(IdentityError::Platform)?;

        let old_identity_public = key_custody
            .public_key(&identity.identity_key)
            .await
            .map_err(IdentityError::Platform)?;

        let sig_bytes: [u8; 64] = proof_sig.into_bytes().try_into().map_err(|v: Vec<u8>| {
            IdentityError::KeyRotationFailed(format!(
                "expected 64-byte signature, got {} bytes",
                v.len()
            ))
        })?;

        let old_pub_bytes: [u8; 32] =
            old_identity_public
                .into_bytes()
                .try_into()
                .map_err(|v: Vec<u8>| {
                    IdentityError::KeyRotationFailed(format!(
                        "expected 32-byte public key, got {} bytes",
                        v.len()
                    ))
                })?;

        Ok(MigrationProof {
            signature: sig_bytes,
            old_public_key: old_pub_bytes,
        })
    }

    /// Builds a pre-rotation proof from the old document's
    /// `PreRotationCommitment` service, if present, against the revealed
    /// new identity public key (32 bytes).
    fn build_pre_rotation_proof_from_bytes(
        old_document: &DidDocument,
        new_identity_public_bytes: &[u8; 32],
    ) -> Result<Option<PreRotationProof>, IdentityError> {
        let Some(svc) = old_document.pre_rotation_service() else {
            return Ok(None);
        };
        let Some(hex_str) = svc.service_endpoint.strip_prefix("sha256:") else {
            return Ok(None);
        };

        let commitment_vec = hex::decode(hex_str).map_err(|e| {
            IdentityError::KeyRotationFailed(format!(
                "failed to decode pre-rotation commitment: {e}"
            ))
        })?;
        let commitment: [u8; 32] = commitment_vec.try_into().map_err(|v: Vec<u8>| {
            IdentityError::KeyRotationFailed(format!(
                "pre-rotation commitment must be 32 bytes, got {}",
                v.len()
            ))
        })?;

        Ok(Some(PreRotationProof {
            commitment,
            revealed_key: *new_identity_public_bytes,
        }))
    }
}

/// Verifies that the identity key in a DID document matches the DID string's
/// z-base-32 encoded public key (self-certification check).
///
/// This is the single, consolidated implementation used by:
/// - `DidDht::resolve_did` (DHT resolution path)
/// - `verify_and_deserialize` in `resolver.rs` (dual-layer resolution path)
/// - `relay_resolve` in `resolution.rs` (relay resolution path)
///
/// # Errors
///
/// Returns [`IdentityError::SelfCertificationFailed`] if the document's identity
/// key (`#0` verification method) does not match the public key encoded in the
/// DID string.
pub fn verify_self_certification(
    did_string: &str,
    document: &DidDocument,
) -> Result<(), IdentityError> {
    let public_key = extract_public_key(did_string)?;

    // Find the #0 verification method (identity key).
    let vm0 = document
        .verification_method_by_fragment("0")
        .ok_or_else(|| {
            IdentityError::SelfCertificationFailed(
                "no #0 verification method in document".to_owned(),
            )
        })?;

    // Decode the multibase public key from the document.
    let doc_key_bytes = decode_multibase_key(&vm0.public_key_multibase)?;

    if doc_key_bytes != public_key {
        return Err(IdentityError::SelfCertificationFailed(format!(
            "identity key in document does not match DID suffix for {did_string}"
        )));
    }

    Ok(())
}

/// Decodes a multibase-encoded public key (z-prefix = base58btc).
///
/// Beyond the encoding check, the decoded 32-byte payload is validated
/// as an Ed25519 Edwards-curve point via
/// `ed25519_dalek::VerifyingKey::from_bytes`. This rejects non-curve
/// payloads only (ZIP-215 rules) — low-order / small-subgroup points
/// are NOT rejected here; they are caught at signature verification
/// time via `verify_strict`. Matches the WASM bridge's `from_did`
/// curve-point gate so both decoding entry points behave consistently.
///
/// # Errors
///
/// Returns [`IdentityError::InvalidDidFormat`] if the key is not properly
/// base58btc encoded, not exactly 32 bytes, or does not decompress to a
/// valid Ed25519 Edwards-curve point.
pub fn decode_multibase_key(encoded: &str) -> Result<[u8; 32], IdentityError> {
    let b58_str = encoded.strip_prefix('z').ok_or_else(|| {
        IdentityError::InvalidDidFormat("multibase key must start with 'z' (base58btc)".to_owned())
    })?;

    let decoded = base58btc_decode(b58_str)
        .map_err(|e| IdentityError::InvalidDidFormat(format!("base58btc decode failed: {e}")))?;

    let decoded_array: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
        IdentityError::InvalidDidFormat(format!("expected 32-byte key, got {} bytes", v.len()))
    })?;

    // Curve-point validation: `ed25519_dalek::VerifyingKey::from_bytes`
    // rejects byte strings that don't decompress to an Edwards-curve
    // point (ZIP-215 rules). Low-order / small-subgroup points are NOT
    // rejected here — they are caught at signature verification time
    // via `verify_strict`. Matches the WASM `from_did_inner` gate so
    // both decoding entry points reject non-curve payloads early.
    ed25519_dalek::VerifyingKey::from_bytes(&decoded_array).map_err(|e| {
        IdentityError::InvalidDidFormat(format!(
            "multibase key payload is not a valid Ed25519 public key: {e}"
        ))
    })?;

    Ok(decoded_array)
}

/// Base58btc decoding (Bitcoin alphabet) via the `bs58` crate.
///
/// Inverse of the `base58btc_encode` function in `document.rs`.
fn base58btc_decode(input: &str) -> Result<Vec<u8>, String> {
    bs58::decode(input)
        .into_vec()
        .map_err(|e| format!("base58btc decode error: {e}"))
}

// The trait uses RPITIT (`-> impl Future<...> + Send`), so each impl method
// must return a future rather than use `async fn` directly.
#[allow(clippy::manual_async_fn)]
impl<D: DhtClient + 'static, C: Clock + 'static> DidMethod for DidDht<D, C> {
    fn create(
        &self,
        key_custody: &impl KeyCustody,
        pre_rotation_custody: &impl PreRotationCustody,
    ) -> impl Future<
        Output = Result<(ScpIdentity, DidDocument, PreRotationKeyHandle), IdentityError>,
    > + Send {
        async move {
            // Step 1: Generate the operational keypairs in `key_custody`
            // (Identity Key #0, Active Signing Key #active).
            let identity_key = key_custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .map_err(IdentityError::Platform)?;

            let active_signing_key = key_custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .map_err(IdentityError::Platform)?;

            // Step 2: Mint an ephemeral pre-rotation seed using the SAME
            // RNG stream as the operational keypairs. This preserves the
            // ADR-046 cross-bridge byte-parity invariant (seed[0..32] →
            // identity, seed[32..64] → active, seed[64..96] → pre-rotation)
            // while ensuring the private bytes never sit in operational
            // custody (spec §9.7.4.1 §1, §5(a)). For HSM-backed custody
            // that cannot export ephemeral seed bytes, callers must
            // surface the pre-rotation key through a platform-CSPRNG
            // path and route it directly into `pre_rotation_custody`.
            let pre_rotation_seed = key_custody
                .generate_ephemeral_ed25519_seed()
                .await
                .map_err(IdentityError::Platform)?;
            let pre_rotation_signing = ed25519_dalek::SigningKey::from_bytes(&pre_rotation_seed);
            let pre_rotation_public_bytes = pre_rotation_signing.verifying_key().to_bytes();

            // Step 3: Get operational public keys.
            let identity_public = key_custody
                .public_key(&identity_key)
                .await
                .map_err(IdentityError::Platform)?;

            let active_public = key_custody
                .public_key(&active_signing_key)
                .await
                .map_err(IdentityError::Platform)?;

            // Step 4: Derive the DID string: did:dht:z<z-base-32(identity_public_key)>
            let did = format!(
                "{DID_DHT_PREFIX}z{}",
                zbase32::encode(identity_public.as_bytes())
            );

            // Step 5: Compute pre-rotation commitment: SHA-256(pre_rotation_public)
            let mut hasher = Sha256::new();
            hasher.update(pre_rotation_public_bytes);
            let commitment_bytes = hasher.finalize();
            let mut pre_rotation_commitment = [0u8; 32];
            pre_rotation_commitment.copy_from_slice(&commitment_bytes);

            // Step 6: Hand the pre-rotation private bytes to cold custody
            // (spec §9.7.4.1 §3 — separate substrate). The operational
            // copy is ephemeral: `pre_rotation_seed` is a `Zeroizing<[u8;
            // 32]>` and drops here.
            let pre_rotation_handle = pre_rotation_custody
                .store_committed_pre_rotation_key(&pre_rotation_public_bytes, pre_rotation_seed)
                .await
                .map_err(IdentityError::PreRotation)?;
            // The intermediate SigningKey carries its own copy of the
            // private bytes; drop it explicitly so it zeroizes before the
            // function returns.
            drop(pre_rotation_signing);

            // Step 7: Build the DID document. Verifiers see only the
            // commitment hash; the public key is never published until
            // migration, when `revealed_key` is filled by
            // `pre_rotation_custody.reveal_public_key`.
            let document = DidDocument::new(
                &did,
                identity_public.as_bytes(),
                active_public.as_bytes(),
                &pre_rotation_commitment,
            );

            // Step 8: Return the identity, document, and pre-rotation
            // handle. Callers persist all three so that `migrate_identity`
            // can present the handle back to the same `pre_rotation_custody`.
            let identity = ScpIdentity {
                identity_key,
                active_signing_key,
                agent_signing_key: None,
                pre_rotation_commitment,
                did,
            };

            Ok((identity, document, pre_rotation_handle))
        }
    }

    fn verify(&self, did_string: &str, public_key: &[u8]) -> bool {
        // Strip the "did:dht:z" prefix to get the z-base-32 encoded key.
        let Some(encoded) = did_string
            .strip_prefix(DID_DHT_PREFIX)
            .and_then(|s| s.strip_prefix('z'))
        else {
            return false;
        };

        // Decode z-base-32.
        let Ok(decoded) = zbase32::decode(encoded) else {
            return false;
        };

        // Compare decoded bytes to provided public key.
        decoded == public_key
    }

    fn publish(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        // Delegate to the internal method that uses the stored signing function.
        self.publish_document(identity, document)
    }

    fn resolve(
        &self,
        did_string: &str,
    ) -> impl Future<Output = Result<DidDocument, IdentityError>> + Send {
        let did_owned = did_string.to_owned();
        async move {
            let result = self.resolve_did(&did_owned).await?;
            Ok(result.document)
        }
    }

    fn rotate(
        &self,
        identity: &ScpIdentity,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send {
        // Resolve the current document, then delegate to rotate_active_key.
        let did_owned = identity.did.clone();
        async move {
            // Resolve the current DID document from the DHT/cache.
            let resolution = self.resolve_did(&did_owned).await.map_err(|e| {
                IdentityError::KeyRotationFailed(format!(
                    "failed to resolve current document for rotation: {e}"
                ))
            })?;

            self.rotate_active_key(identity, &resolution.document, key_custody)
                .await
        }
    }
}

/// Verifies that a DID string is self-certifying for the given public key.
///
/// This is a convenience function that delegates to [`DidDht::verify`].
/// It is a local operation — no network call required.
///
/// # Arguments
///
/// * `did_string` - A `did:dht:z...` string.
/// * `public_key` - The raw Ed25519 public key bytes (32 bytes).
///
/// # Returns
///
/// `true` if the z-base-32 decoded suffix of the DID matches the public key,
/// `false` otherwise.
///
/// See ADR-003 acceptance criterion 5.
#[must_use]
pub fn verify_did(did_string: &str, public_key: &[u8]) -> bool {
    DidDht::new().verify(did_string, public_key)
}

/// Validates that a migration's `rotated_at` timestamp is within the
/// accepted sanity window relative to the verifier's clock and above
/// the protocol epoch floor.
///
/// # Errors
///
/// Returns [`IdentityError::MigrationVerificationFailed`] when:
/// - `rotated_at > now + MAX_FUTURE_SKEW_SECS` (forged near-future).
/// - `rotated_at < MIGRATION_EPOCH_FLOOR_UNIX_SECS` (pre-protocol;
///   defends against the saturating-past-window edge case where
///   `now < MAX_PAST_WINDOW_SECS` clamps the lower bound to zero).
/// - `rotated_at < now - MAX_PAST_WINDOW_SECS` (forged ancient,
///   relative to a well-clocked verifier).
fn check_rotated_at_window(rotated_at: u64, now: u64) -> Result<(), IdentityError> {
    if rotated_at > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return Err(IdentityError::MigrationVerificationFailed(format!(
            "migration_proof.rotated_at ({rotated_at}) is more than {MAX_FUTURE_SKEW_SECS}s in the future of now ({now})"
        )));
    }
    // Hard epoch floor: a `rotated_at` strictly older than the
    // SCP protocol's earliest plausible date is rejected regardless
    // of `now`. This closes the gap that the saturating
    // `now - MAX_PAST_WINDOW_SECS` check leaves on a clock that
    // reads before approximately 1975-01-01 UTC — without this
    // floor, such a verifier would accept any `rotated_at >= 0`,
    // including an attacker-forged `rotated_at = 0` (1970-01-01).
    if rotated_at < MIGRATION_EPOCH_FLOOR_UNIX_SECS {
        return Err(IdentityError::MigrationVerificationFailed(format!(
            "migration_proof.rotated_at ({rotated_at}) is below the protocol epoch floor \
             ({MIGRATION_EPOCH_FLOOR_UNIX_SECS}) — pre-protocol timestamp"
        )));
    }
    // Sliding 5-year past window: reject migrations claimed to be
    // older than `MAX_PAST_WINDOW_SECS` relative to the verifier's
    // clock. When `now < MAX_PAST_WINDOW_SECS` the `saturating_sub`
    // clamps to 0 and this bound is no-op — but the epoch floor
    // above already rejected all plausible-attack `rotated_at`
    // values for that case.
    if rotated_at < now.saturating_sub(MAX_PAST_WINDOW_SECS) {
        return Err(IdentityError::MigrationVerificationFailed(format!(
            "migration_proof.rotated_at ({rotated_at}) is more than {MAX_PAST_WINDOW_SECS}s in the past of now ({now})"
        )));
    }
    Ok(())
}

/// Best-effort destruction of the OLD identity's operational
/// signing keys (`#active` and, when present, `#agent`) after a
/// successful migration.
///
/// Spec §9.12 ("compromise recovery"): once the new identity is
/// published and the old DID document delegates via `alsoKnownAs`,
/// the old `#active` and `#agent` verification methods are revoked
/// and must not remain decryptable from operational custody. The
/// OLD identity key (`#0`) is intentionally retained: the
/// post-step-7b code path re-publishes the OLD document with the
/// updated `alsoKnownAs`, and that publish is signed by `#0`.
///
/// Failures are logged via `tracing::warn!` rather than propagated:
/// the migration is already committed (new doc published), so a
/// destroy failure surfaces as orphaned key material rather than as
/// a failed migration. Operators can audit `tracing` output to clean
/// up out-of-band.
///
/// # Idempotency contract (load-bearing for resume)
///
/// This function MUST swallow `PlatformError::KeyNotFound` (and every
/// other per-key destroy error) as `tracing::warn!`. A
/// `PublishNew`-phase resume calls this function unconditionally after
/// step 7 succeeds — even though the first-pass attempt may have
/// already destroyed the OLD `#active` (and `#agent`) before its
/// step-8 publish failed. Re-invocation on already-destroyed handles
/// must therefore be a no-op, not an error. The pinning test
/// `destroy_old_operational_keys_is_idempotent_when_keys_already_gone`
/// asserts this contract; do NOT promote `KeyNotFound` to a hard error
/// without first updating the resume path.
async fn destroy_old_operational_keys<C: KeyCustody>(key_custody: &C, identity: &ScpIdentity) {
    if let Err(e) = key_custody.destroy_key(&identity.active_signing_key).await {
        tracing::warn!(
            old_did = %identity.did,
            error = %e,
            "step 7b: failed to destroy old #active key during migration; \
             migration completed but old operational key remains in custody"
        );
    }
    if let Some(agent_handle) = identity.agent_signing_key.as_ref()
        && let Err(e) = key_custody.destroy_key(agent_handle).await
    {
        tracing::warn!(
            old_did = %identity.did,
            error = %e,
            "step 7b: failed to destroy old #agent key during migration; \
             migration completed but old operational key remains in custody"
        );
    }
}

/// Verifies that the supplied `old_document`'s `#0` verification method
/// byte-matches the public key derivable from `old_did` (did:dht is
/// self-certifying — the DID string is z-base-32 of the `#0`
/// identity-key public). This catches mismatched documents passed by
/// mistake, but does NOT verify document authenticity: an attacker who
/// knows `old_did` can publicly derive its `#0` public key and forge a
/// document with a matching VM (and arbitrary other VMs/services).
///
/// Callers MUST obtain `old_document` from the authoritative DHT (or a
/// BEP44-signature-verified cache) for the pre-rotation-chain
/// enforcement in `verify_migration` to be sound. See `verify_migration`
/// rustdoc `# Caller contract` for the trusted-resolution paths.
fn bind_old_document_to_old_did(
    old_did: &str,
    old_document: &DidDocument,
) -> Result<(), IdentityError> {
    let old_did_pubkey = extract_public_key(old_did).map_err(|e| {
        IdentityError::MigrationVerificationFailed(format!("old_did is not a valid did:dht: {e}"))
    })?;
    let old_doc_vm0 = old_document
        .verification_method_by_fragment("0")
        .ok_or_else(|| {
            IdentityError::MigrationVerificationFailed(
                "old_document has no #0 verification method".to_owned(),
            )
        })?;
    let old_doc_vm0_pubkey =
        decode_multibase_key(&old_doc_vm0.public_key_multibase).map_err(|e| {
            IdentityError::MigrationVerificationFailed(format!(
                "old_document #0 verification method has malformed publicKeyMultibase: {e}"
            ))
        })?;
    if old_doc_vm0_pubkey != old_did_pubkey {
        return Err(IdentityError::MigrationVerificationFailed(format!(
            "old_document #0 verification method does not derive old_did \
             (did-derived: {}..., document-derived: {}...)",
            hex::encode(&old_did_pubkey[..12]),
            hex::encode(&old_doc_vm0_pubkey[..12]),
        )));
    }
    Ok(())
}

/// Verifies a DID identity migration (Layer 3).
///
/// Checks the cryptographic proofs that an identity migration from `old_did`
/// to `new_did` was authorized by the old Identity Key owner.
///
/// # Verification Steps
///
/// Always-checked invariants (run on every call; correspond to invariants
/// 1-7 in ADR-003 §4c):
///
/// 0. **Document self-cert binding (Step 0 precondition).** [`bind_old_document_to_old_did`]
///    verifies that the `#0` verification method of the supplied `old_document`
///    z-base-32-decodes (under the `did:dht:z` prefix interpretation) to bytes
///    equal to the public key derivable from `old_did`. Rejects mismatched
///    documents before any downstream invariant — notably Step 1c
///    (STRONG-when-committed enforcement) — consults
///    `old_document.pre_rotation_service()`. (ADR-003 invariant 1.)
/// 1. **Migration proof signature (MODERATE assurance, invariant 2).**
///    Verifies via `verify_strict` that the old Identity Key signed
///    `SHA-256(DOMAIN_MIGRATION_V1 || u32_be(len(old_did)) || old_did ||
///    u32_be(len(new_did)) || new_did || u64_be(rotated_at))`. Length
///    prefixes (u32 big-endian for the DID strings and the implicit u64
///    big-endian width of `rotated_at`) prevent concatenation ambiguity
///    between variable-length DID strings.
///    - Step 1b. **`old_public_key` self-certifies to `old_did`
///      (invariant 3).** `migration_proof.old_public_key` MUST
///      z-base-32-encode (with the `did:dht:z` prefix) to exactly the
///      `old_did` argument. did:dht is self-certifying — without this
///      check, an attacker could substitute their own pubkey and a valid
///      signature and forge "MODERATE assurance" migrations.
///    - Step 1c. **STRONG-when-committed enforcement (invariant 7).** If
///      the OLD DID document publishes a `PreRotationCommitment` service
///      entry, `pre_rotation_proof` MUST be `Some(_)`. Rejects the silent
///      downgrade to MODERATE-only when STRONG was committed to at
///      creation time. Passes vacuously when both
///      `pre_rotation_proof.is_none()` AND
///      `old_document.pre_rotation_service().is_none()`.
///
/// Also always-checked: invariants 4, 5, 6 — `rotated_at` future-skew
/// bound (saturating, [`MAX_FUTURE_SKEW_SECS`]), past-window bound
/// (saturating, [`MAX_PAST_WINDOW_SECS`]), and the hard epoch floor at
/// [`MIGRATION_EPOCH_FLOOR_UNIX_SECS`]. See the `now` parameter
/// documentation below for rationale.
///
/// Conditional invariants — applied only when `pre_rotation_proof` is
/// `Some(_)` (STRONG assurance; correspond to invariants 8-10):
///
/// 2. **Pre-rotation proof.** Verifies ALL OF:
///    - 2a. `SHA-256(pre_rot.revealed_key) == pre_rot.commitment` — the
///      cryptographic invariant (invariant 8).
///    - 2b. `pre_rot.commitment` matches the `PreRotationCommitment`
///      service published in the **old DID document** — prevents an
///      attacker from replaying a valid `PreRotationProof` with a different
///      `commitment` value than the one the victim DID actually committed
///      to (invariant 9).
///    - 2c. `pre_rot.revealed_key` derives the **`new_did`** via
///      `did:dht:z<z-base-32(revealed_key)>` — prevents a valid proof for
///      one new DID from being substituted under a different `new_did`
///      string (invariant 10).
///
/// Returns `true` only if all provided proofs verify successfully.
///
/// # Arguments
///
/// * `old_did` - The DID being migrated from.
/// * `old_document` - The old DID document. Required so the verifier can
///   bind `pre_rot.commitment` to the commitment service entry the
///   victim actually published.
/// * `new_did` - The DID being migrated to.
/// * `migration_proof` - The migration proof (signature + old public key).
/// * `pre_rotation_proof` - Optional pre-rotation proof for STRONG assurance.
/// * `rotated_at` - The timestamp that was signed in the migration proof.
/// * `now` - The verifier's current Unix-seconds timestamp. Used to bound
///   `rotated_at`: callers should pass a real `Clock`-derived value so the
///   sanity-window check is testable. The verifier rejects `rotated_at`
///   values further than [`MAX_FUTURE_SKEW_SECS`] in the future of `now`
///   (forged near-future proofs), strictly below
///   [`MIGRATION_EPOCH_FLOOR_UNIX_SECS`] (pre-protocol timestamps,
///   robust to a faulty verifier clock), or further than
///   [`MAX_PAST_WINDOW_SECS`] in the past relative to `now` (forged
///   ancient proofs against a well-clocked verifier). Without these
///   bounds a holder of a briefly-captured old `#0` key could mint a
///   `migration_proof` with an absurd `rotated_at` (e.g. `0` or
///   `u64::MAX`) and the verifier would still return `Ok(true)`.
///
/// # Errors
///
/// Returns [`IdentityError::MigrationVerificationFailed`] if:
/// - `old_document` does not derive `old_did` via self-certification
///   (the document's `#0` verification method does not match the
///   z-base-32 encoded public key in the `old_did` string). See
///   [`bind_old_document_to_old_did`] and the `# Caller contract`
///   section below for the scope and limitations of this binding.
/// - `rotated_at` is more than [`MAX_FUTURE_SKEW_SECS`] ahead of `now`,
///   strictly below [`MIGRATION_EPOCH_FLOOR_UNIX_SECS`], or more than
///   [`MAX_PAST_WINDOW_SECS`] behind `now`.
/// - The old public key in the migration proof is invalid.
/// - The migration proof signature does not verify.
/// - `pre_rotation_proof` is `None` AND the old DID document publishes
///   a `PreRotationCommitment` service entry. The OLD identity holder
///   committed to STRONG assurance at creation time; verifiers MUST
///   refuse to silently fall back to MODERATE-only.
/// - The pre-rotation proof's `SHA-256(revealed_key) != commitment`.
/// - The pre-rotation proof's `commitment` does not match the
///   `PreRotationCommitment` service in the old DID document.
/// - The pre-rotation proof's `revealed_key` does not derive `new_did`.
///
/// # Caller contract
///
/// Callers MUST supply `old_document` from a verified resolution path
/// — [`DidDht::resolve_did`], [`crate::resolver::verify_and_deserialize`],
/// or [`crate::resolution::relay_resolve`] — so the document's BEP44
/// signature has been validated against the published DHT record (or
/// an authoritative cache thereof). This function trusts its
/// `old_document` argument: the Step 0 self-cert binding catches
/// mismatched documents passed by mistake, but does NOT re-verify
/// BEP44 authenticity. An attacker who knows `old_did` can publicly
/// derive its `#0` public key and forge a document with a matching
/// `#0` VM but arbitrary other VMs/services (notably an omitted
/// `PreRotationCommitment`), so calling `verify_migration` with an
/// unverified document forfeits the STRONG-when-committed defence.
///
/// See ADR-003 acceptance criterion 4c.
pub fn verify_migration(
    old_did: &str,
    old_document: &DidDocument,
    new_did: &str,
    migration_proof: &MigrationProof,
    pre_rotation_proof: Option<&PreRotationProof>,
    rotated_at: u64,
    now: u64,
) -> Result<bool, IdentityError> {
    // Step 0: defense-in-depth binding of `old_document` to `old_did`.
    // Run before any other invariant so a mismatched document is
    // rejected before its `pre_rotation_service` can influence
    // downstream decisions (notably step 1c's STRONG-when-committed
    // enforcement). See `bind_old_document_to_old_did` for rationale.
    bind_old_document_to_old_did(old_did, old_document)?;

    // Step 1: Verify the migration proof signature.
    // Reconstruct the signed digest:
    //   SHA-256(DOMAIN_MIGRATION_V1 || len(old_did) || old_did || len(new_did) || new_did || rotated_at)
    // Length prefixes (u32 big-endian) prevent concatenation ambiguity between
    // variable-length DID strings.
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MIGRATION_V1);
    let old_len = u32::try_from(old_did.len())
        .map_err(|_| IdentityError::InvalidDidFormat("DID too long for length prefix".into()))?;
    let new_len = u32::try_from(new_did.len())
        .map_err(|_| IdentityError::InvalidDidFormat("DID too long for length prefix".into()))?;
    hasher.update(old_len.to_be_bytes());
    hasher.update(old_did.as_bytes());
    hasher.update(new_len.to_be_bytes());
    hasher.update(new_did.as_bytes());
    hasher.update(rotated_at.to_be_bytes());
    let digest = hasher.finalize();

    // Sanity-window bound on `rotated_at`. A holder of a briefly-captured
    // old `#0` key could otherwise mint a `migration_proof` with an absurd
    // `rotated_at` (e.g. `0`, claiming the rotation happened in 1970, or
    // `u64::MAX`, claiming it happened in year 584 billion). Mirroring the
    // 5-minute future skew tolerance from spec §9.8.2(c) and a 5-year past
    // window keeps verification cheap and rejects implausible timestamps
    // before the signature check is even attempted.
    check_rotated_at_window(rotated_at, now)?;

    let verifying_key = VerifyingKey::from_bytes(&migration_proof.old_public_key).map_err(|e| {
        IdentityError::MigrationVerificationFailed(format!("invalid old public key: {e}"))
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(&migration_proof.signature);

    verifying_key
        .verify_strict(&digest, &signature)
        .map_err(|e| {
            IdentityError::MigrationVerificationFailed(format!(
                "migration proof signature verification failed: {e}"
            ))
        })?;

    // Step 1b: bind `migration_proof.old_public_key` to `old_did`.
    // Without this check, step 1 only proves "SOMEONE signed the
    // migration digest using the public key in the proof" — not that
    // the signer is actually the holder of `old_did`'s identity key.
    // An attacker could substitute their own pubkey + valid signature
    // and the function would return Ok(true), defeating the
    // "MODERATE assurance" the migration proof is supposed to deliver
    // when no pre-rotation proof is present (ADR-003 §4c). did:dht is
    // self-certifying — the DID string is z-base-32 of the identity
    // key public — so deriving the expected DID from
    // `old_public_key` and comparing against the `old_did` argument
    // closes the gap.
    let expected_old_did = format!(
        "{DID_DHT_PREFIX}z{}",
        zbase32::encode(&migration_proof.old_public_key)
    );
    if expected_old_did != old_did {
        return Err(IdentityError::MigrationVerificationFailed(format!(
            "migration_proof.old_public_key derives DID {expected_old_did:?} \
             but the migration is from {old_did:?}"
        )));
    }

    // Step 1c: enforce STRONG-assurance pre-rotation proof presence
    // when the OLD document committed to it. did:dht migrations
    // honour the published commitment: if the OLD document publishes
    // a `PreRotationCommitment` service entry, the OLD identity's
    // holder pre-committed at creation time to STRONG assurance, and
    // the verifier MUST refuse to silently fall back to the
    // MODERATE-only path. Without this check, an attacker who briefly
    // captured the OLD `#0` key could mint a valid `migration_proof`
    // for any `new_did` they control, omit the pre-rotation proof,
    // and pass verification at MODERATE — defeating the entire
    // pre-rotation chain that the OLD identity advertised.
    //
    // The MODERATE-only path remains valid only when the OLD document
    // has no `PreRotationCommitment` service (legacy or non-committing
    // identities — see ADR-003 §4c).
    if pre_rotation_proof.is_none() && old_document.pre_rotation_service().is_some() {
        return Err(IdentityError::MigrationVerificationFailed(
            "OLD DID document publishes a PreRotationCommitment service; \
             migration verification REQUIRES a PreRotationProof — STRONG \
             assurance was committed but not provided"
                .to_owned(),
        ));
    }

    // Step 2: Verify the pre-rotation proof if present.
    if let Some(pre_rot) = pre_rotation_proof {
        // Step 2a: SHA-256(revealed_key) == commitment.
        let mut commitment_hasher = Sha256::new();
        commitment_hasher.update(pre_rot.revealed_key);
        let computed_commitment = commitment_hasher.finalize();

        if computed_commitment.as_slice() != pre_rot.commitment {
            return Err(IdentityError::MigrationVerificationFailed(
                "pre-rotation proof failed: SHA-256(revealed_key) != commitment".to_owned(),
            ));
        }

        // Step 2b: bind `commitment` to the old DID document's
        // PreRotationCommitment service entry. Without this check, an
        // attacker could substitute a `(commitment, revealed_key)` pair
        // satisfying step 2a but committed to by a different DID
        // (potentially attacker-controlled).
        let svc = old_document.pre_rotation_service().ok_or_else(|| {
            IdentityError::MigrationVerificationFailed(
                "pre-rotation proof present but old DID document has no PreRotationCommitment service"
                    .to_owned(),
            )
        })?;
        let svc_hex = svc
            .service_endpoint
            .strip_prefix("sha256:")
            .ok_or_else(|| {
                IdentityError::MigrationVerificationFailed(format!(
                    "old PreRotationCommitment service endpoint missing 'sha256:' prefix: {:?}",
                    svc.service_endpoint
                ))
            })?;
        let svc_commitment_vec = hex::decode(svc_hex).map_err(|e| {
            IdentityError::MigrationVerificationFailed(format!(
                "old PreRotationCommitment service hex decode failed: {e}"
            ))
        })?;
        if svc_commitment_vec.len() != 32 {
            return Err(IdentityError::MigrationVerificationFailed(format!(
                "old PreRotationCommitment service must be 32 bytes, got {}",
                svc_commitment_vec.len()
            )));
        }
        if svc_commitment_vec.as_slice() != pre_rot.commitment.as_slice() {
            return Err(IdentityError::MigrationVerificationFailed(
                "pre-rotation proof commitment does not match the old DID document's \
                 PreRotationCommitment service entry"
                    .to_owned(),
            ));
        }

        // Step 2c: bind `revealed_key` to `new_did`. The new DID is
        // self-certifying (`did:dht:z<zbase32(public_key)>`); reject if
        // an attacker tries to substitute a different `new_did` string
        // under the same proof.
        let expected_new_did = format!(
            "{DID_DHT_PREFIX}z{}",
            zbase32::encode(&pre_rot.revealed_key)
        );
        if expected_new_did != new_did {
            return Err(IdentityError::MigrationVerificationFailed(format!(
                "pre-rotation proof revealed_key derives DID {expected_new_did:?} but \
                 migration is to {new_did:?}"
            )));
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// BEP44 utility functions — public for use by relay-based resolution (§3.10.2)
// ---------------------------------------------------------------------------

/// Constructs the BEP44 signable payload for a value and sequence number.
///
/// BEP44 signing payload format (without salt):
/// `"3:seqi" + seq + "e1:v" + val_len + ":" + val`
///
/// This is a standalone function usable from both [`DidDht`] and relay-based
/// resolution (§3.10.2).
#[must_use]
pub fn bep44_signable(value: &[u8], seq: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"3:seqi");
    payload.extend_from_slice(seq.to_string().as_bytes());
    payload.extend_from_slice(b"e1:v");
    payload.extend_from_slice(value.len().to_string().as_bytes());
    payload.extend_from_slice(b":");
    payload.extend_from_slice(value);
    payload
}

/// Verifies a BEP44 Ed25519 signature over the given value and sequence.
///
/// Constructs the BEP44 signable payload, then verifies the Ed25519 signature
/// against `public_key`. Used by both DHT resolution and relay-based resolution
/// (§3.10.2).
///
/// # Errors
///
/// Returns [`IdentityError::Bep44SignatureInvalid`] if the signature does
/// not verify or the public key is invalid.
pub fn verify_bep44_signature(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    value: &[u8],
    seq: u64,
) -> Result<(), IdentityError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| IdentityError::Bep44SignatureInvalid(format!("invalid public key: {e}")))?;

    let sig = ed25519_dalek::Signature::from_bytes(signature);
    let payload = bep44_signable(value, seq);

    verifying_key.verify_strict(&payload, &sig).map_err(|e| {
        IdentityError::Bep44SignatureInvalid(format!("signature verification failed: {e}"))
    })
}

/// Derives the `did:dht:z...` string from a raw Ed25519 public key.
///
/// Encodes the 32-byte public key as z-base-32 and prepends the `did:dht:z`
/// prefix per the did:dht method specification. This is the inverse of
/// [`extract_public_key`].
///
/// Used by bridge authentication (SCP-247) to verify that a claimed
/// `routing_id` corresponds to the DID derived from the provided public key.
#[must_use]
pub fn did_from_ed25519_public_key(public_key: &[u8; 32]) -> String {
    format!("{DID_DHT_PREFIX}z{}", zbase32::encode(public_key))
}

/// Extracts the 32-byte Ed25519 public key from a `did:dht:z...` string.
///
/// Strips the `did:dht:z` prefix and z-base-32 decodes the remainder to recover
/// the 32-byte Identity Key public key. Used by both DHT resolution and
/// relay-based resolution (§3.10.2).
///
/// # Errors
///
/// Returns [`IdentityError::InvalidDidFormat`] if the DID format is wrong,
/// the z-base-32 payload is non-canonical, or the decoded bytes are not
/// 32 bytes. Returns [`IdentityError::ZBase32DecodeError`] if z-base-32
/// decoding fails.
///
/// # Canonicality
///
/// z-base-32 encoding of 32-byte payloads is NOT injective on its
/// trailing bit-padding: 256 bits = 51 full chars (255 bits) + a 52nd
/// char carrying 1 payload bit + 4 padding bits, so 16 alternate
/// encodings decode to the same 32-byte payload. We re-encode the
/// decoded bytes and require the input to match the canonical form,
/// so two distinct DID strings cannot resolve to the same `#0` key
/// (would otherwise enable petname squatting, log/UI spoofing, and
/// equality-by-string mismatches downstream).
pub fn extract_public_key(did_string: &str) -> Result<[u8; 32], IdentityError> {
    let encoded = did_string
        .strip_prefix(DID_DHT_PREFIX)
        .and_then(|s| s.strip_prefix('z'))
        .ok_or_else(|| {
            IdentityError::InvalidDidFormat(format!(
                "expected 'did:dht:z...' prefix, got: {did_string}"
            ))
        })?;

    let decoded = zbase32::decode(encoded)
        .map_err(|e| IdentityError::ZBase32DecodeError(format!("z-base-32 decode failed: {e}")))?;

    let key_bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
        IdentityError::InvalidDidFormat(format!(
            "expected 32-byte public key, got {} bytes",
            v.len()
        ))
    })?;

    // Canonicality check: the encoder is not strictly injective on
    // the trailing bit-padding of a 32-byte payload. Reject inputs
    // that don't round-trip through the canonical encoding.
    let canonical = zbase32::encode(&key_bytes);
    if canonical != encoded {
        return Err(IdentityError::InvalidDidFormat(format!(
            "did:dht z-base-32 payload is not canonical (expected {canonical:?}, got {encoded:?})"
        )));
    }

    Ok(key_bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use scp_platform::testing::InMemoryKeyCustody;

    use super::*;
    use crate::cache::TestClock;
    use crate::dht_client::InMemoryDhtClient;

    /// Helper to create a fully-configured `DidDht` for testing.
    fn make_dht_with_custody(
        custody: &Arc<InMemoryKeyCustody>,
    ) -> DidDht<InMemoryDhtClient, Arc<TestClock>> {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
    }

    // -----------------------------------------------------------------------
    // Existing SCP-006 tests (preserved, using default DidDht::new())
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_identity_produces_valid_did_format() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        // DID starts with "did:dht:z"
        assert!(identity.did.starts_with("did:dht:z"));

        // Document ID matches identity DID
        assert_eq!(document.id, identity.did);

        // Pre-rotation commitment is non-zero (SHA-256 of a public key)
        assert_ne!(identity.pre_rotation_commitment, [0u8; 32]);
    }

    #[tokio::test]
    async fn create_identity_verify_self_certifying() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        // Get the identity public key
        let identity_public = custody.public_key(&identity.identity_key).await.unwrap();

        // verify_did should return true for the matching key
        assert!(dht.verify(&identity.did, identity_public.as_bytes()));
    }

    #[tokio::test]
    async fn verify_did_returns_false_for_mismatched_key() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        // Use a different key (the active signing key, not the identity key)
        let active_public = custody
            .public_key(&identity.active_signing_key)
            .await
            .unwrap();

        assert!(!dht.verify(&identity.did, active_public.as_bytes()));
    }

    #[test]
    fn verify_did_returns_false_for_invalid_prefix() {
        let dht = DidDht::new();
        assert!(!dht.verify("did:web:example.com", &[1u8; 32]));
    }

    #[test]
    fn verify_did_returns_false_for_missing_z_prefix() {
        let dht = DidDht::new();
        assert!(!dht.verify("did:dht:notzbased", &[1u8; 32]));
    }

    #[test]
    fn verify_did_convenience_function_works() {
        // Manually construct a valid did:dht
        let key_bytes = [42u8; 32];
        let encoded = zbase32::encode(&key_bytes);
        let did = format!("did:dht:z{encoded}");

        assert!(verify_did(&did, &key_bytes));
        assert!(!verify_did(&did, &[0u8; 32]));
    }

    #[tokio::test]
    async fn document_has_correct_verification_methods() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        // Should have two verification methods
        assert_eq!(document.verification_method.len(), 2);

        // #0 is the identity key
        let vm0 = document.verification_method_by_fragment("0").unwrap();
        assert_eq!(vm0.id, format!("{}#0", identity.did));

        // #active is the active signing key
        let vm_active = document.verification_method_by_fragment("active").unwrap();
        assert_eq!(vm_active.id, format!("{}#active", identity.did));

        // authentication and assertionMethod reference #active
        assert_eq!(
            document.authentication,
            vec![format!("{}#active", identity.did)]
        );
        assert_eq!(
            document.assertion_method,
            vec![format!("{}#active", identity.did)]
        );
    }

    #[tokio::test]
    async fn document_has_pre_rotation_service() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        let svc = document.pre_rotation_service().unwrap();
        assert_eq!(svc.service_type, "PreRotationCommitment");
        assert!(svc.service_endpoint.starts_with("sha256:"));

        // The hex string after "sha256:" should be 64 chars (32 bytes)
        let hex_part = svc.service_endpoint.strip_prefix("sha256:").unwrap();
        assert_eq!(hex_part.len(), 64);
    }

    #[tokio::test]
    async fn create_identity_deterministic_with_seeded_custody() {
        let custody1 = InMemoryKeyCustody::from_seed_bytes([42u8; 32]);
        let custody2 = InMemoryKeyCustody::from_seed_bytes([42u8; 32]);
        let dht = DidDht::new();

        let pre_rotation_custody1 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let pre_rotation_custody2 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity1, doc1, _pre_rotation_handle1) = dht
            .create(&custody1, &*pre_rotation_custody1)
            .await
            .unwrap();
        let (identity2, doc2, _pre_rotation_handle2) = dht
            .create(&custody2, &*pre_rotation_custody2)
            .await
            .unwrap();

        // Same seed produces the same DID
        assert_eq!(identity1.did, identity2.did);
        assert_eq!(
            identity1.pre_rotation_commitment,
            identity2.pre_rotation_commitment
        );
        assert_eq!(doc1, doc2);
    }

    /// Prints the DID and verifying-key hex produced under the fixed
    /// parity seed ([0x7b; 32]). Used to regenerate the ground-truth
    /// values committed in `bindings/python/tests/bridge_parity/
    /// seed_operations.py` when the KDF algorithm is intentionally bumped.
    /// Run with: `cargo test -p scp-identity
    /// print_parity_seed_expected_values -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "diagnostic helper — run with --ignored --nocapture"]
    async fn print_parity_seed_expected_values() {
        let custody = InMemoryKeyCustody::from_seed_bytes([0x7bu8; 32]);
        let dht = DidDht::new();
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _doc, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();
        let pk = custody.public_key(&identity.identity_key).await.unwrap();
        println!("EXPECTED_SEEDED_DID = \"{}\"", identity.did);
        println!(
            "EXPECTED_SEEDED_VERIFYING_KEY_HEX = \"{}\"",
            hex::encode(pk.as_bytes())
        );
    }

    #[tokio::test]
    async fn create_identity_deterministic_with_32byte_seed() {
        // ADR-046 cross-bridge parity: a full 32-byte seed must produce the
        // same DID AND the same active verifying key across two custodies.
        // This is the invariant that bridges rely on when plumbing
        // `identity_create(seed: [u8; 32])` through to a seeded
        // `InMemoryKeyCustody`.
        let seed = [0x7Bu8; 32];
        let custody1 = InMemoryKeyCustody::from_seed_bytes(seed);
        let custody2 = InMemoryKeyCustody::from_seed_bytes(seed);
        let dht = DidDht::new();

        let pre_rotation_custody1 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let pre_rotation_custody2 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (id1, doc1, _pre_rotation_handle1) = dht
            .create(&custody1, &*pre_rotation_custody1)
            .await
            .unwrap();
        let (id2, doc2, _pre_rotation_handle2) = dht
            .create(&custody2, &*pre_rotation_custody2)
            .await
            .unwrap();

        assert_eq!(id1.did, id2.did);
        assert_eq!(id1.pre_rotation_commitment, id2.pre_rotation_commitment);
        assert_eq!(doc1, doc2);

        // Active signing key (the #active VM that scpid_sign uses) is also
        // byte-identical.
        let active1 = custody1.public_key(&id1.active_signing_key).await.unwrap();
        let active2 = custody2.public_key(&id2.active_signing_key).await.unwrap();
        assert_eq!(active1.as_bytes(), active2.as_bytes());
    }

    #[tokio::test]
    async fn document_json_roundtrip_from_create() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        let json = document.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        assert_eq!(document, parsed);
    }

    // -----------------------------------------------------------------------
    // SCP-007 tests — publish, resolve, cache, staleness
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn publish_and_resolve_roundtrip() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Publish the document.
        dht.publish_document(&identity, &document).await.unwrap();

        // Resolve the document.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.document, document);
        assert_eq!(result.staleness, Staleness::Fresh);
    }

    #[tokio::test]
    async fn publish_increments_sequence_number() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        assert_eq!(dht.current_sequence(), 0);
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 1);
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 2);
    }

    #[tokio::test]
    async fn resolve_returns_cached_result() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // First resolve populates cache.
        let result1 = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result1.staleness, Staleness::Fresh);

        // Second resolve should come from cache (still fresh).
        let result2 = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result2.document, document);
        assert_eq!(result2.staleness, Staleness::Fresh);
    }

    #[tokio::test]
    async fn resolve_verifies_self_certification() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(Arc::clone(&dht_client), cache, sign_fn);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Clear the cache so resolve hits DHT again.
        dht.cache().remove(&identity.did).await;

        // Should succeed because self-certification passes.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.document, document);
    }

    #[tokio::test]
    async fn resolve_rejects_tampered_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(Arc::clone(&dht_client), cache, sign_fn);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Publish a tampered document by directly writing to the DHT client
        // with a different document but same DID. The BEP44 signature won't match.
        let tampered_doc = DidDocument::new(
            &identity.did,
            &[99u8; 32], // different identity key
            &[98u8; 32],
            &[97u8; 32],
        );
        let tampered_json = tampered_doc.to_json().unwrap();
        let public_key =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::extract_public_key(&identity.did).unwrap();
        dht_client
            .publish(&public_key, &[0u8; 64], tampered_json.as_bytes(), 1)
            .await
            .unwrap();

        // Resolve should fail because BEP44 signature is invalid.
        let result = dht.resolve_did(&identity.did).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resolve_returns_not_found_for_unpublished() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Don't publish. Resolve should return DhtNotFound.
        let result = dht.resolve_did(&identity.did).await;
        assert!(matches!(result, Err(IdentityError::DhtNotFound(_))));
    }

    #[tokio::test]
    async fn publish_without_signer_returns_error() {
        let custody = InMemoryKeyCustody::new();
        let dht = DidDht::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&custody, &*pre_rotation_custody).await.unwrap();

        let result = dht.publish_document(&identity, &document).await;
        assert!(matches!(result, Err(IdentityError::DhtPublishFailed(_))));
    }

    #[tokio::test]
    async fn bep44_signable_format_is_correct() {
        let value = b"test";
        let seq = 42;
        let signable = DidDht::<InMemoryDhtClient>::bep44_signable(value, seq);

        // Expected: "3:seqi42e1:v4:test"
        let expected = b"3:seqi42e1:v4:test";
        assert_eq!(signable, expected);
    }

    #[tokio::test]
    async fn resolve_with_staleness_detection() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // First resolve: fresh.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.staleness, Staleness::Fresh);

        // Advance past staleness threshold (2h30m + 1s).
        clock.advance(2 * 60 * 60 + 30 * 60 + 1);

        // Resolve again: should return stale from cache.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert!(matches!(result.staleness, Staleness::Stale { .. }));
    }

    #[tokio::test]
    async fn resolve_bypasses_expired_cache() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // First resolve populates cache.
        dht.resolve_did(&identity.did).await.unwrap();

        // Advance past inactive TTL (7 days + 1s).
        clock.advance(7 * 24 * 60 * 60 + 1);

        // Cache is expired, resolve goes to DHT again and succeeds.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.document, document);
        assert_eq!(result.staleness, Staleness::Fresh);
    }

    #[tokio::test]
    async fn resolve_active_contact_24h_ttl() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(Arc::clone(&clock)));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // First resolve + mark active.
        dht.resolve_did(&identity.did).await.unwrap();
        dht.cache().mark_active(&identity.did).await;

        // Advance past 24h TTL.
        clock.advance(24 * 60 * 60 + 1);

        // Cache is expired for active contact, resolve goes to DHT.
        let result = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(result.staleness, Staleness::Fresh);
    }

    #[test]
    fn base58btc_decode_roundtrip() {
        let original = [42u8; 32];
        // Use the document module's encode (via the multibase_encode path)
        let encoded =
            crate::document::DidDocument::new("did:dht:zTest", &original, &[0u8; 32], &[0u8; 32]);
        let vm = encoded.verification_method_by_fragment("0").unwrap();
        let decoded = decode_multibase_key(&vm.public_key_multibase).unwrap();
        assert_eq!(decoded, original);
    }

    /// `decode_multibase_key` MUST reject payloads that don't decompress
    /// to a valid Ed25519 Edwards-curve point. ed25519-dalek's
    /// `from_bytes` enforces ZIP-215 curve-point decompression. About
    /// half of random 32-byte strings fail this check, so we search for
    /// one rather than hardcoding a specific value. Matches the WASM
    /// bridge's `from_did_rejects_non_ed25519_curve_point` guard so
    /// both decoding entry points reject non-curve payloads early.
    #[test]
    fn decode_multibase_key_rejects_non_curve_point() {
        use rand::RngCore;

        // Search for a 32-byte payload that fails Ed25519 decompression.
        let non_curve_bytes: [u8; 32] = {
            let mut found: Option<[u8; 32]> = None;
            for _ in 0..512 {
                let mut candidate = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut candidate);
                if ed25519_dalek::VerifyingKey::from_bytes(&candidate).is_err() {
                    found = Some(candidate);
                    break;
                }
            }
            found.expect(
                "should find a non-curve 32-byte payload within 512 tries (~50% rejection rate)",
            )
        };

        // base58btc-encode the non-curve payload and prefix with `z`
        // (matches the on-the-wire multibase form).
        let encoded = format!("z{}", bs58::encode(&non_curve_bytes).into_string());

        let err = decode_multibase_key(&encoded).expect_err("non-curve payload must be rejected");
        match err {
            IdentityError::InvalidDidFormat(msg) => {
                assert!(
                    msg.contains("not a valid Ed25519 public key"),
                    "expected curve-point error message; got: {msg}"
                );
            }
            other => panic!("expected InvalidDidFormat, got: {other:?}"),
        }
    }

    #[test]
    fn base58btc_decode_known_vector() {
        // "JxF12TrwUP45BMd" is the base58btc encoding of "Hello World".
        let decoded = base58btc_decode("JxF12TrwUP45BMd").unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn base58btc_decode_leading_ones() {
        // Leading '1' characters map to leading zero bytes.
        let decoded = base58btc_decode("112").unwrap();
        assert_eq!(decoded, vec![0x00, 0x00, 0x01]);
    }

    #[test]
    fn base58btc_decode_empty_input() {
        let decoded = base58btc_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base58btc_decode_rejects_invalid_characters() {
        // '0', 'O', 'I', 'l' are not in the Bitcoin base58 alphabet.
        assert!(base58btc_decode("0OIl").is_err());
    }

    #[test]
    fn base58btc_roundtrip_32_byte_key() {
        // Direct roundtrip: encode with bs58, then decode with our function.
        let key = [0xABu8; 32];
        let encoded = bs58::encode(&key).into_string();
        let decoded = base58btc_decode(&encoded).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn extract_public_key_from_valid_did() {
        let key = [42u8; 32];
        let encoded = zbase32::encode(&key);
        let did = format!("did:dht:z{encoded}");

        let extracted = DidDht::<InMemoryDhtClient>::extract_public_key(&did).unwrap();
        assert_eq!(extracted, key);
    }

    #[test]
    fn extract_public_key_rejects_invalid_prefix() {
        let result = DidDht::<InMemoryDhtClient>::extract_public_key("did:web:example.com");
        assert!(result.is_err());
    }

    /// z-base-32 encoding of 32-byte payloads is not strictly
    /// injective on its trailing bit-padding (4 zero padding bits in
    /// the 52nd char yield 16 alternate encodings that decode to the
    /// same bytes). The native parser MUST reject non-canonical
    /// inputs to prevent two distinct DID strings from resolving to
    /// the same `#0` key.
    #[test]
    fn extract_public_key_rejects_non_canonical_zbase32_padding() {
        // The z-base-32 alphabet. The last char of a canonical 32-byte
        // encoding carries 1 payload bit + 4 padding bits = 5 bits
        // total. Toggling the lowest bit (a padding bit) yields a
        // different char that still decodes to the same bytes — that's
        // the attack vector we're rejecting.
        const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

        let key = [42u8; 32];
        let canonical_encoded = zbase32::encode(&key);
        let canonical_did = format!("did:dht:z{canonical_encoded}");

        // Sanity: the canonical form is accepted.
        let canonical_result =
            DidDht::<InMemoryDhtClient>::extract_public_key(&canonical_did).unwrap();
        assert_eq!(canonical_result, key);

        // Construct a non-canonical alternate by mutating the trailing
        // padding bits of the last char.
        let last_char = canonical_encoded.as_bytes()[canonical_encoded.len() - 1];
        let last_idx = ALPHABET
            .iter()
            .position(|&c| c == last_char)
            .expect("canonical char must be in alphabet");
        let mutated_idx = last_idx ^ 1;
        let mut mutated_bytes = canonical_encoded.as_bytes().to_vec();
        let last_pos = mutated_bytes.len() - 1;
        mutated_bytes[last_pos] = ALPHABET[mutated_idx];
        let mutated_encoded =
            String::from_utf8(mutated_bytes).expect("z-base-32 alphabet is ASCII");
        let mutated_did = format!("did:dht:z{mutated_encoded}");

        // Sanity: the mutated input still decodes to the same 32 bytes
        // (proving it's a real non-canonical alternate, not a mistake).
        let raw_decoded = zbase32::decode(&mutated_encoded).expect("alternate decodes");
        assert_eq!(raw_decoded.as_slice(), &key[..]);

        // The canonicality check MUST reject it.
        let err = DidDht::<InMemoryDhtClient>::extract_public_key(&mutated_did)
            .expect_err("non-canonical DID MUST be rejected");
        match err {
            IdentityError::InvalidDidFormat(msg) => {
                assert!(
                    msg.contains("not canonical"),
                    "expected canonicality error, got: {msg}"
                );
            }
            other => panic!("expected InvalidDidFormat, got: {other:?}"),
        }
    }

    /// Helper that creates an identity with a fresh
    /// [`InMemoryPreRotationCustody`]. Returns the identity, document, the
    /// pre-rotation handle (so migration tests can present it back), and
    /// the pre-rotation custody (so migration tests can pass the same
    /// instance to `migrate_identity`).
    async fn create_identity_with_pre_rotation_key(
        custody: &InMemoryKeyCustody,
        dht: &DidDht<InMemoryDhtClient, Arc<TestClock>>,
    ) -> (
        ScpIdentity,
        DidDocument,
        PreRotationKeyHandle,
        Arc<scp_platform::testing::InMemoryPreRotationCustody>,
    ) {
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, pre_rotation_handle) =
            dht.create(custody, &*pre_rotation_custody).await.unwrap();
        let identity_public = custody.public_key(&identity.identity_key).await.unwrap();
        assert!(dht.verify(&identity.did, identity_public.as_bytes()));
        (
            identity,
            document,
            pre_rotation_handle,
            pre_rotation_custody,
        )
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Layer 1: rotate_active_key
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_active_key_preserves_did_string() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (rotated_identity, _rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // DID string must NOT change during active key rotation.
        assert_eq!(rotated_identity.did, identity.did);
    }

    #[tokio::test]
    async fn rotate_active_key_changes_active_signing_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let old_active_public = custody
            .public_key(&identity.active_signing_key)
            .await
            .unwrap();

        let (rotated_identity, _rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        let new_active_public = custody
            .public_key(&rotated_identity.active_signing_key)
            .await
            .unwrap();

        // The active signing key handle must change.
        assert_ne!(old_active_public.as_bytes(), new_active_public.as_bytes());
    }

    #[tokio::test]
    async fn rotate_active_key_preserves_identity_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (rotated_identity, _rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // The identity key handle must be unchanged.
        assert_eq!(rotated_identity.identity_key, identity.identity_key);
    }

    #[tokio::test]
    async fn rotate_active_key_retires_old_key_in_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (_, rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // The document should have 3 verification methods: #0, #retired-N, #active.
        assert_eq!(rotated_doc.verification_method.len(), 3);

        // #active must exist with a new key.
        let new_active_vm = rotated_doc.verification_method_by_fragment("active");
        assert!(new_active_vm.is_some());

        // A retired key should exist.
        let has_retired = rotated_doc
            .verification_method
            .iter()
            .any(|vm| vm.id.contains("#retired-"));
        assert!(has_retired);

        // #0 (identity key) must still be present.
        let vm0 = rotated_doc.verification_method_by_fragment("0");
        assert!(vm0.is_some());
    }

    #[tokio::test]
    async fn rotate_active_key_updates_auth_and_assertion_refs() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (_, rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // authentication and assertionMethod should reference #active.
        assert_eq!(
            rotated_doc.authentication,
            vec![format!("{}#active", identity.did)]
        );
        assert_eq!(
            rotated_doc.assertion_method,
            vec![format!("{}#active", identity.did)]
        );
    }

    #[tokio::test]
    async fn rotate_active_key_preserves_pre_rotation_commitment() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let (rotated_identity, _) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // Pre-rotation commitment must be unchanged during active key rotation.
        assert_eq!(
            rotated_identity.pre_rotation_commitment,
            identity.pre_rotation_commitment
        );
    }

    #[tokio::test]
    async fn rotate_active_key_publishes_updated_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let seq_before = dht.current_sequence();

        let (_, _rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // Publishing should have incremented the sequence number.
        assert!(dht.current_sequence() > seq_before);
    }

    #[tokio::test]
    async fn rotate_via_did_method_trait() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Use the trait method which resolves the document internally.
        let (rotated_identity, rotated_doc) =
            <DidDht<InMemoryDhtClient, Arc<TestClock>> as DidMethod>::rotate(
                &dht, &identity, &*custody,
            )
            .await
            .unwrap();

        // DID preserved.
        assert_eq!(rotated_identity.did, identity.did);
        // Document updated.
        assert!(rotated_doc.verification_method.len() >= 3);
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Layer 2: migrate_identity
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn migrate_identity_creates_new_did() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity,
            new_document: _new_doc,
            rotation_event: _event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // The new DID must be different from the old DID.
        assert_ne!(new_identity.did, identity.did);
        // The new DID must still be a valid did:dht.
        assert!(new_identity.did.starts_with("did:dht:z"));
    }

    #[tokio::test]
    async fn migrate_identity_new_did_is_self_certifying() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let pre_rot_public_bytes = pre_rotation_custody
            .reveal_public_key(&pre_rotation_handle)
            .await
            .unwrap();
        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity,
            new_document: _new_doc,
            rotation_event: _event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // The new DID must be self-certifying for the pre-rotation key.
        assert!(dht.verify(&new_identity.did, &pre_rot_public_bytes));
    }

    #[tokio::test]
    async fn migrate_identity_updates_old_document_with_also_known_as() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity,
            new_document: _new_doc,
            rotation_event: _event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Re-resolve the old DID to check alsoKnownAs was published.
        // Clear the cache first to force a fresh DHT read.
        dht.cache().remove(&identity.did).await;
        let old_resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(old_resolved.document.also_known_as, vec![new_identity.did]);
    }

    /// Defense-in-depth (spec §9.12): the OLD DID document
    /// republished by `migrate_identity` MUST drop its `#active`
    /// (and any `#agent`) verification methods. The OLD `#active`
    /// has been destroyed in operational custody (step 7b); leaving
    /// it listed as a current verification method would let a
    /// verifier resolving the OLD doc still treat the destroyed key
    /// as authoritative.
    #[tokio::test]
    async fn migrate_identity_retires_active_in_old_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        // Sanity: the pre-migration document has `#active`.
        assert!(
            document
                .verification_method
                .iter()
                .any(|vm| vm.id.ends_with("#active")),
            "pre-migration document MUST contain #active"
        );

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: _event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Re-resolve the OLD DID and assert the republished doc has
        // no `#active` (or `#agent`) verification method, and no
        // `#active` reference in `authentication` / `assertionMethod`.
        dht.cache().remove(&identity.did).await;
        let old_resolved = dht.resolve_did(&identity.did).await.unwrap();
        let old_doc = &old_resolved.document;

        assert!(
            !old_doc
                .verification_method
                .iter()
                .any(|vm| vm.id.ends_with("#active")),
            "OLD doc MUST NOT contain #active after migration; got verification_method = {:?}",
            old_doc.verification_method,
        );
        assert!(
            !old_doc
                .verification_method
                .iter()
                .any(|vm| vm.id.ends_with("#agent")),
            "OLD doc MUST NOT contain #agent after migration; got verification_method = {:?}",
            old_doc.verification_method,
        );
        assert!(
            !old_doc
                .authentication
                .iter()
                .any(|r| r.ends_with("#active")),
            "OLD doc authentication MUST NOT reference #active after migration; got {:?}",
            old_doc.authentication,
        );
        assert!(
            !old_doc
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#active")),
            "OLD doc assertionMethod MUST NOT reference #active after migration; got {:?}",
            old_doc.assertion_method,
        );

        // `#0` (Identity Key) MUST remain — it signs the
        // `alsoKnownAs` republish and is the verifier's anchor.
        assert!(
            old_doc
                .verification_method
                .iter()
                .any(|vm| vm.id.ends_with("#0")),
            "OLD doc MUST retain #0 after migration; got verification_method = {:?}",
            old_doc.verification_method,
        );

        // `alsoKnownAs` MUST still be present (this is what the
        // OLD doc post-migration is for).
        assert_eq!(old_doc.also_known_as.len(), 1);
    }

    #[tokio::test]
    async fn migrate_identity_produces_valid_rotation_event() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // The rotation event should reference old and new DIDs.
        assert_eq!(event.old_did, identity.did);
        assert_eq!(event.new_did, new_identity.did);
        assert_eq!(event.rotated_at, rotated_at);

        // The migration proof should have the old public key.
        let old_pub = custody.public_key(&identity.identity_key).await.unwrap();
        assert_eq!(
            event.migration_proof.old_public_key,
            <[u8; 32]>::try_from(old_pub.as_bytes()).unwrap()
        );

        // The signature should be 64 bytes.
        assert_eq!(event.migration_proof.signature.len(), 64);
    }

    #[tokio::test]
    async fn migrate_identity_includes_pre_rotation_proof() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        // Snapshot the pre-rotation public BEFORE migrate, since
        // `migrate_identity` consumes the handle (§9.7.4.1 §6 destroys
        // the old pre-rotation key) — calling `reveal_public_key` after
        // would fail with `HandleNotFound`.
        let pre_rot_public_bytes = pre_rotation_custody
            .reveal_public_key(&pre_rotation_handle)
            .await
            .unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Pre-rotation proof should be present if the old document had a
        // PreRotationCommitment service.
        assert!(event.pre_rotation_proof.is_some());
        let pre_rot_proof = event.pre_rotation_proof.unwrap();

        assert_eq!(pre_rot_proof.revealed_key, pre_rot_public_bytes);
    }

    #[tokio::test]
    async fn migrate_identity_publishes_new_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity,
            new_document: new_doc,
            rotation_event: _event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // The new DID should be resolvable from the DHT.
        let resolved = dht.resolve_did(&new_identity.did).await.unwrap();
        assert_eq!(resolved.document.id, new_doc.id);
    }

    #[tokio::test]
    async fn migrate_identity_new_identity_has_fresh_pre_rotation_commitment() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity,
            new_document: _new_doc,
            rotation_event: _event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // The new identity should have a non-zero pre-rotation commitment.
        assert_ne!(new_identity.pre_rotation_commitment, [0u8; 32]);
        // It should differ from the old commitment.
        assert_ne!(
            new_identity.pre_rotation_commitment,
            identity.pre_rotation_commitment
        );
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Layer 3: verify_migration
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn verify_migration_accepts_valid_proof() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Verify the migration proof.
        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
            event.rotated_at + 1,
        );
        assert!(result.is_ok(), "verify_migration failed: {result:?}");
        assert!(result.unwrap());

        // Also verify self-certification of the new DID.
        let new_pub = custody
            .public_key(&new_identity.identity_key)
            .await
            .unwrap();
        assert!(dht.verify(&new_identity.did, new_pub.as_bytes()));
    }

    #[tokio::test]
    async fn verify_migration_rejects_tampered_signature() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Tamper with the signature.
        let mut tampered_proof = event.migration_proof.clone();
        tampered_proof.signature[0] ^= 0xFF;

        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &tampered_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
            event.rotated_at + 1,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IdentityError::MigrationVerificationFailed(_))
        ));
    }

    #[tokio::test]
    async fn verify_migration_rejects_wrong_timestamp() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Use a different timestamp — the digest won't match. `now` is
        // chosen so both bounds pass and the failure is the signature
        // mismatch, not the sanity-window check.
        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            rotated_at + 1,
            rotated_at + 2,
        );
        assert!(result.is_err());
    }

    /// MODERATE-only path is valid only when the OLD document publishes
    /// no `PreRotationCommitment` service. Strip the service to model a
    /// legacy / non-committing identity, then verify with
    /// `pre_rotation_proof = None`.
    #[tokio::test]
    async fn verify_migration_accepts_missing_pre_rotation_proof_when_old_doc_lacks_commitment() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Model a legacy OLD document that did NOT commit to a
        // pre-rotation key — strip the service entry. With no
        // commitment service published, MODERATE-only verification is
        // permissible (ADR-003 §4c).
        let mut doc_no_commitment = document.clone();
        doc_no_commitment
            .service
            .retain(|s| s.service_type != "PreRotationCommitment");
        assert!(doc_no_commitment.pre_rotation_service().is_none());

        let result = verify_migration(
            &event.old_did,
            &doc_no_commitment,
            &event.new_did,
            &event.migration_proof,
            None,
            event.rotated_at,
            event.rotated_at + 1,
        );
        assert!(
            result.is_ok(),
            "MODERATE-only verification must accept a None proof when the OLD \
             document has no PreRotationCommitment service: {result:?}"
        );
        assert!(result.unwrap());
    }

    /// When the OLD document publishes a `PreRotationCommitment`
    /// service, MODERATE-only verification (`pre_rotation_proof = None`)
    /// MUST be rejected. STRONG assurance was committed to at creation
    /// and cannot be silently downgraded — see ADR-003 §4c invariant 6.
    #[tokio::test]
    async fn verify_migration_rejects_missing_pre_rotation_proof_when_old_doc_has_commitment() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();
        // The OLD document MUST carry a PreRotationCommitment service —
        // that's the precondition this test exercises.
        assert!(document.pre_rotation_service().is_some());

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &event.migration_proof,
            None,
            event.rotated_at,
            event.rotated_at + 1,
        );
        assert!(
            result.is_err(),
            "verify_migration must reject None proof when the OLD document \
             publishes a PreRotationCommitment service: {result:?}"
        );
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("PreRotationCommitment") && msg.contains("REQUIRES"),
            "rejection message should name the missing proof requirement: {msg}"
        );
    }

    #[tokio::test]
    async fn verify_migration_rejects_invalid_pre_rotation_proof() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Create a tampered pre-rotation proof with wrong revealed_key.
        let tampered_pre_rot = PreRotationProof {
            commitment: event.pre_rotation_proof.as_ref().unwrap().commitment,
            revealed_key: [99u8; 32], // wrong key
        };

        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &event.migration_proof,
            Some(&tampered_pre_rot),
            event.rotated_at,
            event.rotated_at + 1,
        );
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IdentityError::MigrationVerificationFailed(_))
        ));
    }

    /// `migration_proof.old_public_key` MUST derive `old_did`. Without
    /// this binding, step 1's signature verification only proves
    /// "SOMEONE signed the digest using the public key in the proof"
    /// — not that the signer holds `old_did`'s identity key. An
    /// attacker could substitute their own pubkey + valid signature
    /// and the function would return Ok with no pre-rotation proof.
    #[tokio::test]
    async fn verify_migration_rejects_old_public_key_not_deriving_old_did() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Build a SECOND independent identity (different `#0` key,
        // different `old_did`). Sign a migration_proof for the
        // FIRST identity's old_did using the SECOND identity's #0.
        // The signature verifies (it's a valid Ed25519 over the
        // digest), but `migration_proof.old_public_key` derives
        // identity_2's DID, not identity_1's old_did.
        let pre_rotation_custody_2 =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity_2, _doc_2, _h_2) = dht
            .create(&*custody, &*pre_rotation_custody_2)
            .await
            .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_MIGRATION_V1);
        let old_len = u32::try_from(event.old_did.len()).unwrap();
        let new_len = u32::try_from(event.new_did.len()).unwrap();
        hasher.update(old_len.to_be_bytes());
        hasher.update(event.old_did.as_bytes());
        hasher.update(new_len.to_be_bytes());
        hasher.update(event.new_did.as_bytes());
        hasher.update(rotated_at.to_be_bytes());
        let digest = hasher.finalize();

        let attacker_sig = custody
            .sign(&identity_2.identity_key, &digest)
            .await
            .unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(attacker_sig.as_bytes());

        let attacker_pub = custody.public_key(&identity_2.identity_key).await.unwrap();
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(attacker_pub.as_bytes());

        let crafted_proof = MigrationProof {
            signature: sig_arr,
            old_public_key: pub_arr,
        };

        // Verify with NO pre-rotation proof so step 1b is the only
        // binding to old_did.
        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &crafted_proof,
            None,
            rotated_at,
            rotated_at + 1,
        );
        let err = result.expect_err(
            "step 1b MUST reject migration_proof whose old_public_key does not derive old_did",
        );
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("old_public_key derives DID"),
                    "expected step 1b error, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }
    }

    /// `verify_migration` MUST reject a caller-supplied `old_document`
    /// whose `#0` verification method does not derive `old_did`. The
    /// step-0 binding is defense-in-depth against forged documents
    /// (e.g. one with no `PreRotationCommitment` service) silently
    /// downgrading STRONG-when-committed enforcement to MODERATE: the
    /// verifier consults `old_document.pre_rotation_service()` to
    /// decide whether a `PreRotationProof` is required, so a forged
    /// document with the same `id` string but different VMs would
    /// otherwise let an attacker who briefly captured the OLD `#0`
    /// key bypass the pre-rotation chain entirely.
    #[tokio::test]
    async fn verify_migration_rejects_forged_old_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        // Identity A: legitimate, gets migrated.
        let (identity_a, document_a, pre_rotation_handle_a, pre_rotation_custody_a) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity_a, &document_a)
            .await
            .unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity_a,
            new_document: _new_doc_a,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle_a,
        } = dht
            .migrate_identity(
                &identity_a,
                &document_a,
                &pre_rotation_handle_a,
                &*pre_rotation_custody_a,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Identity B: an unrelated identity with its own `#0`. Its
        // document derives identity_b.did (zB), NOT identity_a.did
        // (zA) — passing document_b under old_did = identity_a.did
        // is precisely the forgery step 0 must catch.
        let pre_rotation_custody_b =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity_b, document_b, _pre_rotation_handle_b) = dht
            .create(&*custody, &*pre_rotation_custody_b)
            .await
            .unwrap();

        let result = verify_migration(
            &event.old_did,
            &document_b,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
            event.rotated_at + 1,
        );
        let err = result
            .expect_err("step 0 MUST reject an old_document whose #0 VM does not derive old_did");
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("does not derive old_did"),
                    "expected step 0 binding error, got: {msg}"
                );
                // The error message MUST surface short hex prefixes of
                // both the DID-derived and document-derived public keys
                // so operators can eyeball which side disagrees.
                assert!(
                    msg.contains("did-derived:") && msg.contains("document-derived:"),
                    "expected hex-prefixed mismatch operability hint, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }
    }

    /// `verify_migration` MUST reject a caller-supplied `old_document`
    /// that does not contain a `#0` verification method at all. This is
    /// the sibling case to `verify_migration_rejects_forged_old_document`
    /// (WRONG-#0): without a `#0` VM the Step 0 self-cert binding cannot
    /// proceed and the function MUST return a typed
    /// `MigrationVerificationFailed` describing the missing fragment
    /// rather than falling through.
    #[tokio::test]
    async fn verify_migration_rejects_old_document_without_vm0() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        // Legitimate migration: produce a real `DidRotationEvent` we
        // can replay against a degenerate document.
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;
        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Construct a degenerate document whose `id` matches the
        // legitimate `old_did` but whose `verification_method` list is
        // empty — there is no `#0` fragment to bind against.
        let degenerate = DidDocument {
            context: document.context.clone(),
            id: event.old_did.clone(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            also_known_as: Vec::new(),
            service: Vec::new(),
        };

        let result = verify_migration(
            &event.old_did,
            &degenerate,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
            event.rotated_at + 1,
        );
        let err = result
            .expect_err("step 0 MUST reject an old_document that has no #0 verification method");
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("old_document has no #0 verification method"),
                    "expected missing-#0 error, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }
    }

    /// Step 0's `decode_multibase_key` failure path MUST surface as
    /// `MigrationVerificationFailed`, not the raw `InvalidDidFormat`
    /// error the underlying helper returns. The `verify_migration`
    /// rustdoc promises callers that Step 0 failures are uniformly
    /// reported as `MigrationVerificationFailed`; a forged document
    /// with a malformed `publicKeyMultibase` on `#0` (no `z` prefix,
    /// truncated payload, non-base58 characters, etc.) must not leak
    /// through as a different error variant.
    #[tokio::test]
    async fn verify_migration_rejects_old_document_with_malformed_vm0_multibase() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;
        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Document whose `id` matches the legitimate `old_did` but
        // whose `#0` verification method has a malformed
        // `publicKeyMultibase`: missing the `z` base58btc prefix that
        // `decode_multibase_key` requires.
        let malformed_vm0 = crate::document::VerificationMethod {
            id: format!("{}#0", event.old_did),
            method_type: "Ed25519VerificationKey2020".to_owned(),
            controller: event.old_did.clone(),
            public_key_multibase: "not-a-multibase-encoded-key".to_owned(),
        };
        let malformed_doc = DidDocument {
            context: document.context.clone(),
            id: event.old_did.clone(),
            verification_method: vec![malformed_vm0],
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            also_known_as: Vec::new(),
            service: Vec::new(),
        };

        let result = verify_migration(
            &event.old_did,
            &malformed_doc,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
            event.rotated_at + 1,
        );
        let err = result.expect_err(
            "step 0 MUST reject an old_document whose #0 publicKeyMultibase is malformed",
        );
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("malformed publicKeyMultibase"),
                    "expected malformed-multibase error, got: {msg}"
                );
            }
            other => panic!(
                "expected MigrationVerificationFailed, got: {other:?} \
                 (Step 0 must not surface InvalidDidFormat to callers)"
            ),
        }
    }

    /// A `PreRotationProof` whose `SHA-256(revealed_key) == commitment`
    /// invariant holds but whose `commitment` does NOT match the old
    /// DID document's `PreRotationCommitment` service entry MUST be
    /// rejected. Without this binding, an attacker could pair a
    /// `(commitment, revealed_key)` they control with someone else's
    /// `migration_proof`.
    #[tokio::test]
    async fn verify_migration_rejects_commitment_mismatch_with_old_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Substitute an attacker-controlled `(commitment, revealed_key)`
        // pair: revealed_key = some attacker-key, commitment =
        // SHA-256(attacker-key). The pair satisfies step 2a but not the
        // step 2b binding to the old document.
        let attacker_key = [0xEEu8; 32];
        let mut attacker_commitment_hasher = Sha256::new();
        attacker_commitment_hasher.update(attacker_key);
        let attacker_commitment: [u8; 32] = attacker_commitment_hasher.finalize().into();
        let substituted = PreRotationProof {
            commitment: attacker_commitment,
            revealed_key: attacker_key,
        };

        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &event.migration_proof,
            Some(&substituted),
            event.rotated_at,
            event.rotated_at + 1,
        );
        let err = result.expect_err("substituted commitment MUST be rejected");
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("commitment does not match"),
                    "expected 'commitment does not match' error, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }
    }

    /// A `PreRotationProof` whose `SHA-256(revealed_key) == commitment`
    /// AND whose `commitment` matches the old DID doc, but whose
    /// `revealed_key` does NOT derive the `new_did` argument MUST be
    /// rejected. Without this binding, a valid proof for one
    /// `new_did` could be replayed under a different `new_did` string.
    #[tokio::test]
    async fn verify_migration_rejects_revealed_key_not_deriving_new_did() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let rotated_at = 1_700_000_000u64;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Step 2c isolation: hand-craft a `migration_proof_B` for an
        // ATTACKER-CHOSEN `new_did_B`, signed with the OLD identity
        // key (which the legitimate user / a custody-compromise
        // attacker holds), then pair it with the LEGITIMATE
        // `pre_rotation_proof` (revealed_key derives new_did_A, not
        // new_did_B). With this construct:
        //   - step 1 (signature) passes — we re-signed for new_did_B
        //   - step 2a (SHA-256 invariant) passes — legit proof
        //   - step 2b (commitment matches old doc) passes — legit proof
        //   - step 2c (revealed_key derives new_did) MUST fail because
        //     revealed_key = X.public derives new_did_A, not new_did_B
        //
        // This is the only path that exercises step 2c in isolation.
        // The earlier "pass a different new_did with the legit
        // migration_proof" path is rejected at step 1 because the
        // signature won't verify for the substituted new_did.
        let attacker_new_did =
            "did:dht:zfakenewdidforstep2cisolationxxxxxxxxxxxxxxxxxxxxxxxxx".to_owned();

        // Re-sign the migration digest for (old_did, attacker_new_did,
        // rotated_at) using the old identity key. The old identity
        // key is still in operational custody after migrate (only the
        // pre-rotation handle is destroyed there).
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_MIGRATION_V1);
        let old_len = u32::try_from(event.old_did.len()).unwrap();
        let new_len = u32::try_from(attacker_new_did.len()).unwrap();
        hasher.update(old_len.to_be_bytes());
        hasher.update(event.old_did.as_bytes());
        hasher.update(new_len.to_be_bytes());
        hasher.update(attacker_new_did.as_bytes());
        hasher.update(rotated_at.to_be_bytes());
        let digest = hasher.finalize();

        let resigned_sig = custody.sign(&identity.identity_key, &digest).await.unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(resigned_sig.as_bytes());

        let crafted_migration_proof = MigrationProof {
            signature: sig_arr,
            old_public_key: event.migration_proof.old_public_key,
        };

        let result = verify_migration(
            &event.old_did,
            &document,
            &attacker_new_did,
            &crafted_migration_proof,
            event.pre_rotation_proof.as_ref(),
            rotated_at,
            rotated_at + 1,
        );
        let err = result
            .expect_err("step 2c MUST reject revealed_key not deriving new_did even when the migration_proof signs the attacker's new_did");
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("revealed_key derives DID"),
                    "expected step 2c failure message, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }
    }

    /// `rotated_at` more than [`MAX_FUTURE_SKEW_SECS`] ahead of `now`
    /// MUST be rejected. A holder of a briefly-captured old `#0` key
    /// could otherwise mint a far-future migration claim. The
    /// `migration_proof` is fully valid (signature, key binding,
    /// pre-rotation proof) — only the timestamp is implausible.
    #[tokio::test]
    async fn verify_migration_rejects_rotated_at_in_future() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        // Pick a `now` and a `rotated_at` that is `now + 600` (10 minutes
        // future, beyond the 5-minute future-skew tolerance).
        let now = 1_700_000_000u64;
        let rotated_at = now + 600;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
            now,
        );
        let err = result.expect_err("rotated_at beyond future-skew tolerance MUST be rejected");
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("future"),
                    "expected future-skew error, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }
    }

    /// `rotated_at` more than [`MAX_PAST_WINDOW_SECS`] behind `now` MUST
    /// be rejected. Migrations claimed to be older than the past window
    /// are beyond any reasonable offline-recovery flow.
    #[tokio::test]
    async fn verify_migration_rejects_rotated_at_too_far_in_past() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        // 6 years past, beyond the 5-year window.
        let six_years_secs: u64 = 6 * 365 * 24 * 3600;
        let rotated_at = 1_700_000_000u64;
        let now = rotated_at + six_years_secs;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
            now,
        );
        let err = result.expect_err("rotated_at beyond past window MUST be rejected");
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("past"),
                    "expected past-window error, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }
    }

    /// Hard epoch floor: a `rotated_at` strictly older than the
    /// SCP protocol's earliest plausible date MUST be rejected, even
    /// when the verifier's clock is so broken that the sliding
    /// `now - MAX_PAST_WINDOW_SECS` window clamps to zero. Without
    /// this floor, a faulty-clock verifier (`now < MAX_PAST_WINDOW_SECS`)
    /// would accept any `rotated_at >= 0`, including
    /// `rotated_at = 0` (1970-01-01).
    #[tokio::test]
    async fn verify_migration_rejects_rotated_at_below_epoch_floor_with_zero_now() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        // `rotated_at = 0` would pass the past-window check when
        // `now = 0` (saturating_sub clamps to 0). The epoch floor
        // must reject it regardless.
        let rotated_at: u64 = 0;
        let now: u64 = 0;

        let MigrationOutcome {
            new_identity: _new_identity,
            new_document: _new_doc,
            rotation_event: event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        let result = verify_migration(
            &event.old_did,
            &document,
            &event.new_did,
            &event.migration_proof,
            event.pre_rotation_proof.as_ref(),
            event.rotated_at,
            now,
        );
        let err = result.expect_err(
            "rotated_at = 0 with now = 0 MUST be rejected by the epoch floor, \
             not silently passed through the saturating past-window check",
        );
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("epoch floor") || msg.contains("pre-protocol"),
                    "expected epoch-floor error, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }
    }

    /// Hard epoch floor boundary: `rotated_at` exactly one second
    /// below the floor MUST be rejected; `rotated_at` exactly equal
    /// to the floor MUST be accepted (when other bounds pass). Pins
    /// the inclusive/exclusive contract on the floor.
    #[tokio::test]
    async fn verify_migration_epoch_floor_boundary_is_inclusive() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        // `rotated_at` exactly one second below the floor MUST fail.
        let rotated_at_below = MIGRATION_EPOCH_FLOOR_UNIX_SECS - 1;
        // Use `now = rotated_at_below` so the sliding past-window
        // bound is satisfied; only the epoch floor should fire.
        let now_for_below = rotated_at_below;

        let MigrationOutcome {
            rotation_event: event_below,
            ..
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at_below,
            )
            .await
            .unwrap();

        let err = verify_migration(
            &event_below.old_did,
            &document,
            &event_below.new_did,
            &event_below.migration_proof,
            event_below.pre_rotation_proof.as_ref(),
            event_below.rotated_at,
            now_for_below,
        )
        .expect_err("rotated_at < MIGRATION_EPOCH_FLOOR_UNIX_SECS MUST be rejected");
        match err {
            IdentityError::MigrationVerificationFailed(msg) => {
                assert!(
                    msg.contains("epoch floor") || msg.contains("pre-protocol"),
                    "expected epoch-floor error, got: {msg}"
                );
            }
            other => panic!("expected MigrationVerificationFailed, got: {other:?}"),
        }

        // `rotated_at` exactly equal to the floor MUST pass (with
        // `now` set so other bounds also pass).
        let rotated_at_floor = MIGRATION_EPOCH_FLOOR_UNIX_SECS;
        let now_for_floor = rotated_at_floor;

        // Need fresh identity for the second migration since the
        // first consumed the pre-rotation key.
        let (identity2, document2, pre_rotation_handle2, pre_rotation_custody2) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity2, &document2).await.unwrap();

        let MigrationOutcome {
            rotation_event: event_floor,
            ..
        } = dht
            .migrate_identity(
                &identity2,
                &document2,
                &pre_rotation_handle2,
                &*pre_rotation_custody2,
                &*custody,
                rotated_at_floor,
            )
            .await
            .unwrap();

        let ok = verify_migration(
            &event_floor.old_did,
            &document2,
            &event_floor.new_did,
            &event_floor.migration_proof,
            event_floor.pre_rotation_proof.as_ref(),
            event_floor.rotated_at,
            now_for_floor,
        )
        .expect("rotated_at exactly equal to MIGRATION_EPOCH_FLOOR_UNIX_SECS MUST pass");
        assert!(
            ok,
            "verify_migration must return Ok(true) at the floor boundary"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-008 tests — Document-level rotation helpers
    // -----------------------------------------------------------------------

    #[test]
    fn retire_active_key_renames_and_adds_new() {
        let did = "did:dht:zTestRotation";
        let doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        let mut rotated_doc = doc;
        rotated_doc.retire_active_key(&[4u8; 32], 1);

        // Should have 3 verification methods now.
        assert_eq!(rotated_doc.verification_method.len(), 3);

        // The retired key should exist.
        let retired = rotated_doc
            .verification_method
            .iter()
            .find(|vm| vm.id.contains("#retired-1"));
        assert!(retired.is_some());

        // The new #active should exist.
        let active = rotated_doc.verification_method_by_fragment("active");
        assert!(active.is_some());

        // #0 should still exist.
        let identity = rotated_doc.verification_method_by_fragment("0");
        assert!(identity.is_some());
    }

    #[test]
    fn retire_operational_keys_for_migration_drops_active_and_agent() {
        let did = "did:dht:zTestRetireMigration";
        let mut doc = DidDocument::new_with_agent_key(
            did,
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            Some(&[4u8; 32]),
        );

        // Sanity: pre-retire doc has #0, #active, #agent (and the
        // pre-rotation service, which is unaffected).
        assert!(doc.verification_method_by_fragment("0").is_some());
        assert!(doc.verification_method_by_fragment("active").is_some());
        assert!(doc.verification_method_by_fragment("agent").is_some());

        doc.retire_operational_keys_for_migration();

        // #0 retained; #active and #agent dropped.
        assert!(
            doc.verification_method_by_fragment("0").is_some(),
            "#0 MUST be retained — it signs the alsoKnownAs republish"
        );
        assert!(
            doc.verification_method_by_fragment("active").is_none(),
            "#active MUST be dropped"
        );
        assert!(
            doc.verification_method_by_fragment("agent").is_none(),
            "#agent MUST be dropped"
        );

        // Authentication / assertionMethod arrays must not reference
        // the dropped fragments.
        assert!(
            !doc.authentication.iter().any(|r| r.ends_with("#active")),
            "authentication MUST NOT reference #active; got {:?}",
            doc.authentication,
        );
        assert!(
            !doc.authentication.iter().any(|r| r.ends_with("#agent")),
            "authentication MUST NOT reference #agent; got {:?}",
            doc.authentication,
        );
        assert!(
            !doc.assertion_method.iter().any(|r| r.ends_with("#active")),
            "assertion_method MUST NOT reference #active; got {:?}",
            doc.assertion_method,
        );
        assert!(
            !doc.assertion_method.iter().any(|r| r.ends_with("#agent")),
            "assertion_method MUST NOT reference #agent; got {:?}",
            doc.assertion_method,
        );
    }

    #[test]
    fn retire_operational_keys_for_migration_preserves_retired_history() {
        let did = "did:dht:zTestRetireHistory";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);

        // Layer-1 rotation: retire #active to #retired-1, install new #active.
        doc.retire_active_key(&[4u8; 32], 1);
        assert!(
            doc.verification_method
                .iter()
                .any(|vm| vm.id.ends_with("#retired-1")),
            "Layer-1 rotation must produce a #retired-1 entry"
        );

        // Now retire-for-migration: #active dropped, but #retired-1
        // history must remain auditable.
        doc.retire_operational_keys_for_migration();
        assert!(
            doc.verification_method_by_fragment("active").is_none(),
            "#active MUST be dropped after migration retirement"
        );
        assert!(
            doc.verification_method
                .iter()
                .any(|vm| vm.id.ends_with("#retired-1")),
            "Layer-1 #retired-1 history MUST be preserved across migration retirement"
        );
    }

    #[test]
    fn set_also_known_as_sets_field() {
        let did = "did:dht:zTestAKA";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert!(doc.also_known_as.is_empty());

        doc.set_also_known_as("did:dht:zNewDid");
        assert_eq!(doc.also_known_as, vec!["did:dht:zNewDid"]);
    }

    #[test]
    fn also_known_as_omitted_from_json_when_empty() {
        let did = "did:dht:zTestJSON";
        let doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let json = doc.to_json().unwrap();

        // alsoKnownAs should not appear in the JSON when empty.
        assert!(!json.contains("alsoKnownAs"));
    }

    #[test]
    fn also_known_as_present_in_json_when_set() {
        let did = "did:dht:zTestJSON2";
        let mut doc = DidDocument::new(did, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
        doc.set_also_known_as("did:dht:zNewDid");

        let json = doc.to_json().unwrap();
        assert!(json.contains("alsoKnownAs"));
        assert!(json.contains("did:dht:zNewDid"));

        // Roundtrip should preserve alsoKnownAs.
        let parsed = DidDocument::from_json(&json).unwrap();
        assert_eq!(parsed.also_known_as, vec!["did:dht:zNewDid"]);
    }

    #[test]
    fn rotation_event_json_roundtrip() {
        let event = DidRotationEvent {
            old_did: "did:dht:zOld".to_owned(),
            new_did: "did:dht:zNew".to_owned(),
            migration_proof: MigrationProof {
                signature: [0xAA; 64],
                old_public_key: [0xBB; 32],
            },
            pre_rotation_proof: Some(PreRotationProof {
                commitment: [0xCC; 32],
                revealed_key: [0xDD; 32],
            }),
            rotated_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: DidRotationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -----------------------------------------------------------------------
    // SCP-141 tests — Relay URL publication in DID publish flow
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn publish_with_relay_urls_includes_scp_relay_entries() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        let relay_urls = &[
            "wss://relay1.example.com/scp/v1",
            "wss://relay2.example.com/scp/v1",
        ];

        let published_doc = dht
            .publish_with_relay_urls(&identity, &document, relay_urls)
            .await
            .unwrap();

        // Published document should include SCPRelay entries.
        let resolved_urls = published_doc.relay_service_urls();
        assert_eq!(resolved_urls.len(), 2);
        assert_eq!(resolved_urls[0], "wss://relay1.example.com/scp/v1");
        assert_eq!(resolved_urls[1], "wss://relay2.example.com/scp/v1");

        // Resolve from DHT and verify relay entries survive roundtrip.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        let resolved_relay_urls = resolved.document.relay_service_urls();
        assert_eq!(resolved_relay_urls.len(), 2);
        assert_eq!(resolved_relay_urls[0], "wss://relay1.example.com/scp/v1");
        assert_eq!(resolved_relay_urls[1], "wss://relay2.example.com/scp/v1");
    }

    #[tokio::test]
    async fn publish_without_relay_urls_has_no_relay_entries() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Publish without relay URLs (empty slice).
        let published_doc = dht
            .publish_with_relay_urls(&identity, &document, &[])
            .await
            .unwrap();

        // No SCPRelay entries.
        assert!(published_doc.relay_service_urls().is_empty());

        // Resolve from DHT and verify no relay entries.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.relay_service_urls().is_empty());
    }

    #[tokio::test]
    async fn update_relay_urls_returns_new_urls_and_increments_sequence() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Initial publish with one relay URL.
        let initial_doc = dht
            .publish_with_relay_urls(&identity, &document, &["wss://relay1.example.com/scp/v1"])
            .await
            .unwrap();

        let seq_after_initial = dht.current_sequence();
        assert_eq!(initial_doc.relay_service_urls().len(), 1);

        // Update to a different set of relay URLs.
        let updated_doc = dht
            .update_relay_urls(
                &identity,
                &initial_doc,
                &[
                    "wss://new-relay1.example.com/scp/v1",
                    "wss://new-relay2.example.com/scp/v1",
                    "wss://new-relay3.example.com/scp/v1",
                ],
            )
            .await
            .unwrap();

        // Sequence number must have incremented.
        let seq_after_update = dht.current_sequence();
        assert!(seq_after_update > seq_after_initial);

        // Updated document should have the new relay URLs.
        let updated_urls = updated_doc.relay_service_urls();
        assert_eq!(updated_urls.len(), 3);
        assert_eq!(updated_urls[0], "wss://new-relay1.example.com/scp/v1");
        assert_eq!(updated_urls[1], "wss://new-relay2.example.com/scp/v1");
        assert_eq!(updated_urls[2], "wss://new-relay3.example.com/scp/v1");

        // Resolve from DHT and verify the updated relay URLs.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        let resolved_urls = resolved.document.relay_service_urls();
        assert_eq!(resolved_urls.len(), 3);
        assert_eq!(resolved_urls[0], "wss://new-relay1.example.com/scp/v1");
        assert_eq!(resolved_urls[1], "wss://new-relay2.example.com/scp/v1");
        assert_eq!(resolved_urls[2], "wss://new-relay3.example.com/scp/v1");
    }

    #[tokio::test]
    async fn publish_with_relay_urls_rejects_invalid_url() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Invalid scheme.
        let result = dht
            .publish_with_relay_urls(&identity, &document, &["http://relay.example.com/scp/v1"])
            .await;
        assert!(matches!(result, Err(IdentityError::InvalidRelayUrl(_))));

        // Invalid path.
        let result = dht
            .publish_with_relay_urls(&identity, &document, &["wss://relay.example.com/other"])
            .await;
        assert!(matches!(result, Err(IdentityError::InvalidRelayUrl(_))));
    }

    #[tokio::test]
    async fn update_relay_urls_preserves_non_relay_services() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Verify the document starts with a PreRotationCommitment service.
        assert!(document.pre_rotation_service().is_some());

        // Publish with relay URLs.
        let published_doc = dht
            .publish_with_relay_urls(&identity, &document, &["wss://relay.example.com/scp/v1"])
            .await
            .unwrap();

        // PreRotationCommitment should still be present.
        assert!(published_doc.pre_rotation_service().is_some());
        assert_eq!(published_doc.relay_service_urls().len(), 1);

        // Update relay URLs.
        let updated_doc = dht
            .update_relay_urls(
                &identity,
                &published_doc,
                &["wss://new-relay.example.com/scp/v1"],
            )
            .await
            .unwrap();

        // PreRotationCommitment should still be present after update.
        assert!(updated_doc.pre_rotation_service().is_some());
        assert_eq!(updated_doc.relay_service_urls().len(), 1);
        assert_eq!(
            updated_doc.relay_service_urls()[0],
            "wss://new-relay.example.com/scp/v1"
        );
    }

    #[tokio::test]
    async fn update_relay_urls_to_empty_removes_all_relay_entries() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Publish with relay URLs.
        let published_doc = dht
            .publish_with_relay_urls(&identity, &document, &["wss://relay.example.com/scp/v1"])
            .await
            .unwrap();
        assert_eq!(published_doc.relay_service_urls().len(), 1);

        // Update to empty relay list.
        let updated_doc = dht
            .update_relay_urls(&identity, &published_doc, &[])
            .await
            .unwrap();

        assert!(updated_doc.relay_service_urls().is_empty());

        // Resolve and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.relay_service_urls().is_empty());
    }

    #[tokio::test]
    async fn bep44_signature_covers_relay_entries() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        let relay_urls = &["wss://relay.example.com/scp/v1"];
        dht.publish_with_relay_urls(&identity, &document, relay_urls)
            .await
            .unwrap();

        // Clear cache and resolve from DHT. The resolve_did method verifies
        // the BEP44 signature, which covers the complete document including
        // relay entries. If the signature didn't cover relay entries, this
        // would fail.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();

        // The resolved document should have the relay entries, proving the
        // BEP44 signature covered them.
        assert_eq!(resolved.document.relay_service_urls().len(), 1);
        assert_eq!(
            resolved.document.relay_service_urls()[0],
            "wss://relay.example.com/scp/v1"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-AB-009 tests — Agent key DHT wiring (ADR-039)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_with_agent_key_produces_four_verification_methods() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();

        // DID format is valid.
        assert!(identity.did.starts_with("did:dht:z"));
        assert_eq!(document.id, identity.did);

        // Should have three verification methods: #0, #active, #agent.
        assert_eq!(document.verification_method.len(), 3);
        assert!(document.verification_method_by_fragment("0").is_some());
        assert!(document.verification_method_by_fragment("active").is_some());
        assert!(document.verification_method_by_fragment("agent").is_some());

        // agent_signing_key should be set.
        assert!(identity.agent_signing_key.is_some());

        // authentication and assertionMethod should reference both #active and #agent.
        assert_eq!(document.authentication.len(), 2);
        assert!(
            document
                .authentication
                .iter()
                .any(|r| r.ends_with("#active"))
        );
        assert!(
            document
                .authentication
                .iter()
                .any(|r| r.ends_with("#agent"))
        );
        assert_eq!(document.assertion_method.len(), 2);
        assert!(
            document
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#active"))
        );
        assert!(
            document
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#agent"))
        );
    }

    #[tokio::test]
    async fn create_without_agent_key_backward_compat() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Should have two verification methods: #0 and #active.
        assert_eq!(document.verification_method.len(), 2);
        assert!(!document.has_agent_key());

        // agent_signing_key should be None.
        assert!(identity.agent_signing_key.is_none());

        // authentication and assertionMethod should reference only #active.
        assert_eq!(document.authentication.len(), 1);
        assert_eq!(document.assertion_method.len(), 1);
    }

    #[tokio::test]
    async fn create_with_agent_key_self_certifies() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();

        // Self-certification: identity key in document matches DID string.
        let identity_public = custody.public_key(&identity.identity_key).await.unwrap();
        assert!(dht.verify(&identity.did, identity_public.as_bytes()));

        // verify_self_certification should succeed.
        verify_self_certification(&identity.did, &document).unwrap();
    }

    #[tokio::test]
    async fn create_with_agent_key_publish_and_resolve_roundtrip() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Resolve and verify the agent key survives the roundtrip.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert_eq!(resolved.document, document);
        assert!(resolved.document.has_agent_key());
        assert_eq!(resolved.document.verification_method.len(), 3);
    }

    #[tokio::test]
    async fn add_agent_key_to_existing_identity() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        // Create identity without agent key.
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();
        assert!(!document.has_agent_key());
        assert!(identity.agent_signing_key.is_none());

        // Add agent key.
        let (updated_identity, updated_doc) = dht
            .add_agent_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // Identity should now have an agent key.
        assert!(updated_identity.agent_signing_key.is_some());
        assert!(updated_doc.has_agent_key());

        // DID and identity key preserved.
        assert_eq!(updated_identity.did, identity.did);
        assert_eq!(updated_identity.identity_key, identity.identity_key);
        assert_eq!(
            updated_identity.active_signing_key,
            identity.active_signing_key
        );

        // Resolve from DHT and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.has_agent_key());
        assert_eq!(resolved.document.verification_method.len(), 3);
    }

    #[tokio::test]
    async fn add_agent_key_fails_if_already_exists() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Trying to add again should fail.
        let result = dht.add_agent_key(&identity, &document, &*custody).await;
        assert!(matches!(result, Err(IdentityError::AgentKeyAlreadyExists)));
    }

    #[tokio::test]
    async fn rotate_agent_key_produces_new_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let old_agent_key = identity.agent_signing_key.unwrap();
        let old_agent_public = custody.public_key(&old_agent_key).await.unwrap();

        // Rotate the agent key.
        let (rotated_identity, rotated_doc) = dht
            .rotate_agent_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // New agent key should be different.
        let new_agent_key = rotated_identity.agent_signing_key.unwrap();
        let new_agent_public = custody.public_key(&new_agent_key).await.unwrap();
        assert_ne!(old_agent_public.as_bytes(), new_agent_public.as_bytes());

        // Document should have #agent with new key.
        assert!(rotated_doc.has_agent_key());
        let agent_vm = rotated_doc
            .verification_method_by_fragment("agent")
            .unwrap();
        assert!(agent_vm.id.ends_with("#agent"));

        // Should have a retired agent key.
        assert!(rotated_doc.retired_agent_key_count() >= 1);

        // DID, identity key, active key preserved.
        assert_eq!(rotated_identity.did, identity.did);
        assert_eq!(rotated_identity.identity_key, identity.identity_key);
        assert_eq!(
            rotated_identity.active_signing_key,
            identity.active_signing_key
        );

        // Resolve from DHT and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.has_agent_key());
    }

    #[tokio::test]
    async fn rotate_agent_key_fails_without_existing_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let result = dht.rotate_agent_key(&identity, &document, &*custody).await;
        assert!(matches!(result, Err(IdentityError::AgentKeyNotFound)));
    }

    #[tokio::test]
    async fn remove_agent_key_clears_identity_and_document() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();
        assert!(document.has_agent_key());

        // Remove the agent key.
        let (updated_identity, updated_doc) =
            dht.remove_agent_key(&identity, &document).await.unwrap();

        // Agent key should be gone from identity and document.
        assert!(updated_identity.agent_signing_key.is_none());
        assert!(!updated_doc.has_agent_key());

        // DID, identity key, active key preserved.
        assert_eq!(updated_identity.did, identity.did);
        assert_eq!(updated_identity.identity_key, identity.identity_key);
        assert_eq!(
            updated_identity.active_signing_key,
            identity.active_signing_key
        );

        // authentication and assertionMethod should only reference #active.
        assert_eq!(updated_doc.authentication.len(), 1);
        assert!(updated_doc.authentication[0].ends_with("#active"));
        assert_eq!(updated_doc.assertion_method.len(), 1);
        assert!(updated_doc.assertion_method[0].ends_with("#active"));

        // Resolve from DHT and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(!resolved.document.has_agent_key());
        assert_eq!(resolved.document.verification_method.len(), 2);
    }

    #[tokio::test]
    async fn remove_agent_key_fails_without_existing_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let result = dht.remove_agent_key(&identity, &document).await;
        assert!(matches!(result, Err(IdentityError::AgentKeyNotFound)));
    }

    #[tokio::test]
    async fn rotate_active_key_preserves_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        // Create identity with agent key.
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let agent_key = identity.agent_signing_key.unwrap();
        let agent_public = custody.public_key(&agent_key).await.unwrap();

        // Rotate the active key.
        let (rotated_identity, rotated_doc) = dht
            .rotate_active_key(&identity, &document, &*custody)
            .await
            .unwrap();

        // Agent key should be preserved in the identity.
        assert_eq!(rotated_identity.agent_signing_key, Some(agent_key));

        // Document should still have #agent.
        assert!(rotated_doc.has_agent_key());
        let agent_vm = rotated_doc
            .verification_method_by_fragment("agent")
            .unwrap();
        let doc_agent_bytes = super::decode_multibase_key(&agent_vm.public_key_multibase).unwrap();
        assert_eq!(
            doc_agent_bytes,
            <[u8; 32]>::try_from(agent_public.as_bytes()).unwrap()
        );

        // authentication and assertionMethod should reference both #active and #agent.
        assert_eq!(rotated_doc.authentication.len(), 2);
        assert!(
            rotated_doc
                .authentication
                .iter()
                .any(|r| r.ends_with("#active"))
        );
        assert!(
            rotated_doc
                .authentication
                .iter()
                .any(|r| r.ends_with("#agent"))
        );
        assert_eq!(rotated_doc.assertion_method.len(), 2);
        assert!(
            rotated_doc
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#active"))
        );
        assert!(
            rotated_doc
                .assertion_method
                .iter()
                .any(|r| r.ends_with("#agent"))
        );

        // Resolve from DHT and verify.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        assert!(resolved.document.has_agent_key());
    }

    #[tokio::test]
    async fn verify_self_certification_works_with_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        // Self-certification only checks #0 (identity key), so it should work
        // regardless of how many VMs exist.
        dht.cache().remove(&identity.did).await;
        let resolved = dht.resolve_did(&identity.did).await.unwrap();
        verify_self_certification(&identity.did, &resolved.document).unwrap();
    }

    #[tokio::test]
    async fn migrate_identity_drops_agent_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        // Create identity with agent key via the production constructor.
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();

        dht.publish_document(&identity, &document).await.unwrap();

        // Migrate the identity.
        let rotated_at = 1_700_000_000u64;
        let MigrationOutcome {
            new_identity,
            new_document: new_doc,
            rotation_event: _event,
            new_pre_rotation_handle: _new_pre_rotation_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Migration creates a new identity -- agent key is NOT carried forward.
        // The agent relationship must be re-established with add_agent_key.
        assert!(new_identity.agent_signing_key.is_none());
        assert!(!new_doc.has_agent_key());
    }

    /// Records every `publish` call's DID (derived from the public key)
    /// in arrival order. Used by the step-7-before-step-8 ordering
    /// regression test below to assert that `migrate_identity` publishes
    /// the NEW DID document BEFORE updating the OLD document with
    /// `alsoKnownAs`. A storage-layer record is the only honest signal —
    /// in-memory mutation order in `migrate_identity` is not directly
    /// observable from tests, so the only acceptable assertion is on
    /// what hits the wire.
    #[derive(Default)]
    struct PublishOrderRecorder {
        published: tokio::sync::Mutex<Vec<String>>,
        inner: InMemoryDhtClient,
    }

    impl PublishOrderRecorder {
        fn new() -> Self {
            Self {
                published: tokio::sync::Mutex::new(Vec::new()),
                inner: InMemoryDhtClient::new(),
            }
        }

        async fn snapshot(&self) -> Vec<String> {
            self.published.lock().await.clone()
        }
    }

    #[allow(clippy::manual_async_fn)]
    impl DhtClient for PublishOrderRecorder {
        fn publish(
            &self,
            public_key: &[u8; 32],
            signature: &[u8; 64],
            value: &[u8],
            seq: u64,
        ) -> impl Future<Output = Result<(), IdentityError>> + Send {
            let pk = *public_key;
            let sig = *signature;
            let val = value.to_vec();
            async move {
                // Reconstruct the DID string from the public key bytes
                // exactly the way `migrate_identity` does — this is what
                // a remote verifier would observe on the wire.
                let did = format!("did:dht:z{}", zbase32::encode(&pk));
                self.published.lock().await.push(did);
                self.inner.publish(&pk, &sig, &val, seq).await
            }
        }

        fn resolve(
            &self,
            public_key: &[u8; 32],
        ) -> impl Future<Output = Result<Option<crate::dht_client::DhtRecord>, IdentityError>> + Send
        {
            let pk = *public_key;
            async move { self.inner.resolve(&pk).await }
        }
    }

    /// `migrate_identity` MUST publish the NEW DID document FIRST and
    /// THEN update the OLD DID document with `alsoKnownAs`. The reverse
    /// order would briefly leave verifiers following `alsoKnownAs[new_did]`
    /// against an unpublished new document, breaking the chain-forward
    /// invariant from `dht.rs::migrate_identity` step-7-vs-step-8 commentary.
    /// This test records the `publish` arrival order at the wire layer
    /// and asserts the sequence is exactly `[new_did, old_did]`.
    #[tokio::test]
    async fn migrate_identity_publishes_new_did_before_old_alsoknownas() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let recorder = Arc::new(PublishOrderRecorder::new());
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<PublishOrderRecorder, Arc<TestClock>>::make_sign_fn(Arc::clone(&custody));
        let dht: DidDht<PublishOrderRecorder, Arc<TestClock>> =
            DidDht::with_client_and_signer(Arc::clone(&recorder), cache, sign_fn);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        // Publish the OLD document before migration so the recorder
        // starts with a clean slate after migration alone.
        dht.publish_document(&identity, &document).await.unwrap();
        let pre_migration_publishes = recorder.snapshot().await.len();

        let rotated_at = 1_700_000_000u64;
        let MigrationOutcome {
            new_identity,
            new_document: _new_doc,
            rotation_event: _event,
            new_pre_rotation_handle: _new_handle,
        } = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        let after = recorder.snapshot().await;
        let migration_publishes = &after[pre_migration_publishes..];
        assert_eq!(
            migration_publishes.len(),
            2,
            "migrate_identity must publish exactly two documents (new DID, then OLD with alsoKnownAs); got {migration_publishes:?}"
        );
        assert_eq!(
            migration_publishes[0], new_identity.did,
            "step 7 (publish new DID document) MUST occur before step 8 (publish old doc with alsoKnownAs); recorded order: {migration_publishes:?}"
        );
        assert_eq!(
            migration_publishes[1], identity.did,
            "step 8 (publish old doc with alsoKnownAs) MUST occur after step 7; recorded order: {migration_publishes:?}"
        );
    }

    /// `migrate_identity` MUST destroy the old `#active` operational key
    /// after the migration commits. Spec §9.12 ("compromise recovery")
    /// requires that revoked verification methods do not remain
    /// decryptable from operational custody — leaving the old `#active`
    /// usable would let a holder of the operational substrate continue
    /// signing under the now-revoked key. The `#0` (`identity_key`) MUST
    /// be retained because step 8 (publishing the old document with
    /// `alsoKnownAs`) signs with it.
    #[tokio::test]
    async fn migrate_identity_destroys_old_active_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            create_identity_with_pre_rotation_key(&custody, &dht).await;
        dht.publish_document(&identity, &document).await.unwrap();

        let old_active = identity.active_signing_key;
        let old_identity_key = identity.identity_key;

        let rotated_at = 1_700_000_000u64;
        let _ = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        // Old #active MUST be destroyed — `public_key` MUST surface
        // `KeyNotFound` (the documented post-`destroy_key` contract).
        let after_active = custody.public_key(&old_active).await;
        assert!(
            matches!(after_active, Err(scp_platform::PlatformError::KeyNotFound)),
            "old #active must be destroyed after migrate_identity; got {after_active:?}"
        );
        // Old `#0` MUST remain — step 8 used it to republish the old
        // document. Destroying it would break the `alsoKnownAs`
        // signing path (and any future republish for forwarding).
        let after_identity = custody.public_key(&old_identity_key).await;
        assert!(
            after_identity.is_ok(),
            "old #0 (identity_key) must be RETAINED after migrate_identity (needed to re-sign old document); got {after_identity:?}"
        );
    }

    /// Migration of an identity that carries an `#agent` key MUST
    /// destroy the old `#agent` handle alongside the old `#active`.
    #[tokio::test]
    async fn migrate_identity_destroys_old_agent_key_when_present() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, pre_rotation_handle) = dht
            .create_with_agent_key(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht.publish_document(&identity, &document).await.unwrap();

        let old_agent = *identity
            .agent_signing_key
            .as_ref()
            .expect("create_with_agent_key produces an agent handle");

        let rotated_at = 1_700_000_000u64;
        let _ = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .unwrap();

        let after_agent = custody.public_key(&old_agent).await;
        assert!(
            matches!(after_agent, Err(scp_platform::PlatformError::KeyNotFound)),
            "old #agent must be destroyed after migrate_identity; got {after_agent:?}"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-176 — Concurrent sequence number monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_fetch_add_produces_unique_monotonic_values() {
        use std::sync::atomic::AtomicU64;
        use std::thread;

        let num_threads = 8;
        let increments_per_thread = 1_000;
        let seq = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let seq = Arc::clone(&seq);
                thread::spawn(move || {
                    let mut values = Vec::with_capacity(increments_per_thread);
                    for _ in 0..increments_per_thread {
                        let v = seq.fetch_add(1, Ordering::AcqRel);
                        values.push(v);
                    }
                    values
                })
            })
            .collect();

        let mut all_values: Vec<u64> = Vec::with_capacity(num_threads * increments_per_thread);
        for handle in handles {
            let thread_values = handle.join().unwrap();
            // Each thread's values must be strictly monotonically increasing.
            for window in thread_values.windows(2) {
                assert!(
                    window[0] < window[1],
                    "per-thread values not monotonic: {} >= {}",
                    window[0],
                    window[1]
                );
            }
            all_values.extend(thread_values);
        }

        // All values across all threads must be unique.
        all_values.sort_unstable();
        all_values.dedup();
        assert_eq!(
            all_values.len(),
            num_threads * increments_per_thread,
            "duplicate sequence values detected across threads"
        );

        // Final counter value must equal total increments.
        assert_eq!(
            seq.load(Ordering::Acquire),
            (num_threads * increments_per_thread) as u64
        );
    }

    // -----------------------------------------------------------------------
    // BEP44 sequence persistence tests (issue #327)
    // -----------------------------------------------------------------------

    /// Helper to create a `DidDht` with a shared DHT client, custody, and
    /// sequence store — simulating restart by creating a new `DidDht` that
    /// shares the same store and DHT.
    fn make_dht_with_store(
        custody: &Arc<InMemoryKeyCustody>,
        dht_client: Arc<InMemoryDhtClient>,
        store: Arc<InMemorySequenceStore>,
    ) -> DidDht<InMemoryDhtClient, Arc<TestClock>> {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<InMemoryDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_signer_and_store(dht_client, cache, sign_fn, store)
    }

    #[tokio::test]
    async fn publish_persists_sequence_to_store() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Publish increments and persists.
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 1);

        let stored = store.load(&identity.did).await.unwrap();
        assert_eq!(stored, Some(1));

        // Second publish persists 2.
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 2);

        let stored = store.load(&identity.did).await.unwrap();
        assert_eq!(stored, Some(2));
    }

    #[tokio::test]
    async fn initialize_sequence_from_store() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Publish 3 times to get sequence to 3.
        for _ in 0..3 {
            dht.publish_document(&identity, &document).await.unwrap();
        }
        assert_eq!(dht.current_sequence(), 3);
        assert_eq!(store.load(&identity.did).await.unwrap(), Some(3));

        // Simulate restart: create a new DidDht with same store and DHT.
        let dht2 = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        assert_eq!(dht2.current_sequence(), 0); // Not yet initialized.

        dht2.initialize_sequence(&identity.did).await.unwrap();
        assert_eq!(dht2.current_sequence(), 3); // Loaded from store.

        // Next publish must be > 3.
        dht2.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht2.current_sequence(), 4);
        assert_eq!(store.load(&identity.did).await.unwrap(), Some(4));
    }

    #[tokio::test]
    async fn initialize_sequence_from_dht_when_no_store() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());

        // First instance: publish with a store.
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        for _ in 0..5 {
            dht.publish_document(&identity, &document).await.unwrap();
        }
        assert_eq!(dht.current_sequence(), 5);

        // Second instance: fresh store (simulating lost storage), but same DHT.
        let fresh_store = Arc::new(InMemorySequenceStore::new());
        let dht2 = make_dht_with_store(&custody, Arc::clone(&dht_client), fresh_store);

        dht2.initialize_sequence(&identity.did).await.unwrap();
        // Should have recovered seq 5 from the DHT record.
        assert_eq!(dht2.current_sequence(), 5);

        // Next publish must be > 5.
        dht2.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht2.current_sequence(), 6);
    }

    #[tokio::test]
    async fn initialize_sequence_uses_max_of_store_and_dht() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());

        // First instance: publish to get DHT seq to 3.
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        for _ in 0..3 {
            dht.publish_document(&identity, &document).await.unwrap();
        }

        // Manually set the store to a higher value (simulating store ahead of DHT).
        store.store(&identity.did, 10).await.unwrap();

        let dht2 = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        dht2.initialize_sequence(&identity.did).await.unwrap();
        // max(10, 3) = 10
        assert_eq!(dht2.current_sequence(), 10);

        // Next publish: 11.
        dht2.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht2.current_sequence(), 11);
    }

    #[tokio::test]
    async fn publish_restart_publish_produces_higher_sequence() {
        // This is the exact acceptance criterion test:
        // "publish -> restart -> publish again -> second publication has higher sequence"
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());

        // First session: create and publish.
        let dht1 = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) = dht1
            .create(&*custody, &*pre_rotation_custody)
            .await
            .unwrap();
        dht1.publish_document(&identity, &document).await.unwrap();
        let seq_before_restart = dht1.current_sequence();
        assert_eq!(seq_before_restart, 1);

        // Simulate restart: new DidDht, same store + DHT.
        let dht2 = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));
        dht2.initialize_sequence(&identity.did).await.unwrap();

        // Second session: publish again.
        dht2.publish_document(&identity, &document).await.unwrap();
        let seq_after_restart = dht2.current_sequence();

        // The second publication MUST have a strictly higher sequence.
        assert!(
            seq_after_restart > seq_before_restart,
            "sequence after restart ({seq_after_restart}) must be > sequence before restart ({seq_before_restart})"
        );
        assert_eq!(seq_after_restart, 2);
    }

    #[tokio::test]
    async fn no_store_works_without_persistence() {
        // Backward compatibility: DidDht without a store still works.
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 1);
        dht.publish_document(&identity, &document).await.unwrap();
        assert_eq!(dht.current_sequence(), 2);
    }

    #[tokio::test]
    async fn initialize_sequence_no_store_no_dht_record() {
        // New identity, no store, no DHT record: sequence stays at 0.
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let store = Arc::new(InMemorySequenceStore::new());
        let dht = make_dht_with_store(&custody, Arc::clone(&dht_client), Arc::clone(&store));

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, _document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();
        dht.initialize_sequence(&identity.did).await.unwrap();
        assert_eq!(dht.current_sequence(), 0);
    }

    // -----------------------------------------------------------------------
    // Device attestation integration tests (issue #362)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn attach_device_attestation_adds_service_entry() {
        use scp_platform::testing::InMemoryDeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Before attaching: no device attestation service entry.
        assert!(!document.has_device_attestation());
        assert!(document.device_attestation_token().unwrap().is_none());

        // Attach device attestation.
        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // After attaching: device attestation service entry present.
        assert!(updated_doc.has_device_attestation());
        let token = updated_doc.device_attestation_token().unwrap().unwrap();
        assert!(
            token.starts_with(b"scp-test-attestation-v1:"),
            "token should have synthetic prefix"
        );
    }

    #[tokio::test]
    async fn device_attestation_roundtrip_verify() {
        use scp_platform::testing::InMemoryDeviceAttestation;
        use scp_platform::traits::DeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Attach device attestation.
        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // Extract token from service entry and verify it.
        let token_bytes = updated_doc.device_attestation_token().unwrap().unwrap();
        let token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
        let verified = attestation.verify(&token).await.unwrap();
        assert!(verified, "roundtrip token should verify successfully");
    }

    #[tokio::test]
    async fn device_attestation_tampered_token_does_not_verify() {
        use scp_platform::testing::InMemoryDeviceAttestation;
        use scp_platform::traits::DeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // Attach device attestation.
        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // Extract and tamper with the token.
        let mut token_bytes = updated_doc.device_attestation_token().unwrap().unwrap();
        assert!(!token_bytes.is_empty());
        // Bitflip the first byte (in the prefix) so the synthetic prefix check
        // fails. The InMemoryDeviceAttestation verifier checks the prefix, so
        // corrupting a prefix byte produces a verifiable false result.
        token_bytes[0] ^= 0xFF;

        let tampered_token = scp_platform::traits::DeviceAttestationToken::new(token_bytes);
        let result = attestation.verify(&tampered_token).await;
        // Should return Ok(false) or an error -- never panic.
        if let Ok(verified) = result {
            assert!(!verified, "tampered token should not verify");
        } // Err is acceptable — tampered token may fail to parse
    }

    #[tokio::test]
    async fn create_without_device_attestation_has_no_service_entry() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // No device attestation service entry when not explicitly attached.
        assert!(!document.has_device_attestation());
        assert!(document.device_attestation_token().unwrap().is_none());
    }

    #[tokio::test]
    async fn device_attestation_service_entry_format() {
        use base64::Engine;
        use scp_platform::testing::InMemoryDeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // Find the service entry and verify format.
        let service = updated_doc
            .service
            .iter()
            .find(|s| s.service_type == "ScpDeviceAttestation")
            .expect("ScpDeviceAttestation service entry should exist");

        assert_eq!(
            service.id,
            format!("{}#device-attestation", identity.did),
            "service ID should use {{did}}#device-attestation format"
        );
        assert_eq!(service.service_type, "ScpDeviceAttestation");
        // Endpoint should be valid base64.
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(&service.service_endpoint)
                .is_ok(),
            "service endpoint should be valid base64"
        );
    }

    #[tokio::test]
    async fn device_attestation_json_roundtrip() {
        use scp_platform::testing::InMemoryDeviceAttestation;

        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = make_dht_with_custody(&custody);
        let attestation = InMemoryDeviceAttestation::new();

        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (_identity, document, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        let updated_doc = dht
            .attach_device_attestation(&document, &attestation)
            .await
            .unwrap();

        // Serialize to JSON and back.
        let json = updated_doc.to_json().unwrap();
        let parsed = DidDocument::from_json(&json).unwrap();

        assert!(parsed.has_device_attestation());
        let original_token = updated_doc.device_attestation_token().unwrap().unwrap();
        let parsed_token = parsed.device_attestation_token().unwrap().unwrap();
        assert_eq!(original_token, parsed_token);
    }

    // -----------------------------------------------------------------------
    // Convenience constructor tests (issue #530)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn with_in_memory_custody_creates_signing_capable_instance() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let dht = DidDht::with_in_memory_custody(Arc::clone(&custody));
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, doc, _pre_rotation_handle) =
            dht.create(&*custody, &*pre_rotation_custody).await.unwrap();

        // DID is valid.
        assert!(identity.did.starts_with("did:dht:z"));
        assert_eq!(doc.id, identity.did);

        // Publish works (signing is wired up).
        dht.publish(&identity, &doc).await.unwrap();

        // Resolve returns the published document.
        let resolved = dht.resolve(&identity.did).await.unwrap();
        assert_eq!(resolved.id, identity.did);
    }

    #[tokio::test]
    async fn create_in_memory_returns_all_components() {
        let (identity, document, custody, did_dht) = DidDht::create_in_memory().await.unwrap();

        // Identity is valid.
        assert!(identity.did.starts_with("did:dht:z"));
        assert_eq!(document.id, identity.did);

        // Custody is functional — can sign with identity keys.
        let sig = custody
            .sign(&identity.active_signing_key, b"test")
            .await
            .unwrap();
        assert_eq!(sig.as_bytes().len(), 64);

        // DidDht is functional — publish and resolve work.
        did_dht.publish(&identity, &document).await.unwrap();
        let resolved = did_dht.resolve(&identity.did).await.unwrap();
        assert_eq!(resolved.id, identity.did);
    }

    #[tokio::test]
    async fn create_in_memory_produces_unique_identities() {
        let (id1, _, _, _) = DidDht::create_in_memory().await.unwrap();
        let (id2, _, _, _) = DidDht::create_in_memory().await.unwrap();
        assert_ne!(id1.did, id2.did, "each call must produce a unique DID");
    }

    // -----------------------------------------------------------------------
    // migrate_identity partial-publish recovery tests
    //
    // These tests assert the typed recovery handle surfaced when one of
    // `migrate_identity`'s two DHT publishes (step 7 or step 8) fails after
    // the irreversible cold-custody mutation (step 5
    // `destroy_after_migration`). Spec §9.7.4.1 and ADR-003 §4b cover the
    // protocol contract; spec §9.7.4.1 governs the resume byte-parity
    // invariant (ADR-046 is a sibling — cross-bridge byte parity at the
    // seed source, not the resume invariant).
    // -----------------------------------------------------------------------

    /// Modes for [`FailingPublishDhtClient`]. Each variant decides what the
    /// next `publish` call does.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FailingPublishMode {
        /// All publishes succeed and are forwarded to the inner
        /// [`InMemoryDhtClient`].
        Healthy,
        /// Fail the FIRST publish (the step-7 publish of the NEW DID
        /// document in `migrate_identity`).
        FailOnNew,
        /// Forward the first publish (step 7) but fail the second (step 8
        /// republish of the OLD document with `alsoKnownAs`).
        FailOnOldAfterNew,
    }

    /// DHT client that records publish order and can be driven to fail on
    /// either the first or second publish during a single migration. Used
    /// to construct controlled partial-publish failures.
    ///
    /// Mode is read once at the start of each `publish` and reflected in
    /// the recorded outcome — the harness flips the mode atomically
    /// between `migrate_identity` calls when simulating Failing → Healthy
    /// transitions.
    struct FailingPublishDhtClient {
        published: tokio::sync::Mutex<Vec<String>>,
        call_count: std::sync::atomic::AtomicUsize,
        mode: tokio::sync::Mutex<FailingPublishMode>,
        inner: InMemoryDhtClient,
    }

    impl FailingPublishDhtClient {
        fn new(initial_mode: FailingPublishMode) -> Self {
            Self {
                published: tokio::sync::Mutex::new(Vec::new()),
                call_count: std::sync::atomic::AtomicUsize::new(0),
                mode: tokio::sync::Mutex::new(initial_mode),
                inner: InMemoryDhtClient::new(),
            }
        }

        async fn set_mode(&self, mode: FailingPublishMode) {
            *self.mode.lock().await = mode;
        }

        async fn snapshot(&self) -> Vec<String> {
            self.published.lock().await.clone()
        }
    }

    #[allow(clippy::manual_async_fn)]
    impl DhtClient for FailingPublishDhtClient {
        fn publish(
            &self,
            public_key: &[u8; 32],
            signature: &[u8; 64],
            value: &[u8],
            seq: u64,
        ) -> impl Future<Output = Result<(), IdentityError>> + Send {
            let pk = *public_key;
            let sig = *signature;
            let val = value.to_vec();
            async move {
                let mode = *self.mode.lock().await;
                // Track call index BEFORE deciding to fail so the
                // recorded order reflects what migrate_identity attempted.
                let idx = self
                    .call_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let did = format!("did:dht:z{}", zbase32::encode(&pk));
                match mode {
                    FailingPublishMode::FailOnNew => {
                        // Don't record: nothing actually hit the wire.
                        return Err(IdentityError::DhtPublishFailed(
                            "simulated step-7 publish failure".to_owned(),
                        ));
                    }
                    FailingPublishMode::FailOnOldAfterNew if idx == 1 => {
                        // The OLD republish (second publish in migrate_identity).
                        // Don't record — it failed.
                        return Err(IdentityError::DhtPublishFailed(
                            "simulated step-8 publish failure".to_owned(),
                        ));
                    }
                    _ => {}
                }
                self.published.lock().await.push(did);
                self.inner.publish(&pk, &sig, &val, seq).await
            }
        }

        fn resolve(
            &self,
            public_key: &[u8; 32],
        ) -> impl Future<Output = Result<Option<crate::dht_client::DhtRecord>, IdentityError>> + Send
        {
            let pk = *public_key;
            async move { self.inner.resolve(&pk).await }
        }
    }

    /// Helper: builds a `DidDht` over a [`FailingPublishDhtClient`] sharing
    /// the supplied custody for signing. Mirrors `make_dht_with_custody`
    /// but parameterized on the failing client.
    fn make_dht_with_failing_client(
        custody: &Arc<InMemoryKeyCustody>,
        client: Arc<FailingPublishDhtClient>,
    ) -> DidDht<FailingPublishDhtClient, Arc<TestClock>> {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = Arc::new(DidCache::with_clock(clock));
        let sign_fn =
            DidDht::<FailingPublishDhtClient, Arc<TestClock>>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(client, cache, sign_fn)
    }

    /// Builds a published source identity + handles the failing-client
    /// setup needs to drive a migration attempt. Returns the published
    /// document so callers can pass it back to `migrate_identity`.
    async fn setup_failing_migration_inputs(
        custody: &Arc<InMemoryKeyCustody>,
        dht: &DidDht<FailingPublishDhtClient, Arc<TestClock>>,
    ) -> (
        ScpIdentity,
        DidDocument,
        PreRotationKeyHandle,
        Arc<scp_platform::testing::InMemoryPreRotationCustody>,
    ) {
        let pre_rotation_custody =
            Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, pre_rotation_handle) = dht
            .create(&**custody, &*pre_rotation_custody)
            .await
            .unwrap();
        // Publish the source document so the recorder starts in a known
        // post-create state. This uses ONE publish slot of the recorder.
        dht.publish_document(&identity, &document).await.unwrap();
        (
            identity,
            document,
            pre_rotation_handle,
            pre_rotation_custody,
        )
    }

    /// Step 7 fails: the partial state MUST carry the new identity, the
    /// new document, the freshly-registered pre-rotation handle (with
    /// `revealed_key` matching the commitment), and the unchanged OLD
    /// identity. Cold custody MUST already hold the new pre-rotation key.
    #[tokio::test]
    async fn migrate_identity_returns_publish_failed_when_new_publish_fails() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        // Source identity is created and published with the client in
        // Healthy mode, then we flip to FailOnNew.
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        client.set_mode(FailingPublishMode::FailOnNew).await;

        let rotated_at = 1_700_000_000u64;
        let err = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .expect_err("publish failure must surface as Err");

        let partial = err
            .as_migration_partial()
            .expect("must be MigrationPublishFailed { PublishNew, .. }");
        assert_eq!(partial.phase(), MigrationResumePhase::PublishNew);

        // The new DID differs from the source DID — the migration
        // produced a brand-new self-cert DID even though publish failed.
        assert_ne!(partial.new_did(), identity.did);

        // Step-7 failure invariant: step 7b has NOT run yet, so the OLD
        // operational keys (`#active`, optionally `#agent`) AND the OLD
        // `#0` MUST all still be live in operational custody. Verifies
        // the symmetric contract to the step-8-failure test below
        // (which asserts `#active` IS destroyed because step 7b DID
        // run before step 8 was attempted).
        assert!(
            custody
                .public_key(&identity.active_signing_key)
                .await
                .is_ok(),
            "PublishNew failure must NOT destroy OLD #active key (step 7b hasn't run)"
        );
        assert!(
            custody.public_key(&identity.identity_key).await.is_ok(),
            "PublishNew failure must retain OLD #0 (signs the step-8 republish on resume)"
        );
        if let Some(agent) = identity.agent_signing_key {
            assert!(
                custody.public_key(&agent).await.is_ok(),
                "PublishNew failure must NOT destroy OLD #agent (step 7b hasn't run)"
            );
        }

        // SHA-256(revealed_key) MUST equal the OLD document's
        // PreRotationCommitment service entry's commitment. The OLD doc
        // is the one captured in `partial.old_document` — which is the
        // same `document` we published.
        let revealed_key = partial
            .rotation_event
            .pre_rotation_proof
            .as_ref()
            .expect("STRONG-assurance migration must carry pre_rotation_proof")
            .revealed_key;
        let hashed_revealed: [u8; 32] = Sha256::digest(revealed_key).into();
        let service_endpoint = &partial
            .old_document
            .pre_rotation_service()
            .expect("OLD document published a PreRotationCommitment service")
            .service_endpoint;
        let hex_part = service_endpoint
            .strip_prefix("sha256:")
            .expect("PreRotationCommitment serviceEndpoint MUST be sha256:<hex>");
        let commitment_bytes: [u8; 32] = hex::decode(hex_part)
            .expect("commitment is valid hex")
            .try_into()
            .expect("commitment is 32 bytes");
        assert_eq!(
            hashed_revealed, commitment_bytes,
            "SHA-256(revealed_key) MUST equal the published commitment (spec §9.7.4.1 byte parity invariant)"
        );

        // The freshly-registered new pre-rotation handle MUST be live in
        // cold custody — step 4 succeeded before step 7 was reached.
        pre_rotation_custody
            .reveal_public_key(&partial.new_pre_rotation_handle)
            .await
            .expect("new_pre_rotation_handle must be registered in cold custody");
    }

    /// Step 8 fails: the partial state MUST carry phase
    /// `RepublishOldAlsoKnownAs`, and the OLD `#active` MUST already be
    /// destroyed (step 7b ran). The OLD `#0` MUST still be present.
    #[tokio::test]
    async fn migrate_identity_returns_publish_failed_when_old_republish_fails() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        // Reset the call count so FailOnOldAfterNew fires on the 2nd
        // call made by migrate_identity (not the source-publish call).
        client
            .call_count
            .store(0, std::sync::atomic::Ordering::SeqCst);
        client.set_mode(FailingPublishMode::FailOnOldAfterNew).await;

        let old_active = identity.active_signing_key;
        let old_identity_key = identity.identity_key;

        let rotated_at = 1_700_000_000u64;
        let err = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .expect_err("step-8 publish failure must surface as Err");

        let partial = err
            .as_migration_partial()
            .expect("must be MigrationPublishFailed { RepublishOldAlsoKnownAs, .. }");
        assert_eq!(
            partial.phase(),
            MigrationResumePhase::RepublishOldAlsoKnownAs
        );

        // OLD `#active` MUST be destroyed (step 7b ran before step 8).
        let after_active = custody.public_key(&old_active).await;
        assert!(
            matches!(after_active, Err(scp_platform::PlatformError::KeyNotFound)),
            "OLD #active MUST be destroyed before step 8 runs; got {after_active:?}"
        );

        // OLD `#0` MUST be retained — the resume path needs it to sign
        // the step-8 republish.
        custody
            .public_key(&old_identity_key)
            .await
            .expect("OLD #0 MUST be retained for resume to sign step 8");
    }

    /// After a step-7 failure, swap the client to Healthy and call
    /// resume. Result MUST equal the would-be first-pass success, and
    /// the migration-side publish order MUST be `[new_did, old_did]`.
    #[tokio::test]
    async fn resume_migration_publish_completes_after_publish_new_failure() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        let pre_migration_publishes = client.snapshot().await.len();

        client.set_mode(FailingPublishMode::FailOnNew).await;
        let rotated_at = 1_700_000_000u64;
        let err = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .expect_err("step-7 publish failure must surface as Err");
        let partial = err
            .into_migration_partial()
            .expect("must be MigrationPublishFailed { PublishNew, .. }");

        // Snapshot expected return artifacts BEFORE moving into resume.
        let expected_new_did = partial.new_identity.did.clone();
        let expected_new_doc = partial.new_document.clone();
        let expected_event = partial.rotation_event.clone();
        let expected_new_handle = partial.new_pre_rotation_handle;

        // Heal the client and resume.
        client.set_mode(FailingPublishMode::Healthy).await;
        let MigrationOutcome {
            new_identity: resumed_identity,
            new_document: resumed_doc,
            rotation_event: resumed_event,
            new_pre_rotation_handle: resumed_handle,
        } = dht
            .resume_migration_publish(partial, &*custody)
            .await
            .expect("resume MUST complete on a healthy client");

        assert_eq!(resumed_identity.did, expected_new_did);
        assert_eq!(resumed_doc, expected_new_doc);
        assert_eq!(resumed_event, expected_event);
        assert_eq!(resumed_handle, expected_new_handle);

        // Resume must have performed exactly [new_did, old_did] in that
        // order on the wire (step 7 then step 8).
        let after = client.snapshot().await;
        let migration_publishes = &after[pre_migration_publishes..];
        assert_eq!(
            migration_publishes.len(),
            2,
            "resume of a PublishNew failure must publish exactly the new DID then the old DID; got {migration_publishes:?}"
        );
        assert_eq!(migration_publishes[0], expected_new_did);
        assert_eq!(migration_publishes[1], identity.did);
    }

    /// After a step-8 failure, swap the client to Healthy and call
    /// resume. Only ONE additional publish (the OLD republish) must
    /// occur — the resume MUST NOT re-publish the NEW document.
    #[tokio::test]
    async fn resume_migration_publish_completes_after_old_republish_failure() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        // FailOnOldAfterNew fires on the 2nd publish — reset count.
        client
            .call_count
            .store(0, std::sync::atomic::Ordering::SeqCst);
        client.set_mode(FailingPublishMode::FailOnOldAfterNew).await;

        let publishes_before_migrate = client.snapshot().await.len();
        let rotated_at = 1_700_000_000u64;
        let err = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .expect_err("step-8 publish failure must surface as Err");
        let partial = err
            .into_migration_partial()
            .expect("must be MigrationPublishFailed");
        assert_eq!(
            partial.phase(),
            MigrationResumePhase::RepublishOldAlsoKnownAs
        );

        // The failed migration attempt published ONE document (step 7
        // succeeded; step 8 was rejected). Snapshot now to count the
        // delta from resume in isolation.
        let publishes_before_resume = client.snapshot().await.len();
        assert_eq!(
            publishes_before_resume - publishes_before_migrate,
            1,
            "step 7 succeeded, step 8 did not — exactly one publish must be on the wire"
        );

        client.set_mode(FailingPublishMode::Healthy).await;
        dht.resume_migration_publish(partial, &*custody)
            .await
            .expect("resume MUST complete on a healthy client");

        let publishes_after_resume = client.snapshot().await.len();
        assert_eq!(
            publishes_after_resume - publishes_before_resume,
            1,
            "resume of a RepublishOldAlsoKnownAs failure must perform EXACTLY one publish (step 8 only), NOT re-publish the new document"
        );
    }

    /// Idempotency: calling resume twice on a healthy client after a
    /// step-7 failure MUST both succeed. The second call republishes
    /// byte-identical documents under fresh BEP44 sequence numbers.
    #[tokio::test]
    async fn resume_migration_publish_is_idempotent() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        client.set_mode(FailingPublishMode::FailOnNew).await;
        let rotated_at = 1_700_000_000u64;
        let err = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .expect_err("step-7 publish failure must surface as Err");
        let partial = err
            .into_migration_partial()
            .expect("must be MigrationPublishFailed");

        client.set_mode(FailingPublishMode::Healthy).await;
        let first = dht
            .resume_migration_publish(partial.clone(), &*custody)
            .await
            .expect("first resume MUST succeed");
        let second = dht
            .resume_migration_publish(partial, &*custody)
            .await
            .expect("second resume MUST succeed (idempotent under BEP44 monotonicity)");

        assert_eq!(first.new_identity.did, second.new_identity.did);
        assert_eq!(first.new_document, second.new_document);
        assert_eq!(first.rotation_event, second.rotation_event);
        assert_eq!(
            first.new_pre_rotation_handle,
            second.new_pre_rotation_handle
        );
    }

    /// Byte-parity gate (spec §9.7.4.1): the
    /// `SHA-256(revealed_key) == commitment` invariant on the carried
    /// `rotation_event` MUST hold byte-for-byte BOTH before and after
    /// resume. Resume MUST NOT re-derive or re-sign.
    #[tokio::test]
    async fn resume_migration_publish_preserves_sha256_commitment_invariant() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        client.set_mode(FailingPublishMode::FailOnNew).await;
        let rotated_at = 1_700_000_000u64;
        let err = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .expect_err("step-7 publish failure must surface as Err");
        let partial = err
            .into_migration_partial()
            .expect("must be MigrationPublishFailed");

        // BEFORE-resume gate.
        let before_proof = partial
            .rotation_event
            .pre_rotation_proof
            .as_ref()
            .expect("STRONG-assurance migration must carry pre_rotation_proof")
            .clone();
        let new_pre_rotation_pub_bytes = pre_rotation_custody
            .reveal_public_key(&partial.new_pre_rotation_handle)
            .await
            .expect("new pre-rotation handle MUST be live in cold custody");
        // The carried `revealed_key` is the OLD pre-rotation public — the
        // bytes that were revealed at step 1 of migrate_identity (NOT the
        // new pre-rotation public). The byte-parity invariant binds those
        // bytes to the OLD document's commitment.
        let old_service_endpoint = &partial
            .old_document
            .pre_rotation_service()
            .expect("OLD doc publishes a PreRotationCommitment service")
            .service_endpoint;
        let old_hex = old_service_endpoint
            .strip_prefix("sha256:")
            .expect("serviceEndpoint MUST be sha256:<hex>");
        let old_commitment_bytes: [u8; 32] = hex::decode(old_hex)
            .expect("commitment hex valid")
            .try_into()
            .expect("commitment is 32 bytes");
        let hashed_revealed_before: [u8; 32] = Sha256::digest(before_proof.revealed_key).into();
        assert_eq!(hashed_revealed_before, old_commitment_bytes);
        assert_eq!(before_proof.commitment, old_commitment_bytes);

        // The NEW document's commitment binds the NEW pre-rotation
        // public — independent invariant, also checked before resume.
        let new_doc_service_endpoint = &partial
            .new_document
            .pre_rotation_service()
            .expect("NEW doc publishes a PreRotationCommitment service")
            .service_endpoint;
        let new_hex = new_doc_service_endpoint
            .strip_prefix("sha256:")
            .expect("serviceEndpoint MUST be sha256:<hex>");
        let new_commitment_bytes: [u8; 32] = hex::decode(new_hex)
            .expect("commitment hex valid")
            .try_into()
            .expect("commitment is 32 bytes");
        let hashed_new_pre_rot_before: [u8; 32] = Sha256::digest(new_pre_rotation_pub_bytes).into();
        assert_eq!(hashed_new_pre_rot_before, new_commitment_bytes);

        // Heal and resume.
        client.set_mode(FailingPublishMode::Healthy).await;
        let MigrationOutcome {
            new_identity: resumed_identity,
            new_document: resumed_doc,
            rotation_event: resumed_event,
            new_pre_rotation_handle: resumed_handle,
        } = dht
            .resume_migration_publish(partial, &*custody)
            .await
            .expect("resume MUST succeed");

        // AFTER-resume gate: byte-identical proof bytes.
        let after_proof = resumed_event
            .pre_rotation_proof
            .as_ref()
            .expect("resumed event MUST carry pre_rotation_proof");
        assert_eq!(before_proof.revealed_key, after_proof.revealed_key);
        assert_eq!(before_proof.commitment, after_proof.commitment);
        let hashed_revealed_after: [u8; 32] = Sha256::digest(after_proof.revealed_key).into();
        assert_eq!(hashed_revealed_after, old_commitment_bytes);

        // The resumed return MUST also publish a document whose commitment
        // hashes the resumed new pre-rotation public byte-for-byte.
        let resumed_pre_rot_pub_bytes = pre_rotation_custody
            .reveal_public_key(&resumed_handle)
            .await
            .expect("resumed pre-rotation handle MUST be live");
        let hashed_resumed: [u8; 32] = Sha256::digest(resumed_pre_rot_pub_bytes).into();
        let resumed_endpoint = &resumed_doc
            .pre_rotation_service()
            .expect("resumed doc publishes PreRotationCommitment service")
            .service_endpoint;
        let resumed_hex = resumed_endpoint
            .strip_prefix("sha256:")
            .expect("serviceEndpoint MUST be sha256:<hex>");
        let resumed_commitment: [u8; 32] = hex::decode(resumed_hex)
            .expect("commitment hex valid")
            .try_into()
            .expect("commitment is 32 bytes");
        assert_eq!(hashed_resumed, resumed_commitment);
        // And the resumed identity's DID is unchanged — same key, same DID.
        assert_eq!(resumed_identity.did, resumed_doc.id);
    }

    /// Driving Failing → Failing: the second `MigrationPublishFailed`
    /// MUST carry partial-state fields equal to the first's. Resume
    /// re-uses carried artifacts verbatim — no field is re-derived.
    #[tokio::test]
    async fn resume_migration_publish_failure_carries_same_partial_state() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        client.set_mode(FailingPublishMode::FailOnNew).await;
        let rotated_at = 1_700_000_000u64;
        let err_first = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .expect_err("first attempt MUST fail at step 7");
        let first = err_first
            .into_migration_partial()
            .expect("must be MigrationPublishFailed");

        // Drive resume into another failure (client still FailOnNew).
        let err_second = dht
            .resume_migration_publish(first.clone(), &*custody)
            .await
            .expect_err("resume MUST also fail while client is still FailOnNew");
        let second = err_second
            .into_migration_partial()
            .expect("must be MigrationPublishFailed");

        assert_eq!(first.phase, second.phase);
        assert_eq!(first.new_identity.did, second.new_identity.did);
        assert_eq!(first.new_document, second.new_document);
        assert_eq!(first.rotation_event, second.rotation_event);
        assert_eq!(
            first.new_pre_rotation_handle,
            second.new_pre_rotation_handle
        );
        assert_eq!(first.old_identity.did, second.old_identity.did);
        assert_eq!(first.old_document, second.old_document);
    }

    /// S2: pre-flight custody-substrate check. If the caller passes a
    /// different `KeyCustody` instance to `resume_migration_publish`
    /// than was passed to the original `migrate_identity`, every later
    /// sign / `public_key` call inside the publish chain would surface
    /// `PlatformError::KeyNotFound` from the BEP44 signing step,
    /// wrapped as `MigrationPublishFailed` — the diagnostic would read
    /// "publish failed at signing step." The pre-flight probe surfaces
    /// the substrate mismatch as a clean `IdentityError::Platform`
    /// BEFORE any DHT publish runs, so the SDK / operator gets the
    /// precise diagnostic and no DHT side-effects accumulate.
    #[tokio::test]
    async fn resume_migration_publish_fails_fast_on_custody_mismatch() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, document, pre_rotation_handle, pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        // Drive a step-7 failure so we have a partial state to resume.
        client.set_mode(FailingPublishMode::FailOnNew).await;
        let rotated_at = 1_700_000_000u64;
        let err = dht
            .migrate_identity(
                &identity,
                &document,
                &pre_rotation_handle,
                &*pre_rotation_custody,
                &*custody,
                rotated_at,
            )
            .await
            .expect_err("step-7 publish failure must surface as Err");
        let partial = err
            .into_migration_partial()
            .expect("must be MigrationPublishFailed");

        // Snapshot DHT state BEFORE the mismatched-custody resume.
        let publishes_before = client.snapshot().await.len();
        client.set_mode(FailingPublishMode::Healthy).await;

        // Pass a FRESH custody instance — its handle namespace is
        // disjoint from the one used at migrate_identity time, so the
        // OLD `#0` handle (and the NEW `#0` handle) will not resolve.
        let foreign_custody = Arc::new(InMemoryKeyCustody::new());
        let resume_err = dht
            .resume_migration_publish(partial, &*foreign_custody)
            .await
            .expect_err("resume MUST fail fast on a mismatched custody substrate");

        // The surfaced error MUST be Platform(KeyNotFound), NOT
        // MigrationPublishFailed — the substrate mismatch is caught
        // before any publish runs.
        match &resume_err {
            IdentityError::Platform(scp_platform::PlatformError::KeyNotFound) => {}
            other => panic!(
                "expected IdentityError::Platform(KeyNotFound) from substrate \
                 mismatch pre-flight, got {other:?}"
            ),
        }

        // No DHT side-effects must have accumulated — the pre-flight
        // ran BEFORE any publish_document call.
        let publishes_after = client.snapshot().await.len();
        assert_eq!(
            publishes_before, publishes_after,
            "pre-flight substrate check must run before any DHT publish; \
             a mismatched custody must produce zero on-wire publishes"
        );
    }

    /// S6: `destroy_old_operational_keys` MUST be idempotent. A
    /// `PublishNew`-phase resume calls this function unconditionally
    /// after step 7 succeeds, even though the original first-pass
    /// attempt may have already destroyed the OLD `#active` / `#agent`
    /// before its step-8 publish failed. Re-invocation must be a no-op
    /// — per-key `KeyNotFound` failures swallow to `tracing::warn!`,
    /// not propagated as `Err`. Pinning test: weakening this contract
    /// would break the resume path.
    #[tokio::test]
    async fn destroy_old_operational_keys_is_idempotent_when_keys_already_gone() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let client = Arc::new(FailingPublishDhtClient::new(FailingPublishMode::Healthy));
        let dht = make_dht_with_failing_client(&custody, Arc::clone(&client));
        let (identity, _document, _pre_rotation_handle, _pre_rotation_custody) =
            setup_failing_migration_inputs(&custody, &dht).await;

        // Construct an `agent_signing_key` so the function exercises
        // both `#active` and `#agent` arms of the destroy loop.
        let agent_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let identity_with_agent = ScpIdentity {
            identity_key: identity.identity_key,
            active_signing_key: identity.active_signing_key,
            agent_signing_key: Some(agent_handle),
            pre_rotation_commitment: identity.pre_rotation_commitment,
            did: identity.did.clone(),
        };

        // First call: both keys live → both destroyed cleanly.
        destroy_old_operational_keys(&*custody, &identity_with_agent).await;
        // Sanity-check: both keys are now gone.
        assert!(
            matches!(
                custody
                    .public_key(&identity_with_agent.active_signing_key)
                    .await,
                Err(scp_platform::PlatformError::KeyNotFound)
            ),
            "first call MUST have destroyed OLD #active"
        );
        assert!(
            matches!(
                custody
                    .public_key(identity_with_agent.agent_signing_key.as_ref().unwrap())
                    .await,
                Err(scp_platform::PlatformError::KeyNotFound)
            ),
            "first call MUST have destroyed OLD #agent"
        );

        // Second call: both keys already gone — every `destroy_key`
        // surfaces `KeyNotFound`. The function MUST swallow them as
        // `tracing::warn!` and return normally (the function's return
        // type is `()`, so any panic / `?` would surface as a panic
        // here). This is the idempotency contract that
        // `run_migration_publish_chain` relies on for resume.
        destroy_old_operational_keys(&*custody, &identity_with_agent).await;
    }
}
