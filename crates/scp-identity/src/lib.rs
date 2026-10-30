#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Decentralized identity (DID) management for SCP.
//!
//! This module implements decentralized identity (DID) creation, verification,
//! and document management for the SCP protocol. The primary DID method is
//! `did:dht`, which uses the `BitTorrent` Mainline DHT for resolution and the
//! Ed25519 public key as the self-certifying identifier.
//!
//! # Architecture
//!
//! - [`dht::ScpIdentity`] — The identity handle containing key handles, DID string,
//!   and pre-rotation commitment.
//! - [`DidMethod`] — Abstract trait enabling DID method swaps (e.g., `did:web`
//!   fallback) without changing calling code.
//! - [`DidDht`] — The `did:dht` implementation of [`DidMethod`].
//! - [`DidDocument`] — W3C DID Document JSON-LD construction and serialization.
//!
//! # Key Separation
//!
//! SCP separates four key roles (three verification methods per ADR-039):
//! 1. **Identity Key (`#0`)** — Derives the DID string. Highest-security custody
//!    (hardware-backed). Used only for DID document updates. Never rotates.
//! 2. **Active Signing Key (`#active`)** — Human's operational key. Used for MLS,
//!    envelopes, UCANs. Rotatable via Layer 1 rotation.
//! 3. **Agent Signing Key (`#agent`)** — Optional. Software-held key for autonomous
//!    agent operations. Rotatable independently. Generated only when agent
//!    delegation is needed. See ADR-039.
//! 4. **Pre-Rotation Key** — Cold/offline custody. Provides the commitment
//!    for identity migration.
//!
//! See ADR-003 and ADR-039 in `.docs/adrs/phase-1.md` for the full design.

pub mod cache;
pub mod dht;
pub mod kel;
pub mod push_verify;
pub mod relay_querier;
pub mod republish;
pub mod resolution;
pub mod resolver;

pub use cache::{DidCache, DidResolutionResult, Staleness};
#[cfg(any(test, feature = "testing"))]
pub use dht::InMemorySequenceStore;
pub use dht::{
    DidDht, MigrationOutcome, MigrationPartialState, MigrationResumePhase, PostResolveHook,
    SequenceStore, did_from_ed25519_public_key, extract_public_key, verify_migration,
    verify_self_certification,
};
pub use kel::{
    CleanupFailure, CreateError, Created, CreationId, ErasedKeyCustody, ErasedNextSetCustody,
    EventOutcome, GroupSigners, Identity, IdentityConfig, IdentityError, KeptComposition,
    KeyCustodySlot, ListedOperator, NextSetCustodySlot, PendingEvent, RecordLock, ScpIdentity,
    SignerPlan, UndestroyedKey, Unfinished, WitnessChoice, WitnessDesignation, WitnessWarning,
    default_witness_set, parse_identifier, verify_did,
};
#[cfg(any(test, feature = "testing"))]
pub use push_verify::TestPushVerifier;
pub use push_verify::{KelPushVerifier, PushMessage, PushSignatureVerifier, PushVerifyError};
pub use relay_querier::RealMultiRelayQuerier;
pub use republish::RepublishManager;
// The three DID→`routing_id` derivations are re-exported SYMMETRICALLY: they
// are one family (`did_routing_id` ∘ key ∘ frame, see `resolution`), and
// root-exporting only some of them would push consumers back to module paths
// for the rest — the drift that let a production site re-inline the
// composition.
#[cfg(any(test, feature = "testing"))]
pub use resolution::InMemoryRelayQuerier;
pub use resolution::{
    RelayQuerier, RelayQueryRecord, did_key_routing_id, did_record_routing_id, did_routing_id,
};
pub use resolver::{
    DidResolver, DualLayerHealingPublisher, DualLayerResolver, HealingPublisher, MultiRelayQuerier,
    NoHealing, NoOpRelayQuerier, ResolutionSource, ResolvedDidDocument, StaleLayer,
};

use scp_did::DidDocument;
use scp_platform::traits::{KeyCustody, PreRotationCustody, PreRotationKeyHandle};

/// Abstract trait for DID method implementations.
///
/// # This trait names `did:dht` concepts, and ADR-003 acceptance criterion 6 wants it not to
///
/// ADR-003 acceptance criterion 6 in `.docs/adrs/phase-1.md` describes this
/// trait as "enabling did:web fallback swap without changing calling code".
/// Three of its members contradict that today, so a `DidWeb` cannot implement it
/// as written:
///
/// - [`publish`](Self::publish) returns a [`republish::RepublishEntry`], a BEP44
///   `(public_key, seq, signature, value)` record whose
///   [`did()`](republish::RepublishEntry::did) derives a `did:dht` string.
/// - [`initialize_sequence`](Self::initialize_sequence) is defined in terms of a
///   monotonic BEP44 sequence.
/// - [`Dht`](Self::Dht) names a [`DhtClient`](scp_dht::DhtClient).
///
/// Retiring criterion 6 or splitting the `did:dht` members onto a subtrait is an
/// open decision for a human; nothing here decides it. Read this section as the
/// current state of the trait rather than as an argument for either answer.
///
/// # Implementors
///
/// - [`DidDht`] — Primary implementation using the `BitTorrent` Mainline DHT.
///
/// # Async Methods
///
/// All methods are async because production implementations may involve
/// network I/O (DHT publish/resolve) or hardware security module access.
pub trait DidMethod: Send + Sync {
    /// The DHT client this method signs records onto, and the same client that
    /// keeps those records resolvable.
    ///
    /// Publishing a DID document signs `(public_key, seq, signature, value)`
    /// once. Mainline DHT records expire, so §3.10.5 step 4 of the identity spec
    /// schedules a keep-alive that re-puts those exact bytes under that exact
    /// sequence, and
    /// [`RepublishManager`] — the type §3.10.5 names
    /// for the job — takes a [`DhtClient`](scp_dht::DhtClient). This associated
    /// type is where a node that holds only a `DidMethod` obtains one.
    ///
    /// Binding the keep-alive client to the method that signs is the whole point:
    /// a node that took the client as a second, free parameter could pair a
    /// record signed by one method with a client that puts it somewhere else.
    type Dht: scp_dht::DhtClient + 'static;

    /// A shared handle on [`Dht`](Self::Dht).
    ///
    /// Returned by value because every caller clones the `Arc` anyway: the
    /// keep-alive task outlives the borrow.
    fn dht_client(&self) -> std::sync::Arc<Self::Dht>;

    /// Creates a new identity with three Ed25519 keypairs.
    ///
    /// Generates the Identity Key and Active Signing Key in the operational
    /// `key_custody`. Generates an ephemeral pre-rotation keypair, hashes
    /// the public key as the `PreRotationCommitment`, hands the private
    /// bytes off to the cold-storage `pre_rotation_custody`, and discards
    /// the operational copy (spec §9.7.4.1 §1, §5(a), §5(f)). The two
    /// custodies MUST be distinct instances on distinct substrates per
    /// §9.7.4.1 §3 (storage isolation).
    ///
    /// Returns the [`ScpIdentity`](dht::ScpIdentity) handle, the constructed [`DidDocument`],
    /// and the [`PreRotationKeyHandle`] referencing the cold-stored
    /// pre-rotation key. The caller persists the handle alongside the
    /// identity so it can be presented to `migrate_identity` later.
    ///
    /// See ADR-003 acceptance criterion 1.
    fn create(
        &self,
        key_custody: &impl KeyCustody,
        pre_rotation_custody: &impl PreRotationCustody,
    ) -> impl Future<
        Output = Result<(dht::ScpIdentity, DidDocument, PreRotationKeyHandle), dht::IdentityError>,
    > + Send;

    /// Verifies that a DID string is self-certifying for the given public key.
    ///
    /// Decodes the z-base-32 suffix of the DID and compares it to the provided
    /// public key bytes. This is a local operation with no network I/O.
    ///
    /// See ADR-003 acceptance criterion 5.
    fn verify(&self, did_string: &str, public_key: &[u8]) -> bool;

    /// Publishes a DID document to the underlying DID infrastructure and
    /// returns the **signed BEP44 record it just produced**.
    ///
    /// For `did:dht`, this publishes to the Mainline DHT as a BEP44 signed
    /// mutable item. See ADR-003 acceptance criterion 2.
    ///
    /// # The signed record is an output of signing, never a read-back
    ///
    /// Signing already computes `(public_key, seq, signature, value)`;
    /// returning it means every downstream consumer — the relay layer
    /// (§3.10.5), the republish cycle (§3.10.5 step 4) — receives the
    /// byte-identical triple the publisher signed. Discarding it forced callers
    /// to reconstruct the triple by resolving the record back off the network,
    /// which (a) makes a node's own republishing depend on a remote read
    /// succeeding, (b) pins whatever a responder returns with no check against
    /// the locally-known sequence, and (c) freezes at the first read so an
    /// in-lifetime rotation is never re-seeded. The record is returned so that
    /// re-derivation is unnecessary and, structurally, not a thing a caller can
    /// be tempted into.
    ///
    /// # Errors
    ///
    /// Returns an [`IdentityError`](dht::IdentityError) if signing or the underlying publish fails.
    /// An implementation that cannot publish MUST return a typed error — never
    /// a fabricated record.
    fn publish(
        &self,
        identity: &dht::ScpIdentity,
        document: &DidDocument,
    ) -> impl Future<Output = Result<republish::RepublishEntry, dht::IdentityError>> + Send;

    /// Bootstraps this method's monotonic publish sequence counter to the
    /// highest value known across its persistent store and the live network
    /// record, so the NEXT [`publish`](Self::publish) supersedes rather than
    /// collides with an existing record.
    ///
    /// Must be called BEFORE the first publish of a process's lifetime (e.g. a
    /// node's startup publish): a fresh counter starts at 0 and would otherwise
    /// publish at `seq = 1`, which on a restart-within-TTL lands *beneath* a
    /// live `seq = N` record — the real DHT rejects the lower-seq write while the
    /// old (possibly superseded) document stays authoritative. See
    /// `build_domain_inner` / `build_no_domain_inner` in `scp-node`, which call
    /// this inside the builder ahead of the startup publish.
    ///
    /// The default is a no-op success: a DID method with no monotonic-sequence
    /// semantics (nothing to bootstrap) legitimately has nothing to initialize.
    /// `did:dht` overrides it to recover its BEP44 sequence from the store and/or
    /// a DHT resolve. A resolve failure there is fail-closed (propagated): the
    /// caller must not publish at an unknown sequence.
    ///
    /// **Implementors:** any method with monotonic BEP44-style sequence
    /// semantics MUST override this to bootstrap its counter to
    /// `max(persisted, live)` before the first publish. Inheriting the no-op
    /// default reintroduces the restart-within-TTL collision this method exists
    /// to prevent: a fresh counter republishes at `seq = 1` beneath a live
    /// `seq = N` record, and the network rejects the lower-seq write (fail-open —
    /// the stale document stays authoritative). The default is correct ONLY for
    /// methods with no monotonic-sequence semantics at all.
    fn initialize_sequence(
        &self,
        _did: &str,
    ) -> impl Future<Output = Result<(), dht::IdentityError>> + Send {
        async { Ok(()) }
    }

    /// Resolves a DID string to its DID document via the underlying infrastructure.
    ///
    /// For `did:dht`, this performs a Mainline DHT lookup. See ADR-003
    /// acceptance criterion 3.
    ///
    /// **Note:** This method is defined in the trait for completeness but is
    /// implemented in story SCP-007, not SCP-006.
    fn resolve(
        &self,
        did_string: &str,
    ) -> impl Future<Output = Result<DidDocument, dht::IdentityError>> + Send;

    /// Rotates the active signing key for an identity.
    ///
    /// Generates a new Active Signing Key, updates the DID document, and
    /// publishes the update. See ADR-003 acceptance criterion 4a.
    ///
    /// **Note:** This method is defined in the trait for completeness but is
    /// implemented in story SCP-008, not SCP-006.
    fn rotate(
        &self,
        identity: &dht::ScpIdentity,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(dht::ScpIdentity, DidDocument), dht::IdentityError>> + Send;
}
