//! The node's public-record store (`09-security-model.md` §9.10.12,
//! `10-infrastructure-and-self-hosting.md` §10.4 "Every conforming node
//! validates public records").
//!
//! [`NodePublicRecords`] is the [`PublicRecordStore`] every transport of a
//! node reaches storage through. It admits each retained kind under the
//! §9.10.12 table's admission rule, keeps what the kind's selection keeps,
//! and charges the §9.18.B quota classes. The blob store is the record of
//! what it holds: each write recomputes the selection at its routing id from
//! what the store holds, so a restart, a second process or a reloaded store
//! selects the same records. The one thing it keeps beside the store is a
//! bounded cache of replayed key-event logs, which it checks against the
//! store's frames on every read (see `selection::LogCache`).
//!
//! # Locks
//!
//! Each admission reads the records it selects against, so a write between
//! that read and its own store would select against records it never read.
//! The store serializes writes per routing id, not node-wide:
//!
//! - a retained write holds its routing id's lock; a key-event write at an
//!   identity's `scp:did:` routing id then takes, one at a time, the locks of
//!   the routing ids it reselects (the identity's `scp:svc:` and `scp:wcf:`
//!   ids and each pinned `scp:nls:` id the identity governs);
//! - a TTL write holds a lock of its routing id that no retained write takes;
//! - every write and DELETE of one `blob_id` holds that `blob_id`'s lock, the
//!   innermost, around its read and its write of that blob.
//!
//! No path takes a `scp:did:` lock while it holds another routing id's lock,
//! and no path holds two `blob_id` locks, so the order is acyclic.
//!
//! `scp:wit:` admission is SCP-369's; until it lands the store refuses a
//! cosigned head with `4040`.

mod admission;
pub mod quota;
mod selection;

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, PoisonError};

use async_trait::async_trait;
use scp_did::Identifier;
use scp_kel::{RoutingKind, node_list_routing_id, routing_id};
use scp_protocol::node::NodeRecordKind;
use scp_relay_client::code;
use scp_transport::native::public_records::{
    PublicRecordRefusal, PublicRecordStore, RetainedPublish, TtlPublish, delete_unretained,
    refuse_retained_copy,
};
use scp_transport::native::storage::{BlobStorage, StoredBlob, StoredLifetime};
use tokio::sync::{Mutex, OwnedMutexGuard};

pub use quota::{QuotaClass, QuotaLimit, QuotaLimits};

use admission::Selection;
use selection::{LogCache, storage_refusal};

/// How many identities' replayed key-event logs the store caches.
const LOG_CACHE_CAPACITY: usize = 1024;

/// One node-list pointer the node is configured with (`NODE_LIST_POINTER`,
/// §9.6.4).
///
/// The node admits `scp:nls:` records of this (`context_id`, `governor`) pair
/// and reads witness bindings from them (§9.10.12's `scp:nls:` and `scp:wcf:`
/// rows).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeListPin {
    /// The node-list context's identifier string (§9.6.3).
    pub context_id: String,
    /// The identifier of the context's governor.
    pub governor: Identifier,
}

/// The operator's declared terms for the public-record store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRecordTerms {
    /// The bound per routing id of each §9.18.B quota class.
    pub quotas: QuotaLimits,
    /// The node-list pointers the node is configured with. The node refuses
    /// every `scp:nls:` record whose (`context_id`, `governor`) pair no pin
    /// names with `4040`, because a party refuses any other pair (§9.6.3
    /// step 2). An empty set admits no node-list record, binds no node key,
    /// and so admits no conflict statement.
    pub node_lists: BTreeSet<NodeListPin>,
}

impl PublicRecordTerms {
    /// No quota bound and no node-list pointer: §9.18.B's "No value set",
    /// and a store that admits no node-list record and no conflict
    /// statement.
    pub const UNCONFIGURED: Self = Self {
        quotas: QuotaLimits::UNBOUNDED,
        node_lists: BTreeSet::new(),
    };
}

/// What one lock of [`Locks`] serializes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LockKey {
    /// Retained writes at a routing id.
    Retained([u8; 32]),
    /// TTL writes at a routing id: the TTL quota's count and its store.
    Ttl([u8; 32]),
    /// Every read-then-write of one `blob_id`.
    Blob([u8; 32]),
}

/// One [`Locks`] entry: the key's mutex and how many tasks hold or await it.
#[derive(Debug, Default)]
struct LockEntry {
    mutex: Arc<Mutex<()>>,
    users: usize,
}

/// One async mutex per [`LockKey`] in use. An entry lives while a task
/// holds or awaits its lock and is removed when the last one lets go, so the
/// table holds no more entries than writes in flight.
#[derive(Debug, Default)]
struct Locks {
    table: std::sync::Mutex<HashMap<LockKey, LockEntry>>,
}

impl Locks {
    /// Holds `key`'s lock until the guard drops.
    async fn lock(&self, key: LockKey) -> KeyGuard<'_> {
        let mutex = {
            let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
            let entry = table.entry(key).or_default();
            entry.users = entry.users.saturating_add(1);
            Arc::clone(&entry.mutex)
        };
        // The guard exists before the wait, so a wait cancelled before it
        // takes the lock still counts its user out.
        let mut guard = KeyGuard {
            locks: self,
            key,
            held: None,
        };
        guard.held = Some(mutex.lock_owned().await);
        guard
    }

    /// Counts one user of `key` out, and removes its entry with the last.
    fn release(&self, key: LockKey) {
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        if let std::collections::hash_map::Entry::Occupied(mut entry) = table.entry(key) {
            entry.get_mut().users = entry.get().users.saturating_sub(1);
            if entry.get().users == 0 {
                entry.remove();
            }
        }
    }
}

/// One user of a [`Locks`] entry, from before its wait until it drops.
struct KeyGuard<'a> {
    locks: &'a Locks,
    key: LockKey,
    /// The lock once held; `None` while the wait is pending.
    held: Option<OwnedMutexGuard<()>>,
}

impl Drop for KeyGuard<'_> {
    fn drop(&mut self) {
        drop(self.held.take());
        self.locks.release(self.key);
    }
}

/// The node's [`PublicRecordStore`] (§9.10.12).
pub struct NodePublicRecords {
    terms: PublicRecordTerms,
    locks: Locks,
    logs: LogCache,
}

impl std::fmt::Debug for NodePublicRecords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodePublicRecords")
            .field("terms", &self.terms)
            .finish_non_exhaustive()
    }
}

impl NodePublicRecords {
    /// A store under `terms`.
    #[must_use]
    pub fn new(terms: PublicRecordTerms) -> Self {
        Self {
            terms,
            locks: Locks::default(),
            logs: LogCache::new(LOG_CACHE_CAPACITY),
        }
    }

    /// The terms the store runs under.
    #[must_use]
    pub const fn terms(&self) -> &PublicRecordTerms {
        &self.terms
    }

    /// Stores `publish` where `selection` keeps it, charges the retained
    /// class with what the selection keeps, and deletes every held record
    /// the selection drops. The record takes the admission counter one above
    /// every counter `selection.held` carries (§9.10.12 "Held earliest is
    /// admission order").
    ///
    /// The arriving record is stored before any held record is deleted, so a
    /// failure partway leaves the node holding more than its selection, never
    /// less; the next write at the routing id deletes the remainder.
    ///
    /// The caller holds the routing id's [`LockKey::Retained`] lock.
    async fn commit(
        &self,
        storage: &dyn BlobStorage,
        publish: RetainedPublish,
        selection: Selection,
    ) -> Result<StoredBlob, PublicRecordRefusal> {
        if selection
            .held
            .iter()
            .any(|held| held.blob_id == publish.blob_id)
        {
            return Err(PublicRecordRefusal::new(
                code::DID_RECORD_REJECTED,
                "this node already holds the record",
            ));
        }
        if !selection.kept.contains(&publish.blob_id) {
            return Err(PublicRecordRefusal::new(
                code::DID_RECORD_REJECTED,
                "the record's selection keeps a record this node already holds in its place",
            ));
        }
        self.terms
            .quotas
            .charge(QuotaClass::RetainedPublicRecords, selection.kept.len())?;
        let admission = selection::next_admission(&selection.held)?;
        let stored = {
            let _blob = self.locks.lock(LockKey::Blob(publish.blob_id)).await;
            // `blob_id` is the content address across every routing id: a TTL
            // copy of these bytes stored elsewhere would keep this record
            // unretained in a backend that ignores a second store of one
            // `blob_id`.
            let elsewhere = storage
                .get(&publish.blob_id)
                .await
                .map_err(|e| storage_refusal("reading the record's blob_id", &e))?;
            if let Some(elsewhere) = elsewhere {
                if elsewhere.lifetime.is_retained() {
                    return Err(PublicRecordRefusal::new(
                        code::DID_RECORD_REJECTED,
                        "this node holds the record at another routing id",
                    ));
                }
                storage
                    .delete(&publish.blob_id)
                    .await
                    .map_err(|e| storage_refusal("replacing a TTL copy of the record", &e))?;
            }
            storage
                .store(
                    publish.routing_id,
                    publish.blob_id,
                    publish.recipient_hint,
                    StoredLifetime::Retained { admission },
                    publish.blob,
                )
                .await
                .map_err(|e| storage_refusal("storing the record", &e))?
        };
        drop_unselected(storage, &selection.held, &selection.kept).await?;
        Ok(stored)
    }

    /// Re-runs every selection that reads `identifier`'s chains after a
    /// key-event frame changed them: its service records, the conflict
    /// statements about it, and the node list of every pinned context it
    /// governs (§9.10.12: the node drops each node-list record whose signing
    /// key a later governor event marks `Compromised`).
    ///
    /// The caller holds the identity's `scp:did:` lock; each reselection
    /// takes its own routing id's lock in turn.
    async fn reselect_dependents(
        &self,
        storage: &dyn BlobStorage,
        identifier: &Identifier,
    ) -> Result<(), PublicRecordRefusal> {
        {
            let routing = routing_id(RoutingKind::ServiceRecord, identifier);
            let _routing = self.locks.lock(LockKey::Retained(routing)).await;
            let service =
                admission::reselect_service_records(storage, &self.logs, identifier, &routing)
                    .await?;
            drop_unselected(storage, &service.held, &service.kept).await?;
        }
        {
            let routing = routing_id(RoutingKind::ConflictStatements, identifier);
            let _routing = self.locks.lock(LockKey::Retained(routing)).await;
            let conflicts = admission::reselect_conflicts(
                storage,
                &self.logs,
                &self.terms.node_lists,
                identifier,
                &routing,
            )
            .await?;
            drop_unselected(storage, &conflicts.held, &conflicts.kept).await?;
        }
        let governed: BTreeSet<[u8; 32]> = self
            .terms
            .node_lists
            .iter()
            .filter(|pin| pin.governor == *identifier)
            .map(|pin| node_list_routing_id(&pin.context_id))
            .collect();
        for routing in governed {
            let _routing = self.locks.lock(LockKey::Retained(routing)).await;
            let lists = admission::reselect_node_list(storage, &self.logs, &routing).await?;
            drop_unselected(storage, &lists.held, &lists.kept).await?;
        }
        Ok(())
    }
}

/// Deletes every record of `held` that `kept` does not name.
async fn drop_unselected(
    storage: &dyn BlobStorage,
    held: &[StoredBlob],
    kept: &BTreeSet<[u8; 32]>,
) -> Result<(), PublicRecordRefusal> {
    for dropped in held.iter().filter(|held| !kept.contains(&held.blob_id)) {
        storage
            .delete(&dropped.blob_id)
            .await
            .map_err(|e| storage_refusal("deleting a record the selection drops", &e))?;
    }
    Ok(())
}

#[async_trait]
impl PublicRecordStore for NodePublicRecords {
    async fn admit(
        &self,
        storage: &dyn BlobStorage,
        publish: RetainedPublish,
    ) -> Result<StoredBlob, PublicRecordRefusal> {
        let _routing = self.locks.lock(LockKey::Retained(publish.routing_id)).await;
        match publish.kind {
            NodeRecordKind::KeyEvents => {
                let (identifier, held, selection) =
                    admission::admit_key_events(storage, &self.logs, &publish).await?;
                let stored = self.commit(storage, publish, selection).await?;
                // The log admitted the frame under the counter `commit`
                // computed from the same held records; the cache takes it
                // only where the store confirms that counter.
                if stored.lifetime.admission() == held.last_admission() {
                    self.logs.put(identifier, held);
                }
                self.reselect_dependents(storage, &identifier).await?;
                Ok(stored)
            }
            NodeRecordKind::ServiceRecord => {
                let selection =
                    admission::admit_service_record(storage, &self.logs, &publish).await?;
                self.commit(storage, publish, selection).await
            }
            NodeRecordKind::NodeList => {
                let selection = admission::admit_node_list(
                    storage,
                    &self.logs,
                    &self.terms.node_lists,
                    &publish,
                )
                .await?;
                self.commit(storage, publish, selection).await
            }
            NodeRecordKind::ConflictStatements => {
                let selection = admission::admit_conflicts(
                    storage,
                    &self.logs,
                    &self.terms.node_lists,
                    &publish,
                )
                .await?;
                self.commit(storage, publish, selection).await
            }
            // Stub — see SCP-369
            NodeRecordKind::CosignedHeads => Err(PublicRecordRefusal::new(
                code::DID_RECORD_REJECTED,
                "this node admits no cosigned head",
            )),
            // Stub — see SCP-374
            NodeRecordKind::KeyPackageSet => Err(PublicRecordRefusal::new(
                code::KEY_PACKAGE_REJECTED,
                "this node admits no KeyPackage set",
            )),
        }
    }

    async fn store_ttl(
        &self,
        storage: &dyn BlobStorage,
        publish: TtlPublish,
    ) -> Result<StoredBlob, PublicRecordRefusal> {
        let _routing = self.locks.lock(LockKey::Ttl(publish.routing_id)).await;
        if let QuotaLimit::Blobs(limit) = self.terms.quotas.ttl_blobs {
            let bound = usize::try_from(limit).unwrap_or(usize::MAX);
            let held =
                selection::count_ttl(storage, &publish.routing_id, bound.saturating_add(1)).await?;
            self.terms
                .quotas
                .charge(QuotaClass::TtlBlobs, held.saturating_add(1))?;
        }
        let _blob = self.locks.lock(LockKey::Blob(publish.blob_id)).await;
        refuse_retained_copy(storage, &publish.blob_id).await?;
        storage
            .store(
                publish.routing_id,
                publish.blob_id,
                publish.recipient_hint,
                StoredLifetime::Ttl(publish.ttl),
                publish.blob,
            )
            .await
            .map_err(|e| storage_refusal("storing the blob", &e))
    }

    async fn delete(
        &self,
        storage: &dyn BlobStorage,
        blob_id: &[u8; 32],
    ) -> Result<(), PublicRecordRefusal> {
        let _blob = self.locks.lock(LockKey::Blob(*blob_id)).await;
        delete_unretained(storage, blob_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A guard's drop removes its table entry, and a second lock of a held
    /// key waits until the first guard drops.
    #[tokio::test]
    async fn a_lock_serializes_its_key_and_leaves_no_entry() {
        let locks = Arc::new(Locks::default());
        let key = LockKey::Blob([7; 32]);
        let first = locks.lock(key).await;
        let waiter = {
            let locks = Arc::clone(&locks);
            tokio::spawn(async move {
                let _second = locks.lock(key).await;
            })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "the second lock waits on the first");
        assert!(
            locks.lock(LockKey::Blob([8; 32])).await.held.is_some(),
            "another key does not wait"
        );
        drop(first);
        assert!(waiter.await.is_ok(), "the waiter takes the lock");
        assert!(
            locks
                .table
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
    }

    /// A wait cancelled before it takes the lock leaves no entry behind.
    #[tokio::test]
    async fn a_cancelled_wait_leaves_no_entry() {
        let locks = Arc::new(Locks::default());
        let key = LockKey::Retained([9; 32]);
        let first = locks.lock(key).await;
        let waiter = {
            let locks = Arc::clone(&locks);
            tokio::spawn(async move {
                let _second = locks.lock(key).await;
            })
        };
        tokio::task::yield_now().await;
        waiter.abort();
        assert!(waiter.await.is_err_and(|e| e.is_cancelled()));
        drop(first);
        assert!(
            locks
                .table
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
    }

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    /// An identity whose one root key signs each event, its inception
    /// unit, and the snapshot its sequence-1 forks change.
    struct Forking {
        root: scp_crypto::p256::P256SecretKey,
        id: Identifier,
        inception: Vec<u8>,
        inception_digest: [u8; 32],
        snapshot: scp_kel::KeyStateSnapshot,
    }

    impl Forking {
        fn key(seed: u8) -> scp_crypto::p256::P256SecretKey {
            use scp_crypto::p256::{P256SecretKey, SeedLabel};
            P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
        }

        fn entry(seed: u8, role: scp_did::KeyRole) -> scp_did::KeyEntry {
            scp_did::KeyEntry {
                key: Self::key(seed).public_key().to_compressed(),
                role,
                condition: scp_did::KeyCondition::Current,
                compromised_from: 0,
                custody_type: scp_did::CustodyType::Passkey,
                key_algorithm: scp_did::KeyAlgorithm::EcdsaP256Sha256,
            }
        }

        fn root_group() -> scp_kel::SignerGroup {
            scp_kel::SignerGroup {
                indices: vec![0],
                forms: vec![scp_kel::SignatureForm::Raw],
            }
        }

        /// `(unit, event digest, inception identifier)`: `BE32(len) ‖
        /// signed preimage ‖ the root's raw signature`.
        fn signed(
            root: &scp_crypto::p256::P256SecretKey,
            preimage: &scp_kel::EventPreimage,
        ) -> TestResult<(Vec<u8>, [u8; 32], Option<Identifier>)> {
            use sha2::{Digest, Sha256};
            let encoded = scp_kel::encode_preimage(preimage)?;
            let bytes = encoded.signed_preimage();
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            let mut unit = u32::try_from(bytes.len())?.to_be_bytes().to_vec();
            unit.extend_from_slice(&bytes);
            unit.extend_from_slice(&scp_crypto::p256::sign_prehash_rfc6979(root, &digest)?);
            Ok((unit, encoded.event_digest(), encoded.inception_identifier()))
        }

        /// An inception with one root member, one `#active` key and a
        /// commitment to one next key.
        fn new() -> TestResult<Self> {
            use scp_did::{CommitmentEntry, CustodyType, FixedCommitment, KeyAlgorithm, KeyRole};
            use scp_kel::{Continuation, EventPreimage, InceptionFields, KeyStateSnapshot};
            let root = Self::key(0x30);
            let snapshot = KeyStateSnapshot {
                root_threshold: 1,
                keys: vec![
                    Self::entry(0x30, KeyRole::RootMember),
                    Self::entry(0x31, KeyRole::Active),
                ],
                witnesses: vec![Identifier::from_bytes([0x77; 32])],
                witnessing_interval: 3600,
                service_key_role: KeyRole::Active,
                delegator: Identifier::ZERO,
            };
            let next = Self::key(0x32).public_key().to_compressed();
            let (inception, inception_digest, id) = Self::signed(
                &root,
                &EventPreimage::inception(InceptionFields {
                    root_group: Self::root_group(),
                    key_state: snapshot.clone(),
                    continuation: Continuation::FixesCommitment(FixedCommitment {
                        commitments: vec![CommitmentEntry {
                            commitment: scp_kel::prerotation_commitment(&next),
                            custody_type: CustodyType::Passkey,
                            key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
                        }],
                        next_threshold: 1,
                    }),
                }),
            )?;
            Ok(Self {
                root,
                id: id.ok_or("an inception derives its identifier")?,
                inception,
                inception_digest,
                snapshot,
            })
        }

        /// A sequence-1 `KeyState` that changes only the witnessing
        /// interval to `interval`: its frame, its digest and its unit.
        fn fork(&self, interval: u32) -> TestResult<(Vec<u8>, [u8; 32], Vec<u8>)> {
            let (unit, digest, _) = Self::signed(
                &self.root,
                &scp_kel::EventPreimage::key_state(scp_kel::KeyStateFields {
                    identifier: self.id,
                    sequence: 1,
                    predecessor_digest: self.inception_digest,
                    root_group: Self::root_group(),
                    key_state: scp_kel::KeyStateSnapshot {
                        witnessing_interval: interval,
                        ..self.snapshot.clone()
                    },
                    seals: Vec::new(),
                }),
            )?;
            let frame = scp_protocol::node::encode_key_event_frame(&self.id, 1, &[&unit])?;
            Ok((frame, digest, unit))
        }

        /// The retained PUBLISH of `blob` at the identity's `scp:did:` id.
        fn publish(&self, blob: &[u8]) -> TestResult<RetainedPublish> {
            use sha2::{Digest, Sha256};
            let routing = routing_id(RoutingKind::KeyEvents, &self.id);
            Ok(RetainedPublish {
                kind: scp_protocol::node::classify_node_record(&routing, blob)
                    .ok_or("a retained kind")?,
                routing_id: routing,
                recipient_hint: None,
                blob_id: Sha256::digest(blob).into(),
                blob: blob.to_vec(),
            })
        }
    }

    /// The accepted chain's head: the first chain the log retains, in
    /// first-held order.
    fn accepted(held: &selection::HeldLog) -> TestResult<[u8; 32]> {
        Ok(held
            .retained()
            .first()
            .ok_or("the log holds a chain")?
            .head_digest())
    }

    /// Two `scp:did:` forks that tie under R6, admitted in one clock second:
    /// the fork admitted first stays the accepted chain, and a restarted
    /// store's replay of the blob store keeps it accepted, whichever fork
    /// has the smaller `blob_id` (§9.10.12 "Held earliest is admission
    /// order", SCP-366).
    #[tokio::test]
    async fn a_replay_of_two_did_forks_admitted_in_one_second_keeps_the_admission_order()
    -> TestResult {
        use std::sync::atomic::{AtomicU64, Ordering};

        use scp_kel::{HoldOutcome, RetainedChain, RetainedLog};
        use scp_transport::native::storage::InMemoryBlobStorage;

        const INCEPTED_AT: u64 = 1_700_000_000;
        const FORKED_AT: u64 = INCEPTED_AT + 1;

        let identity = Forking::new()?;
        let routing = routing_id(RoutingKind::KeyEvents, &identity.id);
        let inception_frame =
            scp_protocol::node::encode_key_event_frame(&identity.id, 0, &[&identity.inception])?;
        let fork_a = identity.fork(7200)?;
        let fork_b = identity.fork(10_800)?;
        let terms = || PublicRecordTerms {
            quotas: QuotaLimits::UNBOUNDED,
            node_lists: BTreeSet::new(),
        };
        let heads = |held: &selection::HeldLog| -> Vec<[u8; 32]> {
            held.retained()
                .iter()
                .map(RetainedChain::head_digest)
                .collect()
        };

        // Both orders: in one of them the fork admitted second has the
        // smaller `blob_id`, so a replay ordered by `blob_id` within the
        // second would accept the other fork.
        for (first, second) in [(&fork_a, &fork_b), (&fork_b, &fork_a)] {
            // The tie, read off a log: the second fork is held divergent
            // and leaves the first accepted.
            let mut log = RetainedLog::new(identity.id);
            for unit in [&identity.inception, &first.2] {
                assert!(matches!(
                    log.admit(&[unit.as_slice()])?,
                    HoldOutcome::AcceptedExtended { .. }
                ));
            }
            assert!(matches!(
                log.admit(&[second.2.as_slice()])?,
                HoldOutcome::HeldDivergent { .. }
            ));

            let now = Arc::new(AtomicU64::new(INCEPTED_AT));
            let clock = Arc::clone(&now);
            let storage =
                InMemoryBlobStorage::with_clock(Arc::new(move || clock.load(Ordering::SeqCst)));
            let store = NodePublicRecords::new(terms());
            store
                .admit(&storage, identity.publish(&inception_frame)?)
                .await?;
            now.store(FORKED_AT, Ordering::SeqCst);
            store.admit(&storage, identity.publish(&first.0)?).await?;
            store.admit(&storage, identity.publish(&second.0)?).await?;

            let stored = selection::load_retained(&storage, &routing).await?;
            assert_eq!(stored.len(), 3);
            assert!(stored[1..].iter().all(|blob| blob.stored_at == FORKED_AT));
            let live = selection::held_log(&storage, &store.logs, &identity.id).await?;
            assert_eq!(live.retained().len(), 2);
            assert_eq!(accepted(&live)?, first.1);

            // A restarted store replays the blob store into an empty cache
            // and holds the same chains with the same one accepted.
            let restarted = NodePublicRecords::new(terms());
            let replayed = selection::held_log(&storage, &restarted.logs, &identity.id).await?;
            assert_eq!(accepted(&replayed)?, first.1);
            assert_eq!(heads(&replayed), heads(&live));
        }
        Ok(())
    }
}
