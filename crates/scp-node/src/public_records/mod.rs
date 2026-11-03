//! The node's public-record store (`09-security-model.md` §9.10.12,
//! `10-infrastructure-and-self-hosting.md` §10.4 "Every conforming node
//! validates public records").
//!
//! [`NodePublicRecords`] is the [`PublicRecordStore`] every transport of a
//! node reaches storage through. It admits each retained kind under the
//! §9.10.12 table's admission rule, keeps what the kind's selection keeps,
//! and charges the §9.18.B quota classes. It keeps no state beside the blob
//! store: each write recomputes the selection at its routing id from what
//! the store holds, so a restart, a second process or a reloaded store
//! selects the same records.
//!
//! One lock serializes every write, because each admission reads the
//! records it selects against and a write between that read and its own
//! store would select against records it never read.
//!
//! `scp:wit:` admission is SCP-369's; until it lands the store refuses a
//! cosigned head with `4040`.

mod admission;
pub mod quota;
mod selection;

use std::collections::BTreeSet;

use async_trait::async_trait;
use scp_did::Identifier;
use scp_protocol::node::NodeRecordKind;
use scp_relay_client::code;
use scp_transport::native::public_records::{
    PublicRecordRefusal, PublicRecordStore, RetainedPublish, TtlPublish, refuse_retained_copy,
};
use scp_transport::native::storage::{BlobStorage, StoredBlob, StoredLifetime};
use tokio::sync::Mutex;

pub use quota::{QuotaClass, QuotaLimit, QuotaLimits};

use admission::Selection;
use selection::storage_refusal;

/// The node-list context whose bindings decide which node keys may sign a
/// witness statement the node admits (§9.6.3, §9.10.12's `scp:wcf:` row).
///
/// An enum, not an `Option`, per `construction.md` M1: a node with no
/// node-list context names that choice, and admits no conflict statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeListSource {
    /// The node reads the node list of `context_id` that `governor` signs.
    Context {
        /// The node-list context's identifier string (§9.6.3).
        context_id: String,
        /// The identifier of the context's governor.
        governor: Identifier,
    },
    /// The node holds no node-list context: no node key is bound, and every
    /// conflict statement is refused with `4040`.
    Unconfigured,
}

/// The operator's declared terms for the public-record store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRecordTerms {
    /// The bound per routing id of each §9.18.B quota class.
    pub quotas: QuotaLimits,
    /// The node-list context the store reads witness bindings from.
    pub node_list: NodeListSource,
}

impl PublicRecordTerms {
    /// No quota bound and no node-list context: §9.18.B's "No value set",
    /// and a store that admits no conflict statement.
    pub const UNCONFIGURED: Self = Self {
        quotas: QuotaLimits::UNBOUNDED,
        node_list: NodeListSource::Unconfigured,
    };
}

/// The node's [`PublicRecordStore`] (§9.10.12).
pub struct NodePublicRecords {
    terms: PublicRecordTerms,
    writes: Mutex<()>,
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
    pub const fn new(terms: PublicRecordTerms) -> Self {
        Self {
            terms,
            writes: Mutex::const_new(()),
        }
    }

    /// The terms the store runs under.
    #[must_use]
    pub const fn terms(&self) -> &PublicRecordTerms {
        &self.terms
    }

    /// Stores `publish` where `selection` keeps it, charges the retained
    /// class with what the selection keeps, and deletes every held record
    /// the selection drops.
    ///
    /// The arriving record is stored before any held record is deleted, so a
    /// failure partway leaves the node holding more than its selection, never
    /// less; the next write at the routing id deletes the remainder.
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
        // `blob_id` is the content address across every routing id: a TTL copy
        // of these bytes stored elsewhere would keep this record unretained in
        // a backend that ignores a second store of one `blob_id`.
        let elsewhere = storage
            .get(&publish.blob_id)
            .await
            .map_err(|e| storage_refusal("reading the record's blob_id", &e))?;
        if elsewhere.is_some() {
            storage
                .delete(&publish.blob_id)
                .await
                .map_err(|e| storage_refusal("replacing a TTL copy of the record", &e))?;
        }
        let stored = storage
            .store(
                publish.routing_id,
                publish.blob_id,
                publish.recipient_hint,
                StoredLifetime::Retained,
                publish.blob,
            )
            .await
            .map_err(|e| storage_refusal("storing the record", &e))?;
        drop_unselected(storage, &selection.held, &selection.kept).await?;
        Ok(stored)
    }

    /// Re-runs every selection that reads `identifier`'s chains after a
    /// key-event frame changed them: its service records, the conflict
    /// statements about it, and the node list it governs.
    async fn reselect_dependents(
        &self,
        storage: &dyn BlobStorage,
        identifier: &Identifier,
    ) -> Result<(), PublicRecordRefusal> {
        let (_, service) = admission::reselect_service_records(storage, identifier).await?;
        drop_unselected(storage, &service.held, &service.kept).await?;
        let (_, conflicts) =
            admission::reselect_conflicts(storage, &self.terms.node_list, identifier).await?;
        drop_unselected(storage, &conflicts.held, &conflicts.kept).await?;
        if let Some((_, lists)) =
            admission::reselect_node_list(storage, &self.terms.node_list, identifier).await?
        {
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
        let _write = self.writes.lock().await;
        match publish.kind {
            NodeRecordKind::KeyEvents => {
                let (identifier, selection) =
                    admission::admit_key_events(storage, &publish).await?;
                let stored = self.commit(storage, publish, selection).await?;
                self.reselect_dependents(storage, &identifier).await?;
                Ok(stored)
            }
            NodeRecordKind::ServiceRecord => {
                let selection = admission::admit_service_record(storage, &publish).await?;
                self.commit(storage, publish, selection).await
            }
            NodeRecordKind::NodeList => {
                let selection = admission::admit_node_list(storage, &publish).await?;
                self.commit(storage, publish, selection).await
            }
            NodeRecordKind::ConflictStatements => {
                let selection =
                    admission::admit_conflicts(storage, &self.terms.node_list, &publish).await?;
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
        let _write = self.writes.lock().await;
        refuse_retained_copy(storage, &publish.blob_id).await?;
        if let QuotaLimit::Blobs(limit) = self.terms.quotas.ttl_blobs {
            let bound = usize::try_from(limit).unwrap_or(usize::MAX);
            let held =
                selection::count_ttl(storage, &publish.routing_id, bound.saturating_add(1)).await?;
            self.terms
                .quotas
                .charge(QuotaClass::TtlBlobs, held.saturating_add(1))?;
        }
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
}
