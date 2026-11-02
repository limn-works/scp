//! The node public-record seam (`09-security-model.md` §9.10.12,
//! `10-infrastructure-and-self-hosting.md` §10.4 "Every conforming node
//! validates public records").
//!
//! Every transport a node runs (WebSocket, QUIC, UDP/DTLS, WebTransport)
//! reaches storage through the three operations here, so no transport can
//! store a public record the node did not admit or delete one it retains:
//!
//! - [`publish_lifetime`] reads `retain` and `blob_ttl` off a PUBLISH and
//!   makes the two field refusals of §9.10.12 (`4002`, `4003`, `4011`).
//! - [`admit_publish`] classifies the blob by version byte and routing
//!   derivation, makes the kind refusals of §9.10.12, and hands a retained
//!   record to the node's [`PublicRecordStore`] and every other blob to its
//!   TTL path.
//! - [`query_blobs`] and [`delete_blob`] serve QUERY and DELETE, refusing a
//!   DELETE of a retained record with `4041`.
//!
//! A server built with [`PublicRecords::Refused`] stores no retained record:
//! every PUBLISH that sets `retain` is refused with `4040`. That is the
//! fail-closed value [`RelayConfig::defaults`] takes; a node sets
//! [`PublicRecords::Store`].
//!
//! [`RelayConfig::defaults`]: super::server::RelayConfig::defaults

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use scp_protocol::node::{NodeRecordKind, classify_node_record};
use scp_relay_client::{MAX_BLOB_TTL, MIN_BLOB_TTL, RelayMessage, code};

use super::storage::{BlobLifetime, BlobStorage, QueryCursor, StorageError, StoredBlob};
use crate::relay::push_gate::LiveRelayUrl;
use crate::relay::rate_limit::PublishRateLimiter;

/// Why a node refused a PUBLISH, QUERY or DELETE: the ADR-004 code the
/// `ERR` carries and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRecordRefusal {
    code: u16,
    msg: String,
}

impl PublicRecordRefusal {
    /// A refusal answered with `code`.
    #[must_use]
    pub fn new(code: u16, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
        }
    }

    /// The ADR-004 error code.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// The message the `ERR` carries.
    #[must_use]
    pub fn msg(&self) -> &str {
        &self.msg
    }

    /// The code and message, for an `ERR` frame.
    #[must_use]
    pub fn into_parts(self) -> (u16, String) {
        (self.code, self.msg)
    }

    /// The refusal for a failed storage `operation`: `5001` when the backend
    /// is full, `5000` for every other failure.
    #[must_use]
    pub fn storage(operation: &str, err: &StorageError) -> Self {
        let code = match err {
            StorageError::StorageFull => code::STORAGE_FULL,
            StorageError::Internal(_) => code::INTERNAL_ERROR,
        };
        Self::new(code, format!("{operation}: {err}"))
    }
}

impl fmt::Display for PublicRecordRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.msg)
    }
}

impl std::error::Error for PublicRecordRefusal {}

/// A PUBLISH that set `retain`, of a retained kind whose routing derivation
/// over the frame yields `routing_id` (§9.10.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedPublish {
    /// The kind [`classify_node_record`] read.
    pub kind: NodeRecordKind,
    /// The routing id the PUBLISH named.
    pub routing_id: [u8; 32],
    /// The PUBLISH's `recipient_hint`.
    pub recipient_hint: Option<[u8; 32]>,
    /// `SHA-256(blob)`.
    pub blob_id: [u8; 32],
    /// The frame bytes.
    pub blob: Vec<u8>,
}

/// A PUBLISH under the shared TTL whose blob is of no retained kind at its
/// routing id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlPublish {
    /// The routing id the PUBLISH named.
    pub routing_id: [u8; 32],
    /// The PUBLISH's `recipient_hint`.
    pub recipient_hint: Option<[u8; 32]>,
    /// `SHA-256(blob)`.
    pub blob_id: [u8; 32],
    /// The PUBLISH's `blob_ttl`, inside `MIN_BLOB_TTL..=MAX_BLOB_TTL`.
    pub ttl: u32,
    /// The blob bytes.
    pub blob: Vec<u8>,
}

/// The node's public-record store: admission, selection and quota per kind
/// (§9.10.12).
///
/// Both methods write through `storage`, the blob store every transport of
/// the node shares, so the store holds no copy of a record.
#[async_trait::async_trait]
pub trait PublicRecordStore: Send + Sync {
    /// Admits a retained record under its kind's admission rule, stores it
    /// with [`BlobLifetime::Retained`], and drops what its kind's selection
    /// no longer keeps.
    ///
    /// # Errors
    ///
    /// The refusal the §9.10.12 table names for the kind (`4040`, `4044`,
    /// `4042`), `5001` when the retained-record quota cannot hold the
    /// selection, or `5000` on a storage failure.
    async fn admit(
        &self,
        storage: &dyn BlobStorage,
        publish: RetainedPublish,
    ) -> Result<StoredBlob, PublicRecordRefusal>;

    /// Stores a blob under the shared TTL after charging the TTL-bearing
    /// quota class at its routing id.
    ///
    /// # Errors
    ///
    /// `5001` past the TTL-bearing quota or when the backend is full, or
    /// `5000` when the quota cannot be counted or the write fails otherwise.
    async fn store_ttl(
        &self,
        storage: &dyn BlobStorage,
        publish: TtlPublish,
    ) -> Result<StoredBlob, PublicRecordRefusal>;
}

/// Whether a server stores public records, and through which store.
///
/// An enum, not an `Option`, per `construction.md` M1: the absent store is
/// a named, fail-closed choice.
#[derive(Clone, Default)]
pub enum PublicRecords {
    /// The node's store admits, selects and charges every retained record.
    Store(Arc<dyn PublicRecordStore>),
    /// The server stores no retained record and answers every `retain`
    /// PUBLISH with `4040`. The fail-closed default.
    #[default]
    Refused,
}

impl fmt::Debug for PublicRecords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(_) => f.write_str("PublicRecords::Store(..)"),
            Self::Refused => f.write_str("PublicRecords::Refused"),
        }
    }
}

/// The lifetime a PUBLISH's `retain` and `blob_ttl` fields declare
/// (§9.10.12, ADR-004 operation 1).
///
/// # Errors
///
/// `4002` when neither field is present, `4003` for `retain` with
/// `blob_ttl` or `retain` other than `true`, and `4011` for a `blob_ttl`
/// outside `MIN_BLOB_TTL..=MAX_BLOB_TTL`.
pub fn publish_lifetime(
    retain: Option<bool>,
    blob_ttl: Option<u32>,
) -> Result<BlobLifetime, PublicRecordRefusal> {
    match (retain, blob_ttl) {
        (Some(true), None) => Ok(BlobLifetime::Retained),
        (Some(true), Some(_)) => Err(PublicRecordRefusal::new(
            code::INVALID_FIELD,
            "a PUBLISH carries retain or blob_ttl, never both",
        )),
        (Some(false), _) => Err(PublicRecordRefusal::new(
            code::INVALID_FIELD,
            "retain is true or absent",
        )),
        (None, Some(ttl)) if (MIN_BLOB_TTL..=MAX_BLOB_TTL).contains(&ttl) => {
            Ok(BlobLifetime::Ttl(ttl))
        }
        (None, Some(ttl)) => Err(PublicRecordRefusal::new(
            code::TTL_TOO_LONG,
            format!("blob_ttl must be {MIN_BLOB_TTL}-{MAX_BLOB_TTL}, got {ttl}"),
        )),
        (None, None) => Err(PublicRecordRefusal::new(
            code::MISSING_FIELD,
            "a PUBLISH carries retain or blob_ttl",
        )),
    }
}

/// Admits and stores one PUBLISH whose fields [`publish_lifetime`] read
/// (§9.10.12).
///
/// The blob's kind is the kind whose version byte opens it and whose routing
/// derivation yields `routing_id` ([`classify_node_record`]):
///
/// - with `retain`, a retained kind goes to the store's
///   [`PublicRecordStore::admit`]; any other blob is refused with `4003`;
/// - without it, a retained kind is refused with `4003`, a `KeyPackage` set
///   with `4042`, a blob whose `blob_id` names a retained record with
///   `4040`, and every other blob goes to the TTL path.
///
/// # Errors
///
/// The [`PublicRecordRefusal`] whose code the `ERR` carries.
pub async fn admit_publish<S: BlobStorage>(
    records: &PublicRecords,
    storage: &S,
    routing_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    lifetime: BlobLifetime,
    blob: &[u8],
) -> Result<StoredBlob, PublicRecordRefusal> {
    let blob_id = *crate::traits::BlobId::from_sha256(blob).as_bytes();
    let kind = classify_node_record(&routing_id, blob);
    match lifetime {
        BlobLifetime::Retained => {
            let Some(kind) = kind.filter(|kind| kind.is_retained()) else {
                return Err(PublicRecordRefusal::new(
                    code::INVALID_FIELD,
                    "retain is set on a blob of no retained kind at this routing id",
                ));
            };
            let PublicRecords::Store(store) = records else {
                return Err(PublicRecordRefusal::new(
                    code::DID_RECORD_REJECTED,
                    "this server stores no public records",
                ));
            };
            store
                .admit(
                    storage,
                    RetainedPublish {
                        kind,
                        routing_id,
                        recipient_hint,
                        blob_id,
                        blob: blob.to_vec(),
                    },
                )
                .await
        }
        BlobLifetime::Ttl(ttl) => {
            match kind {
                Some(NodeRecordKind::KeyPackageSet) => {
                    // Stub — see SCP-374
                    return Err(PublicRecordRefusal::new(
                        code::KEY_PACKAGE_REJECTED,
                        "this node admits no KeyPackage set",
                    ));
                }
                Some(_) => {
                    return Err(PublicRecordRefusal::new(
                        code::INVALID_FIELD,
                        "a record of a retained kind requires retain",
                    ));
                }
                None => {}
            }
            let publish = TtlPublish {
                routing_id,
                recipient_hint,
                blob_id,
                ttl,
                blob: blob.to_vec(),
            };
            match records {
                PublicRecords::Store(store) => store.store_ttl(storage, publish).await,
                PublicRecords::Refused => {
                    refuse_retained_copy(storage, &publish.blob_id).await?;
                    storage
                        .store(
                            publish.routing_id,
                            publish.blob_id,
                            publish.recipient_hint,
                            BlobLifetime::Ttl(publish.ttl),
                            publish.blob,
                        )
                        .await
                        .map_err(|e| PublicRecordRefusal::storage("storing the blob", &e))
                }
            }
        }
    }
}

/// Refuses a TTL publish whose `blob_id` names a retained record.
///
/// `blob_id` is the blob's content address across every routing id, so a TTL copy of a
/// retained record's bytes would overwrite the retained row. A
/// [`PublicRecordStore`] calls it under the lock that serializes its writes,
/// so no admission lands between the check and the TTL store.
///
/// # Errors
///
/// `4040` when `blob_id` names a retained record, or `5000` when the store
/// cannot be read.
pub async fn refuse_retained_copy<S: BlobStorage + ?Sized>(
    storage: &S,
    blob_id: &[u8; 32],
) -> Result<(), PublicRecordRefusal> {
    let held = storage
        .get(blob_id)
        .await
        .map_err(|e| PublicRecordRefusal::storage("reading the blob", &e))?;
    if held.is_some_and(|held| held.lifetime == BlobLifetime::Retained) {
        return Err(PublicRecordRefusal::new(
            code::DID_RECORD_REJECTED,
            "the blob is a retained record",
        ));
    }
    Ok(())
}

/// The `BLOB` message that carries a stored blob to a QUERY, a SUBSCRIBE
/// backfill or a subscriber.
#[must_use]
pub fn blob_message(stored: StoredBlob) -> RelayMessage {
    RelayMessage::Blob {
        routing_id: stored.routing_id,
        blob_id: stored.blob_id,
        recipient_hint: stored.recipient_hint,
        blob_ttl: stored.lifetime.ttl(),
        stored_at: stored.stored_at,
        blob: stored.blob,
    }
}

/// The blobs a QUERY or a SUBSCRIBE backfill returns: none at a reserved
/// push routing id (§10.7.1 "No blob storage"), otherwise the live blobs
/// after `cursor` in ascending (`stored_at`, `blob_id`) order.
///
/// # Errors
///
/// The [`StorageError`] the query hit.
pub async fn query_blobs<S: BlobStorage + ?Sized>(
    reserved: &LiveRelayUrl,
    storage: &S,
    routing_id: [u8; 32],
    cursor: QueryCursor,
    limit: u32,
) -> Result<Vec<StoredBlob>, StorageError> {
    if reserved.reserves(&routing_id) {
        return Ok(Vec::new());
    }
    storage.query(&routing_id, cursor, limit).await
}

/// Serves one DELETE: the per-IP publish budget first, then `4041` for a
/// retained record (§9.10.12), then the delete.
///
/// # Errors
///
/// `4020` over budget, `4041` for a retained record, or `5000` when storage
/// fails, before or during the delete.
pub async fn delete_blob<S: BlobStorage + ?Sized>(
    storage: &S,
    blob_id: &[u8; 32],
    rate_limiter: &PublishRateLimiter,
    ip: IpAddr,
) -> Result<(), PublicRecordRefusal> {
    if !rate_limiter.check(ip).await {
        return Err(PublicRecordRefusal::new(
            code::RATE_LIMITED,
            "delete rate limit exceeded",
        ));
    }
    let held = storage
        .get(blob_id)
        .await
        .map_err(|e| PublicRecordRefusal::storage("reading the blob", &e))?;
    if held.is_some_and(|held| held.lifetime == BlobLifetime::Retained) {
        return Err(PublicRecordRefusal::new(
            code::RETAINED_RECORD,
            "the blob is a retained record",
        ));
    }
    storage
        .delete(blob_id)
        .await
        .map(|_| ())
        .map_err(|e| PublicRecordRefusal::storage("deleting the blob", &e))
}

#[cfg(test)]
mod tests {
    use scp_did::Identifier;

    use super::super::storage::InMemoryBlobStorage;
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const SUBJECT: Identifier = Identifier::from_bytes([9; 32]);

    /// A frame of `kind` and the routing id its derivation yields.
    fn record(kind: NodeRecordKind) -> Result<([u8; 32], Vec<u8>), String> {
        let routing_id = kind
            .routing_id_for(&SUBJECT)
            .ok_or_else(|| format!("{kind:?} has an identifier derivation"))?;
        Ok((
            routing_id,
            scp_protocol::node::join_frame(kind.version(), &SUBJECT, b"value"),
        ))
    }

    fn code_of(result: Result<StoredBlob, PublicRecordRefusal>) -> Option<u16> {
        result.err().map(|refusal| refusal.code())
    }

    #[test]
    fn publish_lifetime_reads_each_field_combination() {
        assert_eq!(
            publish_lifetime(Some(true), None),
            Ok(BlobLifetime::Retained)
        );
        assert_eq!(
            publish_lifetime(None, Some(MIN_BLOB_TTL)),
            Ok(BlobLifetime::Ttl(MIN_BLOB_TTL))
        );
        let refused = |retain, ttl| publish_lifetime(retain, ttl).err().map(|r| r.code());
        assert_eq!(refused(Some(true), Some(60)), Some(code::INVALID_FIELD));
        assert_eq!(refused(Some(false), None), Some(code::INVALID_FIELD));
        assert_eq!(refused(None, None), Some(code::MISSING_FIELD));
        assert_eq!(
            refused(None, Some(MAX_BLOB_TTL + 1)),
            Some(code::TTL_TOO_LONG)
        );
    }

    #[tokio::test]
    async fn a_server_without_a_store_refuses_every_retained_record_with_4040() -> TestResult {
        let storage = InMemoryBlobStorage::new();
        let (routing_id, blob) = record(NodeRecordKind::KeyEvents)?;
        let result = admit_publish(
            &PublicRecords::Refused,
            &storage,
            routing_id,
            None,
            BlobLifetime::Retained,
            &blob,
        )
        .await;
        assert_eq!(code_of(result), Some(code::DID_RECORD_REJECTED));
        assert!(
            storage
                .query(&routing_id, QueryCursor::All, 10)
                .await?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn retain_on_a_blob_of_no_retained_kind_is_refused_with_4003() {
        let storage = InMemoryBlobStorage::new();
        let result = admit_publish(
            &PublicRecords::Refused,
            &storage,
            [1; 32],
            None,
            BlobLifetime::Retained,
            b"opaque",
        )
        .await;
        assert_eq!(code_of(result), Some(code::INVALID_FIELD));
    }

    #[tokio::test]
    async fn a_ttl_publish_of_a_retained_kind_or_a_key_package_set_is_refused() -> TestResult {
        let storage = InMemoryBlobStorage::new();
        for (kind, expected) in [
            (NodeRecordKind::KeyEvents, code::INVALID_FIELD),
            (NodeRecordKind::ServiceRecord, code::INVALID_FIELD),
            (NodeRecordKind::KeyPackageSet, code::KEY_PACKAGE_REJECTED),
        ] {
            let (routing_id, blob) = record(kind)?;
            let result = admit_publish(
                &PublicRecords::Refused,
                &storage,
                routing_id,
                None,
                BlobLifetime::Ttl(60),
                &blob,
            )
            .await;
            assert_eq!(code_of(result), Some(expected), "{kind:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_ttl_copy_of_a_retained_record_is_refused_and_the_record_kept() -> TestResult {
        let storage = InMemoryBlobStorage::new();
        let (routing_id, blob) = record(NodeRecordKind::KeyEvents)?;
        let blob_id = *crate::traits::BlobId::from_sha256(&blob).as_bytes();
        storage
            .store(
                routing_id,
                blob_id,
                None,
                BlobLifetime::Retained,
                blob.clone(),
            )
            .await?;

        assert_eq!(
            refuse_retained_copy(&storage, &blob_id)
                .await
                .err()
                .map(|r| r.code()),
            Some(code::DID_RECORD_REJECTED)
        );
        // The same bytes at an unclassified routing id reach the TTL path.
        let result = admit_publish(
            &PublicRecords::Refused,
            &storage,
            [2; 32],
            None,
            BlobLifetime::Ttl(60),
            &blob,
        )
        .await;
        assert_eq!(code_of(result), Some(code::DID_RECORD_REJECTED));
        let held = storage.get(&blob_id).await?.ok_or("the record is gone")?;
        assert_eq!(held.lifetime, BlobLifetime::Retained);
        assert_eq!(held.routing_id, routing_id);
        Ok(())
    }

    #[tokio::test]
    async fn an_ordinary_ttl_blob_is_stored_and_passes_the_retained_check() -> TestResult {
        let storage = InMemoryBlobStorage::new();
        let stored = admit_publish(
            &PublicRecords::Refused,
            &storage,
            [3; 32],
            None,
            BlobLifetime::Ttl(60),
            b"ciphertext",
        )
        .await?;
        assert_eq!(stored.lifetime, BlobLifetime::Ttl(60));
        assert_eq!(
            refuse_retained_copy(&storage, &stored.blob_id).await,
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn a_full_backend_is_5001_and_every_other_storage_failure_5000() {
        assert_eq!(
            PublicRecordRefusal::storage("storing", &StorageError::StorageFull).code(),
            code::STORAGE_FULL
        );
        assert_eq!(
            PublicRecordRefusal::storage("storing", &StorageError::Internal("io".into())).code(),
            code::INTERNAL_ERROR
        );
    }

    #[tokio::test]
    async fn delete_refuses_a_retained_record_with_4041_and_deletes_a_ttl_blob() -> TestResult {
        let storage = InMemoryBlobStorage::new();
        let limiter = PublishRateLimiter::new(100);
        let ip = IpAddr::from([127, 0, 0, 1]);
        storage
            .store(
                [4; 32],
                [5; 32],
                None,
                BlobLifetime::Retained,
                b"r".to_vec(),
            )
            .await?;
        storage
            .store([4; 32], [6; 32], None, BlobLifetime::Ttl(60), b"t".to_vec())
            .await?;

        assert_eq!(
            delete_blob(&storage, &[5; 32], &limiter, ip)
                .await
                .err()
                .map(|r| r.code()),
            Some(code::RETAINED_RECORD)
        );
        assert!(storage.get(&[5; 32]).await?.is_some());
        assert_eq!(delete_blob(&storage, &[6; 32], &limiter, ip).await, Ok(()));
        assert!(storage.get(&[6; 32]).await?.is_none());
        Ok(())
    }
}
