//! S3-compatible blob storage adapter for the SCP native relay.
//!
//! Implements [`BlobStorage`] using an S3-compatible object store (AWS S3,
//! `MinIO`, Cloudflare R2, etc.) as the backend. Intended for large-scale relay
//! deployments where `SQLite` or redb are insufficient.
//!
//! # S3 Key Layout (per spec §17.7)
//!
//! ```text
//! {prefix}/blobs/{blob_id_hex}                            — blob content + metadata headers
//! {prefix}/routing/{routing_id_hex}/r/{blob_id_hex}       — routing index of a retained record
//! {prefix}/routing/{routing_id_hex}/t/{blob_id_hex}       — routing index of a TTL blob
//! {prefix}/expiry/{expires_at:020}/{blob_id_hex}          — empty expiry index objects
//! ```
//!
//! Metadata is stored as S3 object metadata (user-defined `x-amz-meta-*`
//! headers). Numeric values are serialized as decimal strings. A routing
//! object is empty and carries `stored_at`, plus `admission` (retained) or
//! `expires_at` (TTL), so a query filters, orders and limits from routing
//! metadata and reads the body only of a blob it returns (spec §17.7
//! "Retained records and the lifetime filter").
//!
//! # Request signing and TLS
//!
//! Requests are signed with `SigV4`. The adapter does not enable the AWS SDK's
//! `sigv4a` feature, so it cannot address an S3 Multi-Region Access Point: pass
//! a bucket name or a regional endpoint, not a Multi-Region Access Point ARN.
//! §17.7 "Why S3-Compatible" of `.docs/specs/17-persistence-and-storage.md`
//! scopes this adapter to the S3-compatible ecosystem — AWS S3, `MinIO`, Ceph,
//! `SeaweedFS`, Garage, Cloudflare R2, Backblaze B2 — and no store on that list
//! other than AWS implements `SigV4A`.
//!
//! TLS runs on rustls over ring, matching every other TLS path this crate owns.
//! rustls offers the X25519MLKEM768 hybrid key exchange only through its aws-lc
//! backend, so an HTTPS session to the object store negotiates X25519. Blob
//! contents are MLS-encrypted before they reach this adapter, and §17.7 places
//! no confidentiality requirement on the transport to the store, so no protocol
//! guarantee rests on that session.
//!
//! # Feature flag
//!
//! This module is gated behind the `s3-blob` feature:
//!
//! ```toml
//! scp-transport = { path = "...", features = ["s3-blob"] }
//! ```
//!
//! # Testing
//!
//! The unit tests need a running S3-compatible endpoint, named by
//! `S3_TEST_ENDPOINT` and `S3_TEST_BUCKET`, and credentials the AWS SDK's
//! environment chain reads (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//! `AWS_REGION`). CI's `transport-blob` leg starts one and sets them
//! (`.github/workflows/ci.yml`, "Run the blob-backend tests"):
//!
//! ```bash
//! cargo test -p scp-transport --features s3-blob --lib s3_blob
//! ```
//!
//! The construction failure path needs no endpoint:
//! `crates/scp-transport/tests/s3_blob_fail_closed.rs` opens the store against
//! an address nothing listens on and asserts `StorageError::Internal`.
//!
//! See SCP-PERSIST-068 for the full story.

use std::collections::HashMap;
use std::sync::Arc;

use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_http_client::tls;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;

use super::storage::{
    BlobBodyStream, BlobMetadata, BlobStorage, ClockFn, LifetimeFilter, QueryCursor, StorageError,
    StoredBlob, StoredLifetime, system_clock,
};

/// The metadata value that marks a retained record, under [`RETAIN_KEY`].
const RETAIN_VALUE: &str = "true";
/// The metadata key a retained record carries in place of `blob_ttl`.
const RETAIN_KEY: &str = "retain";
/// The metadata key a retained record's admission counter rides under.
const ADMISSION_KEY: &str = "admission";

/// The routing-index class segment of a lifetime: `r` retained, `t` TTL.
const fn class_segment(lifetime: StoredLifetime) -> &'static str {
    if lifetime.is_retained() { "r" } else { "t" }
}

/// The routing-index class segments a filter lists.
const fn filter_segments(filter: LifetimeFilter) -> &'static [&'static str] {
    match filter {
        LifetimeFilter::Any => &["r", "t"],
        LifetimeFilter::Retained => &["r"],
        LifetimeFilter::Ttl => &["t"],
    }
}

/// The largest part a streaming store buffers before it uploads it, above
/// S3's 5 MiB floor for every part but the last.
const PART_SIZE: usize = 8 * 1024 * 1024;

/// The most parts one multipart upload carries (S3's bound).
const MAX_PARTS: i32 = 10_000;

/// Appends the body's chunks to `part` until it holds [`PART_SIZE`] bytes
/// or the body ends; `true` when the body ended.
async fn fill_part(body: &mut BlobBodyStream, part: &mut Vec<u8>) -> Result<bool, StorageError> {
    use futures::StreamExt;

    while part.len() < PART_SIZE {
        match body.next().await {
            Some(chunk) => part.extend_from_slice(&chunk?),
            None => return Ok(true),
        }
    }
    Ok(false)
}

/// A blob object's user metadata: its routing ID, `blob_id`, `stored_at`,
/// lifetime and recipient hint.
fn object_metadata(
    routing_id: [u8; 32],
    blob_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    lifetime: StoredLifetime,
    stored_at: u64,
) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    metadata.insert("routing_id".to_owned(), hex::encode(routing_id));
    metadata.insert("blob_id".to_owned(), hex::encode(blob_id));
    metadata.insert("stored_at".to_owned(), stored_at.to_string());
    insert_lifetime_metadata(&mut metadata, lifetime, stored_at);
    if let Some(hint) = &recipient_hint {
        metadata.insert("recipient_hint".to_owned(), hex::encode(hint));
    }
    metadata
}

/// Writes a blob's lifetime into its object metadata: `blob_ttl` and
/// `expires_at` for a TTL blob, `retain` and `admission` for a retained
/// record.
fn insert_lifetime_metadata(
    metadata: &mut HashMap<String, String>,
    lifetime: StoredLifetime,
    stored_at: u64,
) {
    match lifetime {
        StoredLifetime::Ttl(ttl) => {
            metadata.insert("blob_ttl".to_owned(), ttl.to_string());
            metadata.insert(
                "expires_at".to_owned(),
                stored_at.saturating_add(u64::from(ttl)).to_string(),
            );
        }
        StoredLifetime::Retained { admission } => {
            metadata.insert(RETAIN_KEY.to_owned(), RETAIN_VALUE.to_owned());
            metadata.insert(ADMISSION_KEY.to_owned(), admission.to_string());
        }
    }
}

/// Reads a blob's lifetime back from its object metadata.
///
/// An object must carry exactly one of `blob_ttl` and `retain=true`, and an
/// `admission` counter exactly when it carries `retain=true`; any other
/// object is refused, so a damaged object never reads as a record TTL purge
/// must keep.
fn lifetime_from_metadata(
    metadata: &HashMap<String, String>,
) -> Result<StoredLifetime, StorageError> {
    let admission = metadata.get(ADMISSION_KEY);
    match (metadata.get("blob_ttl"), metadata.get(RETAIN_KEY)) {
        (Some(_), None) if admission.is_some() => Err(StorageError::Internal(
            "metadata carries blob_ttl and an admission counter".to_owned(),
        )),
        (Some(ttl), None) => Ok(StoredLifetime::Ttl(S3BlobStore::parse_u32(ttl)?)),
        (None, Some(retain)) if retain == RETAIN_VALUE => Ok(StoredLifetime::Retained {
            admission: S3BlobStore::parse_u64(admission.ok_or_else(|| {
                StorageError::Internal("a retained object carries no admission counter".to_owned())
            })?)?,
        }),
        (None, Some(_)) => Err(StorageError::Internal(
            "invalid retain value in metadata".to_owned(),
        )),
        (Some(_), Some(_)) => Err(StorageError::Internal(
            "metadata carries both blob_ttl and retain".to_owned(),
        )),
        (None, None) => Err(StorageError::Internal(
            "metadata carries neither blob_ttl nor retain".to_owned(),
        )),
    }
}

/// Resolves the AWS SDK configuration over an HTTPS client that uses the ring rustls backend.
///
/// The AWS SDK's `default-https-client` feature hardwires `aws-smithy-http-client`'s
/// `rustls-aws-lc` connector, which brings a second rustls crypto provider into the
/// process and compiles the `aws-lc-sys` C library. `scp-transport` pins one ring-backed
/// rustls provider for every other TLS path it owns (see the `quinn`, `rustls` and
/// `reqwest` notes in this crate's Cargo.toml), so this builds the same connector over
/// ring and hands it to the loader. Every request the SDK makes goes through it: the S3
/// calls and the credential-chain calls both.
async fn load_ring_backed_aws_config() -> aws_config::SdkConfig {
    let http_client = aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
        .build_https();
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .http_client(http_client)
        .load()
        .await
}

/// S3-compatible blob storage backend for the SCP native relay.
///
/// Stores blobs as S3 objects with a three-index key layout:
/// - `blobs/` — primary storage (blob content + metadata)
/// - `routing/` — secondary index by routing ID
/// - `expiry/` — TTL index for background purge
///
/// Compatible with AWS S3, `MinIO`, Cloudflare R2, and any S3-compatible
/// object store. Use [`S3BlobStore::open_with_endpoint`] for non-AWS
/// endpoints.
pub struct S3BlobStore {
    client: Client,
    bucket: String,
    prefix: String,
    clock: ClockFn,
}

impl std::fmt::Debug for S3BlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3BlobStore")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("client", &"<aws_sdk_s3::Client>")
            .field("clock", &"<fn>")
            .finish()
    }
}

impl Clone for S3BlobStore {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            clock: Arc::clone(&self.clock),
        }
    }
}

/// Returns the key prefix `purge_expired` lists and the construction probe
/// lists, so both requests need the same permission.
fn expiry_list_prefix(prefix: &str) -> String {
    format!("{prefix}/expiry/")
}

impl S3BlobStore {
    /// Creates an `S3BlobStore` using the default AWS credential chain.
    ///
    /// Credentials are resolved via the standard AWS SDK chain:
    /// environment variables, shared config, IAM role, etc.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] when the `ListObjectsV2` probe every
    /// construction path issues under `{prefix}/expiry/` does not succeed: the
    /// endpoint refuses or does not answer, the credential chain resolves no
    /// credentials, the credentials are rejected, no region is configured, the
    /// bucket does not exist, or the caller may not list that prefix.
    pub async fn open(bucket: &str, prefix: &str) -> Result<Self, StorageError> {
        Self::open_with_clock(bucket, prefix, system_clock()).await
    }

    /// Creates an `S3BlobStore` with a custom clock function.
    ///
    /// The clock is used for `stored_at` timestamps and expiry checks.
    /// Pass [`system_clock()`] for production use; inject a fixed clock
    /// for deterministic tests.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] when the `ListObjectsV2` probe every
    /// construction path issues under `{prefix}/expiry/` does not succeed: the
    /// endpoint refuses or does not answer, the credential chain resolves no
    /// credentials, the credentials are rejected, no region is configured, the
    /// bucket does not exist, or the caller may not list that prefix.
    pub async fn open_with_clock(
        bucket: &str,
        prefix: &str,
        clock: ClockFn,
    ) -> Result<Self, StorageError> {
        let config = load_ring_backed_aws_config().await;
        let client = Client::new(&config);
        Self::from_client(client, bucket, prefix, clock).await
    }

    /// Creates an `S3BlobStore` with a custom S3-compatible endpoint URL.
    ///
    /// Use this for `MinIO`, Cloudflare R2, or any non-AWS S3 endpoint.
    /// Path-style access is forced (required by most S3-compatible stores).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] when the `ListObjectsV2` probe every
    /// construction path issues under `{prefix}/expiry/` does not succeed: the
    /// endpoint refuses or does not answer, the credential chain resolves no
    /// credentials, the credentials are rejected, no region is configured, the
    /// bucket does not exist, or the caller may not list that prefix.
    pub async fn open_with_endpoint(
        bucket: &str,
        prefix: &str,
        endpoint_url: &str,
        clock: ClockFn,
    ) -> Result<Self, StorageError> {
        let config = load_ring_backed_aws_config().await;
        let s3_config = aws_sdk_s3::config::Builder::from(&config)
            .endpoint_url(endpoint_url)
            .force_path_style(true)
            .build();
        let client = Client::from_conf(s3_config);
        Self::from_client(client, bucket, prefix, clock).await
    }

    /// Probes `bucket` with one `ListObjectsV2` request, then builds the store.
    ///
    /// The probe is the request `purge_expired` sends, limited to one key: the
    /// same bucket, the same `{prefix}/expiry/` prefix, and so the same
    /// `s3:ListBucket` permission and `s3:prefix` condition key. A credential
    /// scoped to the store's prefix passes it, and a `HeadBucket` request,
    /// which carries no `s3:prefix`, would not.
    ///
    /// Both constructors go through here, so neither can skip the probe.
    /// Loading the SDK configuration and building a `Client` perform no I/O,
    /// so without this request a constructor returned `Ok` for an endpoint
    /// nothing listens on, a missing bucket, or absent credentials, and the
    /// relay learned of it on its first `store`. A selected production backend
    /// that cannot be satisfied is a terminal error at the construction
    /// boundary (`.docs/specs/17-persistence-and-storage.md` §17.17.1
    /// SCP-CAPSEL-8001, §17.7).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] carrying the SDK's error context when
    /// the `ListObjectsV2` request does not succeed.
    async fn from_client(
        client: Client,
        bucket: &str,
        prefix: &str,
        clock: ClockFn,
    ) -> Result<Self, StorageError> {
        let probe_prefix = expiry_list_prefix(prefix);
        client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(&probe_prefix)
            .max_keys(1)
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!(
                    "S3 list probe failed for {bucket} under {probe_prefix}: {}",
                    aws_sdk_s3::error::DisplayErrorContext(&e)
                ))
            })?;
        Ok(Self {
            client,
            bucket: bucket.to_owned(),
            prefix: prefix.to_owned(),
            clock,
        })
    }

    // ── Key helpers ─────────────────────────────────────────────────────

    /// Returns the S3 key for a blob's primary content object.
    fn blob_key(&self, blob_id: &[u8; 32]) -> String {
        format!("{}/blobs/{}", self.prefix, hex::encode(blob_id))
    }

    /// Returns the S3 key prefix of a routing id's index entries of one
    /// class segment (`r` or `t`).
    fn routing_class_prefix(&self, routing_id: &[u8; 32], segment: &str) -> String {
        format!(
            "{}/routing/{}/{segment}/",
            self.prefix,
            hex::encode(routing_id)
        )
    }

    /// Returns the S3 key for a blob's routing index entry, under its
    /// lifetime's class.
    fn routing_key(
        &self,
        routing_id: &[u8; 32],
        lifetime: StoredLifetime,
        blob_id: &[u8; 32],
    ) -> String {
        format!(
            "{}{}",
            self.routing_class_prefix(routing_id, class_segment(lifetime)),
            hex::encode(blob_id)
        )
    }

    /// Returns the S3 key for a blob's expiry index entry.
    fn expiry_key(&self, expires_at: u64, blob_id: &[u8; 32]) -> String {
        format!(
            "{}/expiry/{:020}/{}",
            self.prefix,
            expires_at,
            hex::encode(blob_id)
        )
    }

    /// Returns the current timestamp from the injected clock.
    fn now(&self) -> u64 {
        (self.clock)()
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Parses a hex-encoded 32-byte value from an S3 metadata header.
    fn parse_hex_32(value: &str) -> Result<[u8; 32], StorageError> {
        let bytes = hex::decode(value)
            .map_err(|e| StorageError::Internal(format!("invalid hex in metadata: {e}")))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| StorageError::Internal(format!("expected 32 bytes, got {}", bytes.len())))
    }

    /// Parses a decimal string from S3 metadata into a u64.
    fn parse_u64(value: &str) -> Result<u64, StorageError> {
        value
            .parse::<u64>()
            .map_err(|e| StorageError::Internal(format!("invalid u64 in metadata: {e}")))
    }

    /// Parses a decimal string from S3 metadata into a u32.
    fn parse_u32(value: &str) -> Result<u32, StorageError> {
        value
            .parse::<u32>()
            .map_err(|e| StorageError::Internal(format!("invalid u32 in metadata: {e}")))
    }

    /// Extracts a required metadata value from a metadata map.
    fn require_metadata<'a>(
        metadata: &'a HashMap<String, String>,
        key: &str,
    ) -> Result<&'a str, StorageError> {
        metadata
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| StorageError::Internal(format!("missing metadata key: {key}")))
    }

    /// Reconstructs a [`StoredBlob`] from S3 object body and metadata.
    fn stored_blob_from_response(
        metadata: &HashMap<String, String>,
        body: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let content_length = Some(body.len() as u64);
        let meta = Self::metadata_from_response(metadata, content_length)?;
        Ok(StoredBlob {
            routing_id: meta.routing_id,
            blob_id: meta.blob_id,
            recipient_hint: meta.recipient_hint,
            lifetime: meta.lifetime,
            stored_at: meta.stored_at,
            blob: body,
        })
    }

    /// Reconstructs [`BlobMetadata`] from S3 object metadata headers.
    fn metadata_from_response(
        metadata: &HashMap<String, String>,
        content_length: Option<u64>,
    ) -> Result<BlobMetadata, StorageError> {
        let routing_id = Self::parse_hex_32(Self::require_metadata(metadata, "routing_id")?)?;
        let blob_id = Self::parse_hex_32(Self::require_metadata(metadata, "blob_id")?)?;
        let lifetime = lifetime_from_metadata(metadata)?;
        let stored_at = Self::parse_u64(Self::require_metadata(metadata, "stored_at")?)?;

        let recipient_hint = metadata
            .get("recipient_hint")
            .map(|v| Self::parse_hex_32(v))
            .transpose()?;

        Ok(BlobMetadata {
            routing_id,
            blob_id,
            recipient_hint,
            lifetime,
            stored_at,
            content_length,
        })
    }

    /// Deletes a single S3 object by key, ignoring "not found" errors.
    async fn delete_object(&self, key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::Internal(format!("S3 delete failed for {key}: {e}")))?;
        Ok(())
    }

    /// Fetches metadata (without body) for a blob from the primary key.
    ///
    /// Returns `None` if the object does not exist.
    async fn head_blob(
        &self,
        blob_id: &[u8; 32],
    ) -> Result<Option<HashMap<String, String>>, StorageError> {
        let key = self.blob_key(blob_id);
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(output) => {
                let metadata = output.metadata().cloned().unwrap_or_default();
                Ok(Some(metadata))
            }
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_not_found() {
                    Ok(None)
                } else {
                    Err(StorageError::Internal(format!(
                        "S3 head failed for {key}: {service_err}"
                    )))
                }
            }
        }
    }

    /// Fetches the metadata of an index object by key; `None` when it does
    /// not exist.
    async fn head_index(&self, key: &str) -> Result<Option<HashMap<String, String>>, StorageError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => Ok(Some(output.metadata().cloned().unwrap_or_default())),
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_not_found() {
                    Ok(None)
                } else {
                    Err(StorageError::Internal(format!(
                        "S3 head failed for {key}: {service_err}"
                    )))
                }
            }
        }
    }

    /// Puts an empty index object at `key` carrying `metadata`.
    async fn put_index(
        &self,
        key: &str,
        metadata: HashMap<String, String>,
    ) -> Result<(), StorageError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(Vec::<u8>::new()))
            .set_metadata(Some(metadata))
            .send()
            .await
            .map_err(|e| StorageError::Internal(format!("S3 put index failed for {key}: {e}")))?;
        Ok(())
    }

    /// The routing and expiry index keys of a blob stored with `meta`.
    fn index_keys(&self, meta: &BlobMetadata) -> (String, Option<String>) {
        (
            self.routing_key(&meta.routing_id, meta.lifetime, &meta.blob_id),
            meta.lifetime
                .expires_at(meta.stored_at)
                .map(|expires_at| self.expiry_key(expires_at, &meta.blob_id)),
        )
    }

    /// Reads the metadata of the blob `blob_id` holds before an overwrite,
    /// so the overwrite can delete its index objects.
    /// Uploads `first` and the rest of `body` as one multipart upload under
    /// `key`, returning the byte count; on any failure the upload is aborted,
    /// so the object under `key` is unchanged.
    async fn put_multipart(
        &self,
        key: &str,
        metadata: HashMap<String, String>,
        first: Vec<u8>,
        body: &mut BlobBodyStream,
    ) -> Result<u64, StorageError> {
        let created = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .set_metadata(Some(metadata))
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!("S3 multipart create failed for {key}: {e}"))
            })?;
        let upload_id = created
            .upload_id()
            .ok_or_else(|| {
                StorageError::Internal(format!(
                    "S3 multipart create for {key} returned no upload id"
                ))
            })?
            .to_owned();
        let uploaded = self.upload_parts(key, &upload_id, first, body).await;
        if uploaded.is_err()
            && let Err(abort) = self
                .client
                .abort_multipart_upload()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(&upload_id)
                .send()
                .await
        {
            tracing::warn!(key, upload_id, %abort, "S3 multipart abort failed");
        }
        uploaded
    }

    /// Uploads `part` and every later part of `body` under `upload_id`, then
    /// completes the upload.
    async fn upload_parts(
        &self,
        key: &str,
        upload_id: &str,
        mut part: Vec<u8>,
        body: &mut BlobBodyStream,
    ) -> Result<u64, StorageError> {
        use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};

        let mut completed = Vec::new();
        let mut total = 0_u64;
        let mut number = 0_i32;
        loop {
            let ended = fill_part(body, &mut part).await?;
            if !part.is_empty() {
                number += 1;
                if number > MAX_PARTS {
                    return Err(StorageError::Internal(format!(
                        "S3 multipart upload for {key} passes {MAX_PARTS} parts"
                    )));
                }
                total = total.saturating_add(part.len() as u64);
                let uploaded = self
                    .client
                    .upload_part()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(upload_id)
                    .part_number(number)
                    .body(ByteStream::from(std::mem::take(&mut part)))
                    .send()
                    .await
                    .map_err(|e| {
                        StorageError::Internal(format!(
                            "S3 part {number} upload failed for {key}: {e}"
                        ))
                    })?;
                completed.push(
                    CompletedPart::builder()
                        .set_e_tag(uploaded.e_tag().map(str::to_owned))
                        .part_number(number)
                        .build(),
                );
            }
            if ended {
                break;
            }
        }
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(completed))
                    .build(),
            )
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!("S3 multipart complete failed for {key}: {e}"))
            })?;
        Ok(total)
    }

    async fn replaced(&self, blob_id: &[u8; 32]) -> Result<Option<BlobMetadata>, StorageError> {
        self.head_blob(blob_id)
            .await?
            .map(|metadata| Self::metadata_from_response(&metadata, None))
            .transpose()
    }

    /// Puts the routing index entry of the blob `meta` describes and, for a
    /// TTL blob, its expiry index entry; then deletes every index object of
    /// the blob it `replaced` that the new blob does not reuse (spec §17.7:
    /// an overwrite leaves no index entry of the blob it replaces).
    async fn write_indexes(
        &self,
        meta: &BlobMetadata,
        replaced: Option<BlobMetadata>,
    ) -> Result<(), StorageError> {
        let (routing_key, expiry_key) = self.index_keys(meta);
        let mut routing_metadata = HashMap::new();
        routing_metadata.insert("stored_at".to_owned(), meta.stored_at.to_string());
        match meta.lifetime {
            StoredLifetime::Retained { admission } => {
                routing_metadata.insert(ADMISSION_KEY.to_owned(), admission.to_string());
            }
            StoredLifetime::Ttl(_) => {
                if let Some(expires_at) = meta.lifetime.expires_at(meta.stored_at) {
                    routing_metadata.insert("expires_at".to_owned(), expires_at.to_string());
                }
            }
        }
        self.put_index(&routing_key, routing_metadata).await?;
        if let Some(expiry_key) = &expiry_key {
            self.put_index(expiry_key, HashMap::new()).await?;
        }
        if let Some(previous) = replaced {
            let (old_routing, old_expiry) = self.index_keys(&previous);
            if old_routing != routing_key {
                self.delete_object(&old_routing).await?;
            }
            if let Some(old_expiry) = old_expiry.filter(|old| Some(old) != expiry_key.as_ref()) {
                self.delete_object(&old_expiry).await?;
            }
        }
        Ok(())
    }

    /// Lists every key under `prefix`, following continuation tokens.
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }
            let output = request.send().await.map_err(|e| {
                StorageError::Internal(format!("S3 list failed for prefix {prefix}: {e}"))
            })?;
            keys.extend(
                output
                    .contents()
                    .iter()
                    .filter_map(|object| object.key().map(str::to_owned)),
            );
            if output.is_truncated() == Some(true) {
                continuation_token = output.next_continuation_token().map(String::from);
            } else {
                break;
            }
        }
        Ok(keys)
    }

    /// The `blob_id` an index key under `prefix` names.
    fn blob_id_under(prefix: &str, key: &str) -> Result<[u8; 32], StorageError> {
        let hex_id = key.strip_prefix(prefix).ok_or_else(|| {
            StorageError::Internal(format!("index key {key} is not under {prefix}"))
        })?;
        Self::parse_hex_32(hex_id)
    }
}

#[async_trait::async_trait]
impl BlobStorage for S3BlobStore {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        lifetime: StoredLifetime,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored_at = self.now();
        let metadata = object_metadata(routing_id, blob_id, recipient_hint, lifetime, stored_at);

        let replaced = self.replaced(&blob_id).await?;

        // 1. Put primary blob object with content and metadata.
        let blob_key = self.blob_key(&blob_id);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&blob_key)
            .body(ByteStream::from(blob.clone()))
            .set_metadata(Some(metadata))
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!("S3 put blob failed for {blob_key}: {e}"))
            })?;

        // 2. Put the index entries and delete the replaced blob's.
        let meta = BlobMetadata {
            routing_id,
            blob_id,
            recipient_hint,
            lifetime,
            stored_at,
            content_length: None,
        };
        self.write_indexes(&meta, replaced).await?;

        Ok(StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            lifetime,
            stored_at,
            blob,
        })
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        let key = self.blob_key(blob_id);

        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_no_such_key() {
                    return Ok(None);
                }
                return Err(StorageError::Internal(format!(
                    "S3 get failed for {key}: {service_err}"
                )));
            }
        };

        let metadata = output.metadata().cloned().unwrap_or_default();

        let body = output
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Internal(format!("S3 body read failed for {key}: {e}")))?
            .into_bytes()
            .to_vec();

        let stored_blob = Self::stored_blob_from_response(&metadata, body)?;

        // Check expiry: if the blob has expired, return None.
        if stored_blob
            .lifetime
            .expired(stored_blob.stored_at, self.now())
        {
            return Ok(None);
        }

        Ok(Some(stored_blob))
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        cursor: QueryCursor,
        filter: LifetimeFilter,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let now = self.now();

        // Pass one reads routing metadata only: list the class prefixes the
        // filter names and keep every live entry the cursor admits.
        let mut candidates: Vec<(u64, [u8; 32])> = Vec::new();
        for segment in filter_segments(filter) {
            let prefix = self.routing_class_prefix(routing_id, segment);
            for key in self.list_keys(&prefix).await? {
                let blob_id = Self::blob_id_under(&prefix, &key)?;
                // An entry deleted between the list and the head is skipped.
                let Some(metadata) = self.head_index(&key).await? else {
                    continue;
                };
                let stored_at = Self::parse_u64(Self::require_metadata(&metadata, "stored_at")?)?;
                let expired = metadata
                    .get("expires_at")
                    .map(|v| Self::parse_u64(v))
                    .transpose()?
                    .is_some_and(|expires_at| expires_at <= now);
                if !expired && cursor.admits(stored_at, &blob_id) {
                    candidates.push((stored_at, blob_id));
                }
            }
        }
        candidates.sort_unstable();

        // Pass two reads bodies in query order until the limit fills. A blob
        // whose own metadata no longer matches the entry (an overwrite that
        // stopped before deleting its old index entries) is skipped, so a
        // stale entry costs one read and never a wrong answer.
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut results = Vec::with_capacity(candidates.len().min(limit));
        for (stored_at, blob_id) in candidates {
            if results.len() >= limit {
                break;
            }
            let Some(stored) = self.get(&blob_id).await? else {
                continue;
            };
            if stored.routing_id == *routing_id
                && stored.stored_at == stored_at
                && filter.admits(stored.lifetime)
            {
                results.push(stored);
            }
        }
        Ok(results)
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        // First, read the blob metadata to get routing_id and expires_at
        // for cleaning up secondary indices.
        let Some(metadata) = self.head_blob(blob_id).await? else {
            return Ok(false);
        };

        let routing_id = Self::parse_hex_32(Self::require_metadata(&metadata, "routing_id")?)?;
        let lifetime = lifetime_from_metadata(&metadata)?;
        let stored_at = Self::parse_u64(Self::require_metadata(&metadata, "stored_at")?)?;

        // Delete the blob, its routing index entry, and a TTL blob's expiry
        // index entry (a retained blob has none).
        let blob_key = self.blob_key(blob_id);
        let routing_key = self.routing_key(&routing_id, lifetime, blob_id);

        self.delete_object(&blob_key).await?;
        self.delete_object(&routing_key).await?;
        if let Some(expires_at) = lifetime.expires_at(stored_at) {
            self.delete_object(&self.expiry_key(expires_at, blob_id))
                .await?;
        }

        Ok(true)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = self.now();
        let prefix = expiry_list_prefix(&self.prefix);

        // Expiry keys sort by their zero-padded `expires_at`, so the walk
        // stops at the first one not yet due.
        let mut purged = 0usize;
        for key in self.list_keys(&prefix).await? {
            let suffix = key.strip_prefix(&prefix).ok_or_else(|| {
                StorageError::Internal(format!("expiry key {key} is not under {prefix}"))
            })?;
            let (expires_at, blob_hex) = suffix
                .split_once('/')
                .ok_or_else(|| StorageError::Internal(format!("expiry key {key} names no blob")))?;
            let expires_at = Self::parse_u64(expires_at)?;
            if expires_at > now {
                break;
            }
            let blob_id = Self::parse_hex_32(blob_hex)?;

            // The entry is stale unless the blob it names still expires at
            // this second: a deleted blob, a retained overwrite, or a TTL
            // overwrite with another expiry. A stale entry is deleted and the
            // blob is left alone.
            let current = self.replaced(&blob_id).await?;
            let due = current
                .as_ref()
                .filter(|meta| meta.lifetime.expires_at(meta.stored_at) == Some(expires_at));
            if let Some(meta) = due {
                self.delete_object(&self.blob_key(&blob_id)).await?;
                self.delete_object(&self.routing_key(&meta.routing_id, meta.lifetime, &blob_id))
                    .await?;
                purged = purged.saturating_add(1);
            }
            self.delete_object(&key).await?;
        }
        Ok(purged)
    }

    async fn count(&self) -> Result<usize, StorageError> {
        let prefix = format!("{}/blobs/", self.prefix);
        let mut total: usize = 0;
        let mut continuation_token: Option<String> = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);

            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }

            let output = request
                .send()
                .await
                .map_err(|e| StorageError::Internal(format!("S3 list failed for count: {e}")))?;

            total += output.contents().len();

            if output.is_truncated() == Some(true) {
                continuation_token = output.next_continuation_token().map(String::from);
            } else {
                break;
            }
        }

        Ok(total)
    }

    /// Streams the body to S3 holding at most one part in memory: a body
    /// that ends within `PART_SIZE` is one `PutObject` of its exact
    /// length, a longer one a multipart upload. `content_length` is advisory
    /// and sizes only the first buffer; the stored length is the count of
    /// bytes the body yielded.
    async fn store_streaming(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        lifetime: StoredLifetime,
        content_length: Option<u64>,
        mut body: BlobBodyStream,
    ) -> Result<BlobMetadata, StorageError> {
        let stored_at = self.now();
        let metadata = object_metadata(routing_id, blob_id, recipient_hint, lifetime, stored_at);
        let replaced = self.replaced(&blob_id).await?;
        let key = self.blob_key(&blob_id);
        let first_capacity = content_length
            .and_then(|len| usize::try_from(len).ok())
            .map_or(0, |len| len.min(PART_SIZE));
        let mut first = Vec::with_capacity(first_capacity);
        let total = if fill_part(&mut body, &mut first).await? {
            let total = first.len() as u64;
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .body(ByteStream::from(first))
                .set_metadata(Some(metadata))
                .send()
                .await
                .map_err(|e| {
                    StorageError::Internal(format!("S3 streaming put failed for {key}: {e}"))
                })?;
            total
        } else {
            self.put_multipart(&key, metadata, first, &mut body).await?
        };
        let meta = BlobMetadata {
            routing_id,
            blob_id,
            recipient_hint,
            lifetime,
            stored_at,
            content_length: Some(total),
        };
        self.write_indexes(&meta, replaced).await?;
        Ok(meta)
    }

    async fn get_streaming(
        &self,
        blob_id: &[u8; 32],
    ) -> Result<Option<(BlobMetadata, BlobBodyStream)>, StorageError> {
        use futures::stream::unfold;

        let key = self.blob_key(blob_id);

        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_no_such_key() {
                    return Ok(None);
                }
                return Err(StorageError::Internal(format!(
                    "S3 get failed for {key}: {service_err}"
                )));
            }
        };

        let metadata = output.metadata().cloned().unwrap_or_default();
        let s3_content_length = output.content_length().and_then(|l| u64::try_from(l).ok());

        let meta = Self::metadata_from_response(&metadata, s3_content_length)?;

        // Check expiry.
        if meta.lifetime.expired(meta.stored_at, self.now()) {
            return Ok(None);
        }

        // Stream the S3 body directly without collecting to Vec<u8>.
        // Wrap ByteStream in Option so the stream terminates on error (returning
        // None from the unfold closure).
        let body: BlobBodyStream = Box::pin(unfold(Some(output.body), |state| async move {
            let mut byte_stream = state?;
            match byte_stream.next().await {
                Some(Ok(bytes)) => Some((Ok(bytes), Some(byte_stream))),
                Some(Err(e)) => Some((
                    Err(StorageError::Internal(format!("S3 body read error: {e}"))),
                    None, // terminate stream after error
                )),
                None => None,
            }
        }));

        Ok(Some((meta, body)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! S3 blob store integration tests.
    //!
    //! These tests require a running S3-compatible endpoint. Run with:
    //!
    //! ```bash
    //! cargo test -p scp-transport --features s3-blob --lib s3_blob
    //! ```
    //!
    //! Environment variables:
    //! - `S3_TEST_ENDPOINT` — S3-compatible endpoint URL (default: `http://localhost:9000`)
    //! - `S3_TEST_BUCKET` — bucket name (default: `scp-test`)
    //!
    //! The bucket must exist before running tests.

    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn lifetime_round_trip(lifetime: StoredLifetime) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        insert_lifetime_metadata(&mut metadata, lifetime, 1_000);
        assert_eq!(lifetime_from_metadata(&metadata).unwrap(), lifetime);
        metadata
    }

    #[test]
    fn ttl_lifetime_writes_ttl_and_expiry_metadata() {
        let metadata = lifetime_round_trip(StoredLifetime::Ttl(60));
        assert_eq!(metadata.get("blob_ttl").map(String::as_str), Some("60"));
        assert_eq!(metadata.get("expires_at").map(String::as_str), Some("1060"));
        assert!(!metadata.contains_key(RETAIN_KEY));
    }

    #[test]
    fn retained_lifetime_writes_retain_admission_and_no_expiry() {
        let metadata = lifetime_round_trip(StoredLifetime::Retained { admission: 42 });
        assert_eq!(metadata.get(RETAIN_KEY).map(String::as_str), Some("true"));
        assert_eq!(metadata.get(ADMISSION_KEY).map(String::as_str), Some("42"));
        assert!(!metadata.contains_key("blob_ttl"));
        assert!(!metadata.contains_key("expires_at"));
    }

    #[test]
    fn lifetime_metadata_refuses_neither_both_or_a_bad_retain() {
        let mut metadata = HashMap::new();
        assert!(lifetime_from_metadata(&metadata).is_err());
        metadata.insert(RETAIN_KEY.to_owned(), "yes".to_owned());
        assert!(lifetime_from_metadata(&metadata).is_err());
        metadata.insert(RETAIN_KEY.to_owned(), RETAIN_VALUE.to_owned());
        metadata.insert("blob_ttl".to_owned(), "60".to_owned());
        assert!(lifetime_from_metadata(&metadata).is_err());
    }

    /// A retained object without its admission counter, and a TTL object
    /// carrying one, are refused: neither reads as a lifetime.
    #[test]
    fn lifetime_metadata_refuses_a_misplaced_admission_counter() {
        let mut retained = HashMap::new();
        retained.insert(RETAIN_KEY.to_owned(), RETAIN_VALUE.to_owned());
        assert!(lifetime_from_metadata(&retained).is_err());
        let mut ttl = HashMap::new();
        ttl.insert("blob_ttl".to_owned(), "60".to_owned());
        ttl.insert(ADMISSION_KEY.to_owned(), "1".to_owned());
        assert!(lifetime_from_metadata(&ttl).is_err());
    }

    /// Returns the test endpoint URL from env, defaulting to localhost `MinIO`.
    fn test_endpoint() -> String {
        std::env::var("S3_TEST_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_owned())
    }

    /// Returns the test bucket name from env.
    fn test_bucket() -> String {
        std::env::var("S3_TEST_BUCKET").unwrap_or_else(|_| "scp-test".to_owned())
    }

    /// Returns a unique prefix for test isolation.
    fn test_prefix() -> String {
        use rand::Rng;
        let suffix: u64 = rand::thread_rng().r#gen();
        format!("test/{suffix:016x}")
    }

    /// Creates a deterministic `blob_id` from data (SHA-256).
    fn make_blob_id(data: &[u8]) -> [u8; 32] {
        let hash = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    /// Creates a controllable clock for testing.
    fn test_clock(start: u64) -> (ClockFn, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(start));
        let time_clone = Arc::clone(&time);
        let clock: ClockFn = Arc::new(move || time_clone.load(Ordering::SeqCst));
        (clock, time)
    }

    /// Creates an `S3BlobStore` connected to the test endpoint.
    async fn test_store(clock: ClockFn) -> S3BlobStore {
        S3BlobStore::open_with_endpoint(&test_bucket(), &test_prefix(), &test_endpoint(), clock)
            .await
            .expect("failed to create S3BlobStore")
    }

    #[tokio::test]
    async fn store_and_get_returns_blob() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;

        let routing_id = [0xAA; 32];
        let blob_data = vec![1, 2, 3, 4];
        let blob_id = make_blob_id(&blob_data);

        let stored = store
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                blob_data.clone(),
            )
            .await
            .unwrap();

        assert_eq!(stored.blob_id, blob_id);
        assert_eq!(stored.routing_id, routing_id);
        assert_eq!(stored.blob, blob_data);
        assert_eq!(stored.lifetime, StoredLifetime::Ttl(3600));
        assert_eq!(stored.stored_at, 1_000_000);

        let retrieved = store.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.blob, blob_data);
        assert_eq!(retrieved.blob_id, blob_id);
    }

    /// `09-security-model.md` §9.10.12: a retained record carries no TTL, so
    /// no purge removes it while a TTL blob beside it expires.
    #[tokio::test]
    async fn retained_record_survives_every_purge() {
        let (clock, time) = test_clock(1_000_000);
        let storage = test_store(clock).await;
        let routing_id = [0xAD; 32];
        let retained = vec![0x52; 16];
        let retained_id = make_blob_id(&retained);
        storage
            .store(
                routing_id,
                retained_id,
                None,
                crate::native::storage::StoredLifetime::Retained { admission: 0 },
                retained.clone(),
            )
            .await
            .unwrap();
        let ttl_data = vec![0x54; 16];
        let ttl_id = make_blob_id(&ttl_data);
        storage
            .store(
                routing_id,
                ttl_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(10),
                ttl_data,
            )
            .await
            .unwrap();

        // Past the longest TTL a blob may carry, twice.
        for _ in 0..2 {
            time.fetch_add(
                u64::from(scp_relay_client::MAX_BLOB_TTL) + 1,
                Ordering::SeqCst,
            );
            storage.purge_expired().await.unwrap();
        }

        let held = storage.get(&retained_id).await.unwrap().unwrap();
        assert_eq!(held.blob, retained);
        assert_eq!(
            held.lifetime,
            crate::native::storage::StoredLifetime::Retained { admission: 0 }
        );
        assert!(storage.get(&ttl_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;

        let blob_id = [0xFF; 32];
        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_removes_blob() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;

        let routing_id = [0xAA; 32];
        let blob_data = vec![5, 6, 7];
        let blob_id = make_blob_id(&blob_data);

        store
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                blob_data,
            )
            .await
            .unwrap();

        let deleted = store.delete(&blob_id).await.unwrap();
        assert!(deleted);

        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_false() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;

        let blob_id = [0xFF; 32];
        let deleted = store.delete(&blob_id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn query_returns_blobs_for_routing_id() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];

        for i in 0u8..5 {
            time.store(1_000_000 + u64::from(i), Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(3600),
                    data,
                )
                .await
                .unwrap();
        }

        let results = store
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn query_respects_limit() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xBB; 32];

        for i in 0u8..10 {
            time.store(1_000_000 + u64::from(i), Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(3600),
                    data,
                )
                .await
                .unwrap();
        }

        let results = store
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                3,
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn query_returns_oldest_first() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xCC; 32];

        for i in 0u8..3 {
            time.store(1_000_000 + u64::from(i), Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(3600),
                    data,
                )
                .await
                .unwrap();
        }

        let results = store
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        for window in results.windows(2) {
            assert!(window[0].stored_at <= window[1].stored_at);
        }
    }

    #[tokio::test]
    async fn query_different_routing_id_returns_empty() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);
        store
            .store(
                routing_id_a,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        let results = store
            .query(
                &routing_id_b,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_with_recipient_hint_preserves_it() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let hint = [0xBB; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        let stored = store
            .store(
                routing_id,
                blob_id,
                Some(hint),
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        assert_eq!(stored.recipient_hint, Some(hint));

        let retrieved = store.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.recipient_hint, Some(hint));
    }

    #[tokio::test]
    async fn purge_expired_removes_old_blobs() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 100 seconds.
        store
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(100),
                data,
            )
            .await
            .unwrap();

        // Advance clock past expiry.
        time.store(1_000_200, Ordering::SeqCst);

        let purged = store.purge_expired().await.unwrap();
        assert_eq!(purged, 1);

        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn purge_expired_does_not_remove_active_blobs() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let data = vec![4, 5, 6];
        let blob_id = make_blob_id(&data);

        store
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        let purged = store.purge_expired().await.unwrap();
        assert_eq!(purged, 0);

        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_some());
    }

    /// Every index key under `prefix`.
    async fn keys_under(store: &S3BlobStore, prefix: &str) -> Vec<String> {
        store.list_keys(prefix).await.unwrap()
    }

    /// §17.7: a TTL blob overwritten at another routing id as a retained
    /// record leaves neither its routing object nor its expiry object, and
    /// a TTL overwrite under another TTL leaves only the new expiry object.
    #[tokio::test]
    async fn overwrite_deletes_the_replaced_blobs_index_objects() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let (first, second) = ([0xA1; 32], [0xA2; 32]);
        let data = vec![0xA1; 4];
        let blob_id = make_blob_id(&data);
        let expiry = expiry_list_prefix(&store.prefix);

        store
            .store(first, blob_id, None, StoredLifetime::Ttl(10), data.clone())
            .await
            .unwrap();
        time.store(1_000_005, Ordering::SeqCst);
        store
            .store(first, blob_id, None, StoredLifetime::Ttl(60), data.clone())
            .await
            .unwrap();
        assert_eq!(
            keys_under(&store, &expiry).await,
            vec![store.expiry_key(1_000_065, &blob_id)],
            "the TTL overwrite leaves only its own expiry object",
        );

        store
            .store(
                second,
                blob_id,
                None,
                StoredLifetime::Retained { admission: 0 },
                data,
            )
            .await
            .unwrap();
        assert!(
            keys_under(&store, &store.routing_class_prefix(&first, "t"))
                .await
                .is_empty()
        );
        assert!(keys_under(&store, &expiry).await.is_empty());
        assert_eq!(
            keys_under(&store, &store.routing_class_prefix(&second, "r")).await,
            vec![store.routing_key(&second, StoredLifetime::Retained { admission: 0 }, &blob_id)],
        );
    }

    /// Purge re-reads the blob an expiry object names: a stale expiry object
    /// of a blob since overwritten as a retained record, or re-stored under a
    /// later expiry, deletes only itself.
    #[tokio::test]
    async fn purge_skips_a_retained_or_unexpired_blob_behind_a_stale_expiry_object() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xA3; 32];
        let retained = vec![0xA3; 4];
        let retained_id = make_blob_id(&retained);
        let restored = vec![0xA4; 4];
        let restored_id = make_blob_id(&restored);
        store
            .store(
                routing_id,
                retained_id,
                None,
                StoredLifetime::Retained { admission: 0 },
                retained,
            )
            .await
            .unwrap();
        store
            .store(
                routing_id,
                restored_id,
                None,
                StoredLifetime::Ttl(3600),
                restored,
            )
            .await
            .unwrap();
        // Index objects an older write would have left behind.
        for blob_id in [&retained_id, &restored_id] {
            store
                .put_index(&store.expiry_key(1_000_010, blob_id), HashMap::new())
                .await
                .unwrap();
        }

        time.store(1_000_100, Ordering::SeqCst);
        assert_eq!(store.purge_expired().await.unwrap(), 0);
        assert!(store.get(&retained_id).await.unwrap().is_some());
        assert!(store.get(&restored_id).await.unwrap().is_some());
        assert_eq!(
            keys_under(&store, &expiry_list_prefix(&store.prefix)).await,
            vec![store.expiry_key(1_003_600, &restored_id)],
            "purge deletes the stale objects and keeps the live one",
        );
    }

    #[tokio::test]
    async fn delete_cleans_up_routing_index() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xDD; 32];
        let data = vec![7, 8, 9];
        let blob_id = make_blob_id(&data);

        store
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        store.delete(&blob_id).await.unwrap();

        // After deletion, query should return empty.
        let results = store
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn query_with_since_filter() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xEE; 32];

        // Store 3 blobs at different timestamps.
        for i in 0u8..3 {
            time.store(1_000_000 + u64::from(i) * 100, Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(36_000),
                    data,
                )
                .await
                .unwrap();
        }

        // Query with since = 1_000_000 should skip the first blob.
        let results = store
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::Since(1_000_000),
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].stored_at > 1_000_000);
    }

    #[tokio::test]
    async fn store_returns_correct_blob_id() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let blob_data = vec![11, 22, 33, 44, 55];
        let expected_id = make_blob_id(&blob_data);

        let stored = store
            .store(
                routing_id,
                expected_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                blob_data,
            )
            .await
            .unwrap();

        assert_eq!(stored.blob_id, expected_id);
    }

    #[tokio::test]
    async fn concurrent_store_purge() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];

        // Store blobs with short TTL.
        for i in 0u8..5 {
            time.store(1_000_000 + u64::from(i), Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(10),
                    data,
                )
                .await
                .unwrap();
        }

        // Advance clock past TTL.
        time.store(1_000_020, Ordering::SeqCst);

        // Run purge and store concurrently.
        let store_clone = store.clone();
        let purge_handle = tokio::spawn(async move { store_clone.purge_expired().await });

        // Store new blobs while purge runs.
        for i in 10u8..15 {
            time.store(1_000_020 + u64::from(i), Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(3600),
                    data,
                )
                .await
                .unwrap();
        }

        let purge_result = purge_handle.await.unwrap();
        assert!(purge_result.is_ok());

        // Verify newly stored blobs are still retrievable.
        for i in 10u8..15 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            let result = store.get(&blob_id).await.unwrap();
            assert!(result.is_some(), "blob {i} should survive concurrent purge");
            assert_eq!(result.unwrap().blob, data);
        }
    }

    #[tokio::test]
    async fn purge_expired_only_removes_expired() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];

        // Store a short-lived blob (TTL 10s).
        let short_data = vec![1, 2, 3];
        let short_id = make_blob_id(&short_data);
        store
            .store(
                routing_id,
                short_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(10),
                short_data,
            )
            .await
            .unwrap();

        // Store a long-lived blob (TTL 3600s).
        time.store(1_000_001, Ordering::SeqCst);
        let long_data = vec![4, 5, 6];
        let long_id = make_blob_id(&long_data);
        store
            .store(
                routing_id,
                long_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                long_data.clone(),
            )
            .await
            .unwrap();

        // Advance clock past short TTL but not long TTL.
        time.store(1_000_011, Ordering::SeqCst);

        let purged = store.purge_expired().await.unwrap();
        assert_eq!(purged, 1);

        // Short-lived blob should be gone.
        let short_result = store.get(&short_id).await.unwrap();
        assert!(short_result.is_none());

        // Long-lived blob should still exist.
        let long_result = store.get(&long_id).await.unwrap().unwrap();
        assert_eq!(long_result.blob, long_data);
    }

    #[tokio::test]
    async fn get_expired_blob_returns_none() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 100 seconds.
        store
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(100),
                data,
            )
            .await
            .unwrap();

        // Advance clock past expiry.
        time.store(1_000_200, Ordering::SeqCst);

        // Get should return None for expired blobs.
        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    /// `data` as a body of 1 MiB chunks, failing after `fail_after` chunks
    /// when that is set.
    fn chunked(data: &[u8], fail_after: Option<usize>) -> BlobBodyStream {
        let mut chunks: Vec<Result<bytes::Bytes, StorageError>> = data
            .chunks(1024 * 1024)
            .map(|chunk| Ok(bytes::Bytes::copy_from_slice(chunk)))
            .collect();
        if let Some(at) = fail_after {
            chunks.truncate(at);
            chunks.push(Err(StorageError::Internal("the body broke".to_owned())));
        }
        Box::pin(futures::stream::iter(chunks))
    }

    /// A body longer than one part goes up as a multipart upload whatever
    /// length the advisory hint names, and the stored length is the count of
    /// bytes the body yielded.
    #[tokio::test]
    async fn streaming_store_past_one_part_uploads_every_byte_under_a_wrong_hint() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let data: Vec<u8> = (0..251u8).cycle().take(PART_SIZE * 2 + 3).collect();
        let blob_id = make_blob_id(&data);

        let meta = store
            .store_streaming(
                [0xD1; 32],
                blob_id,
                None,
                StoredLifetime::Ttl(3600),
                Some(5),
                chunked(&data, None),
            )
            .await
            .unwrap();

        assert_eq!(meta.content_length, Some(data.len() as u64));
        let stored = store.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(stored.blob.len(), data.len());
        assert!(
            stored.blob == data,
            "the multipart object holds the body's bytes in order"
        );
        assert_eq!(stored.lifetime, StoredLifetime::Ttl(3600));
        let listed = store
            .query(&[0xD1; 32], QueryCursor::All, LifetimeFilter::Any, 10)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
    }

    /// A body that fails after its first part aborts the upload: the store
    /// returns the body's error and holds no object, no index and no open
    /// multipart upload for it.
    #[tokio::test]
    async fn streaming_store_failing_after_one_part_leaves_no_object() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let data: Vec<u8> = (0..241u8).cycle().take(PART_SIZE * 2).collect();
        let blob_id = make_blob_id(&data);
        let first_part_chunks = PART_SIZE / (1024 * 1024) + 1;

        let refused = store
            .store_streaming(
                [0xD2; 32],
                blob_id,
                None,
                StoredLifetime::Ttl(3600),
                None,
                chunked(&data, Some(first_part_chunks)),
            )
            .await;

        match refused {
            Err(StorageError::Internal(detail)) => assert_eq!(detail, "the body broke"),
            other => panic!("expected the body's error, got {other:?}"),
        }
        assert!(store.get(&blob_id).await.unwrap().is_none());
        assert!(
            store
                .query(&[0xD2; 32], QueryCursor::All, LifetimeFilter::Any, 10)
                .await
                .unwrap()
                .is_empty()
        );
        let key = store.blob_key(&blob_id);
        let open = store
            .client
            .list_multipart_uploads()
            .bucket(&store.bucket)
            .prefix(&key)
            .send()
            .await
            .unwrap();
        assert!(
            open.uploads()
                .iter()
                .all(|upload| upload.key() != Some(key.as_str())),
            "the failed upload is aborted, not left open: {:?}",
            open.uploads()
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod probe_tests {
    //! The construction probe needs only the permission the store's runtime
    //! list calls need. A loopback endpoint stands in for an S3 policy that
    //! grants `s3:ListBucket` under one `s3:prefix` and denies everything else.

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serves an endpoint that answers an empty listing to a `ListObjectsV2`
    /// request whose `prefix` is `allowed_prefix`, and 403 `AccessDenied` to
    /// every other request, `HeadBucket` included.
    async fn prefix_scoped_endpoint(allowed_prefix: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("listener address");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut head = Vec::new();
                let mut chunk = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&head);
                let line = text
                    .lines()
                    .next()
                    .unwrap_or("")
                    .replace("%2F", "/")
                    .replace("%2f", "/");
                let allowed = line.starts_with("GET ")
                    && line.contains("list-type=2")
                    && (line.contains(&format!("prefix={allowed_prefix}&"))
                        || line.contains(&format!("prefix={allowed_prefix} ")));
                let (status, body) = if allowed {
                    (
                        "200 OK",
                        format!(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult \
                             xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>b</Name>\
                             <Prefix>{allowed_prefix}</Prefix><KeyCount>0</KeyCount>\
                             <MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated>\
                             </ListBucketResult>"
                        ),
                    )
                } else {
                    (
                        "403 Forbidden",
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error>\
                         <Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
                            .to_owned(),
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/xml\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    /// Builds a client with static credentials against `endpoint`, so the
    /// endpoint's answer alone decides the probe.
    fn client_for(endpoint: &str) -> Client {
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "probe-test-key",
                "probe-test-secret",
                None,
                None,
                "probe-test",
            ))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .http_client(
                aws_smithy_http_client::Builder::new()
                    .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
                    .build_https(),
            )
            .build();
        Client::from_conf(config)
    }

    /// A credential that may list only under the store's prefix opens the
    /// store. A `HeadBucket` probe carries no `s3:prefix`, so it would get 403
    /// here and fail this test.
    #[tokio::test]
    async fn probe_passes_with_list_permission_scoped_to_the_store_prefix() {
        let endpoint = prefix_scoped_endpoint("relay/expiry/").await;
        let result =
            S3BlobStore::from_client(client_for(&endpoint), "bucket", "relay", system_clock())
                .await;
        assert!(
            result.is_ok(),
            "a prefix-scoped credential must open the store: {:?}",
            result.err()
        );
    }

    /// A credential that may not list under the store's prefix fails at
    /// construction with `StorageError::Internal` naming the probe.
    #[tokio::test]
    async fn probe_fails_closed_when_the_store_prefix_is_not_listable() {
        let endpoint = prefix_scoped_endpoint("other/expiry/").await;
        match S3BlobStore::from_client(client_for(&endpoint), "bucket", "relay", system_clock())
            .await
        {
            Err(StorageError::Internal(message)) => assert!(
                message.contains("S3 list probe failed for bucket under relay/expiry/"),
                "the error must name the probe: {message}"
            ),
            Err(other) => panic!("expected StorageError::Internal, got {other:?}"),
            Ok(_) => panic!("a credential that cannot list the store prefix must not open it"),
        }
    }
}
