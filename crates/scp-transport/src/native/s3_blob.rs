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
//! {prefix}/routing/{routing_id_hex}/{blob_id_hex}         — empty routing index objects
//! {prefix}/expiry/{expires_at:020}/{blob_id_hex}          — empty expiry index objects
//! ```
//!
//! Metadata is stored as S3 object metadata (user-defined `x-amz-meta-*`
//! headers). Numeric values are serialized as decimal strings.
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
//! Tests require a running S3-compatible endpoint (e.g., MinIO):
//!
//! ```bash
//! cargo test -p scp-transport --features s3-blob -- --ignored
//! ```
//!
//! Set `S3_TEST_ENDPOINT` and `S3_TEST_BUCKET` environment variables.
//!
//! See SCP-PERSIST-068 for the full story.

use std::collections::HashMap;
use std::sync::Arc;

use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;

use super::storage::{
    BlobBodyStream, BlobMetadata, BlobStorage, ClockFn, StorageError, StoredBlob, system_clock,
};

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

impl S3BlobStore {
    /// Creates an `S3BlobStore` using the default AWS credential chain.
    ///
    /// Credentials are resolved via the standard AWS SDK chain:
    /// environment variables, shared config, IAM role, etc.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the AWS SDK configuration
    /// cannot be loaded.
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
    /// Returns [`StorageError::Internal`] if the AWS SDK configuration
    /// cannot be loaded.
    pub async fn open_with_clock(
        bucket: &str,
        prefix: &str,
        clock: ClockFn,
    ) -> Result<Self, StorageError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        Ok(Self {
            client,
            bucket: bucket.to_owned(),
            prefix: prefix.to_owned(),
            clock,
        })
    }

    /// Creates an `S3BlobStore` with a custom S3-compatible endpoint URL.
    ///
    /// Use this for `MinIO`, Cloudflare R2, or any non-AWS S3 endpoint.
    /// Path-style access is forced (required by most S3-compatible stores).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the AWS SDK configuration
    /// cannot be loaded.
    pub async fn open_with_endpoint(
        bucket: &str,
        prefix: &str,
        endpoint_url: &str,
        clock: ClockFn,
    ) -> Result<Self, StorageError> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3_config = aws_sdk_s3::config::Builder::from(&config)
            .endpoint_url(endpoint_url)
            .force_path_style(true)
            .build();
        let client = Client::from_conf(s3_config);
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

    /// Returns the S3 key for a blob's routing index entry.
    fn routing_key(&self, routing_id: &[u8; 32], blob_id: &[u8; 32]) -> String {
        format!(
            "{}/routing/{}/{}",
            self.prefix,
            hex::encode(routing_id),
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
            blob_ttl: meta.blob_ttl,
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
        let blob_ttl = Self::parse_u32(Self::require_metadata(metadata, "blob_ttl")?)?;
        let stored_at = Self::parse_u64(Self::require_metadata(metadata, "stored_at")?)?;

        let recipient_hint = metadata
            .get("recipient_hint")
            .map(|v| Self::parse_hex_32(v))
            .transpose()?;

        Ok(BlobMetadata {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
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
}

#[async_trait::async_trait]
impl BlobStorage for S3BlobStore {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored_at = self.now();
        let expires_at = stored_at.saturating_add(u64::from(blob_ttl));

        // Build metadata map for S3 object user metadata.
        let mut metadata = HashMap::new();
        metadata.insert("routing_id".to_owned(), hex::encode(routing_id));
        metadata.insert("blob_id".to_owned(), hex::encode(blob_id));
        metadata.insert("blob_ttl".to_owned(), blob_ttl.to_string());
        metadata.insert("stored_at".to_owned(), stored_at.to_string());
        metadata.insert("expires_at".to_owned(), expires_at.to_string());
        if let Some(hint) = &recipient_hint {
            metadata.insert("recipient_hint".to_owned(), hex::encode(hint));
        }

        // 1. Put primary blob object with content and metadata.
        let blob_key = self.blob_key(&blob_id);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&blob_key)
            .body(ByteStream::from(blob.clone()))
            .set_metadata(Some(metadata.clone()))
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!("S3 put blob failed for {blob_key}: {e}"))
            })?;

        // 2. Put routing index entry (empty body, metadata with stored_at).
        let routing_key = self.routing_key(&routing_id, &blob_id);
        let mut routing_metadata = HashMap::new();
        routing_metadata.insert("stored_at".to_owned(), stored_at.to_string());
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&routing_key)
            .body(ByteStream::from(Vec::<u8>::new()))
            .set_metadata(Some(routing_metadata))
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!(
                    "S3 put routing index failed for {routing_key}: {e}"
                ))
            })?;

        // 3. Put expiry index entry (empty body, metadata with routing_id).
        let expiry_key = self.expiry_key(expires_at, &blob_id);
        let mut expiry_metadata = HashMap::new();
        expiry_metadata.insert("routing_id".to_owned(), hex::encode(routing_id));
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&expiry_key)
            .body(ByteStream::from(Vec::<u8>::new()))
            .set_metadata(Some(expiry_metadata))
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!("S3 put expiry index failed for {expiry_key}: {e}"))
            })?;

        Ok(StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
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
        let expires_at = stored_blob
            .stored_at
            .saturating_add(u64::from(stored_blob.blob_ttl));
        if expires_at <= self.now() {
            return Ok(None);
        }

        Ok(Some(stored_blob))
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let prefix = format!("{}/routing/{}/", self.prefix, hex::encode(routing_id));

        // List all routing index entries for this routing_id.
        let mut blob_id_hexes = Vec::new();
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

            let output = request.send().await.map_err(|e| {
                StorageError::Internal(format!("S3 list failed for prefix {prefix}: {e}"))
            })?;

            for object in output.contents() {
                if let Some(key) = object.key() {
                    // Extract the blob_id hex from the key suffix.
                    if let Some(blob_id_hex) = key.strip_prefix(&prefix).filter(|s| !s.is_empty()) {
                        blob_id_hexes.push(blob_id_hex.to_owned());
                    }
                }
            }

            if output.is_truncated() == Some(true) {
                continuation_token = output.next_continuation_token().map(String::from);
            } else {
                break;
            }
        }

        // Fetch each blob and filter/sort.
        let now = self.now();
        let mut results = Vec::new();

        for blob_id_hex in &blob_id_hexes {
            let blob_id_bytes = hex::decode(blob_id_hex).map_err(|e| {
                StorageError::Internal(format!("invalid blob_id hex in routing index: {e}"))
            })?;
            let blob_id: [u8; 32] = blob_id_bytes.try_into().map_err(|_| {
                StorageError::Internal("blob_id in routing index is not 32 bytes".to_owned())
            })?;

            // Fetch the full blob.
            let key = self.blob_key(&blob_id);
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
                    // Blob may have been deleted between list and get — skip.
                    if service_err.is_no_such_key() {
                        continue;
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

            // Skip expired blobs.
            let expires_at = stored_blob
                .stored_at
                .saturating_add(u64::from(stored_blob.blob_ttl));
            if expires_at <= now {
                continue;
            }

            // Apply since filter.
            if since.is_some_and(|since_ts| stored_blob.stored_at <= since_ts) {
                continue;
            }

            results.push(stored_blob);
        }

        // Sort oldest-first (ascending stored_at).
        results.sort_by_key(|b| b.stored_at);

        // Apply limit.
        // u32 fits in usize on all supported platforms (32-bit+).
        #[allow(clippy::cast_possible_truncation)]
        results.truncate(limit as usize);

        Ok(results)
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        // First, read the blob metadata to get routing_id and expires_at
        // for cleaning up secondary indices.
        let Some(metadata) = self.head_blob(blob_id).await? else {
            return Ok(false);
        };

        let routing_id = Self::parse_hex_32(Self::require_metadata(&metadata, "routing_id")?)?;
        let expires_at = Self::parse_u64(Self::require_metadata(&metadata, "expires_at")?)?;

        // Delete all three objects: blob, routing index, expiry index.
        let blob_key = self.blob_key(blob_id);
        let routing_key = self.routing_key(&routing_id, blob_id);
        let expiry_key = self.expiry_key(expires_at, blob_id);

        self.delete_object(&blob_key).await?;
        self.delete_object(&routing_key).await?;
        self.delete_object(&expiry_key).await?;

        Ok(true)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = self.now();
        let prefix = format!("{}/expiry/", self.prefix);

        // List all expiry index entries.
        let mut expired_entries: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new();
        let mut continuation_token: Option<String> = None;
        let mut reached_non_expired = false;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);

            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }

            let output = request.send().await.map_err(|e| {
                StorageError::Internal(format!("S3 list failed for prefix {prefix}: {e}"))
            })?;

            for object in output.contents() {
                let Some(key) = object.key() else {
                    continue;
                };
                // Key format: {prefix}/expiry/{expires_at:020}/{blob_id_hex}
                // Strip the prefix to get "{expires_at:020}/{blob_id_hex}"
                let Some(suffix) = key.strip_prefix(&prefix) else {
                    continue;
                };
                let parts: Vec<&str> = suffix.splitn(2, '/').collect();
                if parts.len() != 2 {
                    continue;
                }
                let Ok(expires_at) = parts[0].parse::<u64>() else {
                    continue;
                };

                // If not yet expired, we can stop — keys are sorted
                // lexicographically and the zero-padded timestamp
                // ensures chronological order.
                if expires_at > now {
                    reached_non_expired = true;
                    break;
                }

                let Ok(blob_id_bytes) = hex::decode(parts[1]) else {
                    continue;
                };
                let Ok(blob_id) = <[u8; 32]>::try_from(blob_id_bytes) else {
                    continue;
                };

                // Fetch routing_id from the expiry entry's metadata.
                let routing_id = match self
                    .client
                    .head_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send()
                    .await
                {
                    Ok(head) => {
                        let meta = head.metadata().cloned().unwrap_or_default();
                        match meta.get("routing_id") {
                            Some(v) => match Self::parse_hex_32(v) {
                                Ok(rid) => rid,
                                Err(_) => continue,
                            },
                            None => continue,
                        }
                    }
                    Err(_) => continue,
                };

                expired_entries.push((expires_at, blob_id, routing_id));
            }

            // If we hit a non-expired key, no need to fetch more pages.
            if reached_non_expired {
                break;
            }

            if output.is_truncated() == Some(true) {
                continuation_token = output.next_continuation_token().map(String::from);
            } else {
                break;
            }
        }

        let count = expired_entries.len();

        // Delete each expired blob + its indices.
        for (expires_at, blob_id, routing_id) in &expired_entries {
            let blob_key = self.blob_key(blob_id);
            let routing_key = self.routing_key(routing_id, blob_id);
            let expiry_key = self.expiry_key(*expires_at, blob_id);

            // Best-effort deletion — individual failures are logged but
            // don't abort the purge.
            let _ = self.delete_object(&blob_key).await;
            let _ = self.delete_object(&routing_key).await;
            let _ = self.delete_object(&expiry_key).await;
        }

        Ok(count)
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

    async fn store_streaming(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        content_length: Option<u64>,
        body: BlobBodyStream,
    ) -> Result<BlobMetadata, StorageError> {
        use bytes::Bytes;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        // Adapt BlobBodyStream → http_body::Body → ByteStream for S3 PutObject.
        // This streams directly to S3 without collecting the full blob in memory.
        //
        // Mutex satisfies the `Sync` bound required by `from_body_1_x` without
        // unsafe code. The stream is only polled sequentially by the HTTP client,
        // so the Mutex never actually contends.
        struct StreamBody(std::sync::Mutex<BlobBodyStream>);

        impl http_body::Body for StreamBody {
            type Data = Bytes;
            type Error = Box<dyn std::error::Error + Send + Sync>;

            fn poll_frame(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
                let mut guard = match self.0.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match guard.as_mut().poll_next(cx) {
                    Poll::Ready(Some(Ok(bytes))) => {
                        Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
                    }
                    Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e) as _))),
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        let stored_at = self.now();
        let expires_at = stored_at.saturating_add(u64::from(blob_ttl));

        // Build metadata map for S3 object user metadata.
        let mut metadata = HashMap::new();
        metadata.insert("routing_id".to_owned(), hex::encode(routing_id));
        metadata.insert("blob_id".to_owned(), hex::encode(blob_id));
        metadata.insert("blob_ttl".to_owned(), blob_ttl.to_string());
        metadata.insert("stored_at".to_owned(), stored_at.to_string());
        metadata.insert("expires_at".to_owned(), expires_at.to_string());
        if let Some(hint) = &recipient_hint {
            metadata.insert("recipient_hint".to_owned(), hex::encode(hint));
        }

        let adapter = StreamBody(std::sync::Mutex::new(body));
        let mut put_builder = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.blob_key(&blob_id))
            .set_metadata(Some(metadata.clone()));

        // Set content length if provided — S3 can use it for validation.
        if let Some(len) = content_length {
            #[allow(clippy::cast_possible_wrap)]
            {
                put_builder = put_builder.content_length(len as i64);
            }
        }

        put_builder
            .body(ByteStream::from_body_1_x(adapter))
            .send()
            .await
            .map_err(|e| StorageError::Internal(format!("S3 streaming put failed: {e}")))?;

        // Put routing index entry (empty body, metadata with stored_at).
        let routing_key = self.routing_key(&routing_id, &blob_id);
        let mut routing_metadata = HashMap::new();
        routing_metadata.insert("stored_at".to_owned(), stored_at.to_string());
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&routing_key)
            .body(ByteStream::from(Vec::<u8>::new()))
            .set_metadata(Some(routing_metadata))
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!(
                    "S3 put routing index failed for {routing_key}: {e}"
                ))
            })?;

        // Put expiry index entry (empty body, metadata with routing_id).
        let expiry_key = self.expiry_key(expires_at, &blob_id);
        let mut expiry_metadata = HashMap::new();
        expiry_metadata.insert("routing_id".to_owned(), hex::encode(routing_id));
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&expiry_key)
            .body(ByteStream::from(Vec::<u8>::new()))
            .set_metadata(Some(expiry_metadata))
            .send()
            .await
            .map_err(|e| {
                StorageError::Internal(format!("S3 put expiry index failed for {expiry_key}: {e}"))
            })?;

        Ok(BlobMetadata {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
            stored_at,
            content_length,
        })
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
        let expires_at = meta.stored_at.saturating_add(u64::from(meta.blob_ttl));
        if expires_at <= self.now() {
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
    //! cargo test -p scp-transport --features s3-blob -- --ignored
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
    #[ignore = "requires S3-compatible endpoint"]
    async fn store_and_get_returns_blob() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;

        let routing_id = [0xAA; 32];
        let blob_data = vec![1, 2, 3, 4];
        let blob_id = make_blob_id(&blob_data);

        let stored = store
            .store(routing_id, blob_id, None, 3600, blob_data.clone())
            .await
            .unwrap();

        assert_eq!(stored.blob_id, blob_id);
        assert_eq!(stored.routing_id, routing_id);
        assert_eq!(stored.blob, blob_data);
        assert_eq!(stored.blob_ttl, 3600);
        assert_eq!(stored.stored_at, 1_000_000);

        let retrieved = store.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.blob, blob_data);
        assert_eq!(retrieved.blob_id, blob_id);
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn get_nonexistent_returns_none() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;

        let blob_id = [0xFF; 32];
        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn delete_removes_blob() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;

        let routing_id = [0xAA; 32];
        let blob_data = vec![5, 6, 7];
        let blob_id = make_blob_id(&blob_data);

        store
            .store(routing_id, blob_id, None, 3600, blob_data)
            .await
            .unwrap();

        let deleted = store.delete(&blob_id).await.unwrap();
        assert!(deleted);

        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn delete_nonexistent_returns_false() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;

        let blob_id = [0xFF; 32];
        let deleted = store.delete(&blob_id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn query_returns_blobs_for_routing_id() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];

        for i in 0u8..5 {
            time.store(1_000_000 + u64::from(i), Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = store.query(&routing_id, None, 100).await.unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn query_respects_limit() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xBB; 32];

        for i in 0u8..10 {
            time.store(1_000_000 + u64::from(i), Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = store.query(&routing_id, None, 3).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn query_returns_oldest_first() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xCC; 32];

        for i in 0u8..3 {
            time.store(1_000_000 + u64::from(i), Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            store
                .store(routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = store.query(&routing_id, None, 100).await.unwrap();
        for window in results.windows(2) {
            assert!(window[0].stored_at <= window[1].stored_at);
        }
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn query_different_routing_id_returns_empty() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);
        store
            .store(routing_id_a, blob_id, None, 3600, data)
            .await
            .unwrap();

        let results = store.query(&routing_id_b, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn store_with_recipient_hint_preserves_it() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let hint = [0xBB; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        let stored = store
            .store(routing_id, blob_id, Some(hint), 3600, data)
            .await
            .unwrap();

        assert_eq!(stored.recipient_hint, Some(hint));

        let retrieved = store.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.recipient_hint, Some(hint));
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn purge_expired_removes_old_blobs() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 100 seconds.
        store
            .store(routing_id, blob_id, None, 100, data)
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
    #[ignore = "requires S3-compatible endpoint"]
    async fn purge_expired_does_not_remove_active_blobs() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let data = vec![4, 5, 6];
        let blob_id = make_blob_id(&data);

        store
            .store(routing_id, blob_id, None, 3600, data)
            .await
            .unwrap();

        let purged = store.purge_expired().await.unwrap();
        assert_eq!(purged, 0);

        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn delete_cleans_up_routing_index() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xDD; 32];
        let data = vec![7, 8, 9];
        let blob_id = make_blob_id(&data);

        store
            .store(routing_id, blob_id, None, 3600, data)
            .await
            .unwrap();

        store.delete(&blob_id).await.unwrap();

        // After deletion, query should return empty.
        let results = store.query(&routing_id, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
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
                .store(routing_id, blob_id, None, 36_000, data)
                .await
                .unwrap();
        }

        // Query with since = 1_000_000 should skip the first blob.
        let results = store
            .query(&routing_id, Some(1_000_000), 100)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].stored_at > 1_000_000);
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
    async fn store_returns_correct_blob_id() {
        let (clock, _time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let blob_data = vec![11, 22, 33, 44, 55];
        let expected_id = make_blob_id(&blob_data);

        let stored = store
            .store(routing_id, expected_id, None, 3600, blob_data)
            .await
            .unwrap();

        assert_eq!(stored.blob_id, expected_id);
    }

    #[tokio::test]
    #[ignore = "requires S3-compatible endpoint"]
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
                .store(routing_id, blob_id, None, 10, data)
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
                .store(routing_id, blob_id, None, 3600, data)
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
    #[ignore = "requires S3-compatible endpoint"]
    async fn purge_expired_only_removes_expired() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];

        // Store a short-lived blob (TTL 10s).
        let short_data = vec![1, 2, 3];
        let short_id = make_blob_id(&short_data);
        store
            .store(routing_id, short_id, None, 10, short_data)
            .await
            .unwrap();

        // Store a long-lived blob (TTL 3600s).
        time.store(1_000_001, Ordering::SeqCst);
        let long_data = vec![4, 5, 6];
        let long_id = make_blob_id(&long_data);
        store
            .store(routing_id, long_id, None, 3600, long_data.clone())
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
    #[ignore = "requires S3-compatible endpoint"]
    async fn get_expired_blob_returns_none() {
        let (clock, time) = test_clock(1_000_000);
        let store = test_store(clock).await;
        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 100 seconds.
        store
            .store(routing_id, blob_id, None, 100, data)
            .await
            .unwrap();

        // Advance clock past expiry.
        time.store(1_000_200, Ordering::SeqCst);

        // Get should return None for expired blobs.
        let result = store.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }
}
