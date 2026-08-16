//! DID-signed bearer token authentication for bridge HTTP endpoints.
//!
//! Implements the authentication layer specified in spec section 12.10.2.
//! Bridge operators authenticate using DID-signed JWTs in the
//! `Authorization: Bearer` header. The node verifies the JWT signature
//! against the operator's DID document (section 3.2).
//!
//! For webhook callbacks (platform to bridge node), Ed25519 signatures in
//! the `X-SCP-Signature` header are verified against the platform's
//! pre-registered public key.
//!
//! # Error Codes
//!
//! | Code | HTTP Status | Description |
//! |------|-------------|-------------|
//! | `BRIDGE_NOT_AUTHORIZED` | 401 | Bearer token invalid or expired |
//! | `BRIDGE_SUSPENDED` | 403 | Bridge is suspended by context governance |
//!
//! See ADR-023 in `.docs/adrs/phase-5.md` and spec section 12.10.3.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use scp_core::bridge::{BridgeConnector, BridgeStatus};
use scp_core::store::ProtocolRepository;
use scp_did::{DidDocument, decode_multibase_key};
use scp_platform::traits::Storage;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum allowed JWT token lifetime (1 hour, in seconds).
///
/// Spec section 12.10.2: "Token lifetime MUST NOT exceed 1 hour."
const MAX_TOKEN_LIFETIME_SECS: u64 = 3600;

/// Clock skew tolerance for JWT validation (30 seconds).
///
/// Allows for minor clock differences between bridge operator and node.
const CLOCK_SKEW_TOLERANCE_SECS: u64 = 30;

/// The JWT `alg` header value for Ed25519 signatures (RFC 8037).
const JWT_ALG_EDDSA: &str = "EdDSA";

/// The JWT `typ` header value.
const JWT_TYP: &str = "JWT";

/// Maximum allowed timestamp drift for webhook signature verification
/// (300 seconds = 5 minutes).
///
/// Per spec §12.10.2, the `X-SCP-Timestamp` header must be within this
/// window of the current time to prevent replay attacks.
const WEBHOOK_TIMESTAMP_TOLERANCE_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Bridge error responses (spec section 12.10.3)
// ---------------------------------------------------------------------------

/// Returns a 401 error response with the `BRIDGE_NOT_AUTHORIZED` error code.
///
/// Used when the bearer token is invalid, expired, or has a bad signature.
/// See spec section 12.10.3.
fn bridge_not_authorized(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiError {
            error: msg.into(),
            code: "BRIDGE_NOT_AUTHORIZED".to_owned(),
        }),
    )
}

/// Returns a 403 error response with the `BRIDGE_SUSPENDED` error code.
///
/// Used when the bridge has been suspended by context governance.
/// See spec section 12.10.3.
fn bridge_suspended(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiError {
            error: msg.into(),
            code: "BRIDGE_SUSPENDED".to_owned(),
        }),
    )
}

// ---------------------------------------------------------------------------
// JWT structures
// ---------------------------------------------------------------------------

/// JWT header for DID-signed bridge tokens.
///
/// Only the `EdDSA` algorithm (Ed25519) is supported, per spec section 12.10.2.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    /// Algorithm — must be `"EdDSA"` (RFC 8037).
    alg: String,

    /// Type — must be `"JWT"`.
    #[serde(default)]
    typ: Option<String>,

    /// Key ID — optional. If present, specifies the DID document verification
    /// method fragment to use (e.g., `"#active"`).
    #[serde(default)]
    kid: Option<String>,
}

/// JWT claims for bridge operator authentication.
///
/// The payload contains the operator's DID, the target audience (node URL),
/// timestamps, and SCP-specific bridge/context identifiers.
///
/// See spec section 12.10.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeJwtClaims {
    /// Issuer — the bridge operator's DID (e.g., `"did:dht:z6MkOperator..."`).
    pub iss: String,

    /// Audience — the target node URL (e.g., `"https://platform.example.com"`).
    pub aud: String,

    /// Issued At — Unix timestamp (seconds) when the JWT was created.
    pub iat: u64,

    /// Expiration — Unix timestamp (seconds) when the JWT expires.
    pub exp: u64,

    /// The bridge instance identifier this token authenticates for.
    pub scp_bridge_id: String,

    /// The context this bridge is registered in.
    pub scp_context_id: String,
}

/// Validated bridge authentication context extracted by the middleware.
///
/// Stored as a request extension so downstream handlers can access the
/// authenticated bridge identity without re-parsing the JWT.
///
/// # Authorized scope
///
/// [`bridge_auth_middleware`] admits a request only when the JWT `scp_bridge_id`
/// names a registered bridge, the JWT `iss` equals that bridge's
/// `operator_did`, and the JWT `scp_context_id` equals that bridge's
/// `registration_context`. A `BridgeAuthContext` therefore authorizes exactly
/// one bridge instance acting inside exactly one context — never a set of
/// contexts and never a node-wide role. A handler reading this context MUST
/// restrict every record it enumerates, mutates, or emits to
/// [`context_id`](Self::context_id) and [`bridge_id`](Self::bridge_id).
#[derive(Debug, Clone)]
pub struct BridgeAuthContext {
    /// The verified JWT claims.
    pub claims: BridgeJwtClaims,

    /// The resolved bridge connector from the registry.
    pub bridge: BridgeConnector,
}

impl BridgeAuthContext {
    /// Returns the single context this request is authorized to act inside.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.bridge.registration_context
    }

    /// Returns the single bridge instance this request is authorized to act as.
    #[must_use]
    pub fn bridge_id(&self) -> &str {
        &self.bridge.bridge_id
    }
}

/// A webhook signing key together with the bridge instance it belongs to.
///
/// Spec §12.10.2 registers a platform's Ed25519 public key through the
/// `RegisterBridge` governance action, and step 3 of that flow states that the
/// bridge node "stores the platform key associated with the bridge instance."
/// Storing a bare key without that association lets any platform holding any
/// registered key act on any context's shadows, so this type carries the
/// association that the signature check alone cannot supply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookKeyBinding {
    /// The platform's Ed25519 public key.
    pub public_key: [u8; 32],

    /// The bridge instance this key signs for.
    pub bridge_id: String,
}

/// Validated webhook authentication context extracted by the middleware.
///
/// Stored as a request extension so the webhook handler can restrict the events
/// it processes to the signing platform's own bridge and context.
///
/// # Authorized scope
///
/// [`webhook_auth_middleware`] admits a request only when the `X-SCP-Signature`
/// header verifies under the key registered for the `X-SCP-Platform-Key-Id`
/// header, and that key's [`WebhookKeyBinding::bridge_id`] names an active
/// registered bridge. This context therefore authorizes exactly one bridge
/// instance inside exactly one context, matching what a
/// [`BridgeAuthContext`] authorizes on the bearer-token path.
#[derive(Debug, Clone)]
pub struct WebhookAuthContext {
    /// The resolved bridge connector whose platform key signed the request.
    pub bridge: BridgeConnector,
}

impl WebhookAuthContext {
    /// Returns the single context this request is authorized to act inside.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.bridge.registration_context
    }

    /// Returns the single bridge instance this request is authorized to act as.
    #[must_use]
    pub fn bridge_id(&self) -> &str {
        &self.bridge.bridge_id
    }
}

// ---------------------------------------------------------------------------
// Bridge lookup trait
// ---------------------------------------------------------------------------

/// Trait for looking up registered bridges and resolving DID documents.
///
/// Implementors provide the bridge registry and DID resolution needed
/// by [`bridge_auth_middleware`]. This decouples the auth layer from
/// specific storage and identity implementations.
pub trait BridgeLookup: Send + Sync + 'static {
    /// Look up a bridge by its ID.
    ///
    /// Returns `None` if no bridge with the given ID is registered.
    fn find_bridge(&self, bridge_id: &str) -> Option<BridgeConnector>;

    /// Resolve a DID document for the given DID string.
    ///
    /// Returns `None` if the DID cannot be resolved. Implementations
    /// MAY cache resolved documents with TTL (spec section 12.10.2).
    fn resolve_did_document(&self, did: &str) -> Option<DidDocument>;

    /// Look up a pre-registered webhook signing key by key ID.
    ///
    /// Returns the Ed25519 public key together with the bridge instance the
    /// key was registered for (spec §12.10.2, platform key registration step
    /// 3). Returns `None` if no key with that ID is registered.
    fn find_webhook_key(&self, key_id: &str) -> Option<WebhookKeyBinding>;

    /// Returns the expected audience (node URL) for JWT validation.
    fn expected_audience(&self) -> &str;
}

// ---------------------------------------------------------------------------
// StorageBridgeLookup — production implementation
// ---------------------------------------------------------------------------

/// Key prefix for bridge connector records in storage.
const BRIDGE_REGISTRY_PREFIX: &str = "bridge/registry/";

/// Key prefix for cached DID documents in storage.
const BRIDGE_DID_DOC_PREFIX: &str = "bridge/did_doc/";

/// Key prefix for webhook signing keys in storage.
const BRIDGE_WEBHOOK_KEY_PREFIX: &str = "bridge/webhook_key/";

/// Storage key for the node's audience URL.
const BRIDGE_AUDIENCE_KEY: &str = "bridge/config/audience";

/// Production [`BridgeLookup`] backed by a [`ProtocolRepository`] (and its
/// underlying [`Storage`] implementation).
///
/// Uses an in-memory cache (protected by `std::sync::RwLock`) for synchronous
/// lookups required by the `BridgeLookup` trait. All mutations write through
/// to the underlying storage backend AND update the cache atomically, so the
/// cache always reflects persistent state.
///
/// At node startup, call [`StorageBridgeLookup::load_from_storage`] to hydrate
/// the cache from persisted data. Subsequent registrations via
/// [`register_bridge`](Self::register_bridge),
/// [`register_did_document`](Self::register_did_document), and
/// [`register_webhook_key`](Self::register_webhook_key) keep both the cache
/// and storage in sync.
///
/// See spec section 12.10.2 (bridge authentication).
pub struct StorageBridgeLookup<S: Storage> {
    /// The protocol repository wrapping the storage backend.
    repo: Arc<ProtocolRepository<S>>,
    /// In-memory cache of bridge connectors keyed by bridge ID.
    bridges: std::sync::RwLock<HashMap<String, BridgeConnector>>,
    /// In-memory cache of DID documents keyed by DID string.
    did_docs: std::sync::RwLock<HashMap<String, DidDocument>>,
    /// In-memory cache of webhook signing keys keyed by key ID.
    webhook_keys: std::sync::RwLock<HashMap<String, WebhookKeyBinding>>,
    /// The expected JWT audience (node URL).
    audience: String,
}

impl<S: Storage> StorageBridgeLookup<S> {
    /// Creates a new `StorageBridgeLookup` with an empty cache.
    ///
    /// Call [`load_from_storage`](Self::load_from_storage) after construction
    /// to hydrate the cache from persisted data.
    #[must_use]
    pub fn new(repo: Arc<ProtocolRepository<S>>, audience: String) -> Self {
        Self {
            repo,
            bridges: std::sync::RwLock::new(HashMap::new()),
            did_docs: std::sync::RwLock::new(HashMap::new()),
            webhook_keys: std::sync::RwLock::new(HashMap::new()),
            audience,
        }
    }

    /// Hydrates the in-memory cache from the storage backend.
    ///
    /// Scans all `bridge/registry/*`, `bridge/did_doc/*`, and
    /// `bridge/webhook_key/*` keys, deserializing their values into
    /// the appropriate caches. Also persists the audience URL if it
    /// is not yet stored.
    ///
    /// Should be called once at node startup before serving requests.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a storage operation fails.
    pub async fn load_from_storage(&self) -> Result<(), scp_platform::PlatformError> {
        let storage = self.repo.storage();

        // Load bridges — collect from storage first, then insert into cache.
        let bridge_keys = storage.list_keys(BRIDGE_REGISTRY_PREFIX).await?;
        let mut loaded_bridges = Vec::new();
        for key in &bridge_keys {
            if let Some(data) = storage.retrieve(key).await? {
                if let Ok(connector) = serde_json::from_slice::<BridgeConnector>(&data) {
                    loaded_bridges.push(connector);
                } else {
                    tracing::warn!(key = %key, "skipping bridge record with invalid JSON");
                }
            }
        }
        {
            let mut cache = self
                .bridges
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for connector in loaded_bridges {
                cache.insert(connector.bridge_id.clone(), connector);
            }
        }

        // Load DID documents — collect from storage first, then insert into cache.
        let doc_keys = storage.list_keys(BRIDGE_DID_DOC_PREFIX).await?;
        let mut loaded_docs = Vec::new();
        for key in &doc_keys {
            if let Some(data) = storage.retrieve(key).await? {
                if let Ok(doc) = serde_json::from_slice::<DidDocument>(&data) {
                    loaded_docs.push(doc);
                } else {
                    tracing::warn!(key = %key, "skipping DID document with invalid JSON");
                }
            }
        }
        {
            let mut cache = self
                .did_docs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for doc in loaded_docs {
                cache.insert(doc.id.clone(), doc);
            }
        }

        // Load webhook keys — collect from storage first, then insert into cache.
        //
        // A record that does not deserialize into a `WebhookKeyBinding` carries
        // no bridge association, so the node cannot tell which context the key
        // authorizes. Such a record is dropped rather than loaded with a
        // guessed bridge, because loading it would authorize the key against
        // every context.
        let wh_keys = storage.list_keys(BRIDGE_WEBHOOK_KEY_PREFIX).await?;
        let mut loaded_wh_keys = Vec::new();
        for key in &wh_keys {
            if let Some(data) = storage.retrieve(key).await? {
                if let Ok(binding) = serde_json::from_slice::<WebhookKeyBinding>(&data) {
                    let key_id = key.strip_prefix(BRIDGE_WEBHOOK_KEY_PREFIX).unwrap_or(key);
                    loaded_wh_keys.push((key_id.to_owned(), binding));
                } else {
                    tracing::warn!(
                        key = %key,
                        "skipping webhook key record that carries no bridge binding"
                    );
                }
            }
        }
        {
            let mut cache = self
                .webhook_keys
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (key_id, binding) in loaded_wh_keys {
                cache.insert(key_id, binding);
            }
        }

        // Persist the audience URL if not already stored.
        if storage.retrieve(BRIDGE_AUDIENCE_KEY).await?.is_none() {
            storage
                .store(BRIDGE_AUDIENCE_KEY, self.audience.as_bytes())
                .await?;
        }

        let bridge_count = self
            .bridges
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        let doc_count = self
            .did_docs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        let wh_count = self
            .webhook_keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        tracing::info!(
            bridges = bridge_count,
            did_docs = doc_count,
            webhook_keys = wh_count,
            "bridge auth cache loaded from storage"
        );

        Ok(())
    }

    /// Registers a bridge connector, persisting to storage and updating the cache.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the storage write fails.
    pub async fn register_bridge(
        &self,
        connector: BridgeConnector,
    ) -> Result<(), scp_platform::PlatformError> {
        let key = format!("{BRIDGE_REGISTRY_PREFIX}{}", connector.bridge_id);
        let data = serde_json::to_vec(&connector)
            .map_err(|e| scp_platform::PlatformError::StorageError(e.to_string()))?;
        self.repo.storage().store(&key, &data).await?;
        self.bridges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(connector.bridge_id.clone(), connector);
        Ok(())
    }

    /// Removes a bridge connector by ID.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the storage delete fails.
    pub async fn deregister_bridge(
        &self,
        bridge_id: &str,
    ) -> Result<(), scp_platform::PlatformError> {
        let key = format!("{BRIDGE_REGISTRY_PREFIX}{bridge_id}");
        self.repo.storage().delete(&key).await?;
        self.bridges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(bridge_id);
        Ok(())
    }

    /// Registers (or updates) a DID document, persisting to storage and
    /// updating the cache.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the storage write fails.
    pub async fn register_did_document(
        &self,
        doc: DidDocument,
    ) -> Result<(), scp_platform::PlatformError> {
        let key = format!("{BRIDGE_DID_DOC_PREFIX}{}", doc.id);
        let data = serde_json::to_vec(&doc)
            .map_err(|e| scp_platform::PlatformError::StorageError(e.to_string()))?;
        self.repo.storage().store(&key, &data).await?;
        self.did_docs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(doc.id.clone(), doc);
        Ok(())
    }

    /// Registers a webhook signing key against the bridge instance it signs
    /// for, persisting to storage and updating the cache.
    ///
    /// Spec §12.10.2 requires the node to store a platform key associated with
    /// a bridge instance, so `bridge_id` names the bridge whose registration
    /// carried this key. The webhook middleware resolves that bridge to decide
    /// which context a signed webhook request may touch.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the storage write fails.
    pub async fn register_webhook_key(
        &self,
        key_id: &str,
        bridge_id: &str,
        public_key: [u8; 32],
    ) -> Result<(), scp_platform::PlatformError> {
        let binding = WebhookKeyBinding {
            public_key,
            bridge_id: bridge_id.to_owned(),
        };
        let key = format!("{BRIDGE_WEBHOOK_KEY_PREFIX}{key_id}");
        let data = serde_json::to_vec(&binding)
            .map_err(|e| scp_platform::PlatformError::StorageError(e.to_string()))?;
        self.repo.storage().store(&key, &data).await?;
        self.webhook_keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key_id.to_owned(), binding);
        Ok(())
    }

    /// Removes a webhook signing key by ID.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the storage delete fails.
    pub async fn deregister_webhook_key(
        &self,
        key_id: &str,
    ) -> Result<(), scp_platform::PlatformError> {
        let key = format!("{BRIDGE_WEBHOOK_KEY_PREFIX}{key_id}");
        self.repo.storage().delete(&key).await?;
        self.webhook_keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key_id);
        Ok(())
    }
}

impl<S: Storage + 'static> BridgeLookup for StorageBridgeLookup<S> {
    fn find_bridge(&self, bridge_id: &str) -> Option<BridgeConnector> {
        self.bridges
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(bridge_id)
            .cloned()
    }

    fn resolve_did_document(&self, did: &str) -> Option<DidDocument> {
        self.did_docs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(did)
            .cloned()
    }

    fn find_webhook_key(&self, key_id: &str) -> Option<WebhookKeyBinding> {
        self.webhook_keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key_id)
            .cloned()
    }

    fn expected_audience(&self) -> &str {
        &self.audience
    }
}

// ---------------------------------------------------------------------------
// JWT parsing and verification
// ---------------------------------------------------------------------------

/// Decodes a base64url-encoded JWT segment.
fn decode_jwt_segment(segment: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("invalid base64url encoding: {e}"))
}

/// Parses and verifies a DID-signed JWT bearer token.
///
/// Performs the following checks (spec section 12.10.2):
/// 1. Splits the JWT into header, payload, and signature segments.
/// 2. Validates the header (`alg` must be `EdDSA`).
/// 3. Deserializes the claims payload.
/// 4. Resolves the issuer's DID document.
/// 5. Extracts the signing public key from the DID document.
/// 6. Verifies the Ed25519 signature over `header.payload`.
/// 7. Validates temporal claims (`iat`, `exp`, max lifetime).
///
/// # Errors
///
/// Returns a human-readable error string if any check fails.
fn verify_bridge_jwt(token: &str, lookup: &dyn BridgeLookup) -> Result<BridgeJwtClaims, String> {
    // Step 1: Split into three segments.
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("JWT must have exactly three segments".to_owned());
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Step 2: Decode and validate the header.
    let header_bytes = decode_jwt_segment(header_b64)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("invalid JWT header JSON: {e}"))?;

    if header.alg != JWT_ALG_EDDSA {
        return Err(format!(
            "unsupported JWT algorithm: expected {JWT_ALG_EDDSA}, got {}",
            header.alg
        ));
    }

    if let Some(ref typ) = header.typ
        && !typ.eq_ignore_ascii_case(JWT_TYP)
    {
        return Err(format!(
            "unsupported JWT type: expected {JWT_TYP}, got {typ}"
        ));
    }

    // Step 3: Decode and parse the claims payload.
    let payload_bytes = decode_jwt_segment(payload_b64)?;
    let claims: BridgeJwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("invalid JWT payload JSON: {e}"))?;

    // Step 4: Resolve the issuer's DID document.
    let did_doc = lookup
        .resolve_did_document(&claims.iss)
        .ok_or_else(|| format!("could not resolve DID document for issuer: {}", claims.iss))?;

    // Step 5: Extract the signing public key.
    //
    // Use the `kid` header if present (strip the DID prefix if included),
    // otherwise default to `#active` (the Human Signing Key per ADR-039).
    // Extract fragment from kid header. kid may be a full DID URL like
    // "did:dht:z6Mk...#active", just the fragment like "#active", or bare "active".
    // Default to "active" (the Human Signing Key per ADR-039) when kid is absent.
    let fragment = header.kid.as_ref().map_or_else(
        || "active".to_owned(),
        |kid| {
            kid.strip_prefix('#').map_or_else(
                || {
                    kid.rsplit_once('#')
                        .map_or_else(|| kid.clone(), |(_, f)| (*f).to_owned())
                },
                str::to_owned,
            )
        },
    );

    let vm = did_doc
        .verification_method_by_fragment(&fragment)
        .ok_or_else(|| {
            format!(
                "DID document for {} has no verification method with fragment #{fragment}",
                claims.iss
            )
        })?;

    let pub_key_bytes = decode_multibase_key(&vm.public_key_multibase)
        .map_err(|e| format!("failed to decode public key from DID document: {e}"))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_key_bytes)
        .map_err(|e| format!("invalid Ed25519 public key in DID document: {e}"))?;

    // Step 6: Decode and verify the signature.
    let signature_bytes = decode_jwt_segment(signature_b64)?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "invalid Ed25519 signature length: expected 64, got {}",
            v.len()
        )
    })?;
    let signature = Signature::from_bytes(&signature_array);

    // The signed message is "header.payload" (the raw base64url segments).
    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("JWT signature verification failed: {e}"))?;

    // Step 7: Validate temporal claims.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "system clock is before Unix epoch".to_owned())?;

    // Check expiration (with clock skew tolerance).
    if claims.exp + CLOCK_SKEW_TOLERANCE_SECS < now {
        return Err(format!("JWT has expired: exp={}, now={now}", claims.exp));
    }

    // Check that iat is not in the future (with clock skew tolerance).
    if claims.iat > now + CLOCK_SKEW_TOLERANCE_SECS {
        return Err(format!(
            "JWT issued in the future: iat={}, now={now}",
            claims.iat
        ));
    }

    // Check maximum token lifetime (spec: MUST NOT exceed 1 hour).
    let lifetime = claims.exp.saturating_sub(claims.iat);
    if lifetime > MAX_TOKEN_LIFETIME_SECS {
        return Err(format!(
            "JWT lifetime exceeds maximum: {lifetime}s > {MAX_TOKEN_LIFETIME_SECS}s"
        ));
    }

    // Validate audience matches the expected node URL.
    if claims.aud != lookup.expected_audience() {
        return Err(format!(
            "JWT audience mismatch: expected {}, got {}",
            lookup.expected_audience(),
            claims.aud
        ));
    }

    Ok(claims)
}

// ---------------------------------------------------------------------------
// Bridge auth middleware
// ---------------------------------------------------------------------------

/// Rejects a bridge whose governance status forbids it from acting.
///
/// Both the bearer-token path and the webhook-signature path admit a request
/// only for an `Active` bridge, so this check lives in one place and both
/// middlewares call it.
fn reject_inactive_bridge(bridge: &BridgeConnector) -> Option<(StatusCode, Json<ApiError>)> {
    match bridge.status {
        BridgeStatus::Active => None,
        BridgeStatus::Suspended => Some(bridge_suspended(format!(
            "bridge {} is suspended by context governance",
            bridge.bridge_id
        ))),
        BridgeStatus::Revoked => Some(bridge_not_authorized(format!(
            "bridge {} has been revoked",
            bridge.bridge_id
        ))),
    }
}

/// Authorizes a bearer-token bridge request and returns the scope it grants.
///
/// Verifies the `Authorization: Bearer <JWT>` header against the issuer's DID
/// document, resolves the bridge named by `scp_bridge_id`, and requires the
/// JWT issuer and context to match that bridge's registration. Both
/// [`bridge_auth_middleware`] and [`bridge_auth_middleware_dyn`] call this
/// function, so the generic and type-erased entry points enforce one rule set.
///
/// # Errors
///
/// Returns the HTTP status and body the middleware sends when any check fails.
fn authorize_bearer_request(
    headers: &axum::http::HeaderMap,
    lookup: &dyn BridgeLookup,
) -> Result<BridgeAuthContext, (StatusCode, Json<ApiError>)> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(value) if value.len() > 7 && value[..7].eq_ignore_ascii_case("bearer ") => &value[7..],
        _ => {
            return Err(bridge_not_authorized(
                "missing or invalid Authorization header",
            ));
        }
    };

    let claims = verify_bridge_jwt(token, lookup).map_err(bridge_not_authorized)?;

    let Some(bridge) = lookup.find_bridge(&claims.scp_bridge_id) else {
        return Err(bridge_not_authorized(format!(
            "bridge not found: {}",
            claims.scp_bridge_id
        )));
    };

    // Validate that the JWT issuer matches the bridge operator.
    if bridge.operator_did != claims.iss {
        return Err(bridge_not_authorized(
            "JWT issuer does not match bridge operator DID",
        ));
    }

    // Validate that the context ID matches.
    if claims.scp_context_id != bridge.registration_context {
        return Err(bridge_not_authorized(
            "JWT context ID does not match bridge registration context",
        ));
    }

    if let Some(rejection) = reject_inactive_bridge(&bridge) {
        return Err(rejection);
    }

    Ok(BridgeAuthContext { claims, bridge })
}

/// Axum middleware that validates DID-signed bearer tokens for bridge
/// endpoints.
///
/// Extracts the `Authorization: Bearer <JWT>` header, verifies the JWT
/// signature against the operator's DID document, validates temporal
/// claims, and checks that the bridge is registered and active.
///
/// On success, inserts a [`BridgeAuthContext`] into the request extensions
/// so downstream handlers can access the authenticated bridge identity.
///
/// # Error Responses
///
/// - **401 `BRIDGE_NOT_AUTHORIZED`** — Missing, invalid, or expired token;
///   signature verification failure; bridge not found.
/// - **403 `BRIDGE_SUSPENDED`** — The bridge exists but is suspended by
///   context governance.
///
/// See spec sections 12.10.2 and 12.10.3.
pub async fn bridge_auth_middleware<L: BridgeLookup>(
    State(lookup): State<Arc<L>>,
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let auth_ctx = match authorize_bearer_request(req.headers(), lookup.as_ref()) {
        Ok(ctx) => ctx,
        Err(rejection) => return rejection.into_response(),
    };

    req.extensions_mut().insert(auth_ctx);

    next.run(req).await.into_response()
}

/// Type-erased variant of [`bridge_auth_middleware`] for use with
/// `Arc<dyn BridgeLookup>`.
///
/// This enables the production router to apply the bridge auth middleware
/// without knowing the concrete `StorageBridgeLookup<S>` type at the
/// router construction site (since [`NodeState`](crate::http::NodeState) is
/// not generic over `S`).
pub async fn bridge_auth_middleware_dyn(
    State(lookup): State<Arc<dyn BridgeLookup>>,
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let auth_ctx = match authorize_bearer_request(req.headers(), lookup.as_ref()) {
        Ok(ctx) => ctx,
        Err(rejection) => return rejection.into_response(),
    };

    req.extensions_mut().insert(auth_ctx);

    next.run(req).await.into_response()
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

/// Verifies an Ed25519 webhook signature from an external platform and returns
/// the bridge binding the signing key carries.
///
/// Looks up the key registered under `key_id`, verifies the Ed25519 signature
/// over `timestamp_bytes || body_bytes`, and hands the caller the
/// [`WebhookKeyBinding`] so the caller can restrict the request to the bridge
/// that key was registered for. A verified signature proves which key signed
/// the request; it does not by itself say which context that key may touch,
/// which is why this function returns the binding rather than `()`.
///
/// See spec section 12.10.2.
///
/// # Errors
///
/// Returns a human-readable error string if verification fails.
///
/// # Replay protection
///
/// Per spec §12.10.2, the signed payload is `timestamp_bytes || body_bytes`
/// where `timestamp` is the value of the `X-SCP-Timestamp` header. The
/// timestamp must be within `WEBHOOK_TIMESTAMP_TOLERANCE_SECS` of the
/// current time.
pub fn verify_webhook_signature(
    signature_header: &str,
    key_id: &str,
    timestamp_header: Option<&str>,
    body: &[u8],
    lookup: &dyn BridgeLookup,
) -> Result<WebhookKeyBinding, String> {
    // Validate and check timestamp freshness (replay protection per §12.10.2).
    let timestamp_str =
        timestamp_header.ok_or_else(|| "missing X-SCP-Timestamp header".to_owned())?;

    let timestamp_secs: u64 = timestamp_str
        .parse()
        .map_err(|_| format!("invalid X-SCP-Timestamp value: {timestamp_str}"))?;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let drift = now_secs.abs_diff(timestamp_secs);

    if drift > WEBHOOK_TIMESTAMP_TOLERANCE_SECS {
        return Err(format!(
            "webhook timestamp outside acceptable window: {drift}s drift (max {WEBHOOK_TIMESTAMP_TOLERANCE_SECS}s)"
        ));
    }

    // Look up the platform's signing key together with the bridge it signs for.
    let binding = lookup
        .find_webhook_key(key_id)
        .ok_or_else(|| format!("unknown platform key ID: {key_id}"))?;

    let verifying_key = VerifyingKey::from_bytes(&binding.public_key)
        .map_err(|e| format!("invalid platform public key: {e}"))?;

    // Decode the signature from base64url.
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_header)
        .map_err(|e| format!("invalid signature encoding: {e}"))?;

    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "invalid Ed25519 signature length: expected 64, got {}",
            v.len()
        )
    })?;
    let signature = Signature::from_bytes(&sig_array);

    // Build the signed payload: timestamp_bytes || body_bytes per spec §12.10.2.
    let mut signed_payload = Vec::with_capacity(timestamp_str.len() + body.len());
    signed_payload.extend_from_slice(timestamp_str.as_bytes());
    signed_payload.extend_from_slice(body);

    verifying_key
        .verify_strict(&signed_payload, &signature)
        .map_err(|e| format!("webhook signature verification failed: {e}"))?;

    Ok(binding)
}

/// Maximum webhook request body the middleware buffers for signature
/// verification (10 MiB).
const MAX_WEBHOOK_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Authorizes a signed webhook request and returns the scope it grants.
///
/// Verifies the `X-SCP-Signature` header over `X-SCP-Timestamp || body`, then
/// resolves the bridge that the signing key was registered for and requires
/// that bridge to be active. Both [`webhook_auth_middleware`] and
/// [`webhook_auth_middleware_dyn`] call this function, so the generic and
/// type-erased entry points enforce one rule set.
///
/// # Errors
///
/// Returns the HTTP status and body the middleware sends when any check fails.
fn authorize_webhook_request(
    headers: &axum::http::HeaderMap,
    body: &[u8],
    lookup: &dyn BridgeLookup,
) -> Result<WebhookAuthContext, (StatusCode, Json<ApiError>)> {
    let Some(signature_header) = headers.get("x-scp-signature").and_then(|v| v.to_str().ok())
    else {
        return Err(bridge_not_authorized("missing X-SCP-Signature header"));
    };

    let Some(key_id) = headers
        .get("x-scp-platform-key-id")
        .and_then(|v| v.to_str().ok())
    else {
        return Err(bridge_not_authorized(
            "missing X-SCP-Platform-Key-Id header",
        ));
    };

    let Some(timestamp_header) = headers.get("x-scp-timestamp").and_then(|v| v.to_str().ok())
    else {
        return Err(bridge_not_authorized("missing X-SCP-Timestamp header"));
    };

    let binding = verify_webhook_signature(
        signature_header,
        key_id,
        Some(timestamp_header),
        body,
        lookup,
    )
    .map_err(bridge_not_authorized)?;

    // Resolve the bridge the key was registered against. A verified signature
    // says which platform signed the request; this lookup says which context
    // that platform may touch, and the webhook handler restricts every record
    // it reads or mutates to that context.
    let Some(bridge) = lookup.find_bridge(&binding.bridge_id) else {
        return Err(bridge_not_authorized(format!(
            "webhook key {key_id} is bound to unregistered bridge {}",
            binding.bridge_id
        )));
    };

    if let Some(rejection) = reject_inactive_bridge(&bridge) {
        return Err(rejection);
    }

    Ok(WebhookAuthContext { bridge })
}

/// Axum middleware that validates webhook signatures from external platforms.
///
/// Extracts the `X-SCP-Signature`, `X-SCP-Platform-Key-Id`, and
/// `X-SCP-Timestamp` headers and verifies the Ed25519 signature over the
/// timestamped request body per spec §12.10.2.
///
/// On success, inserts a [`WebhookAuthContext`] into the request extensions so
/// the webhook handler can restrict its work to the signing platform's bridge
/// and context. On failure, returns 401 with error code
/// `BRIDGE_NOT_AUTHORIZED`, or 403 with `BRIDGE_SUSPENDED` when the bound
/// bridge is suspended.
///
/// See spec section 12.10.2.
pub async fn webhook_auth_middleware<L: BridgeLookup>(
    State(lookup): State<Arc<L>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    // Read the body for signature verification, then reconstruct the request
    // for downstream handlers.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_WEBHOOK_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            return bridge_not_authorized(format!("failed to read request body: {e}"))
                .into_response();
        }
    };

    let webhook_ctx = match authorize_webhook_request(&parts.headers, &body_bytes, lookup.as_ref())
    {
        Ok(ctx) => ctx,
        Err(rejection) => return rejection.into_response(),
    };

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(webhook_ctx);
    next.run(req).await.into_response()
}

/// Type-erased variant of [`webhook_auth_middleware`] for use with
/// `Arc<dyn BridgeLookup>`.
///
/// Mirrors [`bridge_auth_middleware_dyn`] — enables the production router to
/// apply webhook signature verification without knowing the concrete
/// `StorageBridgeLookup<S>` type at the router construction site.
pub async fn webhook_auth_middleware_dyn(
    State(lookup): State<Arc<dyn BridgeLookup>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    // Read the body for signature verification, then reconstruct.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_WEBHOOK_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            return bridge_not_authorized(format!("failed to read request body: {e}"))
                .into_response();
        }
    };

    let webhook_ctx = match authorize_webhook_request(&parts.headers, &body_bytes, lookup.as_ref())
    {
        Ok(ctx) => ctx,
        Err(rejection) => return rejection.into_response(),
    };

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(webhook_ctx);
    next.run(req).await.into_response()
}

// ---------------------------------------------------------------------------
// JWT creation helper (for testing and bridge operators)
// ---------------------------------------------------------------------------

/// Creates a DID-signed JWT for bridge authentication.
///
/// This is a convenience function for bridge operators to create
/// authentication tokens. The JWT is signed with the operator's
/// Ed25519 signing key.
///
/// # Arguments
///
/// * `claims` — The JWT claims payload.
/// * `signing_key` — The operator's Ed25519 signing key (32 bytes).
///
/// # Errors
///
/// Returns an error string if signing fails.
pub fn create_bridge_jwt(
    claims: &BridgeJwtClaims,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    use ed25519_dalek::Signer;

    let header = serde_json::json!({
        "alg": JWT_ALG_EDDSA,
        "typ": JWT_TYP
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|e| format!("header serialization failed: {e}"))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(claims).map_err(|e| format!("payload serialization failed: {e}"))?,
    );

    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use rand::rngs::OsRng;
    use scp_core::bridge::{BridgeConnector, BridgeMode, BridgeStatus};
    use scp_did::{DidDocument, VerificationMethod};
    use tower::ServiceExt;

    // -----------------------------------------------------------------------
    // Test BridgeLookup implementation
    // -----------------------------------------------------------------------

    /// Test-only bridge lookup that stores bridges and DID documents in memory.
    struct TestBridgeLookup {
        bridges: Vec<BridgeConnector>,
        did_docs: Vec<(String, DidDocument)>,
        webhook_keys: Vec<(String, WebhookKeyBinding)>,
        audience: String,
    }

    impl TestBridgeLookup {
        fn new(audience: &str) -> Self {
            Self {
                bridges: Vec::new(),
                did_docs: Vec::new(),
                webhook_keys: Vec::new(),
                audience: audience.to_owned(),
            }
        }
    }

    impl BridgeLookup for TestBridgeLookup {
        fn find_bridge(&self, bridge_id: &str) -> Option<BridgeConnector> {
            self.bridges
                .iter()
                .find(|b| b.bridge_id == bridge_id)
                .cloned()
        }

        fn resolve_did_document(&self, did: &str) -> Option<DidDocument> {
            self.did_docs
                .iter()
                .find(|(d, _)| d == did)
                .map(|(_, doc)| doc.clone())
        }

        fn find_webhook_key(&self, key_id: &str) -> Option<WebhookKeyBinding> {
            self.webhook_keys
                .iter()
                .find(|(id, _)| id == key_id)
                .map(|(_, binding)| binding.clone())
        }

        fn expected_audience(&self) -> &str {
            &self.audience
        }
    }

    /// Builds a webhook key binding for `bridge_id` carrying `public_key`.
    fn test_webhook_binding(bridge_id: &str, public_key: [u8; 32]) -> WebhookKeyBinding {
        WebhookKeyBinding {
            public_key,
            bridge_id: bridge_id.to_owned(),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn test_did(signing_key: &SigningKey) -> String {
        // Use a deterministic test DID based on key fingerprint.
        let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
        format!("did:dht:z6Mk{}", &pubkey_hex[..16])
    }

    fn test_did_document(did: &str, signing_key: &SigningKey) -> DidDocument {
        let verifying = signing_key.verifying_key();
        let pub_bytes = verifying.as_bytes();
        let multibase = format!("z{}", bs58::encode(pub_bytes).into_string());

        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#active"),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                public_key_multibase: multibase,
            }],
            authentication: vec![format!("{did}#active")],
            assertion_method: vec![format!("{did}#active")],
            service: vec![],
            also_known_as: Vec::new(),
        }
    }

    fn test_bridge(
        bridge_id: &str,
        operator_did: &str,
        context_id: &str,
        status: BridgeStatus,
    ) -> BridgeConnector {
        BridgeConnector {
            bridge_id: bridge_id.to_owned(),
            operator_did: operator_did.into(),
            platform: "discord".to_owned(),
            mode: BridgeMode::Cooperative,
            status,
            registration_context: context_id.to_owned(),
            registered_at: 1_700_000_000,
        }
    }

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn test_claims(did: &str) -> BridgeJwtClaims {
        let now = current_time();
        BridgeJwtClaims {
            iss: did.to_owned(),
            aud: "https://node.example.com".to_owned(),
            iat: now,
            exp: now + 1800, // 30 minutes
            scp_bridge_id: "bridge-test-001".to_owned(),
            scp_context_id: "ctx-test-001".to_owned(),
        }
    }

    fn test_app(lookup: Arc<TestBridgeLookup>) -> Router {
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                lookup,
                bridge_auth_middleware::<TestBridgeLookup>,
            ))
    }

    async fn response_body(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    // -----------------------------------------------------------------------
    // JWT unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_and_verify_jwt_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let verified = verify_bridge_jwt(&token, &lookup).unwrap();
        assert_eq!(verified.iss, did);
        assert_eq!(verified.scp_bridge_id, "bridge-test-001");
        assert_eq!(verified.scp_context_id, "ctx-test-001");
    }

    #[test]
    fn reject_expired_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        // Set expiration to 2 minutes ago (past the clock skew tolerance).
        claims.iat = current_time() - 7200;
        claims.exp = current_time() - 120;

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("expired"),
            "error should mention expiration"
        );
    }

    #[test]
    fn reject_jwt_with_excessive_lifetime() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        // Set lifetime to 2 hours (exceeds 1-hour maximum).
        claims.exp = claims.iat + 7200;

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("lifetime exceeds maximum"),
            "error should mention lifetime"
        );
    }

    #[test]
    fn reject_jwt_with_wrong_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);

        // Sign with the wrong key.
        let token = create_bridge_jwt(&claims, &wrong_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("signature verification failed"),
            "error should mention signature failure"
        );
    }

    #[test]
    fn reject_jwt_with_wrong_audience() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        claims.aud = "https://wrong-node.example.com".to_owned();

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("audience mismatch"),
            "error should mention audience mismatch"
        );
    }

    #[test]
    fn reject_jwt_with_future_iat() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        // Set iat far in the future.
        claims.iat = current_time() + 3600;
        claims.exp = claims.iat + 1800;

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));

        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("issued in the future"),
            "error should mention future iat"
        );
    }

    #[test]
    fn reject_malformed_jwt() {
        let lookup = TestBridgeLookup::new("https://node.example.com");

        // No segments.
        assert!(verify_bridge_jwt("not-a-jwt", &lookup).is_err());

        // Only two segments.
        assert!(verify_bridge_jwt("header.payload", &lookup).is_err());

        // Four segments.
        assert!(verify_bridge_jwt("a.b.c.d", &lookup).is_err());
    }

    #[test]
    fn reject_unsupported_algorithm() {
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let claims = serde_json::json!({"iss": "did:test", "aud": "test", "iat": 0, "exp": 0, "scp_bridge_id": "b", "scp_context_id": "c"});

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let fake_sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let token = format!("{header_b64}.{payload_b64}.{fake_sig}");

        let lookup = TestBridgeLookup::new("test");
        let result = verify_bridge_jwt(&token, &lookup);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported JWT algorithm"));
    }

    // -----------------------------------------------------------------------
    // Middleware integration tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn middleware_accepts_valid_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Active,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_body(resp).await, "ok");
    }

    #[tokio::test]
    async fn middleware_rejects_missing_auth_header() {
        let lookup = Arc::new(TestBridgeLookup::new("https://node.example.com"));
        let app = test_app(lookup);

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn middleware_rejects_expired_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let mut claims = test_claims(&did);
        claims.iat = current_time() - 7200;
        claims.exp = current_time() - 120;
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Active,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn middleware_rejects_wrong_key_jwt() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &wrong_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Active,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn middleware_returns_403_for_suspended_bridge() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Suspended,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_SUSPENDED"));
    }

    #[tokio::test]
    async fn middleware_rejects_revoked_bridge() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            &did,
            "ctx-test-001",
            BridgeStatus::Revoked,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = response_body(resp).await;
        assert!(body.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn middleware_rejects_operator_did_mismatch() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let claims = test_claims(&did);
        let token = create_bridge_jwt(&claims, &signing_key).unwrap();

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup
            .did_docs
            .push((did.clone(), test_did_document(&did, &signing_key)));
        // Bridge has a different operator DID.
        lookup.bridges.push(test_bridge(
            "bridge-test-001",
            "did:dht:z6MkDifferentOperator",
            "ctx-test-001",
            BridgeStatus::Active,
        ));
        let lookup = Arc::new(lookup);

        let app = test_app(lookup);
        let req = Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // -----------------------------------------------------------------------
    // Webhook signature tests
    // -----------------------------------------------------------------------

    /// Helper: build the signed payload `timestamp_bytes || body_bytes` per §12.10.2.
    fn webhook_signed_payload(timestamp: &str, body: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(timestamp.len() + body.len());
        payload.extend_from_slice(timestamp.as_bytes());
        payload.extend_from_slice(body);
        payload
    }

    /// Helper: current Unix timestamp as string.
    fn current_timestamp_str() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    #[test]
    fn verify_valid_webhook_signature() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let body = b"webhook payload content";
        let ts = current_timestamp_str();
        let signed_payload = webhook_signed_payload(&ts, body);

        let signature = signing_key.sign(&signed_payload);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup.webhook_keys.push((
            "platform-key-1".to_owned(),
            test_webhook_binding("bridge-wh", pub_key),
        ));

        let result = verify_webhook_signature(&sig_b64, "platform-key-1", Some(&ts), body, &lookup);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_invalid_webhook_signature() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let body = b"webhook payload content";
        let ts = current_timestamp_str();
        let signed_payload = webhook_signed_payload(&ts, body);

        // Sign with wrong key.
        let signature = wrong_key.sign(&signed_payload);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup.webhook_keys.push((
            "platform-key-1".to_owned(),
            test_webhook_binding("bridge-wh", pub_key),
        ));

        let result = verify_webhook_signature(&sig_b64, "platform-key-1", Some(&ts), body, &lookup);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn reject_unknown_webhook_key_id() {
        let body = b"webhook payload";
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let ts = current_timestamp_str();
        let lookup = TestBridgeLookup::new("https://node.example.com");

        let result = verify_webhook_signature(&sig_b64, "unknown-key", Some(&ts), body, &lookup);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown platform key ID"));
    }

    #[test]
    fn reject_tampered_webhook_body() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let body = b"original payload";
        let tampered_body = b"tampered payload";
        let ts = current_timestamp_str();
        let signed_payload = webhook_signed_payload(&ts, body);

        let signature = signing_key.sign(&signed_payload);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup.webhook_keys.push((
            "platform-key-1".to_owned(),
            test_webhook_binding("bridge-wh", pub_key),
        ));

        let result = verify_webhook_signature(
            &sig_b64,
            "platform-key-1",
            Some(&ts),
            tampered_body,
            &lookup,
        );
        assert!(result.is_err());
    }

    #[test]
    fn reject_missing_webhook_timestamp() {
        let body = b"webhook payload";
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup.webhook_keys.push((
            "key-1".to_owned(),
            test_webhook_binding("bridge-wh", [0u8; 32]),
        ));

        let result = verify_webhook_signature(&sig_b64, "key-1", None, body, &lookup);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("missing X-SCP-Timestamp"),
            "expected missing timestamp error"
        );
    }

    #[test]
    fn reject_stale_webhook_timestamp() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let body = b"webhook payload";
        // Timestamp 600 seconds in the past (beyond 300s tolerance).
        let stale_ts = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600)
            .to_string();
        let signed_payload = webhook_signed_payload(&stale_ts, body);
        let signature = signing_key.sign(&signed_payload);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup.webhook_keys.push((
            "platform-key-1".to_owned(),
            test_webhook_binding("bridge-wh", pub_key),
        ));

        let result =
            verify_webhook_signature(&sig_b64, "platform-key-1", Some(&stale_ts), body, &lookup);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("timestamp outside acceptable window"),
            "expected timestamp drift error"
        );
    }

    #[test]
    fn verified_webhook_signature_returns_its_bridge_binding() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let body = b"webhook payload content";
        let ts = current_timestamp_str();
        let signature = signing_key.sign(&webhook_signed_payload(&ts, body));
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup.webhook_keys.push((
            "platform-key-1".to_owned(),
            test_webhook_binding("bridge-owner", pub_key),
        ));

        let binding =
            verify_webhook_signature(&sig_b64, "platform-key-1", Some(&ts), body, &lookup).unwrap();
        assert_eq!(binding.bridge_id, "bridge-owner");
        assert_eq!(binding.public_key, pub_key);
    }

    // -------------------------------------------------------------------
    // Webhook middleware scope tests
    //
    // A verified signature says which platform signed a request. These tests
    // require the middleware to also resolve the bridge that signing key was
    // registered against (spec §12.10.2, platform key registration step 3) and
    // to hand that bridge to the handler, so the handler can restrict its work
    // to one context.
    // -------------------------------------------------------------------

    /// Builds a webhook-authenticated app whose handler echoes the bridge ID
    /// and context ID that the middleware authorized.
    fn webhook_test_app(lookup: Arc<TestBridgeLookup>) -> Router {
        Router::new()
            .route(
                "/webhook",
                axum::routing::post(|Extension(ctx): Extension<WebhookAuthContext>| async move {
                    format!("{}|{}", ctx.bridge_id(), ctx.context_id())
                }),
            )
            .layer(middleware::from_fn_with_state(
                lookup,
                webhook_auth_middleware::<TestBridgeLookup>,
            ))
    }

    /// Builds a signed webhook request for `body` under `key_id`.
    fn signed_webhook_request(
        signing_key: &SigningKey,
        key_id: &str,
        body: &'static str,
    ) -> Request<Body> {
        use ed25519_dalek::Signer;

        let ts = current_timestamp_str();
        let signature = signing_key.sign(&webhook_signed_payload(&ts, body.as_bytes()));
        Request::builder()
            .method("POST")
            .uri("/webhook")
            .header(
                "x-scp-signature",
                URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            )
            .header("x-scp-platform-key-id", key_id)
            .header("x-scp-timestamp", ts)
            .body(Body::from(body))
            .unwrap()
    }

    /// Builds a lookup holding one webhook key bound to a bridge with `status`.
    fn webhook_lookup_with_bridge(
        pub_key: [u8; 32],
        bridge_id: &str,
        context_id: &str,
        status: BridgeStatus,
    ) -> TestBridgeLookup {
        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup.webhook_keys.push((
            "platform-key-1".to_owned(),
            test_webhook_binding(bridge_id, pub_key),
        ));
        lookup.bridges.push(test_bridge(
            bridge_id,
            "did:dht:z6MkOperator",
            context_id,
            status,
        ));
        lookup
    }

    #[tokio::test]
    async fn webhook_middleware_hands_the_handler_its_bound_bridge() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let lookup =
            webhook_lookup_with_bridge(pub_key, "bridge-owner", "ctx-owner", BridgeStatus::Active);

        let app = webhook_test_app(Arc::new(lookup));
        let req = signed_webhook_request(&signing_key, "platform-key-1", "{}");

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(response_body(resp).await, "bridge-owner|ctx-owner");
    }

    #[tokio::test]
    async fn webhook_middleware_rejects_a_key_bound_to_an_unregistered_bridge() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();

        // The key names a bridge the registry does not hold, so the node cannot
        // tell which context the request may touch.
        let mut lookup = TestBridgeLookup::new("https://node.example.com");
        lookup.webhook_keys.push((
            "platform-key-1".to_owned(),
            test_webhook_binding("bridge-missing", pub_key),
        ));

        let app = webhook_test_app(Arc::new(lookup));
        let req = signed_webhook_request(&signing_key, "platform-key-1", "{}");

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(response_body(resp).await.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    #[tokio::test]
    async fn webhook_middleware_rejects_a_suspended_bound_bridge() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let lookup = webhook_lookup_with_bridge(
            pub_key,
            "bridge-owner",
            "ctx-owner",
            BridgeStatus::Suspended,
        );

        let app = webhook_test_app(Arc::new(lookup));
        let req = signed_webhook_request(&signing_key, "platform-key-1", "{}");

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(response_body(resp).await.contains("BRIDGE_SUSPENDED"));
    }

    #[tokio::test]
    async fn webhook_middleware_rejects_a_revoked_bound_bridge() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = *signing_key.verifying_key().as_bytes();
        let lookup =
            webhook_lookup_with_bridge(pub_key, "bridge-owner", "ctx-owner", BridgeStatus::Revoked);

        let app = webhook_test_app(Arc::new(lookup));
        let req = signed_webhook_request(&signing_key, "platform-key-1", "{}");

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(response_body(resp).await.contains("BRIDGE_NOT_AUTHORIZED"));
    }

    // -------------------------------------------------------------------
    // StorageBridgeLookup tests
    // -------------------------------------------------------------------

    use scp_core::store::ProtocolRepository;
    use scp_platform::in_memory::InMemoryStorage;

    fn make_storage_lookup() -> StorageBridgeLookup<InMemoryStorage> {
        let storage = InMemoryStorage::new();
        let repo = Arc::new(ProtocolRepository::new_for_testing(storage));
        StorageBridgeLookup::new(repo, "https://node.example.com".to_owned())
    }

    #[tokio::test]
    async fn storage_lookup_register_and_find_bridge() {
        let lookup = make_storage_lookup();

        let bridge = test_bridge(
            "bridge-1",
            "did:dht:operator1",
            "ctx-1",
            BridgeStatus::Active,
        );
        lookup.register_bridge(bridge.clone()).await.unwrap();

        let found = lookup.find_bridge("bridge-1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().bridge_id, "bridge-1");

        assert!(lookup.find_bridge("bridge-nonexistent").is_none());
    }

    #[tokio::test]
    async fn storage_lookup_register_and_find_did_document() {
        let lookup = make_storage_lookup();
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let doc = test_did_document(&did, &signing_key);

        lookup.register_did_document(doc.clone()).await.unwrap();

        let found = lookup.resolve_did_document(&did);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, did);

        assert!(lookup.resolve_did_document("did:dht:nonexistent").is_none());
    }

    #[tokio::test]
    async fn storage_lookup_register_and_find_webhook_key() {
        let lookup = make_storage_lookup();
        let pub_key = [42u8; 32];

        lookup
            .register_webhook_key("platform-key-1", "bridge-wh", pub_key)
            .await
            .unwrap();

        let found = lookup.find_webhook_key("platform-key-1").unwrap();
        assert_eq!(found.public_key, pub_key);
        assert_eq!(found.bridge_id, "bridge-wh");

        assert!(lookup.find_webhook_key("nonexistent-key").is_none());
    }

    #[tokio::test]
    async fn storage_lookup_expected_audience() {
        let lookup = make_storage_lookup();
        assert_eq!(lookup.expected_audience(), "https://node.example.com");
    }

    #[tokio::test]
    async fn storage_lookup_deregister_bridge() {
        let lookup = make_storage_lookup();
        let bridge = test_bridge(
            "bridge-1",
            "did:dht:operator1",
            "ctx-1",
            BridgeStatus::Active,
        );
        lookup.register_bridge(bridge).await.unwrap();

        assert!(lookup.find_bridge("bridge-1").is_some());

        lookup.deregister_bridge("bridge-1").await.unwrap();
        assert!(lookup.find_bridge("bridge-1").is_none());
    }

    #[tokio::test]
    async fn storage_lookup_deregister_webhook_key() {
        let lookup = make_storage_lookup();
        lookup
            .register_webhook_key("key-1", "bridge-wh", [1u8; 32])
            .await
            .unwrap();

        assert!(lookup.find_webhook_key("key-1").is_some());

        lookup.deregister_webhook_key("key-1").await.unwrap();
        assert!(lookup.find_webhook_key("key-1").is_none());
    }

    #[tokio::test]
    async fn storage_lookup_load_from_storage_roundtrip() {
        // Register data via one lookup instance, then create a fresh instance
        // and load from the same storage — it should find everything.
        let storage = InMemoryStorage::new();
        let repo = Arc::new(ProtocolRepository::new_for_testing(storage));

        let lookup1 =
            StorageBridgeLookup::new(Arc::clone(&repo), "https://node.example.com".to_owned());
        let bridge = test_bridge("bridge-rt", "did:dht:op", "ctx-rt", BridgeStatus::Active);
        lookup1.register_bridge(bridge).await.unwrap();

        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let doc = test_did_document(&did, &signing_key);
        lookup1.register_did_document(doc).await.unwrap();

        lookup1
            .register_webhook_key("wh-key-rt", "bridge-rt", [99u8; 32])
            .await
            .unwrap();

        // Create a fresh instance that shares the same storage and load.
        let lookup2 =
            StorageBridgeLookup::new(Arc::clone(&repo), "https://node.example.com".to_owned());
        lookup2.load_from_storage().await.unwrap();

        assert!(lookup2.find_bridge("bridge-rt").is_some());
        assert!(lookup2.resolve_did_document(&did).is_some());
        assert_eq!(
            lookup2.find_webhook_key("wh-key-rt"),
            Some(WebhookKeyBinding {
                public_key: [99u8; 32],
                bridge_id: "bridge-rt".to_owned(),
            })
        );
    }

    #[tokio::test]
    async fn storage_lookup_jwt_roundtrip() {
        // Full round-trip: register bridge + DID doc via StorageBridgeLookup,
        // then use it to verify a JWT.
        let lookup = make_storage_lookup();

        let signing_key = SigningKey::generate(&mut OsRng);
        let did = test_did(&signing_key);
        let doc = test_did_document(&did, &signing_key);
        lookup.register_did_document(doc).await.unwrap();

        let bridge = test_bridge("bridge-jwt", &did, "ctx-jwt", BridgeStatus::Active);
        lookup.register_bridge(bridge).await.unwrap();

        let now = current_time();
        let claims = BridgeJwtClaims {
            iss: did.clone(),
            aud: "https://node.example.com".to_owned(),
            iat: now,
            exp: now + 1800,
            scp_bridge_id: "bridge-jwt".to_owned(),
            scp_context_id: "ctx-jwt".to_owned(),
        };

        let token = create_bridge_jwt(&claims, &signing_key).unwrap();
        let verified = verify_bridge_jwt(&token, &lookup).unwrap();
        assert_eq!(verified.iss, did);
        assert_eq!(verified.scp_bridge_id, "bridge-jwt");
    }
}
