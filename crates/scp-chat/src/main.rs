#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::significant_drop_tightening,
    dead_code
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::SinkExt;
use futures::stream::StreamExt;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, broadcast};
use tracing::info;

use scp_core::context::builder::{ContextCreationError, ContextTransportProvider};
use scp_core::context::manager::{ContextManager, ContextPersistence};
use scp_core::context::membership::KeyPackage;
use scp_core::context::providers::{
    MerkleEventLogProvider, MlsCryptoProvider, ProtocolStorePersistence,
};
use scp_core::context::{ContextError, ContextHandle, ContextParams};
use scp_core::store::ProtocolStore;
use scp_identity::{DID, DidDht, DidMethod};
use scp_node::{ApplicationNodeBuilder, TlsProvider};
use scp_platform::file::FileKeyCustody;
use scp_platform::filesystem::FilesystemStorage;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::Storage;
use scp_transport::nat::PortMapper;
use scp_transport::native::storage::BlobStorageBackend;

const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const YELLOW: &str = "\x1b[33m";

const PORT: u16 = 3000;
const CTX_ID: &str = "scp-chat";
const MAX_HISTORY: usize = 200;
const SALT_FILE_NAME: &str = ".passphrase_salt";

/// Derives a passphrase for `FileKeyCustody` from machine-specific entropy.
///
/// Priority:
/// 1. `SCP_CHAT_PASSPHRASE` environment variable (if set).
/// 2. SHA-256 of the canonical data-directory path concatenated with a random
///    salt stored in `<data_dir>/.passphrase_salt`. The salt is generated once
///    on first run and persisted alongside the identity.
fn derive_passphrase(data_dir: &std::path::Path) -> String {
    // Allow explicit override via environment variable.
    if let Ok(val) = std::env::var("SCP_CHAT_PASSPHRASE") {
        if !val.is_empty() {
            return val;
        }
    }

    let salt_path = data_dir.join(SALT_FILE_NAME);
    let salt = if salt_path.exists() {
        std::fs::read(&salt_path).expect("failed to read passphrase salt file")
    } else {
        use rand::RngCore;
        let mut salt = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        std::fs::write(&salt_path, &salt).expect("failed to write passphrase salt file");
        salt
    };

    // Derive: SHA-256(canonical_path || salt).
    let canonical = data_dir
        .canonicalize()
        .unwrap_or_else(|_| data_dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    hasher.update(&salt);
    hex::encode(hasher.finalize())
}

/// Storage key for app-level member metadata (name, `client_id`, credentials).
/// Protocol-level membership (DIDs, roles) is managed by `ContextManager`.
const STORAGE_KEY_MEMBER_METADATA: &str = "chat/member_metadata";
/// Storage key prefix for persisted chat messages.
const STORAGE_KEY_MESSAGES: &str = "chat/messages";
/// Storage key for persisted identity (DID, key handles, document).
const STORAGE_KEY_IDENTITY: &str = "chat/identity";

type ChatDidDht = DidDht<scp_identity::InMemoryDhtClient, scp_identity::cache::SystemClock>;

// ---------------------------------------------------------------------------
// No-op transport provider — scp-chat handles relay connectivity at the app
// level via `ApplicationNode`, so the `ContextManager`'s transport provider
// is a no-op. MLS-encrypted payloads are produced by `ContextManager` but
// delivery is handled by the chat server's WebSocket push.
// ---------------------------------------------------------------------------

struct NoOpTransportProvider;

impl ContextTransportProvider for NoOpTransportProvider {
    fn is_connected(&self) -> bool {
        true
    }
    fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn send_message(
        &self,
        _context_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }
}

/// Returns a no-op key resolver (governance vote verification not needed for
/// scp-chat's single-admin model).
fn noop_key_resolver() -> scp_core::context::governance::KeyResolver {
    Arc::new(|_| None)
}

// ---------------------------------------------------------------------------
// Data directory helpers
// ---------------------------------------------------------------------------

/// Returns the data directory, local to the binary's working directory.
fn data_dir() -> PathBuf {
    PathBuf::from("scp-chat-data")
}

fn ensure_data_dir() -> PathBuf {
    let dir = data_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir).expect("failed to create scp-chat-data/");
    }
    dir
}

// ---------------------------------------------------------------------------
// Identity persistence
// ---------------------------------------------------------------------------

/// Serializable snapshot of [`ScpIdentity`] + [`DidDocument`] for persistence
/// across restarts. Key handles are opaque u64 indices into the
/// `FileKeyCustody` keyring — they remain valid as long as the keyring file
/// doesn't change.
#[derive(Serialize, Deserialize)]
struct PersistedIdentity {
    identity_key: u64,
    active_signing_key: u64,
    agent_signing_key: Option<u64>,
    pre_rotation_commitment: [u8; 32],
    did: String,
    document: scp_identity::DidDocument,
}

impl PersistedIdentity {
    fn from_identity(id: &scp_identity::ScpIdentity, doc: &scp_identity::DidDocument) -> Self {
        Self {
            identity_key: id.identity_key.id(),
            active_signing_key: id.active_signing_key.id(),
            agent_signing_key: id.agent_signing_key.map(|k| k.id()),
            pre_rotation_commitment: id.pre_rotation_commitment,
            did: id.did.clone(),
            document: doc.clone(),
        }
    }

    fn into_identity(self) -> (scp_identity::ScpIdentity, scp_identity::DidDocument) {
        use scp_platform::traits::KeyHandle;
        let identity = scp_identity::ScpIdentity {
            identity_key: KeyHandle::new(self.identity_key),
            active_signing_key: KeyHandle::new(self.active_signing_key),
            agent_signing_key: self.agent_signing_key.map(KeyHandle::new),
            pre_rotation_commitment: self.pre_rotation_commitment,
            did: self.did,
        };
        (identity, self.document)
    }
}

async fn load_persisted_identity(
    storage: &FilesystemStorage,
) -> Option<(scp_identity::ScpIdentity, scp_identity::DidDocument)> {
    let data = storage.retrieve(STORAGE_KEY_IDENTITY).await.ok()??;
    serde_json::from_slice::<PersistedIdentity>(&data)
        .ok()
        .map(PersistedIdentity::into_identity)
}

async fn save_persisted_identity(
    storage: &FilesystemStorage,
    identity: &scp_identity::ScpIdentity,
    document: &scp_identity::DidDocument,
) {
    let persisted = PersistedIdentity::from_identity(identity, document);
    let json = serde_json::to_vec(&persisted).expect("serialize identity");
    storage
        .store(STORAGE_KEY_IDENTITY, &json)
        .await
        .expect("failed to persist identity");
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

fn detect_lan_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| s.connect("8.8.8.8:80").ok().map(|()| s))
        .and_then(|s| s.local_addr().ok())
        .map_or_else(|| "localhost".to_owned(), |a| a.ip().to_string())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn format_time(ts: u64) -> String {
    // Convert unix timestamp to HH:MM local time via POSIX localtime_r.
    // SAFETY: localtime_r is reentrant and writes to caller-provided buffer.
    #[allow(unsafe_code)]
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let time_val = ts.cast_signed() as libc::time_t;
        libc::localtime_r(&raw const time_val, &raw mut tm);
        format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
    }
}

// ---------------------------------------------------------------------------
// SDK persistence helpers
// ---------------------------------------------------------------------------

/// Loads app-level member metadata from storage.
///
/// Returns an empty map on first run.
async fn load_member_metadata(storage: &FilesystemStorage) -> HashMap<String, MemberMetadata> {
    let bytes = storage
        .retrieve(STORAGE_KEY_MEMBER_METADATA)
        .await
        .expect("failed to read member metadata from storage");
    bytes.map_or_else(HashMap::new, |data| {
        serde_json::from_slice(&data).unwrap_or_default()
    })
}

/// Persists app-level member metadata to storage.
async fn save_member_metadata(
    storage: &FilesystemStorage,
    metadata: &HashMap<String, MemberMetadata>,
) {
    let json = serde_json::to_vec(metadata).expect("serialize member metadata");
    storage
        .store(STORAGE_KEY_MEMBER_METADATA, &json)
        .await
        .expect("failed to write member metadata to storage");
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Message stored in the in-memory ring buffer. Not persisted separately --
/// the `ContextManager` handles context state persistence. Message history
/// is lost on restart (a deliberate simplification for the demo app).
#[derive(Clone, Serialize, Deserialize)]
struct StoredMessage {
    sender_did: String,
    sender_name: String,
    text: String,
    timestamp: u64,
}

/// App-level member metadata that supplements `ContextManager`'s protocol-level
/// membership tracking. The `ContextManager` tracks which DIDs are members (and
/// their roles/capabilities); this struct holds chat-specific data the protocol
/// layer doesn't know about.
#[derive(Clone, Serialize, Deserialize)]
struct MemberMetadata {
    name: String,
    /// SHA-256 of the client's secret, hex-encoded. Used to authenticate
    /// web client rejoin requests. `None` for the terminal host.
    #[serde(default)]
    client_id: Option<String>,
    /// Base64url-encoded `WebAuthn` credential ID for passkey authentication.
    #[serde(default)]
    credential_id: Option<String>,
    /// Base64url-encoded SEC1-encoded P-256 public key for passkey verification.
    #[serde(default)]
    public_key: Option<String>,
}

/// Flattened member representation for API responses (combines DID from
/// `ContextManager` with app-level metadata).
#[derive(Clone, Serialize, Deserialize)]
struct Member {
    did: String,
    name: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
}

struct ChatRoom {
    context_id: String,
    routing_id: [u8; 32],
    relay_addr: SocketAddr,
    bridge_token: String,
    host_ip: String,
    host_did: String,
    host_name: String,
    /// The `ContextManager` is the source of truth for protocol-level
    /// membership (which DIDs are in the context, their roles, capabilities).
    /// Context state is auto-persisted via `ProtocolStorePersistence`.
    /// Messages are encrypted via MLS + sender keys through
    /// `ContextManager::send_message()`.
    manager: Arc<ContextManager>,
    /// A `ContextHandle` for the chat context, used to call `join_context()`
    /// and other manager methods that require a handle.
    handle: ContextHandle,
    /// App-level member metadata (name, `client_id`, credentials). Keyed by DID.
    /// Supplementary to the `ContextManager`'s protocol-level membership.
    member_metadata: RwLock<HashMap<String, MemberMetadata>>,
    /// In-memory message history buffer, capped at `MAX_HISTORY`.
    messages: RwLock<Vec<StoredMessage>>,
    /// Handle to the `FilesystemStorage` for persisting messages and member
    /// metadata.
    storage: Arc<FilesystemStorage>,
    /// Monotonic sequence counter for persisted messages.
    message_seq: std::sync::atomic::AtomicU64,
    /// Broadcast channel for pushing messages to connected WebSocket clients.
    message_tx: broadcast::Sender<String>,
    /// Time-limited challenge store for `WebAuthn` passkey authentication.
    challenges: PasskeyChallengeStore,
    /// Accepted `WebAuthn` origins (e.g. `https://192.168.1.5:3000`). The
    /// `origin` field in `clientDataJSON` must match one of these.
    expected_origins: Vec<String>,
}

impl ChatRoom {
    /// Adds a message to the in-memory ring buffer (capped at `MAX_HISTORY`),
    /// persists it to storage, encrypts via `ContextManager::send_message()`
    /// (MLS + sender keys), and broadcasts to connected WebSocket clients.
    async fn send_and_store_message(&self, msg: StoredMessage) {
        // Persist to storage.
        let seq = self
            .message_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key = format!("{STORAGE_KEY_MESSAGES}/{seq:020}");
        let json = serde_json::to_vec(&msg).expect("serialize message");
        self.storage
            .store(&key, &json)
            .await
            .expect("failed to persist message");

        // Encrypt via ContextManager (MLS + sender keys). The transport
        // provider is a no-op, so the encrypted payload is produced but not
        // sent anywhere by the manager -- delivery is via our WebSocket push.
        let payload = serde_json::to_vec(&msg).expect("serialize message for encryption");
        if let Err(e) = self
            .manager
            .send_message(&self.handle, &DID(msg.sender_did.clone()), &payload, None)
            .await
        {
            tracing::warn!("MLS encrypt via ContextManager failed: {e}");
        }

        // Broadcast to connected WebSocket clients.
        let ws_json = serde_json::to_string(&msg).expect("serialize message for ws");
        let _ = self.message_tx.send(ws_json);

        // Add to in-memory ring buffer.
        let mut messages = self.messages.write().await;
        messages.push(msg);
        if messages.len() > MAX_HISTORY {
            let drain = messages.len() - MAX_HISTORY;
            messages.drain(..drain);
        }
    }

    /// Returns a snapshot of all members by combining `ContextManager` DIDs
    /// with app-level metadata.
    async fn members_snapshot(&self) -> Vec<Member> {
        let dids = self.manager.member_dids(&self.context_id).await;
        let metadata = self.member_metadata.read().await;
        dids.into_iter()
            .map(|did| {
                let meta = metadata.get(&did);
                Member {
                    did: did.clone(),
                    name: meta.map_or_else(|| "Unknown".to_owned(), |m| m.name.clone()),
                    client_id: meta.and_then(|m| m.client_id.clone()),
                    credential_id: meta.and_then(|m| m.credential_id.clone()),
                    public_key: meta.and_then(|m| m.public_key.clone()),
                }
            })
            .collect()
    }

    /// Persists app-level member metadata to storage.
    async fn persist_metadata(&self) {
        let metadata = self.member_metadata.read().await;
        save_member_metadata(&self.storage, &metadata).await;
    }
}

#[derive(Serialize, Deserialize)]
struct ChatMessage {
    sender_did: String,
    sender_name: String,
    text: String,
    #[serde(default)]
    timestamp: u64,
}

#[derive(Deserialize)]
struct JoinRequest {
    name: String,
    /// SHA-256 of the client's secret, hex-encoded. Binds the DID to
    /// proof-of-knowledge of the secret for authenticated rejoin.
    #[serde(default)]
    client_id: Option<String>,
    /// Base64url-encoded `WebAuthn` credential ID (from `navigator.credentials.create()`).
    #[serde(default)]
    credential_id: Option<String>,
    /// Base64url-encoded SEC1-encoded P-256 public key (from `WebAuthn` attestation).
    #[serde(default)]
    public_key: Option<String>,
}

#[derive(Deserialize)]
struct RejoinRequest {
    /// The raw 32-byte secret (hex-encoded). Server computes SHA-256 and
    /// matches against the stored `client_id` to authenticate.
    client_secret: String,
}

#[derive(Deserialize)]
struct PasskeyAuthRequest {
    /// Base64url-encoded `WebAuthn` credential ID (identifies the passkey).
    credential_id: String,
    /// Base64url-encoded authenticator data from the assertion.
    authenticator_data: String,
    /// Base64url-encoded client data JSON from the assertion.
    client_data_json: String,
    /// Base64url-encoded ECDSA P-256 signature over (`authenticator_data` || SHA-256(`client_data_json`)).
    signature: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
}

/// Time-limited challenge store for `WebAuthn` ceremony anti-replay.
/// Challenges expire after 5 minutes.
const CHALLENGE_TTL_SECS: u64 = 300;

struct ChallengeEntry {
    challenge_bytes: Vec<u8>,
    created_at: u64,
}

struct PasskeyChallengeStore {
    challenges: std::sync::Mutex<HashMap<String, ChallengeEntry>>,
}

#[derive(Serialize)]
struct JoinResponse {
    did: String,
    name: String,
    context_id: String,
    routing_id_hex: String,
    members: Vec<Member>,
}

#[derive(Deserialize)]
struct SendRequest {
    sender_did: String,
    sender_name: String,
    text: String,
}

fn routing_id(context_id: &str) -> [u8; 32] {
    Sha256::digest(context_id.as_bytes()).into()
}

fn truncate_did(did: &str) -> String {
    if did.len() > 30 {
        format!("{}...{}", &did[..20], &did[did.len() - 8..])
    } else {
        did.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Self-signed TLS provider
// ---------------------------------------------------------------------------

/// Self-signed TLS provider that generates a cert with multiple Subject
/// Alternative Names (SANs). Covers LAN IP, public IP (if UPnP mapped),
/// localhost, and 127.0.0.1 so devices connecting via any address get a
/// valid cert (after accepting the self-signed warning).
struct SelfSignedTls(Vec<String>);

impl TlsProvider for SelfSignedTls {
    fn provision(
        &self,
    ) -> Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<scp_node::tls::CertificateData, scp_node::tls::TlsError>,
                > + Send
                + '_,
        >,
    > {
        let sans = self.0.clone();
        Box::pin(async move {
            let params = rcgen::CertificateParams::new(sans)
                .map_err(|e| scp_node::tls::TlsError::Certificate(e.to_string()))?;
            let key_pair = rcgen::KeyPair::generate()
                .map_err(|e| scp_node::tls::TlsError::Certificate(e.to_string()))?;
            let cert = params
                .self_signed(&key_pair)
                .map_err(|e| scp_node::tls::TlsError::Certificate(e.to_string()))?;
            Ok(scp_node::tls::CertificateData {
                certificate_chain_pem: cert.pem(),
                private_key_pem: zeroize::Zeroizing::new(key_pair.serialize_pem()),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "scp_chat=info,scp_transport=warn".parse().unwrap()),
        )
        .init();

    println!("\n{BOLD}{YELLOW}=== SCP Encrypted Chat ==={RESET}");

    let dir = ensure_data_dir();
    let host_ip = detect_lan_ip();

    // --- SDK storage backend ---
    let storage_dir = dir.join("storage");
    let fs_storage =
        Arc::new(FilesystemStorage::new(&storage_dir).expect("failed to create storage dir"));

    // --- ContextManager persistence (created here, manager built after identity) ---
    let manager_storage =
        FilesystemStorage::new(&storage_dir).expect("failed to create manager storage dir");
    let protocol_store = Arc::new(ProtocolStore::new(manager_storage));

    // --- Identity ---
    // On restart, load persisted identity (DID + key handles + document) from
    // storage. Key handles index into the FileKeyCustody keyring which is
    // persisted in keys.enc. On first run, create a new identity and persist it.
    let keys_path = dir.join("keys.enc");
    let passphrase = derive_passphrase(&dir);

    let custody = Arc::new(
        FileKeyCustody::new(&keys_path, &passphrase)
            .expect("failed to open/create key file (wrong passphrase?)"),
    );

    let dht_client = Arc::new(scp_identity::InMemoryDhtClient::new());
    let cache = Arc::new(scp_identity::DidCache::new());
    let sign_fn = ChatDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(ChatDidDht::with_client_and_signer(
        dht_client, cache, sign_fn,
    ));

    let upnp = Arc::new(scp_transport::nat::UpnpPortMapper::new());
    println!("{DIM}  UPnP: attempting port mapping...{RESET}");

    // UPnP for HTTP port — do this early so we know the public IP for the TLS
    // cert SANs. The relay port mapping is handled by port_mapper() in build().
    let upnp_http = scp_transport::nat::UpnpPortMapper::new();
    let public_addr = match upnp_http.map_port(PORT).await {
        Ok(result) => {
            println!(
                "{DIM}  UPnP: HTTP port {PORT} mapped to {}{RESET}",
                result.external_addr
            );
            Some(result.external_addr)
        }
        Err(e) => {
            println!("{DIM}  UPnP: HTTP port mapping failed ({e}){RESET}");
            None
        }
    };

    // Build TLS cert with SANs for all reachable addresses.
    let mut sans = vec![host_ip.clone(), "localhost".to_owned(), "127.0.0.1".to_owned()];
    if let Some(addr) = &public_addr {
        sans.push(addr.ip().to_string());
    }
    println!("{DIM}  TLS SANs: {}{RESET}", sans.join(", "));

    // Load or create identity. On restart, the persisted identity has the same
    // key handles as last time — FileKeyCustody reloads the same keyring.
    let (identity, document, is_existing) =
        if let Some((id, doc)) = load_persisted_identity(&fs_storage).await {
            (id, doc, true)
        } else {
            let (id, doc) = did_method
                .create(custody.as_ref())
                .await
                .expect("failed to create identity");
            save_persisted_identity(&fs_storage, &id, &doc).await;
            (id, doc, false)
        };

    // Build the node with the explicit identity (never re-generates).
    let node_storage =
        FilesystemStorage::new(&storage_dir).expect("failed to create node storage dir");

    let node = ApplicationNodeBuilder::new()
        .no_domain()
        .tls_provider(Arc::new(SelfSignedTls(sans)))
        .identity(identity, document, did_method)
        .storage(node_storage)
        .port_mapper(upnp)
        .blob_storage(BlobStorageBackend::in_memory())
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .http_bind_addr(SocketAddr::from(([0, 0, 0, 0], PORT)))
        .build()
        .await
        .expect("failed to build ApplicationNode");

    let host_did = node.identity().did().to_owned();
    if is_existing {
        println!(
            "  {GREEN}Loaded identity:{RESET} {}",
            truncate_did(&host_did)
        );
    } else {
        println!(
            "  {GREEN}Created identity:{RESET} {}",
            truncate_did(&host_did)
        );
    }

    let relay_addr = node.relay().bound_addr();
    let bridge_token = node.bridge_token_hex();
    let host_name = "Host".to_owned();

    // Renew UPnP mapping every 30 minutes (lease is 1 hour, renew at 50%).
    if public_addr.is_some() {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1800)).await;
                let mapper = scp_transport::nat::UpnpPortMapper::new();
                match mapper.map_port(PORT).await {
                    Ok(r) => tracing::info!("UPnP renewed: {}", r.external_addr),
                    Err(e) => tracing::warn!("UPnP renewal failed: {e}"),
                }
            }
        });
    }

    println!("{DIM}  Internal relay on {relay_addr}{RESET}");

    // --- ContextManager with real MLS crypto ---
    // MlsCryptoProvider needs the host DID (for ScpCredential in MLS leaf
    // nodes). MerkleEventLogProvider gives us tamper-evident event ordering.
    let persistence: Box<dyn ContextPersistence> =
        Box::new(ProtocolStorePersistence::new(protocol_store));
    let manager = Arc::new(ContextManager::with_persistence(
        Box::new(MlsCryptoProvider::new(host_did.clone())),
        Box::new(NoOpTransportProvider),
        Box::new(MerkleEventLogProvider::new()),
        persistence,
        noop_key_resolver(),
    ));
    println!("{DIM}  MLS crypto provider initialized{RESET}");

    // Register the host DID as locally controlled (defense-in-depth).
    manager.register_local_did(DID(host_did.clone())).await;

    // Try to restore the context from persisted state. If no persisted context
    // exists (first run), create a new one.
    // NOTE: MlsCryptoProvider is in-memory (#645) — after restart, the MLS
    // group is gone and join_context/send_message crypto ops fail. This is an
    // SDK bug, not an app-level concern.
    let handle = match manager.restore_all_contexts().await {
        Ok(restored) if restored.contains(&CTX_ID.to_owned()) => {
            let member_count = manager.member_count(CTX_ID).await.unwrap_or(0);
            println!("  {GREEN}Restored context:{RESET} {member_count} members");

            let handle = ContextHandle::new(CTX_ID.to_owned(), ContextParams::default());
            let _ = handle
                .transition_to(&scp_core::context::ContextState::Active)
                .await;
            handle
        }
        _ => {
            let handle = manager
                .create_context(
                    CTX_ID.to_owned(),
                    scp_core::context::template_params(
                        &scp_core::context::TemplateId::GroupDiscussion,
                    ),
                    DID(host_did.clone()),
                )
                .await
                .expect("failed to create chat context");
            println!("{DIM}  Created new context{RESET}");
            handle
        }
    };

    // Load app-level member metadata from storage.
    let mut metadata = load_member_metadata(&fs_storage).await;

    // Ensure host has metadata entry.
    metadata
        .entry(host_did.clone())
        .or_insert_with(|| MemberMetadata {
            name: host_name.clone(),
            client_id: None,
            credential_id: None,
            public_key: None,
        });
    save_member_metadata(&fs_storage, &metadata).await;

    let rid = routing_id(CTX_ID);
    println!(
        "{DIM}  Crypto: MLS + sender keys | Routing: {}...{RESET}",
        &hex::encode(rid)[..16]
    );

    // Load persisted messages from storage.
    let (restored_messages, next_seq) = load_persisted_messages(&fs_storage).await;
    if !restored_messages.is_empty() {
        println!(
            "{DIM}  Restored {} messages from storage{RESET}",
            restored_messages.len()
        );
    }

    // Broadcast channel for WebSocket push (256 message backlog).
    let (message_tx, _) = broadcast::channel::<String>(256);

    let room = Arc::new(ChatRoom {
        context_id: CTX_ID.to_owned(),
        routing_id: rid,
        relay_addr,
        bridge_token,
        host_ip: host_ip.clone(),
        host_did: host_did.clone(),
        host_name: host_name.clone(),
        manager: Arc::clone(&manager),
        handle,
        member_metadata: RwLock::new(metadata),
        messages: RwLock::new(restored_messages),
        storage: fs_storage,
        message_seq: std::sync::atomic::AtomicU64::new(next_seq),
        message_tx,
        challenges: PasskeyChallengeStore {
            challenges: std::sync::Mutex::new(HashMap::new()),
        },
        expected_origins: {
            let mut origins = vec![
                format!("https://{host_ip}:{PORT}"),
                format!("https://localhost:{PORT}"),
                format!("https://127.0.0.1:{PORT}"),
            ];
            if let Some(addr) = &public_addr {
                origins.push(format!("https://{}:{}", addr.ip(), PORT));
            }
            origins
        },
    });

    // Application routes.
    let app = Router::new()
        .route("/", get(serve_web_ui))
        .route("/api/join", post(handle_join))
        .route("/api/rejoin", post(handle_rejoin))
        .route("/api/send", post(handle_send))
        .route("/api/passkey-challenge", get(handle_passkey_challenge))
        .route("/api/passkey-auth", post(handle_passkey_auth))
        .route("/api/members", get(handle_members))
        .route("/api/history", get(handle_history))
        .route("/ws/chat", get(handle_ws_upgrade))
        .with_state(room.clone());

    let public_url = public_addr.map(|a| format!("https://{}:{}", a.ip(), PORT));
    let lan_url = format!("https://{host_ip}:{PORT}");

    println!("\n{BOLD}{GREEN}Ready!{RESET}");
    println!("{DIM}  LAN:    {lan_url}{RESET}");
    if let Some(ref url) = public_url {
        println!("  {BOLD}Public: {url}{RESET}");
    }
    println!(
        "\n{DIM}Open the URL on any device. Accept the certificate warning.\n\
         Type a message and press Enter.\n\
         /info  -- room details\n\
         /quit  -- exit{RESET}\n"
    );

    // Run the node. Ctrl+C to stop.
    let room_shutdown = room.clone();
    let shutdown = async move {
        tokio::signal::ctrl_c().await.ok();
        println!("\n{DIM}Shutting down...{RESET}");
        room_shutdown.persist_metadata().await;
        println!("{DIM}State saved.{RESET}");
        // Hard deadline: if serve()'s drain hangs on STUN/relay, force exit.
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            println!("{DIM}Shutdown complete.{RESET}");
            std::process::exit(0);
        });
    };

    if let Err(e) = node.serve(app, shutdown).await {
        eprintln!("Node error: {e}");
    }
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

async fn serve_web_ui() -> impl IntoResponse {
    // Read from disk so frontend changes take effect without rebuilding.
    // Falls back to the compile-time embedded copy if the file is missing
    // (e.g. running the binary outside the source tree).
    match tokio::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/chat.html")).await {
        Ok(html) => Html(html).into_response(),
        Err(_) => Html(include_str!("chat.html")).into_response(),
    }
}

async fn handle_join(
    State(room): State<Arc<ChatRoom>>,
    Json(req): Json<JoinRequest>,
) -> impl IntoResponse {
    // Validate client_id if provided (must be 64 hex chars = 32 bytes SHA-256).
    if let Some(ref cid) = req.client_id
        && (cid.len() != 64 || hex::decode(cid).is_err())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "client_id must be 64 hex characters (SHA-256)"})),
        )
            .into_response();
    }

    let custody = Arc::new(InMemoryKeyCustody::new());
    let dht_client = Arc::new(scp_identity::InMemoryDhtClient::new());
    let cache = Arc::new(scp_identity::DidCache::new());
    let sign_fn = ChatDidDht::make_sign_fn(Arc::clone(&custody));
    let did_method = DidDht::with_client_and_signer(dht_client, cache, sign_fn);
    let (identity, _doc) = match did_method.create(custody.as_ref()).await {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // Add the member to the ContextManager's protocol-level membership.
    let kp = KeyPackage::mock(DID(identity.did.clone()));
    if let Err(e) = room.manager.join_context(&room.handle, kp).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to join context: {e}")})),
        )
            .into_response();
    }

    // Store app-level metadata.
    let meta = MemberMetadata {
        name: req.name.clone(),
        client_id: req.client_id.clone(),
        credential_id: req.credential_id.clone(),
        public_key: req.public_key.clone(),
    };
    {
        let mut metadata = room.member_metadata.write().await;
        metadata.insert(identity.did.clone(), meta);
    }

    // Persist metadata to storage.
    room.persist_metadata().await;

    info!("{} joined as {}", req.name, truncate_did(&identity.did));
    println!("\r{DIM}[{} joined]{RESET}", req.name,);

    // Build response with full member snapshot.
    let members = room.members_snapshot().await;

    let resp = JoinResponse {
        did: identity.did,
        name: req.name,
        context_id: room.context_id.clone(),
        routing_id_hex: hex::encode(room.routing_id),
        members,
    };

    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
}

async fn handle_rejoin(
    State(room): State<Arc<ChatRoom>>,
    Json(req): Json<RejoinRequest>,
) -> impl IntoResponse {
    // Decode the client secret and compute SHA-256 to derive the client_id.
    let secret_bytes = match hex::decode(&req.client_secret) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "client_secret must be 64 hex characters (32 bytes)"})),
            )
                .into_response();
        }
    };
    let derived_id = hex::encode(Sha256::digest(&secret_bytes));

    // Search metadata for a member with matching client_id.
    let metadata = room.member_metadata.read().await;
    let found = metadata
        .iter()
        .find(|(_, meta)| meta.client_id.as_deref() == Some(derived_id.as_str()))
        .map(|(did, meta)| (did.clone(), meta.clone()));
    drop(metadata);

    if let Some((did, meta)) = found {
        // Verify the DID is still a member via ContextManager.
        if !room.manager.is_member(&room.context_id, &did).await {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "member no longer in context"})),
            )
                .into_response();
        }

        info!("{} rejoined (authenticated)", truncate_did(&did));
        println!("\r{DIM}[{} reconnected]{RESET}", meta.name);

        let members = room.members_snapshot().await;

        let resp = JoinResponse {
            did,
            name: meta.name,
            context_id: room.context_id.clone(),
            routing_id_hex: hex::encode(room.routing_id),
            members,
        };

        (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "No member matches this secret"})),
        )
            .into_response()
    }
}

async fn handle_passkey_challenge(State(room): State<Arc<ChatRoom>>) -> impl IntoResponse {
    let mut challenge_bytes = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut challenge_bytes);
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);

    // Garbage-collect expired challenges, then insert the new one.
    let now = now_unix();
    let mut store = room.challenges.challenges.lock().unwrap();
    store.retain(|_, entry| now.saturating_sub(entry.created_at) < CHALLENGE_TTL_SECS);
    store.insert(
        challenge_b64.clone(),
        ChallengeEntry {
            challenge_bytes: challenge_bytes.to_vec(),
            created_at: now,
        },
    );
    drop(store);

    Json(
        serde_json::to_value(ChallengeResponse {
            challenge: challenge_b64,
        })
        .unwrap(),
    )
}

async fn handle_passkey_auth(
    State(room): State<Arc<ChatRoom>>,
    Json(req): Json<PasskeyAuthRequest>,
) -> impl IntoResponse {
    // Decode all base64url fields.
    let Ok(_credential_id_bytes) = URL_SAFE_NO_PAD.decode(&req.credential_id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid base64url in credential_id"})),
        )
            .into_response();
    };
    let Ok(auth_data) = URL_SAFE_NO_PAD.decode(&req.authenticator_data) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid base64url in authenticator_data"})),
        )
            .into_response();
    };
    let Ok(client_data_json) = URL_SAFE_NO_PAD.decode(&req.client_data_json) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid base64url in client_data_json"})),
        )
            .into_response();
    };
    let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(&req.signature) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid base64url in signature"})),
        )
            .into_response();
    };

    // Parse the clientDataJSON to extract and verify the challenge.
    let Ok(client_data) = serde_json::from_slice::<serde_json::Value>(&client_data_json) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid client_data_json"})),
        )
            .into_response();
    };

    let Some(challenge_b64) = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing challenge in client_data_json"})),
        )
            .into_response();
    };

    // Verify the challenge was issued by this server and hasn't expired.
    {
        let mut store = room.challenges.challenges.lock().unwrap();
        let now = now_unix();
        match store.remove(&challenge_b64) {
            Some(entry) if now.saturating_sub(entry.created_at) < CHALLENGE_TTL_SECS => {
                // Valid, consumed.
            }
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "invalid or expired challenge"})),
                )
                    .into_response();
            }
        }
    }

    // Verify the type field is "webauthn.get".
    if client_data.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "client_data_json type must be 'webauthn.get'"})),
        )
            .into_response();
    }

    // Verify origin matches one of the server's expected origins.
    let origin = client_data.get("origin").and_then(|v| v.as_str());
    match origin {
        Some(o) if room.expected_origins.iter().any(|e| e == o) => {}
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "origin mismatch in client_data_json"})),
            )
                .into_response();
        }
    }

    // Look up member by credential_id in app-level metadata.
    let metadata = room.member_metadata.read().await;
    let found = metadata
        .iter()
        .find(|(_, meta)| meta.credential_id.as_deref() == Some(&req.credential_id))
        .map(|(did, meta)| (did.clone(), meta.clone()));
    drop(metadata);

    let Some((did, meta)) = found else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no member found for this credential"})),
        )
            .into_response();
    };

    // Verify the DID is still a member via ContextManager.
    if !room.manager.is_member(&room.context_id, &did).await {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "member no longer in context"})),
        )
            .into_response();
    }

    // Decode the stored public key and verify the signature.
    let Some(pk_bytes) = meta
        .public_key
        .as_deref()
        .and_then(|pk| URL_SAFE_NO_PAD.decode(pk).ok())
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "stored public key is invalid"})),
        )
            .into_response();
    };

    let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(&pk_bytes) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "stored public key is not a valid P-256 key"})),
        )
            .into_response();
    };

    // Authenticator data: [0..32] = SHA-256(rpId), [32] = flags.
    // Verify RP ID hash matches the expected relying party identifier
    // (location.hostname on the client, which is the server's host_ip).
    if auth_data.len() < 33 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "authenticator data too short"})),
        )
            .into_response();
    }

    let expected_rp_ids: Vec<&str> = room
        .expected_origins
        .iter()
        .filter_map(|o| {
            // Extract hostname from "https://host:port".
            o.strip_prefix("https://")
                .and_then(|rest| rest.split(':').next())
        })
        .collect();
    let rp_id_matched = expected_rp_ids.iter().any(|rp_id| {
        let expected_hash = Sha256::digest(rp_id.as_bytes());
        auth_data[..32] == *expected_hash
    });
    if !rp_id_matched {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "RP ID hash mismatch in authenticator data"})),
        )
            .into_response();
    }

    // Verify User Presence (UP) flag — bit 0 of the flags byte.
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "user presence flag not set in authenticator data"})),
        )
            .into_response();
    }

    // `WebAuthn` signature is over: `authenticator_data` || SHA-256(`client_data_json`)
    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(&client_data_hash);

    // `WebAuthn` uses DER-encoded ECDSA signatures.
    let Ok(signature) = Signature::from_der(&sig_bytes) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature format"})),
        )
            .into_response();
    };

    if verifying_key.verify(&signed_data, &signature).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "signature verification failed"})),
        )
            .into_response();
    }

    info!("{} authenticated via passkey", truncate_did(&did));
    println!("\r{DIM}[{} signed in via passkey]{RESET}", meta.name);

    let members = room.members_snapshot().await;

    let resp = JoinResponse {
        did,
        name: meta.name,
        context_id: room.context_id.clone(),
        routing_id_hex: hex::encode(room.routing_id),
        members,
    };

    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
}

async fn handle_members(State(room): State<Arc<ChatRoom>>) -> impl IntoResponse {
    let members = room.members_snapshot().await;
    Json(serde_json::json!({"members": members}))
}

async fn handle_history(State(room): State<Arc<ChatRoom>>) -> impl IntoResponse {
    let messages = room.messages.read().await;
    Json(serde_json::json!({"messages": *messages}))
}

async fn handle_send(
    State(room): State<Arc<ChatRoom>>,
    Json(req): Json<SendRequest>,
) -> impl IntoResponse {
    // Verify the sender is a member.
    if !room
        .manager
        .is_member(&room.context_id, &req.sender_did)
        .await
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "sender is not a member of this context"})),
        )
            .into_response();
    }

    let msg = StoredMessage {
        sender_did: req.sender_did,
        sender_name: req.sender_name,
        text: req.text,
        timestamp: now_unix(),
    };

    room.send_and_store_message(msg).await;

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

async fn handle_ws_upgrade(
    State(room): State<Arc<ChatRoom>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, room))
}

async fn handle_ws_connection(socket: WebSocket, room: Arc<ChatRoom>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = room.message_tx.subscribe();

    // Forward broadcast messages to this WebSocket client.
    let send_fut = async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    };

    // Keep the connection alive by reading (and discarding) client messages.
    // Web clients send messages via POST /api/send, not via WebSocket.
    let recv_fut = async move {
        while let Some(Ok(_)) = receiver.next().await {}
    };

    // When either direction finishes, cancel the other immediately.
    tokio::select! {
        () = send_fut => {},
        () = recv_fut => {},
    }
}

// ---------------------------------------------------------------------------
// Message persistence helpers
// ---------------------------------------------------------------------------

/// Loads persisted messages from storage on startup.
///
/// Returns the messages (capped at `MAX_HISTORY`) and the next sequence number.
async fn load_persisted_messages(storage: &FilesystemStorage) -> (Vec<StoredMessage>, u64) {
    let Ok(keys) = storage.list_keys(STORAGE_KEY_MESSAGES).await else {
        return (Vec::new(), 0);
    };

    let mut entries: Vec<(u64, StoredMessage)> = Vec::new();
    for key in &keys {
        if let Some(seq_str) = key.strip_prefix(&format!("{STORAGE_KEY_MESSAGES}/"))
            && let Ok(seq) = seq_str.parse::<u64>()
            && let Ok(Some(data)) = storage.retrieve(key).await
            && let Ok(msg) = serde_json::from_slice::<StoredMessage>(&data)
        {
            entries.push((seq, msg));
        }
    }

    entries.sort_by_key(|(seq, _)| *seq);

    let next_seq = entries.last().map_or(0, |(seq, _)| seq + 1);

    // Cap at MAX_HISTORY.
    if entries.len() > MAX_HISTORY {
        let drain = entries.len() - MAX_HISTORY;
        entries.drain(..drain);
    }

    let messages = entries.into_iter().map(|(_, msg)| msg).collect();
    (messages, next_seq)
}
