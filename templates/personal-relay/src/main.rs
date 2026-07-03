//! Personal SCP relay with automatic TLS and DID publishing.
//!
//! A self-hosted relay node that:
//! - Creates or reloads a persistent relay identity (DID)
//! - Provisions TLS via Let's Encrypt (ACME), self-signed certs, or manual PEM files
//! - Starts an `ApplicationNode` with relay, HTTP, and WebSocket endpoints
//! - Publishes the relay's DID to the DHT for discovery
//! - Includes a health check endpoint (`/healthz`)
//! - Shuts down gracefully on SIGINT/SIGTERM
//!
//! See `config.rs` for the full list of environment variables.

mod config;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use axum::response::IntoResponse;
use axum::routing::get;
use scp_clock::SystemClock;
use scp_identity::{DidDht, IdentityError, PkarrDhtClient, SequenceStore};
use scp_node::{ApplicationNodeBuilder, TlsProvider};
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};
use scp_platform::traits::Storage;
use scp_transport::native::storage::BlobStorageBackend;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use crate::config::Config;

// ---------------------------------------------------------------------------
// Tracing
// ---------------------------------------------------------------------------

/// Initializes the tracing subscriber from config.
fn init_tracing(config: &Config) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"))
    });

    if config.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Resolves or generates the SQLCipher encryption key.
///
/// Reads from `config.storage_key_hex` (hex-encoded 32 bytes). If unset,
/// generates a random key and persists it to `{storage_dir}/.key` (mode 0600
/// on Unix) for subsequent restarts.
fn resolve_storage_key(
    config: &Config,
    storage_dir: &std::path::Path,
) -> Result<Zeroizing<[u8; 32]>, String> {
    // Check explicit hex key first.
    if let Some(ref hex_key) = config.storage_key_hex {
        let bytes = Zeroizing::new(
            hex::decode(hex_key)
                .map_err(|e| format!("SCP_RELAY_STORAGE_KEY is not valid hex: {e}"))?,
        );
        if bytes.len() != 32 {
            return Err(format!(
                "SCP_RELAY_STORAGE_KEY must be 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            ));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    // Check for existing key file.
    let key_file = storage_dir.join(".key");
    if key_file.exists() {
        let data = Zeroizing::new(
            std::fs::read(&key_file)
                .map_err(|e| format!("failed to read key file {}: {e}", key_file.display()))?,
        );
        if data.len() != 32 {
            return Err(format!(
                "key file {} has invalid length {} (expected 32)",
                key_file.display(),
                data.len()
            ));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&data);
        return Ok(key);
    }

    // Generate a new key and persist it.
    std::fs::create_dir_all(storage_dir)
        .map_err(|e| format!("failed to create storage directory: {e}"))?;

    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_file)
            .map_err(|e| format!("failed to create key file {}: {e}", key_file.display()))?;
        file.write_all(&*key)
            .map_err(|e| format!("failed to write key file {}: {e}", key_file.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&key_file, &*key)
            .map_err(|e| format!("failed to write key file {}: {e}", key_file.display()))?;
    }

    tracing::info!(
        path = %key_file.display(),
        "generated new storage encryption key"
    );
    Ok(key)
}

/// Opens an encrypted SQLite database, exiting on failure.
fn open_sqlite_or_exit(dir: &std::path::Path, key: &Zeroizing<[u8; 32]>) -> SqliteStorage {
    match SqliteStorage::new(dir, key.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, path = %dir.display(), "failed to open SQLite storage");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Storage-backed BEP44 sequence store
// ---------------------------------------------------------------------------

/// Persists BEP44 sequence numbers to SQLite so DID document updates
/// use monotonically increasing sequence numbers across restarts.
struct StorageSequenceStore<S: Storage> {
    storage: Arc<S>,
}

impl<S: Storage + 'static> SequenceStore for StorageSequenceStore<S> {
    fn load(
        &self,
        did: &str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<u64>, IdentityError>> + Send + '_>>
    {
        let key = format!("bep44/seq/{did}");
        Box::pin(async move {
            let data = self
                .storage
                .retrieve(&key)
                .await
                .map_err(IdentityError::Platform)?;
            match data {
                Some(bytes) if bytes.len() == 8 => {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes);
                    Ok(Some(u64::from_le_bytes(buf)))
                }
                Some(_) => Ok(None),
                None => Ok(None),
            }
        })
    }

    fn store(
        &self,
        did: &str,
        seq: u64,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), IdentityError>> + Send + '_>> {
        let key = format!("bep44/seq/{did}");
        let bytes = seq.to_le_bytes();
        Box::pin(async move {
            self.storage
                .store(&key, &bytes)
                .await
                .map_err(IdentityError::Platform)
        })
    }
}

// ---------------------------------------------------------------------------
// Manual TLS provider
// ---------------------------------------------------------------------------

/// TLS provider that loads PEM files from disk (for operators who manage
/// their own certificates via certbot, Caddy, etc.).
struct ManualTlsProvider {
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl TlsProvider for ManualTlsProvider {
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
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        Box::pin(async move {
            let cert_pem = tokio::fs::read_to_string(&cert_path).await.map_err(|e| {
                scp_node::tls::TlsError::Certificate(format!(
                    "failed to read cert file {}: {e}",
                    cert_path.display()
                ))
            })?;
            let key_pem = tokio::fs::read_to_string(&key_path).await.map_err(|e| {
                scp_node::tls::TlsError::Certificate(format!(
                    "failed to read key file {}: {e}",
                    key_path.display()
                ))
            })?;
            Ok(scp_node::tls::CertificateData {
                certificate_chain_pem: cert_pem,
                private_key_pem: Zeroizing::new(key_pem),
            })
        })
    }
}

/// TLS provider that generates a self-signed certificate (development only).
struct SelfSignedTlsProvider {
    domain: String,
}

impl TlsProvider for SelfSignedTlsProvider {
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
        let domain = self.domain.clone();
        Box::pin(async move { scp_node::tls::generate_self_signed(&domain) })
    }
}

// ---------------------------------------------------------------------------
// DHT client
// ---------------------------------------------------------------------------

/// Builds a production pkarr DHT client from config.
fn build_dht_client(config: &Config) -> Arc<PkarrDhtClient> {
    let mut builder = PkarrDhtClient::builder();

    for gateway in &config.dht_gateways {
        tracing::info!(gateway = %gateway, "adding DHT HTTP gateway");
        builder = builder.gateway_url(gateway);
    }

    match builder.build() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "failed to create DHT client");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

/// Simple health check handler returning 200 OK.
async fn health_handler() -> impl IntoResponse {
    (axum::http::StatusCode::OK, "ok")
}

/// Builds the application router with a health check endpoint.
fn app_router() -> axum::Router {
    axum::Router::new().route("/healthz", get(health_handler))
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

/// Waits for SIGINT (Ctrl+C) or SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .unwrap_or_else(|_| {
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                        .unwrap_or_else(|_| std::process::exit(1))
                });
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

// ---------------------------------------------------------------------------
// CLI health probe
// ---------------------------------------------------------------------------

/// TCP health probe: connect to the bind address and exit 0/1.
async fn health_probe(addr: SocketAddr) {
    match tokio::net::TcpStream::connect(addr).await {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Handle --health before initializing tracing (keep probe quiet).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--health") {
        let config = Config::from_env();
        health_probe(config.bind_addr).await;
        return;
    }

    let config = Config::from_env();
    init_tracing(&config);

    // Validate storage path.
    if let Err(e) = std::fs::create_dir_all(&config.storage_path) {
        tracing::error!(
            error = %e,
            path = %config.storage_path.display(),
            "cannot create storage directory"
        );
        std::process::exit(1);
    }

    // Resolve encryption key and open storage.
    let storage_key = match resolve_storage_key(&config, &config.storage_path) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve storage encryption key");
            std::process::exit(1);
        }
    };

    let node_storage = open_sqlite_or_exit(&config.storage_path, &storage_key);
    let custody_storage =
        open_sqlite_or_exit(&config.storage_path.join("custody"), &storage_key);

    let custody = match SqliteKeyCustody::new(custody_storage).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize key custody");
            std::process::exit(1);
        }
    };

    // Build DHT client and DID method.
    let node_storage_arc = Arc::new(node_storage);
    let dht_client = build_dht_client(&config);
    let cache = Arc::new(scp_identity::DidCache::new());
    let sequence_store: Arc<dyn SequenceStore> = Arc::new(StorageSequenceStore {
        storage: Arc::clone(&node_storage_arc),
    });

    let sign_fn =
        DidDht::<PkarrDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_signer_and_store(
        dht_client,
        cache,
        sign_fn,
        sequence_store,
    ));

    // Build the blob storage backend (SQLite by default).
    let blob_db_path = config.storage_path.join("blobs.db");
    let blob_storage = BlobStorageBackend::sqlite(&blob_db_path).unwrap_or_else(|e| {
        tracing::error!(error = %e, "failed to open blob storage");
        std::process::exit(1);
    });

    // Determine the domain. Without a domain, use no_domain (NAT-traversed) mode.
    let domain = config.domain.clone();

    // Re-open a fresh SQLite handle for the ApplicationNodeBuilder (the
    // Arc<SqliteStorage> above is used for the sequence store; the builder
    // needs its own handle for ProtocolRepository).
    let builder_storage = open_sqlite_or_exit(&config.storage_path, &storage_key);

    match domain {
        Some(ref domain_str) => {
            tracing::info!(
                domain = %domain_str,
                bind_addr = %config.bind_addr,
                storage = %config.storage_path.display(),
                "starting personal relay (domain mode)"
            );

            let mut builder = ApplicationNodeBuilder::new()
                .storage(builder_storage)
                .domain(domain_str)
                .identity_with_storage(Arc::clone(&custody), Arc::clone(&did_method))
                .blob_storage(blob_storage)
                .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
                .http_bind_addr(config.bind_addr);

            // TLS provider selection: manual certs > self-signed > ACME (default).
            if let (Some(cert_path), Some(key_path)) =
                (config.tls_cert_path.clone(), config.tls_key_path.clone())
            {
                tracing::info!(
                    cert = %cert_path.display(),
                    key = %key_path.display(),
                    "using manual TLS certificates"
                );
                builder = builder.tls_provider(Arc::new(ManualTlsProvider {
                    cert_path,
                    key_path,
                }));
            } else if config.tls_self_signed {
                tracing::warn!(
                    "using self-signed TLS certificate (development only, not trusted by browsers)"
                );
                builder = builder.tls_provider(Arc::new(SelfSignedTlsProvider {
                    domain: domain_str.clone(),
                }));
            } else if let Some(ref email) = config.acme_email {
                tracing::info!(email = %email, "ACME email set for Let's Encrypt");
                builder = builder.acme_email(email);
            }

            let node = match builder.build().await {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, "failed to build application node");
                    std::process::exit(1);
                }
            };

            // Initialize BEP44 sequence number from persistent store / DHT.
            let did = node.identity().did().to_owned();
            if let Err(e) = did_method.initialize_sequence(&did).await {
                tracing::error!(
                    error = %e,
                    "failed to initialize BEP44 sequence -- DID publishing may fail"
                );
            }

            tracing::info!(
                did = %node.identity().did(),
                relay_url = %node.relay_url(),
                relay_internal_addr = %node.relay().bound_addr(),
                "personal relay identity ready -- DID published to DHT"
            );

            if let Err(e) = node.serve(app_router(), shutdown_signal()).await {
                tracing::error!(error = %e, "relay exited with error");
                std::process::exit(1);
            }
        }
        None => {
            tracing::info!(
                bind_addr = %config.bind_addr,
                storage = %config.storage_path.display(),
                "starting personal relay (no-domain / NAT-traversed mode)"
            );

            let builder = ApplicationNodeBuilder::new()
                .storage(builder_storage)
                .no_domain()
                .identity_with_storage(Arc::clone(&custody), Arc::clone(&did_method))
                .blob_storage(blob_storage)
                .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
                .http_bind_addr(config.bind_addr);

            let node = match builder.build().await {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, "failed to build application node");
                    std::process::exit(1);
                }
            };

            let did = node.identity().did().to_owned();
            if let Err(e) = did_method.initialize_sequence(&did).await {
                tracing::error!(
                    error = %e,
                    "failed to initialize BEP44 sequence -- DID publishing may fail"
                );
            }

            tracing::info!(
                did = %node.identity().did(),
                relay_url = %node.relay_url(),
                relay_internal_addr = %node.relay().bound_addr(),
                "personal relay identity ready -- DID published to DHT"
            );

            if let Err(e) = node.serve(app_router(), shutdown_signal()).await {
                tracing::error!(error = %e, "relay exited with error");
                std::process::exit(1);
            }
        }
    }

    tracing::info!("personal relay stopped");
}
