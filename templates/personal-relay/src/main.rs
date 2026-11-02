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

// Links the one `#[global_allocator]`, which wipes every heap block before
// freeing it (09-security-model.md §9.15, freed heap memory).
use scp_alloc as _;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use axum::response::IntoResponse;
use axum::routing::get;
use scp_identity::{DidCache, SequenceStore};
use scp_node::self_host::{
    build_production_did_method, open_sqlite, resolve_storage_key_file, validate_storage_path,
    StorageSequenceStore,
};
use scp_node::{DhtMode, IdentitySource, Node, NodeConfig, Reach, TlsMode, TlsProvider};
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};
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

/// Resolves the SQLCipher encryption key.
///
/// Reads `config.storage_key_hex` (hex-encoded 32 bytes) when set. Otherwise
/// [`scp_node::self_host::resolve_storage_key_file`] reads `{storage_dir}/.key`,
/// or generates a random key and publishes it there durably (mode 0600 on
/// Unix) on the blocking pool, never replacing a key another process wrote
/// first.
async fn resolve_storage_key(
    config: &Config,
    storage_dir: &std::path::Path,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let Some(ref hex_key) = config.storage_key_hex else {
        return resolve_storage_key_file(storage_dir)
            .await
            .map_err(|e| e.to_string());
    };
    let bytes = Zeroizing::new(
        hex::decode(hex_key).map_err(|e| format!("SCP_RELAY_STORAGE_KEY is not valid hex: {e}"))?,
    );
    if bytes.len() != 32 {
        return Err(format!(
            "SCP_RELAY_STORAGE_KEY must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Opens an encrypted SQLite database on the blocking pool, exiting on
/// failure.
async fn open_sqlite_or_exit(dir: &std::path::Path, key: &Zeroizing<[u8; 32]>) -> SqliteStorage {
    match open_sqlite(dir, key).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, path = %dir.display(), "failed to open SQLite storage");
            std::process::exit(1);
        }
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
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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

/// Selects the TLS mode for a domain relay: manual certificates, then a
/// self-signed certificate, then ACME (the default).
fn tls_mode(config: &Config) -> TlsMode {
    if let (Some(cert_path), Some(key_path)) =
        (config.tls_cert_path.clone(), config.tls_key_path.clone())
    {
        tracing::info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "using manual TLS certificates"
        );
        return TlsMode::Custom(Arc::new(ManualTlsProvider {
            cert_path,
            key_path,
        }));
    }
    if config.tls_self_signed {
        tracing::warn!(
            "using self-signed TLS certificate (development only, not trusted by browsers)"
        );
        return TlsMode::SelfSigned;
    }
    if let Some(ref email) = config.acme_email {
        tracing::info!(email = %email, "ACME email set for Let's Encrypt");
    }
    TlsMode::Acme {
        email: config.acme_email.clone(),
    }
}

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

    // Create the storage directory and check that it is writable.
    if let Err(e) = validate_storage_path(&config.storage_path).await {
        tracing::error!(
            error = %e,
            path = %config.storage_path.display(),
            "cannot use storage directory"
        );
        std::process::exit(1);
    }

    // Resolve encryption key and open storage.
    let storage_key = match resolve_storage_key(&config, &config.storage_path).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve storage encryption key");
            std::process::exit(1);
        }
    };

    let node_storage = Arc::new(open_sqlite_or_exit(&config.storage_path, &storage_key).await);
    let custody_storage =
        open_sqlite_or_exit(&config.storage_path.join("custody"), &storage_key).await;

    let custody = match SqliteKeyCustody::new(custody_storage).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize key custody");
            std::process::exit(1);
        }
    };

    // Build the DID method: BEP44 sequence numbers persist in node storage,
    // so DID document updates stay monotonic across restarts.
    let sequence_store: Arc<dyn SequenceStore> =
        Arc::new(StorageSequenceStore::new(Arc::clone(&node_storage)));
    let did_method = match build_production_did_method(
        Arc::clone(&custody),
        Arc::new(DidCache::new()),
        sequence_store,
        &config.dht_gateways,
    ) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "failed to create DHT client");
            std::process::exit(1);
        }
    };

    // Build the blob storage backend (SQLite by default).
    let blob_db_path = config.storage_path.join("blobs.db");
    let blob_storage = BlobStorageBackend::sqlite(&blob_db_path)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to open blob storage");
            std::process::exit(1);
        });

    // Without a domain, the relay runs NAT-traversed.
    let (reach, tls) = match config.domain.clone() {
        Some(domain) => {
            tracing::info!(
                domain = %domain,
                bind_addr = %config.bind_addr,
                storage = %config.storage_path.display(),
                "starting personal relay (domain mode)"
            );
            (Reach::Domain { domain }, tls_mode(&config))
        }
        None => {
            tracing::info!(
                bind_addr = %config.bind_addr,
                storage = %config.storage_path.display(),
                "starting personal relay (no-domain / NAT-traversed mode)"
            );
            (Reach::NatTraversal, TlsMode::SelfSigned)
        }
    };

    let node_config = NodeConfig {
        tls,
        dht: DhtMode::Production,
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        http_bind_addr: Some(config.bind_addr),
        dht_gateways: config.dht_gateways.clone(),
        ..NodeConfig::defaults(
            reach,
            IdentitySource::Persisted {
                custody: Arc::clone(&custody),
                did_method,
            },
            node_storage,
            blob_storage,
        )
    };

    let node = match Node::start(node_config).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "failed to start application node");
            std::process::exit(1);
        }
    };

    // `Node::start` bootstraps the BEP44 publish-sequence counter before its
    // startup publish, so no sequence initialization is needed here.
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

    tracing::info!("personal relay stopped");
}
