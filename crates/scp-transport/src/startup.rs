//! Shared startup utilities for SCP relay and node binaries.
//!
//! Both `scp-relay` and `scp-node` binaries use identical logic for environment
//! variable parsing, relay configuration, blob storage backend selection,
//! tracing initialization, health checks, and graceful shutdown. This module
//! provides the shared implementations so changes need only be made once.
//!
//! Gated behind the `startup` feature. Not used by the library or FFI bridges.
//!
//! See §10.5 of the SCP infrastructure spec.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use crate::native::server::RelayConfig;
use crate::native::storage::BlobStorageBackend;

// ---------------------------------------------------------------------------
// env_or — typed environment variable with fallback
// ---------------------------------------------------------------------------

/// Reads an environment variable and parses it, returning the default on
/// absence or parse failure (with a warning).
pub fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    match env::var(name) {
        Ok(val) => val.parse().unwrap_or_else(|_| {
            tracing::warn!(
                var = name,
                value_len = val.len(),
                "invalid value, using default"
            );
            default
        }),
        Err(_) => default,
    }
}

// ---------------------------------------------------------------------------
// Relay configuration from environment
// ---------------------------------------------------------------------------

/// Builds a [`RelayConfig`] from `SCP_RELAY_*` environment variables.
///
/// | Variable | Default |
/// |---|---|
/// | `SCP_RELAY_BIND_ADDR` | `0.0.0.0:9000` |
/// | `SCP_RELAY_MAX_BLOB_SIZE` | 262,144 (256 KiB) |
/// | `SCP_RELAY_MAX_BLOB_TTL` | 604,800 (7 days) |
/// | `SCP_RELAY_MAX_CONNECTIONS` | 1,000 |
/// | `SCP_RELAY_MAX_CONNECTIONS_PER_IP` | 10 |
/// | `SCP_RELAY_RATE_LIMIT` | 100 |
#[must_use]
pub fn relay_config_from_env() -> RelayConfig {
    let bind_addr: SocketAddr = env_or(
        "SCP_RELAY_BIND_ADDR",
        SocketAddr::from(([0, 0, 0, 0], 9000)),
    );

    RelayConfig {
        bind_addr,
        max_blob_size: env_or("SCP_RELAY_MAX_BLOB_SIZE", 262_144),
        max_blob_ttl: env_or("SCP_RELAY_MAX_BLOB_TTL", 604_800),
        max_total_connections: env_or("SCP_RELAY_MAX_CONNECTIONS", 1_000),
        max_connections_per_ip: env_or("SCP_RELAY_MAX_CONNECTIONS_PER_IP", 10),
        rate_limit_publishes_per_second: env_or("SCP_RELAY_RATE_LIMIT", 100),
        ..RelayConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Blob storage backend from environment
// ---------------------------------------------------------------------------

/// Valid backend names for error messages.
pub const VALID_BACKENDS: &str = "sqlite, redb, postgres, s3, memory";

/// Constructs the blob storage backend from environment configuration.
///
/// Reads `SCP_RELAY_STORAGE_BACKEND` (default: `sqlite`) and delegates to the
/// appropriate backend constructor. Calls [`std::process::exit`] on
/// misconfiguration with a descriptive error naming the valid options.
///
/// # Storage backend selection
///
/// | Value | Backend | Config env vars | Default |
/// |---|---|---|---|
/// | `sqlite` | `SQLite` | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.db`) | **yes** |
/// | `redb` | redb | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.redb`) | |
/// | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required) | |
/// | `s3` | S3-compat | `SCP_RELAY_S3_BUCKET` (required) + AWS env | |
/// | `memory` | In-memory | — | |
///
/// # Panics
///
/// Backend arms are compiled only when the corresponding feature is enabled
/// (`sqlite-blob`, `redb-blob`, `postgres-blob`, `s3-blob`). If a backend
/// is requested but the feature is not compiled in, the function prints an
/// error and exits.
pub async fn storage_from_env() -> BlobStorageBackend {
    let backend = env::var("SCP_RELAY_STORAGE_BACKEND")
        .unwrap_or_else(|_| "sqlite".to_owned())
        .to_lowercase();

    match backend.as_str() {
        #[cfg(feature = "sqlite-blob")]
        "sqlite" => {
            let path =
                env::var("SCP_RELAY_STORAGE_PATH").unwrap_or_else(|_| "./scp-relay.db".to_owned());
            let path = PathBuf::from(path);
            let store = BlobStorageBackend::sqlite(&path).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(), "failed to open sqlite storage");
                std::process::exit(1);
            });
            tracing::info!(path = %path.display(), "using sqlite blob storage");
            store
        }
        #[cfg(feature = "redb-blob")]
        "redb" => {
            let path = env::var("SCP_RELAY_STORAGE_PATH")
                .unwrap_or_else(|_| "./scp-relay.redb".to_owned());
            let path = PathBuf::from(path);
            let store = BlobStorageBackend::redb(&path).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(), "failed to open redb storage");
                std::process::exit(1);
            });
            tracing::info!(path = %path.display(), "using redb blob storage");
            store
        }
        #[cfg(feature = "postgres-blob")]
        "postgres" => {
            let Ok(url) = env::var("SCP_RELAY_DATABASE_URL") else {
                eprintln!(
                    "error: SCP_RELAY_STORAGE_BACKEND=postgres requires SCP_RELAY_DATABASE_URL to be set"
                );
                std::process::exit(1);
            };
            let store = crate::native::postgres_blob::PostgresBlobStore::open(&url)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to connect to postgres");
                    std::process::exit(1);
                });
            tracing::info!("using postgres blob storage");
            BlobStorageBackend::Postgres(store)
        }
        #[cfg(feature = "s3-blob")]
        "s3" => {
            let Ok(bucket) = env::var("SCP_RELAY_S3_BUCKET") else {
                eprintln!(
                    "error: SCP_RELAY_STORAGE_BACKEND=s3 requires SCP_RELAY_S3_BUCKET to be set"
                );
                std::process::exit(1);
            };
            let prefix = env::var("SCP_RELAY_S3_PREFIX").unwrap_or_else(|_| "blobs/".to_owned());
            // `S3BlobStore::open` probes the bucket, so it reports an
            // unreachable endpoint, absent credentials or a missing bucket as
            // `StorageError::Internal` and this arm exits. The success log runs
            // only after that probe answers, so it never claims a backend the
            // relay does not have.
            let store = crate::native::s3_blob::S3BlobStore::open(&bucket, &prefix)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to initialize s3 storage");
                    std::process::exit(1);
                });
            tracing::info!(bucket = %bucket, prefix = %prefix, "using s3 blob storage");
            BlobStorageBackend::S3(store)
        }
        "memory" => {
            tracing::warn!("using in-memory blob storage — all data will be lost on restart");
            BlobStorageBackend::in_memory()
        }
        other => {
            eprintln!("error: unknown storage backend '{other}'. Valid options: {VALID_BACKENDS}");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Tracing initialization
// ---------------------------------------------------------------------------

/// Initializes the `tracing` subscriber.
///
/// Log level is determined by `RUST_LOG` (takes precedence) or
/// `SCP_RELAY_LOG_LEVEL` (default: `info`). Output format is controlled
/// by `SCP_RELAY_LOG_FORMAT`: `json` for structured JSON, anything else
/// for human-readable pretty output.
pub fn init_tracing() {
    let default_level = env::var("SCP_RELAY_LOG_LEVEL").unwrap_or_else(|_| "info".into());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::try_new(&default_level).unwrap_or_else(|_| EnvFilter::new("info"))
    });

    let format = env::var("SCP_RELAY_LOG_FORMAT").unwrap_or_else(|_| "pretty".into());

    if format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    }
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

/// Runs a TCP health probe: attempts a connection to `addr` and exits with
/// code 0 on success, 1 on failure.
///
/// Designed for container health checks (`--health` CLI flag).
pub async fn health_check(addr: SocketAddr) {
    match tokio::net::TcpStream::connect(addr).await {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

/// Waits for either SIGINT (`ctrl_c`) or SIGTERM.
///
/// On non-Unix platforms, only `ctrl_c` is supported.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|_| {
                // If we cannot register SIGTERM, fall back to ctrl_c only.
                // This is unreachable on any standard Unix system but
                // satisfies the no-panic lint without process::exit.
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
// Relay startup helper
// ---------------------------------------------------------------------------

/// Starts a relay server from environment configuration and returns the
/// server handle, bound address, and storage reference.
///
/// This encapsulates the common pattern of reading config + storage from env,
/// building the relay, starting it, and logging the result.
pub async fn start_relay_from_env() -> (
    crate::native::server::ShutdownHandle,
    SocketAddr,
    Arc<BlobStorageBackend>,
) {
    let config = relay_config_from_env();
    tracing::info!(
        bind_addr = %config.bind_addr,
        max_blob_size = config.max_blob_size,
        max_connections = config.max_total_connections,
        "starting relay"
    );

    let storage = Arc::new(storage_from_env().await);
    let server = crate::native::server::RelayServer::new(config, Arc::clone(&storage));

    let (handle, local_addr) = match server.start().await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "relay failed to start");
            std::process::exit(1);
        }
    };

    tracing::info!(addr = %local_addr, "relay listening");

    (handle, local_addr, storage)
}
