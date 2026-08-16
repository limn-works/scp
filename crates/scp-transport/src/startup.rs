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
// Only a sqlite arm and a redb arm name a path, so this import carries their
// features; a `startup` build without either one would otherwise warn.
#[cfg(any(feature = "sqlite-blob", feature = "redb-blob"))]
use std::path::PathBuf;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use crate::native::server::{RelayConfig, RelayError};
use crate::native::storage::{BlobStorageBackend, StorageError};

// ---------------------------------------------------------------------------
// StartupError
// ---------------------------------------------------------------------------

/// Why a relay failed to start.
///
/// [`start_relay_from_env`] returns this to a binary rather than ending a
/// process itself, so a caller that embeds a relay (a test harness, a node
/// binary that also serves HTTP) chooses its own response.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// An operator named no blob storage backend, named one this build does
    /// not carry, or named one whose resource a relay could not open.
    #[error("blob storage selection failed: {0}")]
    Storage(#[from] StorageError),

    /// A relay bound its listener or started its accept loop and failed.
    #[error("relay failed to start: {0}")]
    Relay(#[from] RelayError),
}

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

/// Every backend name [`storage_from_env`] recognizes, across all builds. A
/// build compiles an arm for each of these names only when that backend's cargo
/// feature is on, so this list names more backends than a given build carries;
/// [`compiled_backends`] names whichever ones this build carries.
const KNOWN_BACKENDS: [&str; 5] = ["sqlite", "redb", "postgres", "s3", "memory"];

/// Backend names this build carries an arm for, drawn from those same
/// `#[cfg]`s that gate match arms in [`storage_from_env`].
///
/// Every operator-facing message lists these rather than [`KNOWN_BACKENDS`],
/// because a message that offers a name this build compiled out sends an
/// operator into a second error.
fn compiled_backends() -> Vec<&'static str> {
    let mut names = Vec::with_capacity(KNOWN_BACKENDS.len());
    #[cfg(feature = "sqlite-blob")]
    names.push("sqlite");
    #[cfg(feature = "redb-blob")]
    names.push("redb");
    #[cfg(feature = "postgres-blob")]
    names.push("postgres");
    #[cfg(feature = "s3-blob")]
    names.push("s3");
    names.push("memory");
    names
}

/// Names [`compiled_backends`] returns, joined for a message.
fn compiled_backends_list() -> String {
    compiled_backends().join(", ")
}

/// Constructs whichever blob storage backend an operator names in
/// `SCP_RELAY_STORAGE_BACKEND`.
///
/// An operator names one backend; this function never picks one. §17.17.1 of
/// `.docs/specs/17-persistence-and-storage.md` (`SCP-CAPSEL-8000`) makes that
/// selection mandatory and forbids a default, and §17.17.1
/// (`SCP-CAPSEL-8001`) makes a failed selection terminal, so every failure
/// returns [`StorageError`] to a caller instead of ending a process. Each
/// binary decides what to do with that error.
///
/// # Storage backend selection
///
/// | Value | Backend | Config env vars |
/// |---|---|---|
/// | `sqlite` | `SQLite` | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.db`) |
/// | `redb` | redb | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.redb`) |
/// | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required) |
/// | `s3` | S3-compat | `SCP_RELAY_S3_BUCKET` (required) + AWS env |
/// | `memory` | In-memory | — |
///
/// # Errors
///
/// Returns [`StorageError::Configuration`] when `SCP_RELAY_STORAGE_BACKEND` is
/// unset or empty, when its value names no backend in that table, when this
/// build carries no arm for a named backend (each arm compiles only under its
/// own feature: `sqlite-blob`, `redb-blob`, `postgres-blob`, `s3-blob`), or
/// when a named backend requires an env var that an operator left unset.
/// Returns whatever [`StorageError`] a backend constructor reports when that
/// constructor cannot open its resource.
// Only a postgres arm and an s3 arm await, and each compiles under its own
// feature, so a build carrying neither sees an await-free async fn.
#[cfg_attr(
    not(any(feature = "postgres-blob", feature = "s3-blob")),
    allow(clippy::unused_async)
)]
pub async fn storage_from_env() -> Result<BlobStorageBackend, StorageError> {
    let raw = env::var("SCP_RELAY_STORAGE_BACKEND").unwrap_or_default();
    let backend = raw.trim().to_lowercase();

    if backend.is_empty() {
        return Err(StorageError::Configuration(format!(
            "SCP_RELAY_STORAGE_BACKEND is not set. Name one backend this build carries: {}. \
             There is no default backend.",
            compiled_backends_list()
        )));
    }

    match backend.as_str() {
        #[cfg(feature = "sqlite-blob")]
        "sqlite" => {
            let path =
                env::var("SCP_RELAY_STORAGE_PATH").unwrap_or_else(|_| "./scp-relay.db".to_owned());
            let path = PathBuf::from(path);
            tracing::info!(path = %path.display(), "using sqlite blob storage");
            BlobStorageBackend::sqlite(&path)
        }
        #[cfg(feature = "redb-blob")]
        "redb" => {
            let path = env::var("SCP_RELAY_STORAGE_PATH")
                .unwrap_or_else(|_| "./scp-relay.redb".to_owned());
            let path = PathBuf::from(path);
            tracing::info!(path = %path.display(), "using redb blob storage");
            BlobStorageBackend::redb(&path)
        }
        #[cfg(feature = "postgres-blob")]
        "postgres" => {
            let Ok(url) = env::var("SCP_RELAY_DATABASE_URL") else {
                return Err(StorageError::Configuration(
                    "SCP_RELAY_STORAGE_BACKEND=postgres requires SCP_RELAY_DATABASE_URL to be set"
                        .to_owned(),
                ));
            };
            tracing::info!("using postgres blob storage");
            let store = crate::native::postgres_blob::PostgresBlobStore::open(&url).await?;
            Ok(BlobStorageBackend::Postgres(store))
        }
        #[cfg(feature = "s3-blob")]
        "s3" => {
            let Ok(bucket) = env::var("SCP_RELAY_S3_BUCKET") else {
                return Err(StorageError::Configuration(
                    "SCP_RELAY_STORAGE_BACKEND=s3 requires SCP_RELAY_S3_BUCKET to be set"
                        .to_owned(),
                ));
            };
            let prefix = env::var("SCP_RELAY_S3_PREFIX").unwrap_or_else(|_| "blobs/".to_owned());
            tracing::info!(bucket = %bucket, prefix = %prefix, "using s3 blob storage");
            let store = crate::native::s3_blob::S3BlobStore::open(&bucket, &prefix).await?;
            Ok(BlobStorageBackend::S3(store))
        }
        "memory" => {
            tracing::warn!("using in-memory blob storage — all data will be lost on restart");
            Ok(BlobStorageBackend::in_memory())
        }
        // A name this build carries an arm for matched above, so a name that
        // reaches here either names no backend at all or names one whose arm
        // this build compiled out. `KNOWN_BACKENDS` separates those two cases,
        // because an operator fixes them differently: one by correcting a
        // value, one by rebuilding with that backend's feature.
        other if KNOWN_BACKENDS.contains(&other) => Err(StorageError::Configuration(format!(
            "storage backend '{other}' is not compiled into this build. Rebuild with its \
             cargo feature, or name one of: {}",
            compiled_backends_list()
        ))),
        other => Err(StorageError::Configuration(format!(
            "unknown storage backend '{other}'. This build carries: {}",
            compiled_backends_list()
        ))),
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

/// Runs a TCP health probe against `addr` and reports whether a connection
/// succeeded.
///
/// Designed for container health checks (`--health` CLI flag). This returns a
/// verdict rather than ending a process, because a library that exits denies
/// every caller — an embedding test harness included — a choice. Each binary
/// turns `false` into its own non-zero exit.
pub async fn health_check(addr: SocketAddr) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
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
        // A kernel that refuses a SIGTERM handler leaves ctrl_c as a sole
        // shutdown path, which is what this arm waits on. This arm ends no
        // process: a library that exits takes that decision away from a caller
        // that may run a relay beside other work.
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "cannot register a SIGTERM handler; waiting on ctrl_c alone"
                );
                let _ = ctrl_c.await;
            }
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
///
/// # Errors
///
/// Returns [`StartupError::Storage`] when [`storage_from_env`] rejects an
/// operator's blob storage configuration, and [`StartupError::Relay`] when a
/// relay cannot bind its address.
pub async fn start_relay_from_env() -> Result<
    (
        crate::native::server::ShutdownHandle,
        SocketAddr,
        Arc<BlobStorageBackend>,
    ),
    StartupError,
> {
    let config = relay_config_from_env();
    tracing::info!(
        bind_addr = %config.bind_addr,
        max_blob_size = config.max_blob_size,
        max_connections = config.max_total_connections,
        "starting relay"
    );

    let storage = Arc::new(storage_from_env().await?);
    let server = crate::native::server::RelayServer::new(config, Arc::clone(&storage));

    let (handle, local_addr) = server.start().await?;

    tracing::info!(addr = %local_addr, "relay listening");

    Ok((handle, local_addr, storage))
}
