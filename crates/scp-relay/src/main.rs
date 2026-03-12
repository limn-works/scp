#![doc = include_str!("../README.md")]
//! Standalone SCP native relay server.
//!
//! Reads configuration from environment variables, starts the relay, and
//! blocks until SIGINT or SIGTERM is received for graceful shutdown.
//!
//! Supports a `--health` flag that probes the relay's bind address via TCP
//! and exits with code 0 (reachable) or 1 (unreachable).
//!
//! ## Storage backend selection
//!
//! The relay selects a blob storage backend via the `SCP_RELAY_STORAGE_BACKEND`
//! environment variable. Valid values:
//!
//! | Value      | Backend    | Config env vars                              | Default |
//! |------------|------------|----------------------------------------------|---------|
//! | `sqlite`   | `SQLite`     | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.db`) | **yes** |
//! | `redb`     | redb       | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.redb`) | |
//! | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required)           | |
//! | `s3`       | S3-compat  | `SCP_RELAY_S3_BUCKET` (required) + AWS env    | |
//! | `memory`   | In-memory  | —                                             | |
//!
//! See §10.5 of the SCP infrastructure spec.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
use tracing_subscriber::EnvFilter;

/// Reads an environment variable and parses it, returning the default on
/// absence or parse failure (with a warning).
fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    match env::var(name) {
        Ok(val) => val.parse().unwrap_or_else(|_| {
            tracing::warn!(var = name, value = %val, "invalid value, using default");
            default
        }),
        Err(_) => default,
    }
}

/// Builds a [`RelayConfig`] from `SCP_RELAY_*` environment variables.
fn config_from_env() -> RelayConfig {
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

/// Valid backend names for error messages.
const VALID_BACKENDS: &str = "sqlite, redb, postgres, s3, memory";

/// Constructs the blob storage backend from environment configuration.
///
/// Reads `SCP_RELAY_STORAGE_BACKEND` (default: `sqlite`) and delegates to the
/// appropriate backend constructor. Exits on misconfiguration with a
/// descriptive error naming the valid options.
async fn storage_from_env() -> BlobStorageBackend {
    let backend = env::var("SCP_RELAY_STORAGE_BACKEND")
        .unwrap_or_else(|_| "sqlite".to_owned())
        .to_lowercase();

    match backend.as_str() {
        "sqlite" => {
            let path =
                env::var("SCP_RELAY_STORAGE_PATH").unwrap_or_else(|_| "./scp-relay.db".to_owned());
            let path = PathBuf::from(path);
            tracing::info!(path = %path.display(), "using sqlite blob storage");
            BlobStorageBackend::sqlite(&path).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(), "failed to open sqlite storage");
                std::process::exit(1);
            })
        }
        "redb" => {
            let path = env::var("SCP_RELAY_STORAGE_PATH")
                .unwrap_or_else(|_| "./scp-relay.redb".to_owned());
            let path = PathBuf::from(path);
            tracing::info!(path = %path.display(), "using redb blob storage");
            BlobStorageBackend::redb(&path).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(), "failed to open redb storage");
                std::process::exit(1);
            })
        }
        "postgres" => {
            let Ok(url) = env::var("SCP_RELAY_DATABASE_URL") else {
                eprintln!(
                    "error: SCP_RELAY_STORAGE_BACKEND=postgres requires SCP_RELAY_DATABASE_URL to be set"
                );
                std::process::exit(1);
            };
            tracing::info!("using postgres blob storage");
            let store = scp_transport::native::postgres_blob::PostgresBlobStore::open(&url)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to connect to postgres");
                    std::process::exit(1);
                });
            BlobStorageBackend::Postgres(store)
        }
        "s3" => {
            let Ok(bucket) = env::var("SCP_RELAY_S3_BUCKET") else {
                eprintln!(
                    "error: SCP_RELAY_STORAGE_BACKEND=s3 requires SCP_RELAY_S3_BUCKET to be set"
                );
                std::process::exit(1);
            };
            let prefix = env::var("SCP_RELAY_S3_PREFIX").unwrap_or_else(|_| "blobs/".to_owned());
            tracing::info!(bucket = %bucket, prefix = %prefix, "using s3 blob storage");
            let store = scp_transport::native::s3_blob::S3BlobStore::open(&bucket, &prefix)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to initialize s3 storage");
                    std::process::exit(1);
                });
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

/// Initializes the `tracing` subscriber.
///
/// Log level is determined by `RUST_LOG` (takes precedence) or
/// `SCP_RELAY_LOG_LEVEL` (default: `info`). Output format is controlled
/// by `SCP_RELAY_LOG_FORMAT`: `json` for structured JSON, anything else
/// for human-readable pretty output.
fn init_tracing() {
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

/// Runs the `--health` probe: attempts a TCP connection to `addr` and
/// exits with 0 on success, 1 on failure.
async fn health_check(addr: SocketAddr) {
    match tokio::net::TcpStream::connect(addr).await {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}

#[tokio::main]
async fn main() {
    // Check for --health before initializing tracing (keep probe quiet).
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--health") {
        let addr: SocketAddr = env_or(
            "SCP_RELAY_BIND_ADDR",
            SocketAddr::from(([127, 0, 0, 1], 9000)),
        );
        health_check(addr).await;
        // health_check always calls process::exit, but satisfy the compiler.
        return;
    }

    init_tracing();

    let config = config_from_env();
    tracing::info!(
        bind_addr = %config.bind_addr,
        max_blob_size = config.max_blob_size,
        max_connections = config.max_total_connections,
        "starting scp-relay"
    );

    let storage = Arc::new(storage_from_env().await);
    let server = RelayServer::new(config, storage);

    let (handle, local_addr) = match server.start().await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "relay failed to start");
            std::process::exit(1);
        }
    };

    tracing::info!(addr = %local_addr, "relay listening");

    // Wait for shutdown signal (SIGINT / SIGTERM).
    shutdown_signal().await;

    tracing::info!("shutdown signal received, stopping relay");
    handle.shutdown();
    tracing::info!("relay stopped");
}

/// Waits for either SIGINT (`ctrl_c`) or SIGTERM.
async fn shutdown_signal() {
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
