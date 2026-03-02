//! Standalone SCP native relay server.
//!
//! Reads configuration from environment variables, starts the relay, and
//! blocks until SIGINT or SIGTERM is received for graceful shutdown.
//!
//! Supports a `--health` flag that probes the relay's bind address via TCP
//! and exits with code 0 (reachable) or 1 (unreachable).

use std::env;
use std::net::SocketAddr;

use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::InMemoryBlobStorage;
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
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
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

    let storage = InMemoryBlobStorage::new();
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
