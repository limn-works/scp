//! SCP application node binary.
//!
//! Two modes of operation:
//!
//! 1. **Full node** (default): Starts an [`ApplicationNode`] with DID identity,
//!    relay, and HTTP server (`.well-known/scp` + WebSocket upgrade).
//! 2. **Relay-only** (`--relay-only`): Runs a bare [`RelayServer`], identical
//!    to the standalone `scp-relay` binary.
//!
//! Configuration is read from environment variables. See module-level
//! constants for defaults.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use scp_core::identity::cache::SystemClock;
use scp_core::identity::{DidCache, DidDht, InMemoryDhtClient};
use scp_node::ApplicationNodeBuilder;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::InMemoryBlobStorage;
use tracing_subscriber::EnvFilter;

// ---------------------------------------------------------------------------
// Environment variable helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tracing
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Relay config from env
// ---------------------------------------------------------------------------

/// Builds a [`RelayConfig`] from `SCP_RELAY_*` environment variables.
fn relay_config_from_env() -> RelayConfig {
    let bind_addr: SocketAddr =
        env_or("SCP_RELAY_BIND_ADDR", SocketAddr::from(([0, 0, 0, 0], 9000)));

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
// Health check
// ---------------------------------------------------------------------------

/// Runs the `--health` probe: attempts a TCP connection to `addr` and
/// exits with 0 on success, 1 on failure.
async fn health_check(addr: SocketAddr) {
    match tokio::net::TcpStream::connect(addr).await {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

/// Waits for either SIGINT (`ctrl_c`) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
// Relay-only mode
// ---------------------------------------------------------------------------

/// Runs a bare relay server (same as `scp-relay` binary).
async fn run_relay_only() {
    let config = relay_config_from_env();
    tracing::info!(
        bind_addr = %config.bind_addr,
        max_blob_size = config.max_blob_size,
        max_connections = config.max_total_connections,
        "starting scp-node in relay-only mode"
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

    shutdown_signal().await;

    tracing::info!("shutdown signal received, stopping relay");
    handle.shutdown();
    tracing::info!("relay stopped");
}

// ---------------------------------------------------------------------------
// Full node mode
// ---------------------------------------------------------------------------

/// Runs the full application node: identity + relay + HTTP.
async fn run_full_node() {
    let domain = match env::var("SCP_NODE_DOMAIN") {
        Ok(d) if !d.is_empty() => d,
        _ => {
            tracing::error!("SCP_NODE_DOMAIN is required in full node mode");
            std::process::exit(1);
        }
    };

    let http_addr: SocketAddr = env_or(
        "SCP_NODE_BIND_ADDR",
        SocketAddr::from(([0, 0, 0, 0], 9000)),
    );

    tracing::info!(
        domain = %domain,
        bind_addr = %http_addr,
        "starting scp-node in full mode"
    );

    // Identity components (in-memory for now; production would use
    // persistent storage and a real DHT client).
    let custody = Arc::new(InMemoryKeyCustody::new());
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = DidDht::<InMemoryDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_and_signer(dht_client, cache, sign_fn));

    // The relay binds to an ephemeral port on localhost; the HTTP server
    // (below) is the public-facing listener that bridges WebSocket
    // connections to the internal relay.
    let node = match ApplicationNodeBuilder::new()
        .storage(Arc::new(InMemoryStorage::new()))
        .domain(&domain)
        .generate_identity_with(custody, did_method)
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .build()
        .await
    {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "application node failed to build");
            std::process::exit(1);
        }
    };

    tracing::info!(
        did = %node.identity().did(),
        relay_url = %node.relay_url(),
        relay_internal_addr = %node.relay().bound_addr(),
        "application node identity ready"
    );

    // Compose the HTTP server manually: .well-known/scp + /scp/v1
    // WebSocket bridge. We don't use node.serve() because it tries to
    // re-bind the relay's internal address (a pre-existing issue).
    let merged = axum::Router::new()
        .merge(node.well_known_router())
        .merge(node.relay_router());

    let listener = match tokio::net::TcpListener::bind(http_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %http_addr, error = %e, "failed to bind HTTP listener");
            std::process::exit(1);
        }
    };

    let local_addr = listener.local_addr().unwrap_or(http_addr);
    tracing::info!(addr = %local_addr, "application node HTTP server started");

    let shutdown = shutdown_signal();
    tokio::select! {
        result = axum::serve(listener, merged) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "application node exited with error");
                std::process::exit(1);
            }
        }
        () = shutdown => {
            tracing::info!("shutdown signal received, stopping node");
            node.shutdown();
        }
    }

    tracing::info!("scp-node stopped");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let relay_only = args.iter().any(|a| a == "--relay-only");

    // --health: probe the appropriate bind address and exit.
    if args.iter().any(|a| a == "--health") {
        let addr: SocketAddr = if relay_only {
            env_or(
                "SCP_RELAY_BIND_ADDR",
                SocketAddr::from(([127, 0, 0, 1], 9000)),
            )
        } else {
            env_or(
                "SCP_NODE_BIND_ADDR",
                SocketAddr::from(([127, 0, 0, 1], 9000)),
            )
        };
        health_check(addr).await;
        return;
    }

    init_tracing();

    if relay_only {
        run_relay_only().await;
    } else {
        run_full_node().await;
    }
}
