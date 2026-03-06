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

use scp_identity::cache::SystemClock;
use scp_identity::{DidCache, DidDht, InMemoryDhtClient, InMemorySequenceStore, PkarrDhtClient};
use scp_node::{ApplicationNodeBuilder, TlsProvider};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
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
// Self-signed TLS provider (development mode)
// ---------------------------------------------------------------------------

/// TLS provider that generates a self-signed certificate for development.
///
/// Activated by `SCP_NODE_TLS_SELF_SIGNED=1`. NOT for production use.
struct SelfSignedTlsProvider {
    domain: String,
}

impl TlsProvider for SelfSignedTlsProvider {
    fn provision(
        &self,
    ) -> std::pin::Pin<
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

    let storage = Arc::new(BlobStorageBackend::in_memory());
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

    let http_addr: SocketAddr =
        env_or("SCP_NODE_BIND_ADDR", SocketAddr::from(([0, 0, 0, 0], 9000)));

    tracing::info!(
        domain = %domain,
        bind_addr = %http_addr,
        "starting scp-node in full mode"
    );

    // Identity components.
    //
    // SCP_NODE_DHT_MODE controls the DHT client:
    //   - "production" (default): PkarrDhtClient with Mainline DHT + optional
    //     HTTP gateway fallback via SCP_NODE_DHT_GATEWAYS (comma-separated).
    //   - "memory": InMemoryDhtClient for testing/development.
    //
    // Sequence persistence uses InMemorySequenceStore. A production deployment
    // should replace this with a persistent SequenceStore backed by the
    // Storage trait (see #327 for the pattern).
    let custody = Arc::new(InMemoryKeyCustody::new());
    let cache = Arc::new(DidCache::new());
    let sequence_store = Arc::new(InMemorySequenceStore::new());

    let dht_mode = env::var("SCP_NODE_DHT_MODE").unwrap_or_else(|_| "production".into());

    if dht_mode == "memory" {
        tracing::warn!(
            "using InMemoryDhtClient — DID documents will NOT be published to the network"
        );
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let sign_fn = DidDht::<InMemoryDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
        let did_method = Arc::new(DidDht::with_client_signer_and_store(
            dht_client,
            cache,
            sign_fn,
            sequence_store,
        ));

        run_full_node_with(domain, http_addr, custody, did_method).await;
        return;
    }

    // Production: PkarrDhtClient with Mainline DHT.
    let mut dht_builder = PkarrDhtClient::builder();

    // Add HTTP gateway URLs from SCP_NODE_DHT_GATEWAYS (comma-separated).
    if let Ok(gateways) = env::var("SCP_NODE_DHT_GATEWAYS") {
        for gateway in gateways.split(',') {
            let gateway = gateway.trim();
            if !gateway.is_empty() {
                tracing::info!(gateway = %gateway, "adding DHT HTTP gateway");
                dht_builder = dht_builder.gateway_url(gateway);
            }
        }
    }

    let dht_client = match dht_builder.build() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "failed to create PkarrDhtClient");
            std::process::exit(1);
        }
    };

    let sign_fn = DidDht::<PkarrDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_signer_and_store(
        dht_client,
        cache,
        sign_fn,
        sequence_store,
    ));

    run_full_node_with(domain, http_addr, custody, did_method).await;
}

/// Shared implementation for `run_full_node`, parameterized over the DID method.
///
/// Builds and runs the `ApplicationNode` with the given identity components.
/// The DID method type `D` is generic so both `DidDht<PkarrDhtClient>` (production)
/// and `DidDht<InMemoryDhtClient>` (development) work without trait objects.
async fn run_full_node_with<D: scp_identity::DidMethod + 'static>(
    domain: String,
    http_addr: SocketAddr,
    custody: Arc<InMemoryKeyCustody>,
    did_method: Arc<D>,
) {
    // If SCP_NODE_TLS_SELF_SIGNED=1, use a self-signed certificate for
    // development/testing. In production, the builder uses ACME by default.
    let use_self_signed = env::var("SCP_NODE_TLS_SELF_SIGNED")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    // The relay binds to an ephemeral port on localhost; the public HTTP
    // server (serve()) binds separately on http_addr.
    let projection_rate: u32 = env_or(
        "SCP_NODE_PROJECTION_RATE_LIMIT",
        scp_node::DEFAULT_PROJECTION_RATE_LIMIT,
    );

    let mut builder = ApplicationNodeBuilder::new()
        .storage(InMemoryStorage::new())
        .domain(&domain)
        .generate_identity_with(custody, did_method)
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .http_bind_addr(http_addr)
        .projection_rate_limit(projection_rate);

    if use_self_signed {
        tracing::info!(domain = %domain, "using self-signed TLS certificate (development mode)");
        builder = builder.tls_provider(Arc::new(SelfSignedTlsProvider {
            domain: domain.clone(),
        }));
    }

    let node = match builder.build().await {
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

    // serve() takes ownership of the node and handles graceful shutdown
    // internally when the shutdown signal fires.
    if let Err(e) = node.serve(axum::Router::new(), shutdown_signal()).await {
        tracing::error!(error = %e, "application node exited with error");
        std::process::exit(1);
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
