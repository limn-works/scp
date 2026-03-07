//! SCP application node binary.
//!
//! Three modes of operation:
//!
//! 1. **Full node** (default): Starts an [`ApplicationNode`] with DID identity,
//!    relay, and HTTP server (`.well-known/scp` + WebSocket upgrade). Uses
//!    persistent `SQLite` storage by default (`SQLCipher` encrypted).
//! 2. **Relay-only** (`--relay-only`): Runs a bare [`RelayServer`], identical
//!    to the standalone `scp-relay` binary.
//! 3. **Ephemeral** (`--ephemeral`): Runs a full node with all in-memory
//!    subsystems — nothing persists across restarts.
//!
//! Configuration is read from CLI flags and environment variables.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use zeroize::Zeroizing;

use scp_identity::cache::SystemClock;
use scp_identity::dht::SequenceStore;
use scp_identity::{
    DidCache, DidDht, IdentityError, InMemoryDhtClient, InMemorySequenceStore, PkarrDhtClient,
};
use scp_node::{ApplicationNodeBuilder, TlsProvider};
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_platform::traits::Storage;
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
use tracing_subscriber::EnvFilter;

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

/// Parsed CLI configuration.
#[allow(clippy::struct_excessive_bools)]
struct CliConfig {
    /// Run in relay-only mode.
    relay_only: bool,
    /// Run health check and exit.
    health: bool,
    /// Use all in-memory subsystems (no persistence).
    ephemeral: bool,
    /// Path to the `SQLite` database directory. `None` = use default XDG path.
    storage_path: Option<PathBuf>,
    /// Show help text and exit.
    show_help: bool,
}

/// Parses CLI arguments.
///
/// Accepts:
///   `--relay-only`       — relay-only mode
///   `--health`           — TCP health probe
///   `--ephemeral`        — all in-memory subsystems
///   `--storage-path <p>` — `SQLite` database directory
///   `--help`             — print usage and exit
fn parse_args() -> CliConfig {
    let args: Vec<String> = env::args().collect();

    let relay_only = args.iter().any(|a| a == "--relay-only");
    let health = args.iter().any(|a| a == "--health");
    let ephemeral = args.iter().any(|a| a == "--ephemeral");
    let show_help = args.iter().any(|a| a == "--help" || a == "-h");

    let storage_path = args
        .iter()
        .position(|a| a == "--storage-path")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .or_else(|| env::var("SCP_STORAGE_PATH").ok().map(PathBuf::from));

    CliConfig {
        relay_only,
        health,
        ephemeral,
        storage_path,
        show_help,
    }
}

/// Prints usage information and exits with code 0.
fn print_help() -> ! {
    eprintln!(
        "\
scp-node — SCP application node

USAGE:
    scp-node [OPTIONS]

OPTIONS:
    --relay-only            Run as a bare relay server only (no identity, no HTTP)
    --ephemeral             Use in-memory storage for all subsystems (no persistence)
    --storage-path <PATH>   SQLite database directory (default: $XDG_DATA_HOME/scp/node)
                            Also configurable via SCP_STORAGE_PATH env var
    --health                TCP health probe (exit 0 on success, 1 on failure)
    --help, -h              Show this help message

ENVIRONMENT VARIABLES:
    SCP_NODE_DOMAIN             Domain for full node mode (required unless --relay-only)
    SCP_NODE_BIND_ADDR          HTTP bind address (default: 0.0.0.0:9000)
    SCP_NODE_TLS_SELF_SIGNED    Set to '1' for self-signed TLS (development only)
    SCP_NODE_PROJECTION_RATE_LIMIT  Per-IP rate limit for projection endpoints (default: 60)
    SCP_NODE_DHT_MODE           DHT client: 'production' (default) or 'memory'
    SCP_NODE_DHT_GATEWAYS       Comma-separated DHT HTTP gateway URLs
    SCP_STORAGE_PATH            SQLite database directory (same as --storage-path)
    SCP_STORAGE_KEY             Hex-encoded 32-byte SQLCipher encryption key
                                (auto-generated and stored if not set)
    SCP_RELAY_BIND_ADDR         Relay bind address (default: 0.0.0.0:9000)
    SCP_RELAY_MAX_BLOB_SIZE     Max blob size in bytes (default: 262144)
    SCP_RELAY_MAX_BLOB_TTL      Max blob TTL in seconds (default: 604800)
    SCP_RELAY_MAX_CONNECTIONS   Max total connections (default: 1000)
    SCP_RELAY_MAX_CONNECTIONS_PER_IP  Max connections per IP (default: 10)
    SCP_RELAY_RATE_LIMIT        Publish rate limit per second (default: 100)
    SCP_RELAY_LOG_LEVEL         Log level (default: info)
    SCP_RELAY_LOG_FORMAT        Log format: 'json' or 'pretty' (default: pretty)
    RUST_LOG                    Override log level (takes precedence over SCP_RELAY_LOG_LEVEL)"
    );
    std::process::exit(0);
}

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
// Storage path resolution
// ---------------------------------------------------------------------------

/// Resolves the storage directory path from CLI args, env var, or XDG default.
///
/// Priority: `--storage-path` > `SCP_STORAGE_PATH` > `$XDG_DATA_HOME/scp/node`
/// > `$HOME/.local/share/scp/node`.
fn resolve_storage_path(cli_path: Option<&PathBuf>) -> PathBuf {
    if let Some(path) = cli_path {
        return path.clone();
    }

    // XDG Base Directory Specification: $XDG_DATA_HOME or $HOME/.local/share
    #[allow(clippy::option_if_let_else)]
    let data_home = env::var("XDG_DATA_HOME").map_or_else(
        |_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
            PathBuf::from(home).join(".local").join("share")
        },
        PathBuf::from,
    );
    data_home.join("scp").join("node")
}

/// Resolves or generates the `SQLCipher` encryption key.
///
/// Reads from `SCP_STORAGE_KEY` env var (hex-encoded 32 bytes). If not set,
/// generates a random key and writes it to `{storage_dir}/.key` (mode 0600).
/// On subsequent runs, reads the key from the file.
///
/// All intermediate key buffers are wrapped in [`Zeroizing`] so they are
/// zeroed on drop, consistent with `key_custody.rs` and `tls.rs`.
fn resolve_storage_key(storage_dir: &std::path::Path) -> Result<Zeroizing<[u8; 32]>, String> {
    // Check env var first.
    if let Ok(hex_key) = env::var("SCP_STORAGE_KEY") {
        let bytes = Zeroizing::new(
            hex::decode(&hex_key)
                .map_err(|e| format!("SCP_STORAGE_KEY is not valid hex: {e}"))?,
        );
        if bytes.len() != 32 {
            return Err(format!(
                "SCP_STORAGE_KEY must be 32 bytes (64 hex chars), got {} bytes",
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

    // On Unix, create the key file with mode 0600 atomically to prevent a
    // TOCTOU window where the file is briefly world-readable.
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

    // On non-Unix, fall back to write + set_permissions (no TOCTOU guarantee).
    #[cfg(not(unix))]
    {
        std::fs::write(&key_file, &*key)
            .map_err(|e| format!("failed to write key file {}: {e}", key_file.display()))?;
    }

    Ok(key)
}

// ---------------------------------------------------------------------------
// Storage-backed SequenceStore
// ---------------------------------------------------------------------------

/// [`SequenceStore`] backed by a [`Storage`] implementation.
///
/// Persists BEP44 sequence numbers to the same storage backend as the rest of
/// the node state. Key format: `bep44/seq/{did}`.
struct StorageSequenceStore<S: Storage> {
    storage: Arc<S>,
}

impl<S: Storage> StorageSequenceStore<S> {
    const fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }
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
                Some(bytes) => {
                    tracing::warn!(
                        key = %key,
                        len = bytes.len(),
                        "BEP44 sequence data has unexpected length (expected 8), treating as absent"
                    );
                    Ok(None)
                }
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
// Tracing
// ---------------------------------------------------------------------------

/// Initializes the `tracing` subscriber.
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
// Full node mode — ephemeral
// ---------------------------------------------------------------------------

/// Runs the full node with all in-memory subsystems (no persistence).
async fn run_full_node_ephemeral() {
    let domain = require_domain();
    let http_addr = node_http_addr();

    tracing::info!(
        domain = %domain,
        bind_addr = %http_addr,
        mode = "ephemeral",
        "starting scp-node with in-memory storage"
    );

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

        let seq_init_method = Arc::clone(&did_method);
        let seq_init = make_seq_init(seq_init_method);
        run_node_with(
            domain,
            http_addr,
            custody,
            seq_init,
            did_method,
            InMemoryStorage::new(),
        )
        .await;
        return;
    }

    // Production DHT.
    let dht_client = build_pkarr_client();
    let sign_fn = DidDht::<PkarrDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_signer_and_store(
        dht_client,
        cache,
        sign_fn,
        sequence_store,
    ));

    let seq_init_method = Arc::clone(&did_method);
    let seq_init = make_seq_init(seq_init_method);
    run_node_with(
        domain,
        http_addr,
        custody,
        seq_init,
        did_method,
        InMemoryStorage::new(),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Full node mode — persistent (default)
// ---------------------------------------------------------------------------

/// Opens an encrypted `SQLite` database, exiting on failure.
fn open_sqlite_or_exit(dir: &std::path::Path, key: &Zeroizing<[u8; 32]>) -> SqliteStorage {
    match SqliteStorage::new(dir, key.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, path = %dir.display(), "failed to open SQLite storage");
            std::process::exit(1);
        }
    }
}

/// Initializes storage path, encryption key, and `SQLite` databases for the
/// persistent node. Returns `(storage_dir, storage_key, node_storage, custody)`.
async fn init_persistent_storage(
    storage_path: Option<&PathBuf>,
) -> (PathBuf, Zeroizing<[u8; 32]>, SqliteStorage, Arc<SqliteKeyCustody>) {
    let storage_dir = resolve_storage_path(storage_path);

    let storage_key = match resolve_storage_key(&storage_dir) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve storage encryption key");
            std::process::exit(1);
        }
    };

    let node_storage = open_sqlite_or_exit(&storage_dir, &storage_key);
    let custody_storage = open_sqlite_or_exit(&storage_dir.join("custody"), &storage_key);

    let custody = match SqliteKeyCustody::new(custody_storage).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize persistent key custody");
            std::process::exit(1);
        }
    };

    (storage_dir, storage_key, node_storage, custody)
}

/// Runs the full node with persistent `SQLite` storage (production default).
async fn run_full_node_persistent(storage_path: Option<&PathBuf>) {
    let domain = require_domain();
    let http_addr = node_http_addr();

    let (storage_dir, storage_key, node_storage, custody) =
        init_persistent_storage(storage_path).await;

    tracing::info!(
        domain = %domain,
        bind_addr = %http_addr,
        storage_path = %storage_dir.display(),
        mode = "persistent",
        "starting scp-node with SQLite storage (SQLCipher encrypted)"
    );

    let node_storage_arc = Arc::new(node_storage);
    let cache = Arc::new(DidCache::new());

    // Use storage-backed sequence store for BEP44 sequence persistence.
    let sequence_store: Arc<dyn SequenceStore> =
        Arc::new(StorageSequenceStore::new(Arc::clone(&node_storage_arc)));

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

        let seq_init_method = Arc::clone(&did_method);
        let seq_init = make_seq_init(seq_init_method);
        let storage = open_sqlite_or_exit(&storage_dir, &storage_key);
        run_node_with(domain, http_addr, custody, seq_init, did_method, storage).await;
        return;
    }

    // Production DHT.
    let dht_client = build_pkarr_client();
    let sign_fn = DidDht::<PkarrDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_signer_and_store(
        dht_client,
        cache,
        sign_fn,
        sequence_store,
    ));

    let seq_init_method = Arc::clone(&did_method);
    let seq_init = make_seq_init(seq_init_method);
    let builder_storage = open_sqlite_or_exit(&storage_dir, &storage_key);

    run_node_with(
        domain,
        http_addr,
        custody,
        seq_init,
        did_method,
        builder_storage,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Reads `SCP_NODE_DOMAIN` or exits with an error.
fn require_domain() -> String {
    match env::var("SCP_NODE_DOMAIN") {
        Ok(d) if !d.is_empty() => d,
        _ => {
            tracing::error!("SCP_NODE_DOMAIN is required in full node mode");
            std::process::exit(1);
        }
    }
}

/// Reads the HTTP bind address from env or returns the default.
fn node_http_addr() -> SocketAddr {
    env_or("SCP_NODE_BIND_ADDR", SocketAddr::from(([0, 0, 0, 0], 9000)))
}

/// Builds a [`PkarrDhtClient`] from env configuration.
fn build_pkarr_client() -> Arc<PkarrDhtClient> {
    let mut dht_builder = PkarrDhtClient::builder();

    if let Ok(gateways) = env::var("SCP_NODE_DHT_GATEWAYS") {
        for gateway in gateways.split(',') {
            let gateway = gateway.trim();
            if !gateway.is_empty() {
                tracing::info!(gateway = %gateway, "adding DHT HTTP gateway");
                dht_builder = dht_builder.gateway_url(gateway);
            }
        }
    }

    match dht_builder.build() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "failed to create PkarrDhtClient");
            std::process::exit(1);
        }
    }
}

/// Boxed callback for BEP44 sequence initialization.
type SeqInitFn = Box<
    dyn FnOnce(
            String,
        )
            -> Pin<Box<dyn std::future::Future<Output = Result<(), IdentityError>> + Send>>
        + Send,
>;

/// Creates a sequence initialization callback for `run_node_with`.
fn make_seq_init<D: scp_identity::DhtClient + 'static>(
    did_method: Arc<DidDht<D, SystemClock>>,
) -> SeqInitFn {
    Box::new(move |did| Box::pin(async move { did_method.initialize_sequence(&did).await }))
}

/// Shared implementation for `run_full_node`, parameterized over DID method
/// and storage type.
///
/// The `seq_init` callback is invoked with the node's DID string after
/// `build()` completes, before any publish operation. It calls
/// `DidDht::initialize_sequence` to recover the BEP44 sequence number from
/// the persistent store and/or DHT.
async fn run_node_with<
    K: scp_platform::KeyCustody + 'static,
    D: scp_identity::DidMethod + 'static,
    S: Storage + 'static,
>(
    domain: String,
    http_addr: SocketAddr,
    custody: Arc<K>,
    seq_init: SeqInitFn,
    did_method: Arc<D>,
    storage: S,
) {
    let use_self_signed = env::var("SCP_NODE_TLS_SELF_SIGNED")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    let projection_rate: u32 = env_or(
        "SCP_NODE_PROJECTION_RATE_LIMIT",
        scp_node::DEFAULT_PROJECTION_RATE_LIMIT,
    );

    let mut builder = ApplicationNodeBuilder::new()
        .storage(storage)
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

    // Initialize BEP44 sequence number from persistent store and/or DHT
    // BEFORE any publish operation.
    let did = node.identity().did().to_owned();
    if let Err(e) = seq_init(did).await {
        tracing::error!(error = %e, "failed to initialize BEP44 sequence — publishing may fail");
    }

    tracing::info!(
        did = %node.identity().did(),
        relay_url = %node.relay_url(),
        relay_internal_addr = %node.relay().bound_addr(),
        "application node identity ready"
    );

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
    let config = parse_args();

    if config.show_help {
        print_help();
    }

    // --health: probe the appropriate bind address and exit.
    if config.health {
        let addr: SocketAddr = if config.relay_only {
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

    if config.relay_only {
        run_relay_only().await;
    } else if config.ephemeral {
        run_full_node_ephemeral().await;
    } else {
        run_full_node_persistent(config.storage_path.as_ref()).await;
    }
}
