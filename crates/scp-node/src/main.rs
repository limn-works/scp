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
use scp_platform::EncryptedStorage;
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_platform::traits::Storage;
use scp_transport::native::server::RelayServer;
use scp_transport::startup;

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
    /// Run in self-host mode: host the static site entirely on SCP.
    self_host: bool,
    /// Directory of static site files to host (self-host mode). `None` = use
    /// the embedded default site.
    site_dir: Option<PathBuf>,
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

    let self_host = args.iter().any(|a| a == "--self-host")
        || env::var("SCP_NODE_SELF_HOST").is_ok_and(|v| v == "1" || v == "true");

    let storage_path = args
        .iter()
        .position(|a| a == "--storage-path")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .or_else(|| env::var("SCP_STORAGE_PATH").ok().map(PathBuf::from));

    let site_dir = args
        .iter()
        .position(|a| a == "--site-dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .or_else(|| env::var("SCP_NODE_SITE_DIR").ok().map(PathBuf::from));

    CliConfig {
        relay_only,
        health,
        ephemeral,
        storage_path,
        self_host,
        site_dir,
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
    --self-host             Host a static site entirely on SCP (no_domain mode).
                            Opens an inbound port to the PUBLIC INTERNET and
                            publishes the host's IP to the DHT. Plaintext HTTP.
                            See the loud startup banner for the full warning.
    --site-dir <PATH>       Directory of static files to host in --self-host mode
                            (must contain index.html). Default: embedded site.
                            Also configurable via SCP_NODE_SITE_DIR env var
    --storage-path <PATH>   SQLite database directory (default: $XDG_DATA_HOME/scp/node)
                            Also configurable via SCP_STORAGE_PATH env var
    --health                TCP health probe (exit 0 on success, 1 on failure)
    --help, -h              Show this help message

ENVIRONMENT VARIABLES:
    SCP_NODE_DOMAIN             Domain for full node mode (required unless --relay-only
                               or --self-host)
    SCP_NODE_SELF_HOST         Set to '1' to enable self-host mode (same as --self-host)
    SCP_NODE_SITE_DIR          Static site directory for self-host mode (same as --site-dir)
    SCP_NODE_SELF_HOST_PORT    HTTP/site port for self-host mode (default: 8443)
    SCP_NODE_BIND_ADDR          HTTP bind address (default: 0.0.0.0:9000)
    SCP_NODE_TLS_SELF_SIGNED    Set to '1' for self-signed TLS (development only)
    SCP_NODE_PROJECTION_RATE_LIMIT  Per-IP rate limit for projection endpoints (default: 60)
    SCP_NODE_DHT_MODE           DHT client: 'production' (default) or 'memory'
    SCP_NODE_DHT_GATEWAYS       Comma-separated DHT HTTP gateway URLs
    SCP_STORAGE_PATH            SQLite database directory (same as --storage-path)
    SCP_STORAGE_KEY             Hex-encoded 32-byte SQLCipher encryption key
                                (auto-generated and stored if not set)
    SCP_RELAY_BIND_ADDR         Relay bind address (default: 0.0.0.0:9000)
    SCP_RELAY_STORAGE_BACKEND   Blob storage backend for relay: sqlite (default), redb,
                                postgres, s3, memory
    SCP_RELAY_STORAGE_PATH      Path for sqlite/redb blob storage (default: ./scp-relay.db)
    SCP_RELAY_DATABASE_URL      PostgreSQL connection URL (required when backend=postgres)
    SCP_RELAY_S3_BUCKET         S3 bucket name (required when backend=s3)
    SCP_RELAY_S3_PREFIX         S3 key prefix (default: blobs/)
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

// `env_or` is provided by `scp_transport::startup::env_or`.

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
            let home = env::var("HOME").unwrap_or_else(|_| {
                eprintln!(
                    "error: HOME environment variable is not set and no \
                     --storage-path or XDG_DATA_HOME was provided.\n\
                     Set HOME, XDG_DATA_HOME, or pass --storage-path explicitly."
                );
                std::process::exit(1);
            });
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
            hex::decode(&hex_key).map_err(|e| format!("SCP_STORAGE_KEY is not valid hex: {e}"))?,
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

// `init_tracing` is provided by `scp_transport::startup::init_tracing`.

// ---------------------------------------------------------------------------
// Relay config from env
// ---------------------------------------------------------------------------

// `relay_config_from_env` is provided by `scp_transport::startup::relay_config_from_env`.

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
// Health check + shutdown signal
// ---------------------------------------------------------------------------

// `health_check` and `shutdown_signal` are provided by
// `scp_transport::startup`.

// ---------------------------------------------------------------------------
// Relay blob storage from env
// ---------------------------------------------------------------------------

// `storage_from_env` is provided by `scp_transport::startup::storage_from_env`.

// ---------------------------------------------------------------------------
// Relay-only mode
// ---------------------------------------------------------------------------

/// Runs a bare relay server (same as `scp-relay` binary).
async fn run_relay_only() {
    let config = startup::relay_config_from_env();
    tracing::info!(
        bind_addr = %config.bind_addr,
        max_blob_size = config.max_blob_size,
        max_connections = config.max_total_connections,
        "starting scp-node in relay-only mode"
    );

    let storage = Arc::new(startup::storage_from_env().await);
    let server = RelayServer::new(config, storage);

    let (handle, local_addr) = match server.start().await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, "relay failed to start");
            std::process::exit(1);
        }
    };

    tracing::info!(addr = %local_addr, "relay listening");

    startup::shutdown_signal().await;

    tracing::info!("shutdown signal received, stopping relay");
    handle.shutdown();
    tracing::info!("relay stopped");
}

// ---------------------------------------------------------------------------
// Full node mode — ephemeral
// ---------------------------------------------------------------------------

/// Runs the full node with all in-memory subsystems (no persistence).
///
/// In ephemeral mode, ALL subsystems use in-memory implementations regardless
/// of environment variable overrides. No mixed mode is permitted — if you want
/// persistent storage or production DHT, omit the `--ephemeral` flag.
async fn run_full_node_ephemeral() {
    let domain = require_domain();
    let http_addr = node_http_addr();

    tracing::info!(
        domain = %domain,
        bind_addr = %http_addr,
        mode = "ephemeral",
        "starting scp-node with all in-memory subsystems (nothing persists across restarts)"
    );

    eprintln!(
        "WARNING: Ephemeral mode — ALL subsystems use in-memory implementations.\n\
         Private keys, storage, and DID documents will be LOST on restart.\n\
         Use persistent mode (default, without --ephemeral) for production."
    );
    tracing::warn!(
        "using InMemoryKeyCustody — private keys exist only in memory and are \
         not persisted. This mode is for development/testing only."
    );
    tracing::warn!("using InMemoryDhtClient — DID documents will NOT be published to the network");

    let custody = Arc::new(InMemoryKeyCustody::new());
    let cache = Arc::new(DidCache::new());
    let sequence_store = Arc::new(InMemorySequenceStore::new());

    // Ephemeral mode: always use in-memory DHT. Ignore SCP_NODE_DHT_MODE to
    // prevent mixed mode (in-memory storage + production DHT is inconsistent).
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
    // Wrap InMemoryStorage in EncryptingAdapter to satisfy the
    // EncryptedStorage bound. Ephemeral mode data is lost on restart
    // anyway, so a random key is fine.
    let mut ephemeral_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ephemeral_key);
    let encrypted_storage = scp_platform::encrypting_adapter::EncryptingAdapter::new(
        InMemoryStorage::new(),
        Zeroizing::new(ephemeral_key),
    );
    run_node_with(
        domain,
        http_addr,
        custody,
        seq_init,
        did_method,
        encrypted_storage,
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
) -> (
    PathBuf,
    Zeroizing<[u8; 32]>,
    SqliteStorage,
    Arc<SqliteKeyCustody>,
) {
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

/// Validates that the storage directory can be created and is writable.
/// Produces a clear error message and exits on failure.
fn validate_storage_path(dir: &std::path::Path) {
    // Attempt to create the directory tree. If it already exists, this is a no-op.
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::error!(
            error = %e,
            path = %dir.display(),
            "storage path is not usable: failed to create directory"
        );
        eprintln!(
            "ERROR: Cannot create storage directory '{}': {e}\n\
             Ensure the parent directory exists and is writable, \
             or specify a different path with --storage-path.",
            dir.display()
        );
        std::process::exit(1);
    }

    // Verify the directory is writable by creating and removing a probe file.
    let probe = dir.join(".scp-write-probe");
    match std::fs::write(&probe, b"probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                path = %dir.display(),
                "storage path is not writable"
            );
            eprintln!(
                "ERROR: Storage directory '{}' is not writable: {e}\n\
                 Ensure the directory has write permissions, \
                 or specify a different path with --storage-path.",
                dir.display()
            );
            std::process::exit(1);
        }
    }
}

/// Runs the full node with persistent `SQLite` storage (production default).
async fn run_full_node_persistent(storage_path: Option<&PathBuf>) {
    let domain = require_domain();
    let http_addr = node_http_addr();

    // Validate the storage path upfront before attempting to open databases.
    let resolved_path = resolve_storage_path(storage_path);
    validate_storage_path(&resolved_path);

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
// Self-host mode (--self-host)
// ---------------------------------------------------------------------------

/// Derives a deterministic, hex-encoded broadcast context id for the
/// self-hosted site from the node's DID.
///
/// `register_broadcast_context` requires the context id to be 1-64 lowercase
/// hex characters, so we hash the DID with SHA-256 and hex-encode it (64 hex
/// chars). The id is stable across restarts for a given identity, so the
/// site's routing id (and thus its URL) is stable.
fn self_host_context_id(node_did: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(node_did.as_bytes());
    hex::encode(digest)
}

/// Default interval, in seconds, between self-host site re-deploys.
///
/// Site assets are published with a fixed 3600s blob TTL (`DEFAULT_BLOB_TTL`
/// in the transport envelope builder), after which the relay's blob store
/// treats them as expired and the projection 404s. Re-deploying on an interval
/// well under that TTL keeps the site continuously reachable. 1800s (half the
/// TTL) leaves ample margin for a slow or transiently-failing refresh to retry
/// before the previous deploy's blobs expire. Configurable via
/// `SCP_NODE_SELF_HOST_REFRESH_SECS`.
const SELF_HOST_DEPLOY_REFRESH_SECS: u64 = 1800;

/// RFC-1123 hostname placeholder for the self-host site projection.
///
/// Reachability is via the routing-id path (`/scp/broadcast/<rid>/site/...`),
/// which ignores the `Host` header, so this value is a non-empty, valid
/// placeholder only. It must not collide with the node's own domain — in
/// no-domain mode there is none, so any valid hostname is safe.
const SELF_HOST_HOSTNAME: &str = "selfhost.scp.local";

/// An optionally-present NAT port mapper handle, retained for clean teardown.
///
/// `Some` only when the binary is built with the `upnp` feature; `None`
/// otherwise (no router mapping is attempted, so there is nothing to release).
type OptionalPortMapper = Option<Arc<dyn scp_transport::nat::PortMapper>>;

/// Loads the site assets to publish.
///
/// When `site_dir` is `Some`, every file under it is read recursively and
/// mapped to a site-absolute path (`<rel>` -> `/<rel>`), with content type
/// inferred from the extension. An `index.html` at the directory root is
/// required. User-supplied files are served verbatim (no DID injection).
///
/// When `site_dir` is `None`, the embedded default site is used and the node
/// DID is injected into `index.html` as a `<meta name="scp-did">` tag.
fn load_self_host_assets(
    site_dir: Option<&PathBuf>,
    node_did: &str,
) -> Result<Vec<scp_node::Asset>, String> {
    match site_dir {
        None => Ok(scp_node::embedded_assets(Some(node_did))),
        Some(dir) => {
            let mut assets = Vec::new();
            read_site_dir_recursive(dir, dir, &mut assets)?;
            if assets.is_empty() {
                return Err(format!(
                    "site directory '{}' contains no files",
                    dir.display()
                ));
            }
            if !assets.iter().any(|a| a.path == "/index.html") {
                return Err(format!(
                    "site directory '{}' must contain an index.html at its root",
                    dir.display()
                ));
            }
            // Deterministic publish order for stable deploys.
            assets.sort_by(|a, b| a.path.cmp(&b.path));
            Ok(assets)
        }
    }
}

/// Recursively reads every file under `dir`, mapping each to an [`Asset`]
/// whose path is site-absolute relative to `root`.
///
/// [`Asset`]: scp_node::Asset
fn read_site_dir_recursive(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<scp_node::Asset>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory '{}': {e}", dir.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("failed to read entry in '{}': {e}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("failed to stat '{}': {e}", path.display()))?;
        if file_type.is_dir() {
            read_site_dir_recursive(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("path '{}' is not under site root: {e}", path.display()))?;
            // Build a forward-slash, site-absolute path.
            let rel_str = rel
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 path: '{}'", rel.display()))?;
            let site_path = format!("/{}", rel_str.replace('\\', "/"));
            let body = std::fs::read(&path)
                .map_err(|e| format!("failed to read file '{}': {e}", path.display()))?;
            let content_type = scp_node::content_type_for(&site_path).to_owned();
            out.push(scp_node::Asset {
                path: site_path,
                content_type,
                body,
            });
        }
        // Symlinks and other special files are skipped intentionally.
    }
    Ok(())
}

/// Builds the loud self-host startup banner shown on stderr before any socket
/// is opened.
///
/// States, in plain language, the three consequences the operator is opting
/// into (public-port exposure, public-IP<->DID DHT disclosure, plaintext
/// transport) plus the Finding-D NAT self-test note so a Tier-2 line in the
/// logs is not mistaken for a hosting failure.
fn self_host_banner(port: u16) -> String {
    format!(
        "================================ SELF-HOST MODE ================================\n\
         scp-node is about to open inbound TCP port {port} to the PUBLIC INTERNET via\n\
         NAT-PMP/UPnP (when built with --features upnp). Consequences you are opting into:\n\
           * Your host's PUBLIC IP will be published to the global Mainline DHT, bound to\n\
             this node's DID. This is an IP<->identity disclosure (approximate-location dox).\n\
           * Transport is PLAINTEXT HTTP (no TLS): traffic is readable and tamper-able in\n\
             transit. The hosted content is public broadcast content anyway.\n\
           * A residential uplink cannot absorb a volumetric/distributed DDoS; per-IP rate\n\
             limiting protects CPU/keys but not raw bandwidth.\n\
         NAT self-test note (Finding D): if the NAT-PMP reachability self-test reports Tier 2\n\
         (STUN) instead of Tier 1, this is EXPECTED and does NOT mean failure -- the inbound\n\
         TCP port mapping is created BEFORE the UDP self-test and is not released, so the\n\
         site remains reachable over the mapped TCP port regardless of the reported tier.\n\
         This mode is opt-in (--self-host) and never a default.\n\
         ==============================================================================="
    )
}

/// Runs the node in self-host mode: an [`ApplicationNode`] in `no_domain`
/// mode hosting a static site published through an in-process supervisor on
/// the node's own loopback relay (`§10.12` / `§18`,
/// `.docs/guides/self-hosting-a-website-on-scp.md`).
///
/// Opens an inbound TCP port to the public internet (via NAT-PMP/UPnP when the
/// `upnp` feature is built) and publishes the host's address to the Mainline
/// DHT. Transport is plaintext HTTP. See the startup banner.
///
/// [`ApplicationNode`]: scp_node::ApplicationNode
async fn run_self_host(storage_path: Option<&PathBuf>, site_dir: Option<&PathBuf>) {
    let port: u16 = startup::env_or("SCP_NODE_SELF_HOST_PORT", 8443u16);
    let http_addr = SocketAddr::from(([0, 0, 0, 0], port));

    // -- Loud startup banner BEFORE opening any socket --
    eprintln!("{}", self_host_banner(port));
    tracing::warn!(
        port,
        "self-host mode enabled — opening inbound port to the public internet"
    );

    // -- Storage + custody (same as the persistent node) --
    let resolved_path = resolve_storage_path(storage_path);
    validate_storage_path(&resolved_path);
    let (storage_dir, storage_key, node_storage, custody) =
        init_persistent_storage(storage_path).await;

    tracing::info!(
        bind_addr = %http_addr,
        storage_path = %storage_dir.display(),
        mode = "self-host",
        "starting scp-node in self-host mode (SQLite storage, no_domain)"
    );

    // -- DID method: production pkarr by default; memory for offline testing --
    let node_storage_arc = Arc::new(node_storage);
    let cache = Arc::new(DidCache::new());
    let sequence_store: Arc<dyn SequenceStore> =
        Arc::new(StorageSequenceStore::new(Arc::clone(&node_storage_arc)));

    let dht_mode = env::var("SCP_NODE_DHT_MODE").unwrap_or_else(|_| "production".into());

    if dht_mode == "memory" {
        tracing::warn!(
            "using InMemoryDhtClient — DID document will NOT be published to the network"
        );
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let sign_fn = DidDht::<InMemoryDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
        let did_method = Arc::new(DidDht::with_client_signer_and_store(
            dht_client,
            cache,
            sign_fn,
            sequence_store,
        ));
        let seq_init = make_seq_init(Arc::clone(&did_method));
        run_self_host_with(
            http_addr,
            port,
            &storage_dir,
            &storage_key,
            custody,
            seq_init,
            did_method,
            site_dir,
        )
        .await;
        return;
    }

    let dht_client = build_pkarr_client();
    let sign_fn = DidDht::<PkarrDhtClient, SystemClock>::make_sign_fn(Arc::clone(&custody));
    let did_method = Arc::new(DidDht::with_client_signer_and_store(
        dht_client,
        cache,
        sign_fn,
        sequence_store,
    ));
    let seq_init = make_seq_init(Arc::clone(&did_method));
    run_self_host_with(
        http_addr,
        port,
        &storage_dir,
        &storage_key,
        custody,
        seq_init,
        did_method,
        site_dir,
    )
    .await;
}

/// Builds the no-domain self-host [`ApplicationNode`] over persistent,
/// disk-backed storage, returning it behind an `Arc` alongside the retained NAT
/// port-mapper handles (`UPnP` + NAT-PMP) for clean teardown.
///
/// The blob storage is a `SQLite` backend under the node's storage dir: it IS the
/// site's system of record (`commit_deploy` scans it; the projection/site
/// handler reads from it), so it must persist across restarts and is the SAME
/// `Arc` the relay and projection share. The in-memory default backend is
/// dev-only and is lost on restart, so it is unsuitable here.
///
/// The mapper handles are only ever `Some` when built with the `upnp` feature;
/// otherwise they are `None` (Tier 2 STUN discovery only, no router mapping).
/// Exits the process on storage or build failure — there is nothing to serve
/// without a node. `build()` establishes the inbound port mapping during its
/// NAT tier selection and can still fail afterward (e.g. DID publish), so on
/// build failure the mappings are released best-effort before exiting.
///
/// [`ApplicationNode`]: scp_node::ApplicationNode
async fn build_self_host_node<D: scp_identity::DidMethod + 'static>(
    http_addr: SocketAddr,
    storage_dir: &std::path::Path,
    storage_key: &Zeroizing<[u8; 32]>,
    custody: Arc<SqliteKeyCustody>,
    did_method: Arc<D>,
) -> (
    Arc<scp_node::ApplicationNode<SqliteStorage>>,
    OptionalPortMapper,
    OptionalPortMapper,
) {
    let projection_rate: u32 = startup::env_or(
        "SCP_NODE_PROJECTION_RATE_LIMIT",
        scp_node::DEFAULT_PROJECTION_RATE_LIMIT,
    );
    let builder_storage = open_sqlite_or_exit(storage_dir, storage_key);

    let blob_db = storage_dir.join("blobs");
    let blob_storage = match scp_transport::native::storage::BlobStorageBackend::sqlite(&blob_db) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                error = %e,
                path = %blob_db.display(),
                "failed to open persistent SQLite blob storage for self-host"
            );
            std::process::exit(1);
        }
    };

    // -- NAT strategy with RETAINED mapper handles for clean teardown --
    #[cfg(feature = "upnp")]
    let (nat_strategy, upnp_mapper, natpmp_mapper): (
        Option<Arc<dyn scp_node::NatStrategy>>,
        OptionalPortMapper,
        OptionalPortMapper,
    ) = {
        let upnp: Arc<dyn scp_transport::nat::PortMapper> =
            Arc::new(scp_transport::nat::UpnpPortMapper::new());
        let natpmp: Arc<dyn scp_transport::nat::PortMapper> =
            Arc::new(scp_transport::nat::NatPmpPortMapper::new());
        let strategy = scp_node::DefaultNatStrategy::new(None, None)
            .with_port_mapper(Arc::clone(&upnp))
            .with_fallback_mapper(Arc::clone(&natpmp));
        (
            Some(Arc::new(strategy) as Arc<dyn scp_node::NatStrategy>),
            Some(upnp),
            Some(natpmp),
        )
    };
    #[cfg(not(feature = "upnp"))]
    let (upnp_mapper, natpmp_mapper): (OptionalPortMapper, OptionalPortMapper) = (None, None);

    let builder = ApplicationNodeBuilder::new()
        .storage(builder_storage)
        .blob_storage(blob_storage)
        .generate_identity_with(custody, did_method)
        .no_domain()
        .http_bind_addr(http_addr)
        .projection_rate_limit(projection_rate);
    #[cfg(feature = "upnp")]
    let builder = match nat_strategy {
        Some(strategy) => builder.nat_strategy(strategy),
        None => builder,
    };

    match builder.build().await {
        Ok(n) => (Arc::new(n), upnp_mapper, natpmp_mapper),
        Err(e) => {
            tracing::error!(error = %e, "self-host application node failed to build");
            // `build()` establishes the inbound port mapping during its NAT
            // tier selection and CAN still fail afterward (e.g. DID publish),
            // so release the mappings best-effort before exiting to avoid
            // leaving the public port mapped at the router.
            release_self_host_mappings(upnp_mapper, natpmp_mapper, http_addr.port()).await;
            std::process::exit(1);
        }
    }
}

/// Builds the no-domain node, deploys the site via [`scp_node::deploy_site`],
/// prints the live URL, and serves until shutdown (releasing the NAT mapping
/// on the way out). Parameterized over the DID method so both the production
/// and memory DHT paths share this body.
///
/// The site is deployed once before the public listener opens, then refreshed
/// on a fixed interval (well under the blob TTL) so the projected content never
/// expires while the node runs (see [`spawn_site_refresh_loop`]). The public
/// listener exposes only the restricted self-host surface (read-only website
/// projection; no relay upgrade, no bridge routes — §10.12.8). The retained NAT
/// port mappings are released on EVERY exit path, graceful or error, via
/// [`release_self_host_mappings`].
#[allow(clippy::too_many_arguments)] // mirrors run_node_with; composing concrete deps in one call
async fn run_self_host_with<D: scp_identity::DidMethod + 'static>(
    http_addr: SocketAddr,
    port: u16,
    storage_dir: &std::path::Path,
    storage_key: &Zeroizing<[u8; 32]>,
    custody: Arc<SqliteKeyCustody>,
    seq_init: SeqInitFn,
    did_method: Arc<D>,
    site_dir: Option<&PathBuf>,
) {
    // -- Build the no-domain node with persistent blob storage + retained NAT
    //    mapper handles for clean teardown on every exit path. --
    let (node, upnp_mapper, natpmp_mapper) = build_self_host_node(
        http_addr,
        storage_dir,
        storage_key,
        custody.clone(),
        did_method,
    )
    .await;

    let node_did = node.identity().did().to_owned();
    if let Err(e) = seq_init(node_did.clone()).await {
        tracing::error!(error = %e, "failed to initialize BEP44 sequence — publishing may fail");
    }

    let context_id = self_host_context_id(&node_did);

    // -- Load the site assets once. The same asset set is (re)published on every
    //    deploy; the embedded default injects the node DID into index.html. --
    let assets = match load_self_host_assets(site_dir, &node_did) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            tracing::error!(error = %e, "failed to load self-host site assets");
            release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;
            std::process::exit(1);
        }
    };
    let asset_count = assets.len();

    // -- Build the deployer ONCE: one supervisor, one broadcast group, one
    //    broadcast key. Reused for the initial deploy and every refresh so all
    //    blobs are sealed under the same epoch key (see `SelfHostDeployer`). --
    let deployer = match build_self_host_deployer(
        node.as_ref(),
        storage_dir,
        storage_key,
        &node_did,
        &context_id,
    )
    .await
    {
        Ok(d) => Arc::new(d),
        Err(e) => {
            tracing::error!(error = %e, "failed to set up self-host deployer");
            release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;
            std::process::exit(1);
        }
    };

    // -- Initial deploy, BEFORE the public port opens, so the site is live the
    //    moment the listener accepts connections. --
    if let Err(e) = deployer
        .deploy(node.as_ref(), &mint_deploy_id(), custody.as_ref(), &assets)
        .await
    {
        tracing::error!(error = %e, "failed to deploy self-host site");
        release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;
        std::process::exit(1);
    }
    tracing::info!(committed = asset_count, "self-host site deployed");

    print_self_host_live_url(&context_id, port, &node_did, asset_count);

    // -- Open the RESTRICTED public surface in the background --
    // Only the read-only website projection (+ `.well-known/scp` + virtual-host
    // fallback) is exposed on the public bind. The relay upgrade (`/scp/v1`)
    // and bridge routes (`/v1/scp/bridge/*`) are NOT mounted publicly — the
    // in-process supervisor reaches the node's relay over loopback `127.0.0.1`
    // instead (§10.12.8).
    if let Err(e) = node
        .serve_background_with_surface(Some(http_addr), scp_node::PublicSurface::SelfHost)
        .await
    {
        tracing::error!(error = %e, "self-host public listener failed to start");
        release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;
        std::process::exit(1);
    }

    // -- Keep the site alive past the blob TTL via a periodic re-deploy --
    let refresh = spawn_site_refresh_loop(
        Arc::clone(&deployer),
        Arc::clone(&node),
        Arc::clone(&custody),
        Arc::clone(&assets),
        node.shutdown_token(),
    );

    // -- Serve until the process receives a shutdown signal --
    startup::shutdown_signal().await;
    tracing::warn!("shutdown signal received — stopping self-host site refresh and listener");

    // Stop the refresh loop and the background listener, then release the NAT
    // mappings. `shutdown()` cancels the node's token, which both the refresh
    // loop and the background HTTP server observe.
    node.shutdown();
    refresh.abort();
    release_self_host_mappings(upnp_mapper, natpmp_mapper, port).await;

    tracing::info!("scp-node (self-host) stopped");
}

/// Builds the supervisor's MLS storage and performs the one-time
/// [`SelfHostDeployer`] setup (loopback supervisor, broadcast group, projection
/// enable).
///
/// The MLS storage is a single `SQLite` database under `storage_dir/mls` for the
/// deployer's whole lifetime — the broadcast group is created once and reused
/// across every deploy, so there is no per-deploy MLS state to isolate or prune.
///
/// [`SelfHostDeployer`]: scp_node::SelfHostDeployer
async fn build_self_host_deployer<S>(
    node: &scp_node::ApplicationNode<S>,
    storage_dir: &std::path::Path,
    storage_key: &Zeroizing<[u8; 32]>,
    node_did: &str,
    context_id: &str,
) -> Result<scp_node::SelfHostDeployer, String>
where
    S: scp_platform::EncryptedStorage + 'static,
{
    let mls_inner = Arc::new(
        scp_platform::sqlite::SqliteStorage::new(&storage_dir.join("mls"), storage_key.as_ref())
            .map_err(|e| format!("failed to open MLS SQLite storage: {e}"))?,
    );
    let mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(mls_inner),
        );

    let signing_key_handle = node.identity().identity().active_signing_key;
    scp_node::SelfHostDeployer::start(
        node,
        node_did.to_owned(),
        context_id.to_owned(),
        SELF_HOST_HOSTNAME.to_owned(),
        signing_key_handle,
        mls_storage,
    )
    .await
    .map_err(|e| format!("deployer setup failed: {e}"))
}

/// Mints a unique deploy id for a single self-host deploy run.
///
/// With persistent blob storage and content within its TTL, `commit_deploy`
/// scans EVERY blob for the site routing id and counts those whose decrypted
/// `deploy_id` matches the requested one. A constant deploy id would therefore
/// count stale blobs from a previous run (e.g. a since-removed `/old.html`)
/// still inside their TTL, producing a `CommitCountMismatch`. Minting a fresh
/// id per run guarantees `commit_deploy` only ever sees the current run's
/// blobs.
///
/// The id combines a process-start-relative nanosecond timestamp with OS
/// randomness so it is unique across runs even on coarse-grained clocks and
/// stable for the lifetime of a single deploy.
fn mint_deploy_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    let mut rand_bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rand_bytes);
    format!("selfhost-{nanos:032x}-{}", hex::encode(rand_bytes))
}

/// Spawns the periodic site refresh loop.
///
/// Site assets are published with a fixed blob TTL (`DEFAULT_BLOB_TTL` =
/// 3600s); after that the relay's blob store treats them as expired and the
/// projection 404s. The broadcast publish path exposes no per-publish TTL
/// override (the TTL is fixed deep in the transport envelope builder, shared by
/// every publish path), so the correct, self-contained fix is to re-publish the
/// site on an interval well under the TTL. Each refresh reuses the deployer's
/// supervisor/group/key, mints a fresh `deploy_id`, and re-points the deploy
/// manifest at fresh, full-TTL blobs.
///
/// The interval is configurable via `SCP_NODE_SELF_HOST_REFRESH_SECS` and
/// defaults to [`SELF_HOST_DEPLOY_REFRESH_SECS`]. The loop runs until the
/// node's shutdown token is cancelled. Returns the task handle so the caller
/// can abort it on shutdown.
fn spawn_site_refresh_loop(
    deployer: Arc<scp_node::SelfHostDeployer>,
    node: Arc<scp_node::ApplicationNode<scp_platform::sqlite::SqliteStorage>>,
    custody: Arc<SqliteKeyCustody>,
    assets: Arc<Vec<scp_node::Asset>>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let refresh_secs: u64 = startup::env_or(
        "SCP_NODE_SELF_HOST_REFRESH_SECS",
        SELF_HOST_DEPLOY_REFRESH_SECS,
    )
    .max(1);
    let period = std::time::Duration::from_secs(refresh_secs);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        // Skip the immediate first tick; the caller already performed the
        // initial deploy before opening the public port.
        interval.tick().await;
        loop {
            tokio::select! {
                () = shutdown_token.cancelled() => {
                    tracing::debug!("self-host refresh loop observed shutdown");
                    break;
                }
                _ = interval.tick() => {
                    match deployer
                        .deploy(node.as_ref(), &mint_deploy_id(), custody.as_ref(), &assets)
                        .await
                    {
                        Ok(committed) => tracing::info!(
                            committed,
                            "self-host site refreshed (TTL renewal)"
                        ),
                        Err(e) => tracing::error!(
                            error = %e,
                            "self-host site refresh failed; will retry next interval"
                        ),
                    }
                }
            }
        }
    })
}

/// Best-effort release of the retained NAT port mappings on BOTH mappers.
///
/// Called on every exit path that occurs after the node (and thus its port
/// mapping) is built — graceful shutdown and every error exit alike — so the
/// public port is never left mapped at the router. The mapper handles are only
/// ever `Some` when built with the `upnp` feature; otherwise this is a no-op.
async fn release_self_host_mappings(
    upnp: OptionalPortMapper,
    natpmp: OptionalPortMapper,
    port: u16,
) {
    for (label, mapper) in [("upnp", upnp), ("natpmp", natpmp)] {
        if let Some(mapper) = mapper {
            match mapper.remove(port).await {
                Ok(()) => tracing::info!(mapper = label, port, "released NAT port mapping"),
                Err(e) => tracing::warn!(
                    mapper = label,
                    port,
                    error = %e,
                    "failed to release NAT port mapping; it will persist until lease expiry"
                ),
            }
        }
    }
}

/// Logs and prints the live site URL after a successful deploy.
///
/// The URL uses the `0.0.0.0` bind placeholder; the operator substitutes their
/// public IP (or an SCP-aware client resolves it via `did:dht`). The node DID
/// is included so the operator can verify the IP<->identity binding.
fn print_self_host_live_url(context_id: &str, port: u16, node_did: &str, asset_count: usize) {
    let routing_hex = scp_node::routing_id_hex(context_id);
    let url = format!("http://0.0.0.0:{port}/scp/broadcast/{routing_hex}/site/index.html");
    tracing::info!(
        did = %node_did,
        assets = asset_count,
        url = %url,
        "self-host site live"
    );
    eprintln!(
        "\nSelf-host site is LIVE:\n  \
         {url}\n  \
         (substitute your public IP for 0.0.0.0; SCP-aware clients can resolve it via did:dht.\n  \
         The node DID is: {node_did})\n"
    );
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
    startup::env_or("SCP_NODE_BIND_ADDR", SocketAddr::from(([0, 0, 0, 0], 9000)))
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
    S: EncryptedStorage + 'static,
>(
    domain: String,
    http_addr: SocketAddr,
    custody: Arc<K>,
    seq_init: SeqInitFn,
    did_method: Arc<D>,
    storage: S,
) {
    let use_self_signed =
        env::var("SCP_NODE_TLS_SELF_SIGNED").is_ok_and(|v| v == "1" || v == "true");

    let use_dns_provider = env::var("SCP_NODE_DNS_PROVIDER").is_ok_and(|v| v == "1" || v == "true");

    let projection_rate: u32 = startup::env_or(
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

    if use_dns_provider {
        // DNS subdomain provider: derive domain from DID, register with DNS
        // API for zero-config TLS (#642). The domain set above is overridden
        // during build() after identity resolution.
        let public_ip: std::net::IpAddr = env::var("SCP_NODE_PUBLIC_IP")
            .unwrap_or_else(|_| {
                tracing::error!("SCP_NODE_PUBLIC_IP is required when SCP_NODE_DNS_PROVIDER=1");
                std::process::exit(1);
            })
            .parse()
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "invalid SCP_NODE_PUBLIC_IP");
                std::process::exit(1);
            });

        let port = http_addr.port();

        let mut dns_config = scp_node::dns_provider::DnsProviderConfig::new(public_ip, port);
        if let Ok(base) = env::var("SCP_NODE_DNS_BASE_DOMAIN") {
            dns_config = dns_config.with_base_domain(&base);
        }
        if let Ok(url) = env::var("SCP_NODE_DNS_API_URL") {
            dns_config = dns_config.with_api_url(&url);
        }

        tracing::info!(
            public_ip = %public_ip,
            port = port,
            "using DNS subdomain provider for zero-config TLS"
        );
        builder = builder.dns_provider(dns_config);
    } else if use_self_signed {
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

    // Install Prometheus metrics recorder and add /metrics endpoint (#1467).
    let metrics_router = install_metrics_recorder();

    if let Err(e) = node.serve(metrics_router, startup::shutdown_signal()).await {
        tracing::error!(error = %e, "application node exited with error");
        std::process::exit(1);
    }

    tracing::info!("scp-node stopped");
}

// ---------------------------------------------------------------------------
// Prometheus metrics (#1467)
// ---------------------------------------------------------------------------

/// Installs the Prometheus metrics recorder and returns an axum router with
/// a `/metrics` endpoint that serves the metrics in Prometheus text format.
///
/// The recorder is installed globally via [`metrics_exporter_prometheus::PrometheusBuilder`].
/// If installation fails (e.g., a recorder is already installed), the endpoint
/// returns an empty body with a 503 status.
fn install_metrics_recorder() -> axum::Router {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    // Best-effort: if a recorder is already installed, the metrics
    // endpoint will return empty data.
    let _ = metrics::set_global_recorder(recorder);

    axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let h = handle.clone();
            async move {
                let body = h.render();
                (
                    axum::http::StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4",
                    )],
                    body,
                )
            }
        }),
    )
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
            startup::env_or(
                "SCP_RELAY_BIND_ADDR",
                SocketAddr::from(([127, 0, 0, 1], 9000)),
            )
        } else if config.self_host {
            // Self-host binds the site listener on SCP_NODE_SELF_HOST_PORT
            // (default 8443), NOT SCP_NODE_BIND_ADDR. Probe that port on
            // loopback so `--health` matches the port `--self-host` opens.
            let port: u16 = startup::env_or("SCP_NODE_SELF_HOST_PORT", 8443u16);
            SocketAddr::from(([127, 0, 0, 1], port))
        } else {
            startup::env_or(
                "SCP_NODE_BIND_ADDR",
                SocketAddr::from(([127, 0, 0, 1], 9000)),
            )
        };
        startup::health_check(addr).await;
        return;
    }

    startup::init_tracing();

    if config.relay_only {
        run_relay_only().await;
    } else if config.self_host {
        run_self_host(config.storage_path.as_ref(), config.site_dir.as_ref()).await;
    } else if config.ephemeral {
        run_full_node_ephemeral().await;
    } else {
        run_full_node_persistent(config.storage_path.as_ref()).await;
    }
}
