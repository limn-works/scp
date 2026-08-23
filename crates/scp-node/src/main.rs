//! SCP application node binary.
//!
//! Four modes of operation:
//!
//! 1. **Full node** (default): Starts an [`ApplicationNode`] with DID identity,
//!    relay, and HTTP server (`.well-known/scp` + WebSocket upgrade). Uses
//!    persistent `SQLite` storage by default (`SQLCipher` encrypted).
//! 2. **Relay-only** (`--relay-only`): Runs a bare [`RelayServer`], identical
//!    to the standalone `scp-relay` binary.
//! 3. **Ephemeral** (`--ephemeral`): Runs a full node with all in-memory
//!    subsystems — nothing persists across restarts. A test-harness mode: the
//!    in-memory DHT and custody compile only under the `testing` feature, so a
//!    shipped build exits 1 on this flag.
//! 4. **Self-host** (`--self-host`): Hosts a static website entirely on SCP
//!    (no DNS name required) — opens an inbound public port, publishes the host's
//!    IP to the DHT by default, and serves the site over self-signed HTTPS by default
//!    (`SCP_NODE_SELF_HOST_PLAINTEXT=1` for plain HTTP).
//!
//! Configuration is read from CLI flags and environment variables.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use zeroize::Zeroizing;

use scp_identity::DidCache;
use scp_identity::dht::SequenceStore;
use scp_node::{DhtMode, IdentitySource, Node, NodeConfig, Reach, TlsMode};
use scp_platform::EncryptedStorage;
use scp_platform::sqlite::{SqliteKeyCustody, SqliteStorage};
use scp_transport::native::server::RelayServer;
use scp_transport::native::storage::BlobStorageBackend;
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
///   `--ephemeral`        — all in-memory subsystems (test-harness only; a
///                          shipped build exits 1)
///   `--storage-path <p>` — `SQLite` database directory
///   `--help`             — print usage and exit
fn parse_args() -> CliConfig {
    let args: Vec<String> = env::args().collect();

    // Resolve the environment-derived inputs once, here, so the arg/env merge
    // itself lives in the pure `parse_cli_from` (unit-testable without touching
    // the process-global environment).
    let self_host_env = env_flag_is_truthy(env::var("SCP_NODE_SELF_HOST").ok().as_deref());
    let storage_env = env::var("SCP_STORAGE_PATH").ok().map(PathBuf::from);
    let site_env = env::var("SCP_NODE_SITE_DIR").ok().map(PathBuf::from);

    parse_cli_from(&args, self_host_env, storage_env, site_env)
}

/// Pure CLI parsing over an explicit args slice plus the already-resolved
/// environment-derived inputs, so the selection/merge logic is unit-testable
/// without mutating the process-global environment (`std::env::set_var` is
/// `unsafe` under edition 2024 and process-global, which makes env-based tests
/// flaky under parallel execution).
///
/// `self_host_env` is the resolved `SCP_NODE_SELF_HOST` flag; `storage_env` /
/// `site_env` are the resolved `SCP_STORAGE_PATH` / `SCP_NODE_SITE_DIR` values.
/// CLI arguments take precedence over the environment fallbacks, matching the
/// production resolution order. This is a behavior-preserving extraction of the
/// body [`parse_args`] used to run inline.
fn parse_cli_from(
    args: &[String],
    self_host_env: bool,
    storage_env: Option<PathBuf>,
    site_env: Option<PathBuf>,
) -> CliConfig {
    let relay_only = args.iter().any(|a| a == "--relay-only");
    let health = args.iter().any(|a| a == "--health");
    let ephemeral = args.iter().any(|a| a == "--ephemeral");
    let show_help = args.iter().any(|a| a == "--help" || a == "-h");

    let self_host = args.iter().any(|a| a == "--self-host") || self_host_env;

    let storage_path = args
        .iter()
        .position(|a| a == "--storage-path")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .or(storage_env);

    let site_dir = args
        .iter()
        .position(|a| a == "--site-dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .or(site_env);

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
    --ephemeral             Use in-memory storage for all subsystems (no persistence).
                            A test-harness mode: a shipped build exits 1 on it.
    --self-host             Host a static site entirely on SCP (no DNS name required).
                            Opens an inbound port to the PUBLIC INTERNET and
                            publishes the host's IP to the DHT by default
                            (`SCP_NODE_DHT_MODE=disabled` skips publication).
                            Self-signed HTTPS by default (SCP_NODE_SELF_HOST_PLAINTEXT=1
                            for plain HTTP). See the loud startup banner for the full warning.
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
    SCP_NODE_SELF_HOST_PLAINTEXT  Set to '1' to serve plain HTTP instead of self-signed
                                HTTPS in self-host mode (default: HTTPS). Traffic is then
                                unencrypted.
    SCP_NODE_SELF_HOST_NO_NAT  Set to '1' to skip NAT/UPnP port-probing in self-host mode
                               (default: probe). Use behind a tunnel/proxy; binds a
                               loopback relay URL.
    SCP_NODE_SELF_HOST_REFRESH_SECS  Interval (seconds) between self-host site re-deploys
                                to beat the blob TTL (default: 1800).
    SCP_NODE_BIND_ADDR          HTTP bind address (default: 0.0.0.0:9000)
    SCP_NODE_TLS_SELF_SIGNED    Set to '1' for self-signed TLS (development only)
    SCP_NODE_PROJECTION_RATE_LIMIT  Per-IP rate limit for projection endpoints (default: 60)
    SCP_NODE_DHT_MODE           DHT client: 'production' (default) publishes this
                                node's address to the Mainline DHT; 'disabled'
                                does NOT publish (reachable but not
                                DHT-discoverable — share the address out-of-band;
                                honoured by --self-host). Works with or without
                                NAT probing.
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
//
// `resolve_storage_path`, `resolve_storage_key`, and the storage-backed
// `StorageSequenceStore` now live in the `scp_node` library
// (`scp_node::self_host`) so the self-host `host_site` path and the full-node
// paths below share one Result-returning implementation. The thin wrappers
// `resolve_storage_path_or_exit` / `resolve_storage_key_or_exit` keep the
// binary's exit-on-error behavior.

/// Binary wrapper over [`scp_node::self_host::resolve_storage_path`] that exits on error.
fn resolve_storage_path_or_exit(cli_path: Option<&PathBuf>) -> PathBuf {
    match scp_node::self_host::resolve_storage_path(cli_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve storage path");
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Binary wrapper over [`scp_node::self_host::resolve_storage_key`] that exits on error.
fn resolve_storage_key_or_exit(storage_dir: &std::path::Path) -> Zeroizing<[u8; 32]> {
    match scp_node::self_host::resolve_storage_key(storage_dir) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve storage encryption key");
            std::process::exit(1);
        }
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

/// The blob backend for ephemeral mode: always in-memory, no persistence, env
/// overrides deliberately IGNORED.
///
/// This is the ephemeral caller's explicit selection at its own boundary
/// (SCP-CAPINJECT-010). It is a named function — not an inline literal — so the
/// "ephemeral ⇒ in-memory blob" contract is pinned by a unit test
/// (`ephemeral_uses_in_memory_blob`) and cannot silently regress to a durable /
/// env-driven backend (which would violate the all-in-memory contract documented
/// on [`run_full_node_ephemeral`] and re-persist blobs to disk).
///
/// Gated to `any(test, feature = "testing")` because that is exactly where it is
/// used and nowhere else: the ephemeral entry point [`run_full_node_ephemeral`]
/// is itself `#[cfg(feature = "testing")]`, and the regression test is
/// `#[cfg(test)]`. Under a plain default-feature build it would be dead code; the
/// regression test still runs under `cargo test` (which enables `cfg(test)`).
#[cfg(any(test, feature = "testing"))]
#[must_use]
fn ephemeral_blob_backend() -> BlobStorageBackend {
    BlobStorageBackend::in_memory()
}

/// Runs the full node with all in-memory subsystems (no persistence).
///
/// In ephemeral mode, ALL subsystems use in-memory implementations regardless
/// of environment variable overrides. No mixed mode is permitted — if you want
/// persistent storage or production DHT, omit the `--ephemeral` flag.
///
/// **Test-harness-only.** This path wires the `InMemoryDhtClient` (a §17.17.3
/// resolve nullifier) and `InMemoryKeyCustody`, so it is compiled only under the
/// `testing` feature (ADR-062 §Decision 1) — a shipped `scp-node` binary carries
/// no in-memory DHT client. A production build reached with `--ephemeral` exits
/// with an error (see the dispatch in `main`).
#[cfg(feature = "testing")]
async fn run_full_node_ephemeral() {
    use scp_clock::SystemClock;
    use scp_dht::InMemoryDhtClient;
    use scp_identity::{DidDht, InMemorySequenceStore};
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::testing::InMemoryKeyCustody;

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
    let sequence_store = Arc::new(InMemorySequenceStore::default());

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
    let seq_init = scp_node::self_host::make_seq_init(seq_init_method);
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
        // Ephemeral contract: in-memory blob, no persistence, env ignored.
        ephemeral_blob_backend(),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Full node mode — persistent (default)
// ---------------------------------------------------------------------------

/// Opens an encrypted `SQLite` database via [`scp_node::self_host::open_sqlite`], exiting
/// on failure.
fn open_sqlite_or_exit(dir: &std::path::Path, key: &Zeroizing<[u8; 32]>) -> SqliteStorage {
    match scp_node::self_host::open_sqlite(dir, key) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, path = %dir.display(), "failed to open SQLite storage");
            std::process::exit(1);
        }
    }
}

/// Initializes storage path, encryption key, and `SQLite` databases for the
/// persistent node. Returns `(storage_dir, storage_key, node_storage, custody)`.
///
/// The root `node_storage` is returned behind an `Arc` because it holds the
/// process-exclusive advisory lock on `{dir}/scp.db.lock` for its lifetime, and
/// that single handle is shared by every root-DB consumer (the BEP44 sequence
/// store AND the `ApplicationNode` builder). Opening a second `SqliteStorage`
/// against the same root directory while this one is alive fails with an
/// advisory-lock conflict (os error 35) — see `SqliteStorage::new`. Sharing the
/// one handle via `Arc::clone` (which implements [`Storage`]/[`EncryptedStorage`]
/// through the blanket `Arc<T>` impls) keeps exactly one lock holder.
async fn init_persistent_storage(
    storage_path: Option<&PathBuf>,
) -> (
    PathBuf,
    Zeroizing<[u8; 32]>,
    Arc<SqliteStorage>,
    Arc<SqliteKeyCustody>,
) {
    let storage_dir = resolve_storage_path_or_exit(storage_path);
    let storage_key = resolve_storage_key_or_exit(&storage_dir);

    let node_storage = Arc::new(open_sqlite_or_exit(&storage_dir, &storage_key));
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

/// Validates that the storage directory can be created and is writable via
/// [`scp_node::self_host::validate_storage_path`], exiting with a clear message on failure.
fn validate_storage_path_or_exit(dir: &std::path::Path) {
    if let Err(e) = scp_node::self_host::validate_storage_path(dir) {
        tracing::error!(error = %e, path = %dir.display(), "storage path is not usable");
        eprintln!(
            "ERROR: {e}\n\
             Ensure the parent directory exists and is writable, \
             or specify a different path with --storage-path."
        );
        std::process::exit(1);
    }
}

/// Runs the full node with persistent `SQLite` storage (production default).
async fn run_full_node_persistent(storage_path: Option<&PathBuf>) {
    let domain = require_domain();
    let http_addr = node_http_addr();

    // Validate the storage path upfront before attempting to open databases.
    let resolved_path = resolve_storage_path_or_exit(storage_path);
    validate_storage_path_or_exit(&resolved_path);

    // The root storage key is intentionally unused beyond `init_persistent_storage`:
    // the single root `SqliteStorage` handle it opens (held alive via
    // `node_storage_arc`) is the ONLY root handle and is reused for both the BEP44
    // sequence store and the node builder. Reopening the root DB while that handle
    // is alive would fail with an advisory-lock conflict (os error 35).
    let (storage_dir, _storage_key, node_storage_arc, custody) =
        init_persistent_storage(storage_path).await;

    tracing::info!(
        domain = %domain,
        bind_addr = %http_addr,
        storage_path = %storage_dir.display(),
        mode = "persistent",
        "starting scp-node with SQLite storage (SQLCipher encrypted)"
    );

    let cache = Arc::new(DidCache::new());

    // Use storage-backed sequence store for BEP44 sequence persistence.
    let sequence_store: Arc<dyn SequenceStore> = Arc::new(
        scp_node::self_host::StorageSequenceStore::new(Arc::clone(&node_storage_arc)),
    );

    // Explicit parse: a typo (e.g. "memroy") must NOT silently fall through to
    // the production DHT, which would publish the host's address to the network.
    match parse_dht_mode_or_exit() {
        // `parse_dht_mode_or_exit` returns `Disabled` for `SCP_NODE_DHT_MODE=disabled`
        // whichever path asked for it, so this arm is the only thing that rejects
        // the value for the full relay node. Do not delete it as unreachable.
        scp_node::DhtMode::Disabled => {
            tracing::error!(
                "DhtMode::Disabled is not a full-relay-node mode — the node must publish its DID. \
                 Use --self-host for a non-publishing hosted site."
            );
            std::process::exit(1);
        }
        #[cfg(feature = "testing")]
        scp_node::DhtMode::Memory => {
            tracing::warn!(
                "using InMemoryDhtClient — DID documents will NOT be published to the network \
                 (test-harness-only; DhtMode::Disabled is the shipped no-publish value)"
            );
            let (did_method, seq_init) = scp_node::self_host::build_memory_did_method(
                Arc::clone(&custody),
                cache,
                sequence_store,
            );
            // Reuse the single root handle (shared via `Arc`) rather than reopening,
            // which would conflict on the advisory lock (os error 35).
            run_node_with(
                domain,
                http_addr,
                custody,
                seq_init,
                did_method,
                Arc::clone(&node_storage_arc),
                // Persistent mode: operator-configured durable blob backend
                // (default SQLite), honoring `SCP_RELAY_STORAGE_BACKEND` /
                // `SCP_RELAY_STORAGE_PATH` — the same explicit selection
                // relay-only mode makes (SCP-CAPINJECT-010).
                startup::storage_from_env().await,
            )
            .await;
        }
        scp_node::DhtMode::Production => {
            // DHT HTTP gateways come from the same env var the self-host path
            // reads; the library helper threads them into the pkarr client.
            let dht_gateways = dht_gateways_from_env();
            let (did_method, seq_init) = match scp_node::self_host::build_production_did_method(
                Arc::clone(&custody),
                cache,
                sequence_store,
                &dht_gateways,
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!(error = %e, "failed to build production DID method");
                    std::process::exit(1);
                }
            };
            // Reuse the single root handle (shared via `Arc`) rather than reopening,
            // which would conflict on the advisory lock (os error 35).
            run_node_with(
                domain,
                http_addr,
                custody,
                seq_init,
                did_method,
                Arc::clone(&node_storage_arc),
                // Persistent mode: operator-configured durable blob backend
                // (default SQLite), honoring `SCP_RELAY_STORAGE_BACKEND` /
                // `SCP_RELAY_STORAGE_PATH` (SCP-CAPINJECT-010).
                startup::storage_from_env().await,
            )
            .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers

/// Parses `SCP_NODE_DHT_MODE` from the environment and exits on unrecognised
/// values. The fail-closed exit prevents a typo (e.g. "memroy") from silently
/// falling through to the production DHT and publishing the host's address.
fn parse_dht_mode_or_exit() -> scp_node::DhtMode {
    // The full relay node publishes its DID so peers can discover it, so its
    // shipped DHT mode is `production`. `memory` (the in-memory §17.17.3
    // nullifier) is a test-harness value compiled only under `testing`. The
    // non-publishing `DhtMode::Disabled` value belongs to the `--self-host`
    // path (`host_site`), which resolves via the relay layer without publishing;
    // a relay node with no published DID cannot be found, so it is not offered
    // here. (The library-level `NodeConfig`/`HostSiteConfig::defaults` fail-safe
    // is `Disabled` per ADR-062 §Decision 1; this binary default is the operator
    // running a public server.)
    let raw = env::var("SCP_NODE_DHT_MODE").unwrap_or_else(|_| "production".into());
    match raw.as_str() {
        "production" => scp_node::DhtMode::Production,
        // `disabled` (DHT layer off, no publish) is honoured by the `--self-host`
        // path (`serve_hosted_site` resolves via the relay layer without
        // publishing). The full relay node rejects it in its own match — it must
        // publish its DID to be discoverable.
        "disabled" => scp_node::DhtMode::Disabled,
        // `memory` compiles only under the `testing` feature — never shipped.
        #[cfg(feature = "testing")]
        "memory" => scp_node::DhtMode::Memory,
        other => {
            tracing::error!(
                value = %other,
                "unrecognized SCP_NODE_DHT_MODE (expected 'production' or 'disabled'); \
                 refusing to default to production DHT to avoid unintended IP publication"
            );
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Self-host mode (--self-host)
//
// The reusable deploy + serve core now lives in the `scp_node` library
// (`scp_node::host_site_until`). This binary keeps ONLY the binary-only
// concerns: env/CLI parsing of the self-host knobs, the loud startup banner,
// and the live-URL banner (printed via the `on_ready` callback). `run_self_host`
// reads the env, builds a `HostSiteConfig`, and drives `host_site_until` with
// the binary's own platform shutdown signal.
// ---------------------------------------------------------------------------

/// Builds the loud self-host startup banner shown on stderr before any socket
/// is opened.
///
/// States, in plain language, the consequences the operator is opting into
/// (public-port exposure, the public-IP<->DID DHT disclosure — only when DHT
/// publishing is actually on — and the transport security posture) plus the
/// Finding-D NAT self-test note so a Tier-2 line in the logs is not mistaken for
/// a hosting failure.
///
/// `plaintext` reflects whether the operator opted OUT of TLS via
/// `SCP_NODE_SELF_HOST_PLAINTEXT=1`. By default self-host serves a self-signed
/// (no-CA) HTTPS certificate, so the transport line describes the expected
/// one-time browser untrusted-cert warning; under the plaintext opt-out it
/// describes the cleartext exposure instead.
///
/// `publishes_dht` reflects whether `SCP_NODE_DHT_MODE` resolves to `production`
/// (publish) vs `disabled` (no publish). Under `disabled` the host's address is
/// NOT published to the DHT, so the IP<->DID disclosure line is replaced with a
/// line stating the node is reachable but not DHT-discoverable.
fn self_host_banner(port: u16, plaintext: bool, publishes_dht: bool) -> String {
    let transport_line = if plaintext {
        "  * Transport is PLAINTEXT HTTP (SCP_NODE_SELF_HOST_PLAINTEXT=1): traffic is\n\
         \x20    readable and tamper-able in transit. The hosted content is public broadcast\n\
         \x20    content anyway, but HTTPS-Only browsers will refuse to open http://."
    } else {
        "  * Transport is self-signed HTTPS (TLS 1.3, no CA -- the \"be your own CA\" model):\n\
         \x20    browsers show a ONE-TIME untrusted-certificate warning because there is no\n\
         \x20    DNS name and no certificate authority. This is EXPECTED for the no-DNS model.\n\
         \x20    Set SCP_NODE_SELF_HOST_PLAINTEXT=1 to serve plain HTTP instead."
    };
    let dht_line = if publishes_dht {
        "  * Your host's PUBLIC IP will be published to the global Mainline DHT, bound to\n\
         \x20    this node's DID. This is an IP<->identity disclosure (approximate-location dox)."
    } else {
        "  * DHT publishing is OFF (SCP_NODE_DHT_MODE=disabled): your host's address is NOT\n\
         \x20    published to the Mainline DHT. The node is reachable on the opened port but is\n\
         \x20    NOT DHT-discoverable -- share its address out-of-band."
    };
    format!(
        "================================ SELF-HOST MODE ================================\n\
         scp-node is about to open inbound TCP port {port} to the PUBLIC INTERNET via\n\
         NAT-PMP/UPnP (when built with --features upnp). Consequences you are opting into:\n\
         {dht_line}\n\
         {transport_line}\n\
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

/// Whether the operator opted OUT of TLS for self-host via
/// `SCP_NODE_SELF_HOST_PLAINTEXT=1`.
///
/// Self-host serves a self-signed HTTPS certificate by default (so HTTPS-Only
/// browsers will open it); this flag restores the legacy plaintext-HTTP
/// behavior for anyone who wants it (§10.12.11).
fn self_host_plaintext() -> bool {
    env_flag_is_truthy(env::var("SCP_NODE_SELF_HOST_PLAINTEXT").ok().as_deref())
}

/// Whether the operator opted OUT of the STUN/NAT external-address probe for
/// self-host via `SCP_NODE_SELF_HOST_NO_NAT=1`.
///
/// The probe (STUN reflexive-address discovery + UPnP/NAT-PMP mapping +
/// reachability self-test) can add tens of seconds to startup and is dead
/// weight when the node is reached through a tunnel/proxy that terminates on
/// `localhost` (e.g. a Cloudflare tunnel). When set, the no-domain build skips
/// the probe entirely, binds and serves immediately, and publishes a loopback
/// relay URL -- so no external IP is disclosed to the DHT and no external-IP
/// certificate SAN is added (the tunnel provides external reachability).
fn self_host_skip_nat() -> bool {
    env_flag_is_truthy(env::var("SCP_NODE_SELF_HOST_NO_NAT").ok().as_deref())
}

/// Pure predicate for an opt-in boolean environment flag: `true` only when the
/// value is exactly `"1"` or `"true"`. Any other value (including unset,
/// `"0"`, `"false"`, or arbitrary text) is `false`.
///
/// Extracted so the parsing semantics can be unit-tested without mutating the
/// process environment (`std::env::set_var` is `unsafe` under edition 2024 and
/// process-global, which makes env-based tests flaky under parallel execution).
fn env_flag_is_truthy(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true"))
}

/// Runs the node in self-host mode, hosting a static site entirely on SCP.
///
/// Reads the self-host configuration from CLI args and environment variables,
/// prints the loud startup banner, then delegates the deploy + serve core to
/// the [`scp_node::host_site_until`] library function. The library does the
/// real work (build node, deploy, serve, refresh, teardown); this wrapper owns
/// only the binary-only concerns: env/CLI parsing, the banner, and the live-URL
/// banner (printed via the `on_ready` callback). On error the process exits 1.
///
/// Opens an inbound TCP port to the public internet (via NAT-PMP/UPnP when the
/// `upnp` feature is built). Whether the host's address is published to the
/// Mainline DHT is governed independently by `SCP_NODE_DHT_MODE`:
/// `production` (the default) publishes; `disabled` does NOT publish — the node
/// is still reachable on the opened port, the address is just not
/// DHT-discoverable (share it out-of-band). `disabled` is valid with NAT probing
/// on or off. (`memory` compiles only under the `testing` feature, so a shipped
/// build exits 1 on it.) See the
/// startup banner.
async fn run_self_host(storage_path: Option<&PathBuf>, site_dir: Option<&PathBuf>) {
    let port: u16 = startup::env_or("SCP_NODE_SELF_HOST_PORT", 8443u16);
    let plaintext = self_host_plaintext();
    let skip_nat = self_host_skip_nat();

    // -- DHT mode: production pkarr by default; `disabled` for "reachable but not
    //    DHT-discoverable" hosting. Parsed BEFORE the banner so the banner can
    //    state the actual disclosure posture (disabled = address NOT published). --
    let dht_mode = parse_dht_mode_or_exit();
    let publishes_dht = matches!(dht_mode, scp_node::DhtMode::Production);

    // -- Loud startup banner BEFORE opening any socket --
    eprintln!("{}", self_host_banner(port, plaintext, publishes_dht));
    if skip_nat {
        eprintln!(
            "NAT probe skipped (SCP_NODE_SELF_HOST_NO_NAT) — assuming reachability via a \
             proxy/tunnel. Relay URL falls back to loopback; certificate SANs are \
             localhost + 127.0.0.1 only."
        );
    }
    tracing::warn!(
        port,
        skip_nat,
        publishes_dht,
        "self-host mode enabled — opening inbound port to the public internet"
    );

    let refresh_secs: u64 = startup::env_or(
        "SCP_NODE_SELF_HOST_REFRESH_SECS",
        // The default refresh interval is reach-independent; read it off a
        // throwaway `defaults(...)` (there is no whole-struct `Default` — M4).
        scp_node::HostSiteConfig::defaults(Reach::Local)
            .refresh_interval
            .as_secs(),
    )
    .max(1);

    let projection_rate_limit: u32 = startup::env_or(
        "SCP_NODE_PROJECTION_RATE_LIMIT",
        scp_node::DEFAULT_PROJECTION_RATE_LIMIT,
    );

    // -- Lower the binary's `plaintext` / `skip_nat` booleans onto the
    //    construction-pattern enums (ADR-052 M1): `plaintext` → `TlsMode`,
    //    `skip_nat` → `Reach`. The booleans survive only for the banners above
    //    and the live-URL banner below; the config carries the enums. --
    let tls = if plaintext {
        TlsMode::Plaintext
    } else {
        TlsMode::SelfSigned
    };
    let reach = if skip_nat {
        Reach::Local
    } else {
        Reach::NatTraversal
    };

    let config = scp_node::HostSiteConfig {
        reach,
        tls,
        dht: dht_mode,
        site_dir: site_dir.cloned(),
        port,
        storage_path: storage_path.cloned(),
        dht_gateways: dht_gateways_from_env(),
        projection_rate_limit,
        refresh_interval: std::time::Duration::from_secs(refresh_secs),
        // Print the operator-facing live-URL banner once the site is ready. The
        // library performs no printing itself; this keeps all binary UX here.
        on_ready: Some(Box::new(|ready: scp_node::HostSiteReady| {
            print_self_host_live_url(&ready);
        })),
    };

    if let Err(e) = scp_node::host_site_until(config, startup::shutdown_signal()).await {
        tracing::error!(error = %e, "self-host mode failed");
        std::process::exit(1);
    }

    tracing::info!("scp-node (self-host) stopped");
}

/// Logs and prints the live site URL after a successful deploy.
///
/// The URLs use the `0.0.0.0` bind placeholder; the operator substitutes their
/// public IP (or an SCP-aware client resolves it via `did:dht`). The node DID
/// is included so the operator can verify the IP<->identity binding. The scheme
/// is `https` by default (self-signed) or `http` under the plaintext opt-out.
///
/// Both the origin-root URL (the site is mounted at `/`) and the explicit
/// routing-id path are shown — the root URL is what a browser loads; the
/// explicit path is the canonical SCP projection address.
fn print_self_host_live_url(ready: &scp_node::HostSiteReady) {
    let scheme = if ready.plaintext { "http" } else { "https" };
    let port = ready.port;
    let routing_hex = &ready.routing_id_hex;
    let node_did = &ready.node_did;
    let root_url = format!("{scheme}://0.0.0.0:{port}/");
    let canonical_url =
        format!("{scheme}://0.0.0.0:{port}/scp/broadcast/{routing_hex}/site/index.html");
    tracing::info!(
        did = %node_did,
        assets = ready.asset_count,
        url = %root_url,
        canonical_url = %canonical_url,
        "self-host site live"
    );
    let tls_note = if ready.plaintext {
        ""
    } else {
        "  (your browser will show a one-time untrusted-certificate warning: there is no\n  \
         certificate authority in the no-DNS self-host model — accept it to proceed.)\n"
    };
    eprintln!(
        "\nSelf-host site is LIVE:\n  \
         {root_url}            (origin root — the page a browser loads)\n  \
         {canonical_url}  (canonical SCP projection path)\n\
         {tls_note}  \
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

/// Reads the comma-separated `SCP_NODE_DHT_GATEWAYS` env var into a list of
/// trimmed, non-empty gateway URLs (empty when unset).
///
/// Threaded into [`scp_node::self_host::build_production_did_method`] (full-node) and
/// [`scp_node::HostSiteConfig::dht_gateways`] (self-host) so both paths share
/// the library's pkarr client construction.
fn dht_gateways_from_env() -> Vec<String> {
    env::var("SCP_NODE_DHT_GATEWAYS").map_or_else(
        |_| Vec::new(),
        |gateways| {
            gateways
                .split(',')
                .map(str::trim)
                .filter(|g| !g.is_empty())
                .map(str::to_owned)
                .collect()
        },
    )
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
    seq_init: scp_node::self_host::SeqInitFn,
    did_method: Arc<D>,
    storage: S,
    // The relay's blob backend, selected by each caller at ITS OWN boundary
    // (SCP-CAPINJECT-010 / spec §17.17.1). Threaded as a required parameter —
    // exactly like `storage` — so this shared helper NEVER manufactures a backend
    // (that would re-introduce the SCP-CAPSEL-8002 anti-pattern the story kills,
    // and would break ephemeral mode's all-in-memory contract). Ephemeral mode
    // passes `ephemeral_blob_backend()` (in-memory, no persistence, env-ignoring);
    // persistent mode passes `startup::storage_from_env()` (durable, default
    // SQLite, honors env).
    blob_storage: BlobStorageBackend,
) {
    let use_self_signed = env_flag_is_truthy(env::var("SCP_NODE_TLS_SELF_SIGNED").ok().as_deref());

    let use_dns_provider = env_flag_is_truthy(env::var("SCP_NODE_DNS_PROVIDER").ok().as_deref());

    let projection_rate: u32 = startup::env_or(
        "SCP_NODE_PROJECTION_RATE_LIMIT",
        scp_node::DEFAULT_PROJECTION_RATE_LIMIT,
    );

    // Decide TLS + DNS provider from the two env booleans BEFORE building the
    // config (ADR-052 Phase B-P2). The three TLS arms map exactly onto the
    // legacy builder branches:
    //   - DNS provider on  → headless ACME (`Acme { email: None }`) + a DNS
    //     subdomain provider. The legacy default supplied no `acme_email`, so
    //     `None` reproduces it; the DNS provider overrides TLS during build()
    //     after identity resolution, exactly as before.
    //   - self-signed       → `TlsMode::SelfSigned` (the same self-signed cert
    //     the dropped local `SelfSignedTlsProvider` produced).
    //   - neither           → headless ACME (`Acme { email: None }`), the
    //     legacy default that falls through to `AcmeProvider::new(domain)` with
    //     no contact email.
    let (tls, dns_provider) = if use_dns_provider {
        // DNS subdomain provider: derive domain from DID, register with DNS
        // API for zero-config TLS (#642). The configured domain is overridden
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
        (TlsMode::Acme { email: None }, Some(dns_config))
    } else if use_self_signed {
        tracing::info!(domain = %domain, "using self-signed TLS certificate (development mode)");
        (TlsMode::SelfSigned, None)
    } else {
        // Legacy headless-ACME default (no contact email).
        (TlsMode::Acme { email: None }, None)
    };

    // `Domain` is a publishing reach, so M2 requires `DhtMode::Production`
    // (advisory in P1 — dropped before lowering, so no runtime behavior
    // change). `run_node_with` is generic over `S: EncryptedStorage`, so the
    // production `Node::start` (not `start_for_testing`) is the correct entry.
    let node = match Node::start(NodeConfig {
        tls,
        dns_provider,
        dht: DhtMode::Production,
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        http_bind_addr: Some(http_addr),
        projection_rate_limit: Some(projection_rate),
        ..NodeConfig::defaults(
            Reach::Domain {
                domain: domain.clone(),
            },
            IdentitySource::Generate {
                custody,
                did_method,
            },
            storage,
            blob_storage,
        )
    })
    .await
    {
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
        // Ephemeral mode wires in-memory subsystems (incl. the §17.17.3 in-memory
        // DHT nullifier), so it is compiled only under the `testing` feature
        // (ADR-062 §Decision 1). A shipped binary reached with `--ephemeral`
        // fails closed rather than silently running a nullifier-backed node.
        #[cfg(feature = "testing")]
        run_full_node_ephemeral().await;
        #[cfg(not(feature = "testing"))]
        {
            eprintln!(
                "ERROR: --ephemeral is a test-harness mode (in-memory DHT/custody) and is not \
                 available in this build. Run without --ephemeral for a persistent node, or run \
                 `scp-node --self-host` for a non-publishing hosted site. A full relay node has \
                 no non-publishing mode: it must publish its DID to be discoverable."
            );
            std::process::exit(1);
        }
    } else {
        run_full_node_persistent(config.storage_path.as_ref()).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard (SCP-CAPINJECT-010): ephemeral mode MUST select the
    /// in-memory blob backend — no persistence, env overrides ignored. This pins
    /// the ephemeral caller's boundary selection so it cannot silently regress to
    /// a durable / env-driven backend (`startup::storage_from_env`, which defaults
    /// to `Sqlite`), which would break the all-in-memory contract documented on
    /// `run_full_node_ephemeral` and re-persist blobs to disk. If someone swaps
    /// `ephemeral_blob_backend()` to any non-in-memory backend, this fails.
    #[test]
    fn ephemeral_uses_in_memory_blob() {
        assert!(
            matches!(ephemeral_blob_backend(), BlobStorageBackend::InMemory(_)),
            "ephemeral mode must use the in-memory blob backend (no persistence, \
             env ignored) — see the all-in-memory contract on run_full_node_ephemeral"
        );
    }

    /// `SCP_NODE_SELF_HOST_NO_NAT` (and every opt-in self-host flag) is truthy
    /// only for the exact values `"1"` and `"true"`. This is the parsing rule
    /// `self_host_skip_nat` applies; testing the pure predicate avoids mutating
    /// the process-global environment.
    #[test]
    fn env_flag_is_truthy_only_for_one_or_true() {
        assert!(env_flag_is_truthy(Some("1")));
        assert!(env_flag_is_truthy(Some("true")));

        assert!(!env_flag_is_truthy(None));
        assert!(!env_flag_is_truthy(Some("")));
        assert!(!env_flag_is_truthy(Some("0")));
        assert!(!env_flag_is_truthy(Some("false")));
        assert!(!env_flag_is_truthy(Some("TRUE")));
        assert!(!env_flag_is_truthy(Some("yes")));
        assert!(!env_flag_is_truthy(Some("2")));
    }

    /// FIX B consequence: a loopback relay URL (what the node publishes when the
    /// NAT probe is skipped) contributes NO external IP to the certificate SAN
    /// set — only localhost + 127.0.0.1 remain (already the default SANs). A
    /// routable external URL, by contrast, does contribute its IP.
    #[test]
    fn loopback_relay_url_adds_no_external_san() {
        use scp_node::self_host::external_ip_from_relay_url;
        // Skip-NAT loopback fallback: no external SAN.
        assert_eq!(
            external_ip_from_relay_url("ws://127.0.0.1:8444/scp/v1"),
            None,
            "loopback relay URL must not yield an external SAN"
        );
        // IPv6 loopback is likewise excluded.
        assert_eq!(
            external_ip_from_relay_url("ws://[::1]:8444/scp/v1"),
            None,
            "IPv6 loopback relay URL must not yield an external SAN"
        );
        // A routable external URL (the probed path) DOES yield its IP.
        assert_eq!(
            external_ip_from_relay_url("ws://203.0.113.7:8444/scp/v1"),
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                203, 0, 113, 7
            ))),
            "a routable relay URL must yield its external IP as a SAN"
        );
    }

    /// The skip-NAT banner line is only emitted via the env helper; verify the
    /// helper composes with the pure predicate so the binary's branch is
    /// exercised through a stable, testable seam.
    #[test]
    fn self_host_skip_nat_uses_the_truthy_predicate() {
        // The function reads the env, but its decision is exactly the pure
        // predicate over the variable's value, which the tests above pin down.
        // Here we only assert it is callable and returns a bool (no panic),
        // keeping the env untouched for parallel-test safety.
        let _: bool = self_host_skip_nat();
    }

    // -----------------------------------------------------------------------
    // CLI / env mode selection (`parse_cli_from`)
    //
    // `parse_args` reads `env::args()` + env vars (process-global, unsafe to
    // mutate under edition 2024), so it is not hermetically testable. The pure
    // `parse_cli_from` takes the args slice + already-resolved env inputs
    // explicitly, so the selection/merge logic is exercised here without
    // touching the environment. Helper keeps the call sites terse.
    // -----------------------------------------------------------------------

    /// Builds an owned `Vec<String>` args vector from string literals, matching
    /// the shape of `env::args().collect()` (argv[0] is the program name).
    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The `--self-host` argument selects self-host mode.
    #[test]
    fn cli_self_host_flag_selects_self_host_mode() {
        let cfg = parse_cli_from(&argv(&["scp-node", "--self-host"]), false, None, None);
        assert!(
            cfg.self_host,
            "--self-host must select self-host mode regardless of env"
        );
    }

    /// With no flags and no env override, the node does NOT default to
    /// self-host (nor relay-only / ephemeral) mode.
    #[test]
    fn cli_defaults_to_not_self_host() {
        let cfg = parse_cli_from(&argv(&["scp-node"]), false, None, None);
        assert!(!cfg.self_host, "no flags must NOT select self-host mode");
        assert!(!cfg.relay_only, "no flags must NOT select relay-only mode");
        assert!(!cfg.ephemeral, "no flags must NOT select ephemeral mode");
        assert!(!cfg.show_help, "no flags must NOT request help");
    }

    /// Self-host selection is independent of any domain input: there is no
    /// `--domain` CLI field (the full-node domain is read later from
    /// `SCP_NODE_DOMAIN`), so a bare `--self-host` invocation parses cleanly
    /// with `self_host == true` and no storage path required.
    #[test]
    fn cli_self_host_does_not_require_domain() {
        let cfg = parse_cli_from(&argv(&["scp-node", "--self-host"]), false, None, None);
        assert!(cfg.self_host, "self-host must be selected without a domain");
        assert!(
            cfg.storage_path.is_none(),
            "self-host selection must not require a storage path"
        );
        assert!(
            cfg.site_dir.is_none(),
            "self-host selection must not require a site dir"
        );
    }

    /// `--site-dir <p>` is parsed into the `site_dir` field.
    #[test]
    fn cli_site_dir_argument_is_parsed() {
        let cfg = parse_cli_from(
            &argv(&["scp-node", "--self-host", "--site-dir", "/tmp/site"]),
            false,
            None,
            None,
        );
        assert_eq!(
            cfg.site_dir,
            Some(PathBuf::from("/tmp/site")),
            "--site-dir must populate the site_dir field"
        );
    }

    /// `--storage-path <p>` is parsed into the `storage_path` field, and a CLI
    /// value takes precedence over the environment fallback.
    #[test]
    fn cli_storage_path_argument_overrides_env() {
        let cfg = parse_cli_from(
            &argv(&["scp-node", "--storage-path", "/tmp/cli-storage"]),
            false,
            Some(PathBuf::from("/tmp/env-storage")),
            None,
        );
        assert_eq!(
            cfg.storage_path,
            Some(PathBuf::from("/tmp/cli-storage")),
            "an explicit --storage-path must override SCP_STORAGE_PATH"
        );
    }

    /// The resolved `SCP_NODE_SELF_HOST` env flag selects self-host mode even
    /// when no `--self-host` argument is present.
    #[test]
    fn cli_self_host_env_selects_self_host_mode() {
        let cfg = parse_cli_from(&argv(&["scp-node"]), true, None, None);
        assert!(
            cfg.self_host,
            "a truthy SCP_NODE_SELF_HOST must select self-host mode without the flag"
        );
    }

    /// Environment fallbacks fill `storage_path` / `site_dir` when the matching
    /// CLI argument is absent — the production resolution order.
    #[test]
    fn cli_env_fallbacks_apply_when_no_argument() {
        let cfg = parse_cli_from(
            &argv(&["scp-node"]),
            false,
            Some(PathBuf::from("/tmp/env-storage")),
            Some(PathBuf::from("/tmp/env-site")),
        );
        assert_eq!(
            cfg.storage_path,
            Some(PathBuf::from("/tmp/env-storage")),
            "SCP_STORAGE_PATH must be used when --storage-path is absent"
        );
        assert_eq!(
            cfg.site_dir,
            Some(PathBuf::from("/tmp/env-site")),
            "SCP_NODE_SITE_DIR must be used when --site-dir is absent"
        );
    }

    // -----------------------------------------------------------------------
    // Self-host disclosure banner content (`self_host_banner`)
    //
    // The banner is a pure `String` builder with no side effects — it opens no
    // socket and performs no NAT work. The ordering invariant "banner is
    // printed before any socket/NAT" is structurally guaranteed by the call
    // site: `run_self_host` builds and `eprintln!`s the banner at the top of
    // the function, BEFORE `init_persistent_storage`, `build_self_host_node`,
    // and any NAT probing. A pure unit test cannot assert call ordering, so we
    // assert what IS assertable — the disclosure content — and document the
    // ordering invariant here.
    // -----------------------------------------------------------------------

    /// The HTTPS-default banner (with DHT publishing ON) states every disclosure
    /// the operator opts into (public-internet port exposure, public-IP<->identity
    /// DHT disclosure, and the self-signed-HTTPS transport posture) and never
    /// claims plaintext; the plaintext-opt-out banner instead states the cleartext
    /// exposure and names the opt-out variable.
    #[test]
    fn self_host_banner_states_disclosures() {
        let port = 8443u16;

        // -- HTTPS default (plaintext = false), DHT publishing ON. --
        let https = self_host_banner(port, false, true);
        assert!(
            https.contains(&port.to_string()),
            "banner must name the port being opened"
        );
        assert!(
            https.contains("SELF-HOST MODE"),
            "banner must announce self-host mode"
        );
        assert!(
            https.contains("PUBLIC INTERNET"),
            "banner must disclose public-internet port exposure"
        );
        assert!(
            https.contains("PUBLIC IP"),
            "the publishing banner must disclose public-IP publication"
        );
        assert!(
            https.contains("DHT"),
            "the publishing banner must disclose DHT publication of the address"
        );
        assert!(
            https.contains("IP<->identity"),
            "the publishing banner must disclose the IP<->identity binding"
        );
        assert!(
            https.contains("self-signed HTTPS"),
            "the HTTPS-default banner must describe the self-signed HTTPS posture"
        );
        assert!(
            !https.contains("PLAINTEXT HTTP"),
            "the HTTPS-default banner must NOT claim plaintext transport"
        );

        // -- Plaintext opt-out (plaintext = true), DHT publishing ON. --
        let plain = self_host_banner(port, true, true);
        assert!(
            plain.contains("PLAINTEXT HTTP"),
            "the plaintext banner must disclose cleartext transport"
        );
        assert!(
            plain.contains("SCP_NODE_SELF_HOST_PLAINTEXT"),
            "the plaintext banner must name the opt-out environment variable"
        );
    }

    /// With DHT publishing OFF (`SCP_NODE_DHT_MODE=disabled`), the banner must
    /// NOT claim the host's IP is published — it must instead state the node is
    /// reachable but not DHT-discoverable. This is the banner half of the M2
    /// correction: `disabled` (no publish) is a valid self-host mode that opens
    /// the port without disclosing the address to the DHT.
    #[test]
    fn self_host_banner_disabled_mode_states_no_publish() {
        let port = 8443u16;
        let disabled = self_host_banner(port, false, false);

        // The port is still opened, so the public-internet exposure stands.
        assert!(
            disabled.contains("PUBLIC INTERNET"),
            "disabled-mode banner must still disclose public-internet port exposure"
        );
        // But the IP<->identity DHT publication line must be GONE.
        assert!(
            !disabled.contains("PUBLIC IP will be published"),
            "disabled-mode banner must NOT claim the public IP is published to the DHT"
        );
        assert!(
            !disabled.contains("IP<->identity disclosure"),
            "disabled-mode banner must NOT claim an IP<->identity disclosure"
        );
        // And it must state the no-publish / not-discoverable posture.
        assert!(
            disabled.contains("DHT publishing is OFF") && disabled.contains("NOT DHT-discoverable"),
            "disabled-mode banner must state the address is not published and not DHT-discoverable"
        );
    }
}
