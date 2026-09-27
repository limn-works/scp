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
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
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

/// The constructor a [`BACKENDS`] row carries: opens the backend from its
/// environment variables, or exits 1 when it cannot.
type OpenFn = fn() -> Pin<Box<dyn Future<Output = BlobStorageBackend> + Send>>;

/// One row of [`BACKENDS`]: a value an operator can write into
/// `SCP_RELAY_STORAGE_BACKEND`, and the constructor for it when this build
/// compiled one.
struct Backend {
    /// The value an operator writes into `SCP_RELAY_STORAGE_BACKEND`.
    name: &'static str,
    /// The `scp-transport` feature that compiles this backend's constructor,
    /// or `None` for a constructor no feature gates.
    transport_feature: Option<&'static str>,
    /// The `scp-node` / `scp-relay` feature an operator enables to get
    /// `transport_feature`, or `None` when no binary feature gates it. This
    /// module compiles only under `startup`, which `scp-node` and `scp-relay`
    /// are the only two crates to enable, so naming their feature here tells a
    /// reader of the diagnostic what to pass to `cargo build`.
    binary_feature: Option<&'static str>,
    /// The environment variable the constructor cannot open the backend
    /// without, if any.
    required_var: Option<&'static str>,
    /// The constructor, or `None` when this build did not enable
    /// `transport_feature`.
    open: Option<OpenFn>,
}

/// Declares one [`BACKENDS`] row and writes each fact about the backend once.
///
/// The `feature` literal becomes both the row's `transport_feature` and the
/// `cfg` that compiles `open`, so the feature a diagnostic names and the
/// feature that decides whether the constructor exists are one token. The
/// `requires` literal becomes both the row's `required_var`, which
/// [`check_storage_selection_from_env`] reads, and the variable the
/// constructor reads into the binding the row names.
macro_rules! backend {
    (name: $name:literal, open: $open:block) => {
        Backend {
            name: $name,
            transport_feature: None,
            binary_feature: None,
            required_var: None,
            open: Some::<OpenFn>(|| Box::pin(async move $open)),
        }
    };
    (
        name: $name:literal,
        feature: $feature:literal,
        binary_feature: $binary:expr,
        $(requires: $var:literal as $value:ident,)?
        open: $open:block
    ) => {
        Backend {
            name: $name,
            transport_feature: Some($feature),
            binary_feature: $binary,
            required_var: backend!(@var $($var)?),
            open: {
                #[cfg(feature = $feature)]
                let open = Some::<OpenFn>(|| {
                    Box::pin(async move {
                        $(let $value = required_var_or_exit($name, $var);)?
                        $open
                    })
                });
                #[cfg(not(feature = $feature))]
                let open = None;
                open
            },
        }
    };
    (@var) => { None };
    (@var $var:literal) => { Some($var) };
}

/// Every value [`storage_from_env`] recognizes, with the constructor for it
/// when this build compiled one.
///
/// Each row is one `backend!` invocation, which names the gating feature once,
/// so no second site can disagree with it. [`valid_backends`],
/// [`backend_is_compiled`], the private `reject_backend_message`, the private
/// `required_var` and [`storage_from_env`] all read this table.
const BACKENDS: &[Backend] = &[
    backend! {
        name: "sqlite",
        feature: "sqlite-blob",
        binary_feature: None,
        open: {
            let path =
                env::var("SCP_RELAY_STORAGE_PATH").unwrap_or_else(|_| "./scp-relay.db".to_owned());
            let path = PathBuf::from(path);
            tracing::info!(path = %path.display(), "using sqlite blob storage");
            BlobStorageBackend::sqlite(&path).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(), "failed to open sqlite storage");
                std::process::exit(1);
            })
        }
    },
    backend! {
        name: "redb",
        feature: "redb-blob",
        binary_feature: None,
        open: {
            let path = env::var("SCP_RELAY_STORAGE_PATH")
                .unwrap_or_else(|_| "./scp-relay.redb".to_owned());
            let path = PathBuf::from(path);
            tracing::info!(path = %path.display(), "using redb blob storage");
            BlobStorageBackend::redb(&path).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(), "failed to open redb storage");
                std::process::exit(1);
            })
        }
    },
    backend! {
        name: "postgres",
        feature: "postgres-blob",
        binary_feature: Some("cloud-blobs"),
        requires: "SCP_RELAY_DATABASE_URL" as url,
        open: {
            tracing::info!("using postgres blob storage");
            let store = crate::native::postgres_blob::PostgresBlobStore::open(&url)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to connect to postgres");
                    std::process::exit(1);
                });
            BlobStorageBackend::Postgres(store)
        }
    },
    backend! {
        name: "s3",
        feature: "s3-blob",
        binary_feature: Some("cloud-blobs"),
        requires: "SCP_RELAY_S3_BUCKET" as bucket,
        open: {
            let prefix = env::var("SCP_RELAY_S3_PREFIX").unwrap_or_else(|_| "blobs/".to_owned());
            tracing::info!(bucket = %bucket, prefix = %prefix, "using s3 blob storage");
            let store = crate::native::s3_blob::S3BlobStore::open(&bucket, &prefix)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to initialize s3 storage");
                    std::process::exit(1);
                });
            BlobStorageBackend::S3(store)
        }
    },
    backend! {
        name: "memory",
        open: {
            tracing::warn!("using in-memory blob storage — all data will be lost on restart");
            BlobStorageBackend::in_memory()
        }
    },
];

/// The `SCP_RELAY_STORAGE_BACKEND` values this build can construct, comma
/// separated, for diagnostics and help text.
///
/// This lists the rows of the private `BACKENDS` table that carry a
/// constructor, in table order, so it never offers a backend the binary
/// cannot open. A build with neither cloud feature returns
/// `"sqlite, redb, memory"`; one with both returns
/// `"sqlite, redb, postgres, s3, memory"`.
///
/// This was the hardcoded string `"sqlite, redb, postgres, s3, memory"` until
/// `scp-node` and `scp-relay` stopped enabling `postgres-blob` and `s3-blob` by
/// default, at which point a default build rejected `postgres` and then listed
/// `postgres` among the valid options.
#[must_use]
pub fn valid_backends() -> String {
    BACKENDS
        .iter()
        .filter(|b| b.open.is_some())
        .map(|b| b.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Reports whether this build compiled the constructor [`storage_from_env`]
/// calls for `name`, for a caller that has to predict which of two outcomes a
/// binary linking this crate will produce.
///
/// This reads whether the row of the private `BACKENDS` table carries a
/// constructor, which the row's own `cfg` decides. It deliberately does
/// not parse [`valid_backends`]: a test that compared a binary's diagnostic
/// against a prediction parsed out of the very list that diagnostic is built
/// from would assert a tautology, and would stay green through a revert of
/// [`valid_backends`] to the hardcoded list that named backends a default build
/// cannot construct.
#[must_use]
pub fn backend_is_compiled(name: &str) -> bool {
    BACKENDS.iter().any(|b| b.name == name && b.open.is_some())
}

/// Names the `scp-node` / `scp-relay` cargo feature that compiles the
/// constructor for `name`.
///
/// Returns `None` when no binary feature gates the constructor for `name`, and
/// when `name` names no backend at all.
///
/// `reject_backend_message` prints this name in the rebuild instruction it
/// writes for an uncompiled backend, and the binary reading that instruction
/// declares the name in its own `Cargo.toml`. Nothing in the type system holds
/// the table row and the two manifests in agreement, so a rename in one place
/// alone would send an operator to `cargo build --features <name>` that cargo
/// answers with "none of the selected packages contains this feature".
/// `the_binary_feature_the_message_names_is_declared_by_both_manifests` in
/// `crates/scp-relay/tests/storage_backend.rs` reads this function and the
/// `[features]` table of each manifest, and fails when either manifest omits
/// what this table names.
#[must_use]
pub fn backend_binary_feature(name: &str) -> Option<&'static str> {
    BACKENDS
        .iter()
        .find(|b| b.name == name)
        .and_then(|b| b.binary_feature)
}

/// Writes the message [`storage_from_env`] prints before it exits, for a
/// `SCP_RELAY_STORAGE_BACKEND` value it will not construct.
///
/// The message separates two cases an operator has to tell apart:
///
/// - `requested` names no backend at all, so the operator mistyped a value and
///   the message lists what this build accepts.
/// - `requested` names a backend this build did not compile, so the operator
///   wrote a real value and needs the cargo feature that compiles it.
fn reject_backend_message(requested: &str) -> String {
    let uncompiled = BACKENDS
        .iter()
        .find(|b| b.name == requested && b.open.is_none());

    let Some(backend) = uncompiled else {
        return format!(
            "error: unknown storage backend '{requested}'. Valid options: {}",
            valid_backends()
        );
    };

    let rebuild = match (backend.binary_feature, backend.transport_feature) {
        (Some(binary), Some(transport)) => format!(
            "Rebuild the binary with `--features {binary}`, which enables `scp-transport/{transport}`."
        ),
        (None, Some(transport)) => {
            format!("Rebuild with `scp-transport/{transport}` enabled.")
        }
        (_, None) => String::from("Rebuild with that backend's cargo feature enabled."),
    };

    format!(
        "error: storage backend '{requested}' is not compiled into this binary. \
         {rebuild} Compiled-in options: {}",
        valid_backends()
    )
}

/// Constructs the blob storage backend from environment configuration.
///
/// Reads `SCP_RELAY_STORAGE_BACKEND` (default: `sqlite`) and delegates to the
/// backend constructor that value names. On a value this build cannot
/// construct, it prints the message the private `reject_backend_message` writes
/// and calls [`std::process::exit`].
///
/// # Storage backend selection
///
/// | Value | Backend | Config env vars | Compiled in by |
/// |---|---|---|---|
/// | `sqlite` | `SQLite` | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.db`) | always; the default value |
/// | `redb` | redb | `SCP_RELAY_STORAGE_PATH` (default `./scp-relay.redb`) | always |
/// | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required) | `cloud-blobs` |
/// | `s3` | S3-compat | `SCP_RELAY_S3_BUCKET` (required) + AWS env | `cloud-blobs` |
/// | `memory` | In-memory | — | always |
///
/// # Exit codes
///
/// Every failure path here exits the process with code 1 rather than returning,
/// because a relay that cannot open its blob store has nothing to serve. The
/// function exits when the requested backend names nothing, when it names a
/// backend this build did not compile, when a required env var is absent, and
/// when the backend constructor fails.
///
/// Each constructor compiles only under its `scp-transport` feature
/// (`sqlite-blob`, `redb-blob`, `postgres-blob`, `s3-blob`), and `scp-node`
/// and `scp-relay` leave `postgres-blob` and `s3-blob` off unless a build
/// passes `--features cloud-blobs`. A request for an uncompiled backend prints
/// the feature to rebuild with; it never falls back to another backend.
pub async fn storage_from_env() -> BlobStorageBackend {
    let backend = selected_backend();
    let Some(open) = BACKENDS
        .iter()
        .find(|b| b.name == backend)
        .and_then(|b| b.open)
    else {
        eprintln!("{}", reject_backend_message(&backend));
        std::process::exit(1);
    };
    open().await
}

/// Exits 1 on every `SCP_RELAY_STORAGE_BACKEND` configuration error that
/// [`storage_from_env`] exits on, and returns without opening, connecting to,
/// or creating anything.
///
/// The configuration errors are a value this build did not compile, a value
/// that names no backend, and a missing variable the selected backend requires.
/// Each prints the message [`storage_from_env`] prints for the same error. A
/// caller that writes state of its own before it opens the blob store calls
/// this first, so a configuration error exits before that state exists.
/// Failures of the open itself, such as an unreachable database or an
/// unwritable file, are not configuration errors and surface only from
/// [`storage_from_env`].
pub fn check_storage_selection_from_env() {
    let backend = selected_backend();
    if !backend_is_compiled(&backend) {
        eprintln!("{}", reject_backend_message(&backend));
        std::process::exit(1);
    }
    if let Some(var) = required_var(&backend) {
        let _ = required_var_or_exit(&backend, var);
    }
}

/// The lowercased `SCP_RELAY_STORAGE_BACKEND` value, `sqlite` when unset.
fn selected_backend() -> String {
    storage_backend_var()
        .unwrap_or_else(|| "sqlite".to_owned())
        .to_lowercase()
}

/// The `SCP_RELAY_STORAGE_BACKEND` value the operator set, or `None` when the
/// variable is unset.
///
/// Every caller that selects a blob backend reads the variable through this
/// function, so an unset variable is the only case that selects the default.
#[must_use]
pub fn storage_backend_var() -> Option<String> {
    storage_backend_value(env::var("SCP_RELAY_STORAGE_BACKEND"))
}

/// Maps the result of reading `SCP_RELAY_STORAGE_BACKEND` to the value the
/// operator set.
///
/// A value that is not valid UTF-8 is still a value the operator set, so it
/// returns that value decoded lossily rather than `None`. The decoded value
/// carries a U+FFFD replacement character, so it names no backend, and every
/// caller rejects it as unknown instead of opening the default store.
fn storage_backend_value(read: Result<String, env::VarError>) -> Option<String> {
    match read {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(raw)) => Some(raw.to_string_lossy().into_owned()),
    }
}

/// The environment variable the constructor for `backend` cannot open the
/// backend without, if any, read from its `BACKENDS` row.
fn required_var(backend: &str) -> Option<&'static str> {
    BACKENDS
        .iter()
        .find(|b| b.name == backend)
        .and_then(|b| b.required_var)
}

/// Reads `var`, and exits 1 with a message naming `backend` and `var` when it
/// is unset.
fn required_var_or_exit(backend: &str, var: &str) -> String {
    env::var(var).unwrap_or_else(|_| {
        eprintln!("error: SCP_RELAY_STORAGE_BACKEND={backend} requires {var} to be set");
        std::process::exit(1);
    })
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

#[cfg(test)]
mod tests {
    use super::{
        BACKENDS, backend_is_compiled, reject_backend_message, required_var, storage_backend_value,
        valid_backends,
    };

    /// A value naming no backend reads as a typo, and the message lists what
    /// this build accepts instead of naming a rebuild.
    #[test]
    fn an_unrecognized_value_is_reported_as_unknown() {
        let message = reject_backend_message("banana");
        assert!(
            message.contains("unknown storage backend 'banana'"),
            "{message}"
        );
        assert!(!message.contains("not compiled"), "{message}");
        assert!(message.contains("memory"), "{message}");
    }

    /// [`valid_backends`] names a backend exactly when this build compiled
    /// that backend's constructor. The list was a hardcoded constant until
    /// `postgres-blob` and `s3-blob` stopped being unconditional, and this test
    /// fails on that hardcoded value for any build leaving a backend feature
    /// off. It reads the features with its own `cfg!` calls rather than the
    /// table, so it fails on a row declared with the wrong feature in any build
    /// that separates the two.
    #[test]
    fn the_options_list_names_every_compiled_backend_and_no_other() {
        let listed = valid_backends();
        let names: Vec<&str> = listed.split(", ").collect();

        for (name, enabled) in [
            ("sqlite", cfg!(feature = "sqlite-blob")),
            ("redb", cfg!(feature = "redb-blob")),
            ("postgres", cfg!(feature = "postgres-blob")),
            ("s3", cfg!(feature = "s3-blob")),
            ("memory", true),
        ] {
            assert_eq!(
                names.contains(&name),
                enabled,
                "'{name}' should appear in valid_backends() exactly when its \
                 feature is enabled; the list read '{listed}'"
            );
        }
    }

    /// No two rows of the table claim the same name, and the set of rows is the
    /// one this module was written against.
    ///
    /// This compares the table against a literal, so it fails when a row is
    /// added or dropped. [`storage_from_env`] dispatches through the table
    /// itself, so no value can reach a constructor without a row.
    #[test]
    fn every_table_row_names_a_distinct_backend() {
        let mut names: Vec<&str> = BACKENDS.iter().map(|b| b.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate backend name in BACKENDS");
        assert_eq!(
            names,
            ["memory", "postgres", "redb", "s3", "sqlite"],
            "BACKENDS must name every value storage_from_env recognizes"
        );
    }

    /// Each row names, as its `transport_feature`, the feature this test
    /// expects to gate it.
    ///
    /// `backend!` writes the row's `transport_feature` and the `cfg` on its
    /// constructor from one literal, so this literal comparison is what catches
    /// a row declared with the wrong feature, such as `postgres` gated on
    /// `s3-blob`. `the_compiled_predicate_answers_from_the_features` catches
    /// the same edit through `cfg!` in any build that enables one of the two
    /// features and not the other.
    #[test]
    fn every_row_names_the_feature_that_gates_its_constructor() {
        let rows: Vec<(&str, Option<&str>, Option<&str>)> = BACKENDS
            .iter()
            .map(|b| (b.name, b.transport_feature, b.binary_feature))
            .collect();
        assert_eq!(
            rows,
            [
                ("sqlite", Some("sqlite-blob"), None),
                ("redb", Some("redb-blob"), None),
                ("postgres", Some("postgres-blob"), Some("cloud-blobs")),
                ("s3", Some("s3-blob"), Some("cloud-blobs")),
                ("memory", None, None),
            ]
        );
    }

    /// [`check_storage_selection_from_env`] rejects a missing variable for
    /// exactly `postgres` and `s3`.
    ///
    /// `scp-node` calls the check before it writes its storage key and opens
    /// the blob store after. `backend!` binds the constructor's variable from
    /// the same `requires` literal that fills the row's `required_var`, which
    /// the check reads, so the check cannot miss a variable a constructor
    /// needs.
    #[test]
    fn the_selection_check_requires_the_cloud_backends_variables() {
        let checked: Vec<(&str, &str)> = BACKENDS
            .iter()
            .filter_map(|b| required_var(b.name).map(|var| (b.name, var)))
            .collect();
        assert_eq!(
            checked,
            [
                ("postgres", "SCP_RELAY_DATABASE_URL"),
                ("s3", "SCP_RELAY_S3_BUCKET")
            ]
        );
        assert_eq!(required_var("banana"), None);
    }

    /// [`backend_is_compiled`] answers from the constructors in [`BACKENDS`],
    /// not from [`valid_backends`].
    ///
    /// That is what makes `scp-relay`'s `invalid_backend_exits_with_error` a
    /// comparison between the binary's message and this build's features. A
    /// predicate that parsed [`valid_backends`] would make that test compare
    /// the list against itself, which stays green through a revert of the list
    /// to a hardcoded one.
    #[test]
    fn the_compiled_predicate_answers_from_the_features() {
        for (name, enabled) in [
            ("sqlite", cfg!(feature = "sqlite-blob")),
            ("redb", cfg!(feature = "redb-blob")),
            ("postgres", cfg!(feature = "postgres-blob")),
            ("s3", cfg!(feature = "s3-blob")),
            ("memory", true),
        ] {
            assert_eq!(
                backend_is_compiled(name),
                enabled,
                "'{name}' is compiled in exactly when its feature is enabled"
            );
        }
        assert!(
            !backend_is_compiled("banana"),
            "a value naming no backend is not compiled in"
        );
    }

    /// `postgres` is a real backend, so a build without `postgres-blob` must
    /// say the constructor is absent and name the feature that compiles it, rather than
    /// calling the value unknown.
    #[cfg(not(feature = "postgres-blob"))]
    #[test]
    fn an_uncompiled_postgres_names_the_feature_to_rebuild_with() {
        let message = reject_backend_message("postgres");
        assert!(
            message.contains("'postgres' is not compiled into this binary"),
            "{message}"
        );
        assert!(message.contains("--features cloud-blobs"), "{message}");
        assert!(message.contains("scp-transport/postgres-blob"), "{message}");
        assert!(!message.contains("unknown storage backend"), "{message}");
        assert!(
            !message.contains("Valid options"),
            "an absent constructor is not a typo; {message}"
        );
    }

    /// The `s3` twin of the `postgres` case above.
    #[cfg(not(feature = "s3-blob"))]
    #[test]
    fn an_uncompiled_s3_names_the_feature_to_rebuild_with() {
        let message = reject_backend_message("s3");
        assert!(
            message.contains("'s3' is not compiled into this binary"),
            "{message}"
        );
        assert!(message.contains("--features cloud-blobs"), "{message}");
        assert!(message.contains("scp-transport/s3-blob"), "{message}");
        assert!(!message.contains("unknown storage backend"), "{message}");
    }

    /// [`reject_backend_message`] names a rebuild only for a backend whose row
    /// carries no constructor.
    ///
    /// The edit this test catches is the `&& b.open.is_none()` filter dropping
    /// out of that function's `find`. Without the filter the function matches
    /// the row of a backend this build did compile, and hands an operator who
    /// typed a working value the rebuild instruction written for an absent
    /// constructor. No other test in this module reads that filter:
    /// `an_unrecognized_value_is_reported_as_unknown` passes a name no row
    /// carries, and the two `an_uncompiled_*` tests pass names whose rows carry
    /// no constructor in the builds that run them.
    #[test]
    fn a_compiled_backend_never_reads_as_absent() {
        for backend in BACKENDS.iter().filter(|b| b.open.is_some()) {
            let message = reject_backend_message(backend.name);
            assert!(
                !message.contains("not compiled into this binary"),
                "'{}' is compiled in; {message}",
                backend.name
            );
        }
    }

    /// Only an unset `SCP_RELAY_STORAGE_BACKEND` selects the default. A value
    /// that is not valid UTF-8 is a value the operator set: it reaches the
    /// callers as a string that names no backend, so `storage_from_env` and
    /// `check_storage_selection_from_env` reject it as unknown and `--self-host`
    /// rejects it too, instead of all three opening `sqlite`.
    #[cfg(unix)]
    #[test]
    fn only_an_unset_variable_selects_the_default_backend() {
        use std::env::VarError;
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        assert_eq!(storage_backend_value(Err(VarError::NotPresent)), None);
        assert_eq!(
            storage_backend_value(Ok("Redb".to_owned())).as_deref(),
            Some("Redb")
        );

        let raw = OsString::from_vec(b"sq\xfflite".to_vec());
        let value = storage_backend_value(Err(VarError::NotUnicode(raw)));
        let value = value.unwrap_or_default();
        assert!(
            !value.is_empty(),
            "a non-UTF-8 value must not read as unset"
        );
        assert!(
            !BACKENDS.iter().any(|b| b.name == value.to_lowercase()),
            "a non-UTF-8 value must name no backend; got '{value}'"
        );
        assert!(
            reject_backend_message(&value.to_lowercase()).contains("unknown storage backend"),
            "a non-UTF-8 value must be rejected as unknown"
        );
    }
}
