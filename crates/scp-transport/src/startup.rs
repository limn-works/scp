//! Shared startup utilities for SCP relay and node binaries.
//!
//! Both `scp-relay` and `scp-node` binaries use identical logic for environment
//! variable parsing, relay configuration, blob storage backend selection,
//! tracing initialization, health checks, and graceful shutdown. This module
//! provides the shared implementations so changes need only be made once.
//!
//! No function in this module ends the process. Every failure returns a
//! [`StartupError`] to the calling binary, and the binary decides the exit
//! code.
//!
//! Gated behind the `startup` feature. Not used by the library or FFI bridges.
//!
//! See §10.5 of the SCP infrastructure spec.

use std::env;
use std::ffi::OsString;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use crate::native::server::{RelayConfig, RelayError};
use crate::native::storage::{BlobStorageBackend, StorageError};

/// The variable that names the relay's blob storage backend.
const BACKEND_VAR: &str = "SCP_RELAY_STORAGE_BACKEND";

/// The variable that names the file a `sqlite` or `redb` backend opens.
#[cfg(any(feature = "sqlite-blob", feature = "redb-blob"))]
const STORAGE_PATH_VAR: &str = "SCP_RELAY_STORAGE_PATH";

// ---------------------------------------------------------------------------
// StartupError
// ---------------------------------------------------------------------------

/// Why a relay or node binary cannot start from its environment.
///
/// Every function in this module returns this error instead of ending the
/// process, so the calling binary prints it and picks the exit code.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// `SCP_RELAY_STORAGE_BACKEND` is unset or empty, names no backend, or
    /// names a backend this build did not compile.
    #[error("{}", rejection_message(error, binary_feature))]
    Backend {
        /// Why [`BackendChoice::parse`] refused the value.
        error: BackendSelectionError,
        /// The calling binary's own cargo feature that compiles the `postgres`
        /// and `s3` backends; the message names it for a backend this build
        /// did not compile.
        binary_feature: &'static str,
    },
    /// The selected backend requires `var`, and `var` is unset or empty. None
    /// of these variables has a default.
    #[error(
        "{BACKEND_VAR}={backend} requires {var} to be set to a non-empty value; {var} has no default"
    )]
    MissingVar {
        /// The backend the operator selected.
        backend: &'static str,
        /// The variable the backend requires.
        var: &'static str,
    },
    /// `var` names a relative path. A relative path resolves against the
    /// working directory the process starts in, so two starts from two
    /// directories open two different stores.
    #[error(
        "{var}='{}' is a relative path, which opens a different store for each working \
         directory the process starts in; set an absolute path",
        path.display()
    )]
    RelativePath {
        /// The variable that holds the path.
        var: &'static str,
        /// The relative path the operator set.
        path: PathBuf,
    },
    /// `var` is set to a value this module cannot parse. The message omits the
    /// value itself.
    #[error("{var} is set to a value that does not parse: {reason}")]
    InvalidValue {
        /// The variable that holds the value.
        var: &'static str,
        /// Why the value does not parse.
        reason: String,
    },
    /// The selected backend's store did not open (SCP-CAPSEL-8001, persistence
    /// spec §17.17.1: a failed selection is terminal).
    #[error("failed to open the {backend} blob store: {error}")]
    StoreOpen {
        /// The backend the operator selected.
        backend: &'static str,
        /// The open failure the store returned.
        error: StorageError,
    },
    /// The relay server did not bind its listener.
    #[error("relay failed to start: {0}")]
    Relay(RelayError),
    /// The tracing subscriber did not install, because another global
    /// subscriber was already installed.
    #[error("failed to install the tracing subscriber: {0}")]
    Tracing(String),
    /// The operating system refused a handler for `signal`, so the process
    /// could not learn when to shut down.
    #[error("failed to register a {signal} handler: {error}")]
    SignalHandler {
        /// The signal the handler was for.
        signal: &'static str,
        /// The registration failure.
        error: std::io::Error,
    },
}

// ---------------------------------------------------------------------------
// env_or — typed environment variable with a documented default
// ---------------------------------------------------------------------------

/// Reads environment variable `name` and parses it as `T`, returning
/// `default` when the variable is unset.
///
/// Use this only for a tunable whose default the operator documentation
/// states, such as a bind address or a limit. A provider selection, such as
/// the blob storage backend, has no default (persistence spec §17.17.1,
/// SCP-CAPSEL-8000) and never goes through this function.
///
/// # Errors
///
/// [`StartupError::InvalidValue`] when the variable is set and its value is
/// not UTF-8 or does not parse as `T`. An empty value does not parse as any
/// type this module reads, so it is an error as well.
pub fn env_or<T>(name: &'static str, default: T) -> Result<T, StartupError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    parse_or(name, env::var_os(name), default)
}

/// Parses `raw`, the value of variable `name`, as `T`, or returns `default`
/// when `raw` is `None`.
fn parse_or<T>(name: &'static str, raw: Option<OsString>, default: T) -> Result<T, StartupError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let Some(raw) = raw else {
        return Ok(default);
    };
    let text = utf8(name, raw)?;
    text.parse()
        .map_err(|e: T::Err| StartupError::InvalidValue {
            var: name,
            reason: e.to_string(),
        })
}

/// Converts `raw`, the value of variable `name`, to a `String`.
fn utf8(name: &'static str, raw: OsString) -> Result<String, StartupError> {
    raw.into_string().map_err(|_| StartupError::InvalidValue {
        var: name,
        reason: "the value is not valid UTF-8".to_owned(),
    })
}

/// Whether `raw` holds nothing but whitespace.
#[cfg(any(
    feature = "sqlite-blob",
    feature = "redb-blob",
    feature = "postgres-blob",
    feature = "s3-blob"
))]
fn is_blank(raw: &std::ffi::OsStr) -> bool {
    raw.to_string_lossy().trim().is_empty()
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
///
/// # Errors
///
/// [`StartupError::InvalidValue`] when one of these variables is set to a
/// value that does not parse.
pub fn relay_config_from_env() -> Result<RelayConfig, StartupError> {
    Ok(RelayConfig {
        bind_addr: env_or(
            "SCP_RELAY_BIND_ADDR",
            SocketAddr::from(([0, 0, 0, 0], 9000)),
        )?,
        max_blob_size: env_or("SCP_RELAY_MAX_BLOB_SIZE", 262_144)?,
        max_blob_ttl: env_or("SCP_RELAY_MAX_BLOB_TTL", scp_relay_client::MAX_BLOB_TTL)?,
        max_total_connections: env_or("SCP_RELAY_MAX_CONNECTIONS", 1_000)?,
        max_connections_per_ip: env_or("SCP_RELAY_MAX_CONNECTIONS_PER_IP", 10)?,
        rate_limit_publishes_per_second: env_or("SCP_RELAY_RATE_LIMIT", 100)?,
        ..RelayConfig::default()
    })
}

// ---------------------------------------------------------------------------
// Blob storage backend from environment
// ---------------------------------------------------------------------------

/// The `SCP_RELAY_STORAGE_BACKEND` values this build can construct, comma
/// separated, derived from the features this build compiled.
#[must_use]
pub fn valid_backends() -> String {
    let mut names: Vec<&str> = Vec::new();
    if cfg!(feature = "sqlite-blob") {
        names.push("sqlite");
    }
    if cfg!(feature = "redb-blob") {
        names.push("redb");
    }
    if cfg!(feature = "postgres-blob") {
        names.push("postgres");
    }
    if cfg!(feature = "s3-blob") {
        names.push("s3");
    }
    names.push("memory");
    names.join(", ")
}

/// A `SCP_RELAY_STORAGE_BACKEND` value [`BackendChoice::parse`] refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendSelectionError {
    /// The variable is unset, empty, or holds only whitespace. The backend
    /// selection has no default (persistence spec §17.7 and §17.17.1,
    /// SCP-CAPSEL-8000).
    Unset,
    /// The value names `postgres` or `s3`, and this build did not compile that
    /// backend. [`BackendChoice::parse`] returns this variant for those two
    /// names only.
    NotCompiled {
        /// The lowercase name of the backend the operator selected,
        /// `postgres` or `s3`, whatever letter case the operator set.
        backend: &'static str,
        /// The `scp-transport` cargo feature that compiles `backend`:
        /// `postgres-blob` or `s3-blob`. The binary's own feature that
        /// enables it is the `binary_feature` its caller passes to
        /// [`backend_choice_from_env`].
        feature: &'static str,
    },
    /// The value names no backend this build compiled, and is neither
    /// `postgres` nor `s3`.
    Unknown {
        /// The value the operator set, with its case as set.
        value: String,
    },
}

impl BackendSelectionError {
    /// The persistence spec rule (§17.17.1) this refusal enforces.
    ///
    /// An unset or unknown value makes no selection, which SCP-CAPSEL-8000
    /// (selection is mandatory; there is no default) forbids. A value naming a
    /// backend this build did not compile selects an implementation that can
    /// never succeed, which SCP-CAPSEL-8001 (selection fails closed) covers.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::Unset | Self::Unknown { .. } => "SCP-CAPSEL-8000",
            Self::NotCompiled { .. } => "SCP-CAPSEL-8001",
        }
    }
}

impl std::fmt::Display for BackendSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unset => write!(
                f,
                "{BACKEND_VAR} is unset or empty, and it has no default ({}: a relay starts \
                 only on a backend the operator names). Set it to one of: {}",
                self.rule(),
                valid_backends()
            ),
            Self::NotCompiled { backend, feature } => write!(
                f,
                "storage backend '{backend}' is not compiled into this binary, which was \
                 built without scp-transport's `{feature}` feature. Compiled-in options: {}",
                valid_backends()
            ),
            Self::Unknown { value } => write!(
                f,
                "unknown storage backend '{value}'. Valid options: {}",
                valid_backends()
            ),
        }
    }
}

impl std::error::Error for BackendSelectionError {}

/// A blob storage backend this build compiled, parsed from a
/// `SCP_RELAY_STORAGE_BACKEND` value.
///
/// A variant exists only in a build that compiled its backend, so
/// [`storage_from_env`] matches every variant with no rejection arm. A caller
/// that asks whether a value selects a cloud backend matches the result of
/// [`BackendChoice::parse`] instead of listing the backend names again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    /// `sqlite`.
    #[cfg(feature = "sqlite-blob")]
    Sqlite,
    /// `redb`.
    #[cfg(feature = "redb-blob")]
    Redb,
    /// `postgres`.
    #[cfg(feature = "postgres-blob")]
    Postgres,
    /// `s3`.
    #[cfg(feature = "s3-blob")]
    S3,
    /// `memory`.
    Memory,
}

impl BackendChoice {
    /// Parses a `SCP_RELAY_STORAGE_BACKEND` value, ignoring case.
    ///
    /// # Errors
    ///
    /// [`BackendSelectionError::Unset`] when the value is empty or holds only
    /// whitespace, [`BackendSelectionError::NotCompiled`] when the value is
    /// `postgres` or `s3` and this build did not compile that backend, and
    /// [`BackendSelectionError::Unknown`] for every other value this build has
    /// no backend for.
    pub fn parse(value: &str) -> Result<Self, BackendSelectionError> {
        if value.trim().is_empty() {
            return Err(BackendSelectionError::Unset);
        }
        match value.to_lowercase().as_str() {
            #[cfg(feature = "sqlite-blob")]
            "sqlite" => Ok(Self::Sqlite),
            #[cfg(feature = "redb-blob")]
            "redb" => Ok(Self::Redb),
            #[cfg(feature = "postgres-blob")]
            "postgres" => Ok(Self::Postgres),
            #[cfg(not(feature = "postgres-blob"))]
            "postgres" => Err(BackendSelectionError::NotCompiled {
                backend: "postgres",
                feature: "postgres-blob",
            }),
            #[cfg(feature = "s3-blob")]
            "s3" => Ok(Self::S3),
            #[cfg(not(feature = "s3-blob"))]
            "s3" => Err(BackendSelectionError::NotCompiled {
                backend: "s3",
                feature: "s3-blob",
            }),
            "memory" => Ok(Self::Memory),
            _ => Err(BackendSelectionError::Unknown {
                value: value.to_owned(),
            }),
        }
    }

    /// Whether this backend stores blobs in a network service (`PostgreSQL`
    /// or S3) rather than on this machine.
    #[must_use]
    pub const fn is_cloud(self) -> bool {
        match self {
            #[cfg(feature = "sqlite-blob")]
            Self::Sqlite => false,
            #[cfg(feature = "redb-blob")]
            Self::Redb => false,
            #[cfg(feature = "postgres-blob")]
            Self::Postgres => true,
            #[cfg(feature = "s3-blob")]
            Self::S3 => true,
            Self::Memory => false,
        }
    }
}

/// The text a binary prints when [`BackendChoice::parse`] rejects
/// `SCP_RELAY_STORAGE_BACKEND`.
///
/// For [`BackendSelectionError::NotCompiled`] the text also tells the
/// operator to rebuild with `binary_feature`, the binary's own cargo feature
/// that enables the missing `scp-transport` feature.
fn rejection_message(error: &BackendSelectionError, binary_feature: &str) -> String {
    match error {
        BackendSelectionError::NotCompiled { .. } => {
            format!("{error}\nrebuild this binary with `--features {binary_feature}`")
        }
        BackendSelectionError::Unset | BackendSelectionError::Unknown { .. } => error.to_string(),
    }
}

/// Parses `SCP_RELAY_STORAGE_BACKEND`, which has no default.
///
/// A binary calls this before it creates a directory, a key, or a store, so a
/// rejected value leaves nothing behind, and passes the result to
/// [`storage_from_env`]. `binary_feature` names the calling binary's own
/// cargo feature that compiles the `postgres` and `s3` backends; when this
/// build lacks either, the error tells the operator to rebuild with that
/// feature.
///
/// # Storage backend selection
///
/// [`storage_from_env`] reads the config variables of the backend this
/// function chose. No variable in this table has a default.
///
/// | Value | Backend | Config env vars |
/// |---|---|---|
/// | `sqlite` | `SQLite` | `SCP_RELAY_STORAGE_PATH` (required, absolute) |
/// | `redb` | redb | `SCP_RELAY_STORAGE_PATH` (required, absolute) |
/// | `postgres` | `PostgreSQL` | `SCP_RELAY_DATABASE_URL` (required) |
/// | `s3` | S3-compat | `SCP_RELAY_S3_BUCKET` (required) + AWS env |
/// | `memory` | In-memory | — |
///
/// # Errors
///
/// [`StartupError::Backend`] carrying [`BackendSelectionError::Unset`] when the
/// variable is unset, empty, or whitespace, and carrying the other
/// [`BackendSelectionError`] variants for a value this build cannot serve.
pub fn backend_choice_from_env(
    binary_feature: &'static str,
) -> Result<BackendChoice, StartupError> {
    backend_choice_from_value(env::var_os(BACKEND_VAR), binary_feature)
}

/// Parses `raw`, the value of `SCP_RELAY_STORAGE_BACKEND`, where `None` means
/// the variable is unset.
fn backend_choice_from_value(
    raw: Option<OsString>,
    binary_feature: &'static str,
) -> Result<BackendChoice, StartupError> {
    raw.map_or(Err(BackendSelectionError::Unset), |raw| {
        BackendChoice::parse(&raw.to_string_lossy())
    })
    .map_err(|error| StartupError::Backend {
        error,
        binary_feature,
    })
}

/// Reads `raw`, the value of `SCP_RELAY_STORAGE_PATH`, as the file a `backend`
/// store opens.
///
/// The path has no default, so an unset or blank value is an error. A relative
/// path is an error too, because it resolves against the working directory: a
/// relay started once from `/srv` and once from `/` would open two files, and
/// the second start would serve none of the blobs the first one stored.
#[cfg(any(feature = "sqlite-blob", feature = "redb-blob"))]
fn storage_path(backend: &'static str, raw: Option<OsString>) -> Result<PathBuf, StartupError> {
    let Some(raw) = raw.filter(|raw| !is_blank(raw)) else {
        return Err(StartupError::MissingVar {
            backend,
            var: STORAGE_PATH_VAR,
        });
    };
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(StartupError::RelativePath {
            var: STORAGE_PATH_VAR,
            path,
        });
    }
    Ok(path)
}

/// Reads `raw`, the value of variable `var` that `backend` requires.
///
/// An unset or blank value is [`StartupError::MissingVar`]; a value that is
/// not UTF-8 is [`StartupError::InvalidValue`].
#[cfg(any(feature = "postgres-blob", feature = "s3-blob"))]
fn required_value(
    backend: &'static str,
    var: &'static str,
    raw: Option<OsString>,
) -> Result<String, StartupError> {
    match raw {
        Some(raw) if !is_blank(&raw) => utf8(var, raw),
        _ => Err(StartupError::MissingVar { backend, var }),
    }
}

/// Constructs the blob storage backend `choice` names, reading that
/// backend's configuration from the environment.
///
/// `choice` comes from [`backend_choice_from_env`]. This function applies no
/// default to any variable it reads, except `SCP_RELAY_S3_PREFIX`, whose
/// default `blobs/` is the key prefix the S3 key layout in persistence spec
/// §17.7 names. The doc comment of [`backend_choice_from_env`] lists each
/// backend's config variables.
///
/// # Backend availability
///
/// Backend arms are compiled only when the corresponding feature is enabled
/// (`sqlite-blob`, `redb-blob`, `postgres-blob`, `s3-blob`), and a
/// [`BackendChoice`] variant exists only for a compiled arm. `scp-node` and
/// `scp-relay` enable `postgres-blob` and `s3-blob` only under their
/// off-by-default `cloud-blobs` feature. A request for `postgres` or `s3` in
/// a build without it fails in [`backend_choice_from_env`] and never reaches
/// this function, so it never falls back to another backend.
///
/// # Errors
///
/// - [`StartupError::MissingVar`] when the chosen backend's required variable
///   (`SCP_RELAY_STORAGE_PATH`, `SCP_RELAY_DATABASE_URL`, or
///   `SCP_RELAY_S3_BUCKET`) is unset or blank.
/// - [`StartupError::RelativePath`] when `SCP_RELAY_STORAGE_PATH` is relative.
/// - [`StartupError::InvalidValue`] when a variable it reads is not UTF-8.
/// - [`StartupError::StoreOpen`] when the store fails to open.
#[cfg_attr(
    not(any(feature = "postgres-blob", feature = "s3-blob")),
    expect(
        clippy::unused_async,
        reason = "only the postgres and s3 arms await, and this build compiled neither"
    )
)]
pub async fn storage_from_env(choice: BackendChoice) -> Result<BlobStorageBackend, StartupError> {
    match choice {
        #[cfg(feature = "sqlite-blob")]
        BackendChoice::Sqlite => {
            let path = storage_path("sqlite", env::var_os(STORAGE_PATH_VAR))?;
            tracing::info!(path = %path.display(), "using sqlite blob storage");
            BlobStorageBackend::sqlite(&path).map_err(|error| StartupError::StoreOpen {
                backend: "sqlite",
                error,
            })
        }
        #[cfg(feature = "redb-blob")]
        BackendChoice::Redb => {
            let path = storage_path("redb", env::var_os(STORAGE_PATH_VAR))?;
            tracing::info!(path = %path.display(), "using redb blob storage");
            BlobStorageBackend::redb(&path).map_err(|error| StartupError::StoreOpen {
                backend: "redb",
                error,
            })
        }
        #[cfg(feature = "postgres-blob")]
        BackendChoice::Postgres => {
            const URL_VAR: &str = "SCP_RELAY_DATABASE_URL";
            let url = required_value("postgres", URL_VAR, env::var_os(URL_VAR))?;
            tracing::info!("using postgres blob storage");
            let store = crate::native::postgres_blob::PostgresBlobStore::open(&url)
                .await
                .map_err(|error| StartupError::StoreOpen {
                    backend: "postgres",
                    error,
                })?;
            Ok(BlobStorageBackend::Postgres(store))
        }
        #[cfg(feature = "s3-blob")]
        BackendChoice::S3 => {
            const BUCKET_VAR: &str = "SCP_RELAY_S3_BUCKET";
            const PREFIX_VAR: &str = "SCP_RELAY_S3_PREFIX";
            let bucket = required_value("s3", BUCKET_VAR, env::var_os(BUCKET_VAR))?;
            let prefix = match env::var_os(PREFIX_VAR) {
                None => "blobs/".to_owned(),
                Some(raw) => utf8(PREFIX_VAR, raw)?,
            };
            tracing::info!(bucket = %bucket, prefix = %prefix, "using s3 blob storage");
            let store = crate::native::s3_blob::S3BlobStore::open(&bucket, &prefix)
                .await
                .map_err(|error| StartupError::StoreOpen {
                    backend: "s3",
                    error,
                })?;
            Ok(BlobStorageBackend::S3(store))
        }
        BackendChoice::Memory => {
            tracing::warn!("using in-memory blob storage — all data will be lost on restart");
            Ok(BlobStorageBackend::in_memory())
        }
    }
}

// ---------------------------------------------------------------------------
// Tracing initialization
// ---------------------------------------------------------------------------

/// Builds the log filter from `rust_log`, the value of `RUST_LOG`, which takes
/// precedence, or else from `level`, the value of `SCP_RELAY_LOG_LEVEL`, whose
/// default is `info`.
fn log_filter(
    rust_log: Option<OsString>,
    level: Option<OsString>,
) -> Result<EnvFilter, StartupError> {
    let (var, directives) = match (rust_log, level) {
        (Some(raw), _) => ("RUST_LOG", utf8("RUST_LOG", raw)?),
        (None, Some(raw)) => ("SCP_RELAY_LOG_LEVEL", utf8("SCP_RELAY_LOG_LEVEL", raw)?),
        (None, None) => ("SCP_RELAY_LOG_LEVEL", "info".to_owned()),
    };
    EnvFilter::try_new(&directives).map_err(|e| StartupError::InvalidValue {
        var,
        reason: e.to_string(),
    })
}

/// Whether `raw`, the value of `SCP_RELAY_LOG_FORMAT`, selects JSON output.
/// The default is `pretty`.
fn log_format_is_json(raw: Option<OsString>) -> Result<bool, StartupError> {
    const VAR: &str = "SCP_RELAY_LOG_FORMAT";
    let Some(raw) = raw else {
        return Ok(false);
    };
    match utf8(VAR, raw)?.as_str() {
        "json" => Ok(true),
        "pretty" => Ok(false),
        _ => Err(StartupError::InvalidValue {
            var: VAR,
            reason: "expected `json` or `pretty`".to_owned(),
        }),
    }
}

/// Installs the global `tracing` subscriber.
///
/// Log level is determined by `RUST_LOG` (takes precedence) or
/// `SCP_RELAY_LOG_LEVEL` (default: `info`). Output format is controlled
/// by `SCP_RELAY_LOG_FORMAT`: `json` for structured JSON, `pretty` (the
/// default) for human-readable output.
///
/// # Errors
///
/// [`StartupError::InvalidValue`] when one of those variables holds a value
/// that does not parse, and [`StartupError::Tracing`] when another global
/// subscriber is already installed.
pub fn init_tracing() -> Result<(), StartupError> {
    let filter = log_filter(env::var_os("RUST_LOG"), env::var_os("SCP_RELAY_LOG_LEVEL"))?;
    let installed = if log_format_is_json(env::var_os("SCP_RELAY_LOG_FORMAT"))? {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init()
    };
    installed.map_err(|e| StartupError::Tracing(e.to_string()))
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

/// Runs a TCP health probe against `addr` and returns whether the connection
/// succeeded.
///
/// Designed for container health checks (`--health` CLI flag). Each binary
/// turns `false` into exit code 1.
pub async fn health_check(addr: SocketAddr) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

/// Registers SIGINT and SIGTERM handlers and returns a future that resolves
/// when either signal arrives.
///
/// The handlers register when this function runs, so a refused registration
/// fails startup instead of leaving a process that cannot learn when to stop.
/// Call it from inside a Tokio runtime.
///
/// # Errors
///
/// [`StartupError::SignalHandler`] when the operating system refuses either
/// handler.
#[cfg(unix)]
pub fn shutdown_signal() -> Result<impl Future<Output = ()> + Send + 'static, StartupError> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| StartupError::SignalHandler {
            signal: "SIGINT",
            error,
        })?;
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| StartupError::SignalHandler {
            signal: "SIGTERM",
            error,
        })?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

/// Registers a Ctrl-C handler and returns a future that resolves when Ctrl-C
/// arrives.
///
/// The handler registers when this function runs, so a refused registration
/// fails startup instead of leaving a process that cannot learn when to stop.
/// Call it from inside a Tokio runtime.
///
/// # Errors
///
/// [`StartupError::SignalHandler`] when the operating system refuses the
/// handler.
#[cfg(windows)]
pub fn shutdown_signal() -> Result<impl Future<Output = ()> + Send + 'static, StartupError> {
    let mut ctrl_c =
        tokio::signal::windows::ctrl_c().map_err(|error| StartupError::SignalHandler {
            signal: "Ctrl-C",
            error,
        })?;
    Ok(async move {
        ctrl_c.recv().await;
    })
}

// ---------------------------------------------------------------------------
// Relay startup helper
// ---------------------------------------------------------------------------

/// Starts a relay server from environment configuration and returns the
/// server handle, bound address, and storage reference.
///
/// This encapsulates the common pattern of reading config + storage from env,
/// building the relay, starting it, and logging the result. `backend` comes
/// from [`backend_choice_from_env`].
///
/// # Errors
///
/// Every error [`relay_config_from_env`] and [`storage_from_env`] return, and
/// [`StartupError::Relay`] when the relay cannot bind its address.
pub async fn start_relay_from_env(
    backend: BackendChoice,
) -> Result<
    (
        crate::native::server::ShutdownHandle,
        SocketAddr,
        Arc<BlobStorageBackend>,
    ),
    StartupError,
> {
    let config = relay_config_from_env()?;
    tracing::info!(
        bind_addr = %config.bind_addr,
        max_blob_size = config.max_blob_size,
        max_connections = config.max_total_connections,
        "starting relay"
    );

    let storage = Arc::new(storage_from_env(backend).await?);
    let server = crate::native::server::RelayServer::new(config, Arc::clone(&storage));
    let (handle, local_addr) = server.start().await.map_err(StartupError::Relay)?;

    tracing::info!(addr = %local_addr, "relay listening");

    Ok((handle, local_addr, storage))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{
        BackendChoice, BackendSelectionError, StartupError, backend_choice_from_value, log_filter,
        log_format_is_json, parse_or, rejection_message, valid_backends,
    };

    /// `parse` accepts a name in either case exactly when this build compiled
    /// its backend, returns `NotCompiled` naming the backend's own
    /// `scp-transport` feature for a cloud backend this build left out, and
    /// calls every other value unknown.
    #[test]
    fn parse_accepts_exactly_the_compiled_backends() {
        for (name, feature, compiled, cloud) in [
            (
                "sqlite",
                "sqlite-blob",
                cfg!(feature = "sqlite-blob"),
                false,
            ),
            ("redb", "redb-blob", cfg!(feature = "redb-blob"), false),
            (
                "postgres",
                "postgres-blob",
                cfg!(feature = "postgres-blob"),
                true,
            ),
            ("s3", "s3-blob", cfg!(feature = "s3-blob"), true),
            ("memory", "", true, false),
        ] {
            for value in [name.to_owned(), name.to_uppercase()] {
                let parsed = BackendChoice::parse(&value);
                if compiled {
                    assert_eq!(parsed.map(BackendChoice::is_cloud), Ok(cloud), "{value}");
                } else if cloud {
                    assert_eq!(
                        parsed,
                        Err(BackendSelectionError::NotCompiled {
                            backend: name,
                            feature,
                        }),
                        "{value}"
                    );
                } else {
                    assert!(
                        matches!(parsed, Err(BackendSelectionError::Unknown { .. })),
                        "{value}: {parsed:?}"
                    );
                }
            }
        }
        assert_eq!(
            BackendChoice::parse("banana"),
            Err(BackendSelectionError::Unknown {
                value: "banana".to_owned()
            })
        );
        // An unknown value keeps the case the operator set, so the exit
        // message echoes the operator's own value.
        let mixed_case = BackendSelectionError::Unknown {
            value: "Banana".to_owned(),
        };
        assert_eq!(BackendChoice::parse("Banana"), Err(mixed_case.clone()));
        let display = mixed_case.to_string();
        assert!(display.contains("'Banana'"), "{display}");
    }

    /// The options list names a backend exactly when this build compiled it.
    #[test]
    fn the_options_list_names_exactly_the_compiled_backends() {
        let listed = valid_backends();
        let names: Vec<&str> = listed.split(", ").collect();
        for (name, compiled) in [
            ("sqlite", cfg!(feature = "sqlite-blob")),
            ("redb", cfg!(feature = "redb-blob")),
            ("postgres", cfg!(feature = "postgres-blob")),
            ("s3", cfg!(feature = "s3-blob")),
            ("memory", true),
        ] {
            assert_eq!(names.contains(&name), compiled, "{name} in '{listed}'");
        }
    }

    /// The not-compiled error names the backend and scp-transport's own
    /// feature for it, and names no binary's feature; the exit message adds
    /// the feature the calling binary passed, and only for a not-compiled
    /// backend.
    #[test]
    fn a_not_compiled_backend_names_the_feature() {
        let error = BackendSelectionError::NotCompiled {
            backend: "postgres",
            feature: "postgres-blob",
        };
        let display = error.to_string();
        assert!(display.contains("'postgres' is not compiled"), "{display}");
        assert!(display.contains("`postgres-blob`"), "{display}");
        assert!(!display.contains("cloud-blobs"), "{display}");
        assert!(!display.contains("unknown"), "{display}");

        let exit = rejection_message(&error, "some-binary-feature");
        assert!(exit.starts_with(&display), "{exit}");
        assert!(exit.contains("--features some-binary-feature"), "{exit}");

        let unknown = BackendSelectionError::Unknown {
            value: "banana".to_owned(),
        };
        let exit = rejection_message(&unknown, "some-binary-feature");
        assert_eq!(exit, unknown.to_string());
    }

    /// An unset `SCP_RELAY_STORAGE_BACKEND`, an empty one, and a whitespace one
    /// each select nothing: the result is `Unset`, which enforces
    /// SCP-CAPSEL-8000, and the message names the variable, the rule, and the
    /// backends this build compiled. Restoring a `sqlite` default for an unset
    /// variable makes the `None` case return `Ok(Sqlite)` and fail here.
    #[test]
    fn an_unset_or_empty_backend_is_unset_under_capsel_8000() {
        for raw in [None, Some(""), Some("   ")] {
            let result = backend_choice_from_value(raw.map(OsString::from), "cloud-blobs");
            assert!(
                matches!(
                    &result,
                    Err(StartupError::Backend {
                        error: BackendSelectionError::Unset,
                        binary_feature: "cloud-blobs",
                    })
                ),
                "{raw:?} must be rejected as Unset; got {result:?}"
            );
            assert_eq!(BackendSelectionError::Unset.rule(), "SCP-CAPSEL-8000");
            let message = result.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(message.contains("SCP_RELAY_STORAGE_BACKEND"), "{message}");
            assert!(message.contains("SCP-CAPSEL-8000"), "{message}");
            assert!(message.contains(&valid_backends()), "{message}");
            assert!(!message.contains("--features"), "{message}");
        }
        assert_eq!(BackendChoice::parse(""), Err(BackendSelectionError::Unset));
    }

    /// Each refusal maps to the persistence spec rule it enforces.
    #[test]
    fn each_refusal_names_its_capsel_rule() {
        assert_eq!(BackendSelectionError::Unset.rule(), "SCP-CAPSEL-8000");
        assert_eq!(
            BackendSelectionError::Unknown {
                value: "banana".to_owned()
            }
            .rule(),
            "SCP-CAPSEL-8000"
        );
        assert_eq!(
            BackendSelectionError::NotCompiled {
                backend: "s3",
                feature: "s3-blob"
            }
            .rule(),
            "SCP-CAPSEL-8001"
        );
    }

    /// A named backend parses through the same path the binaries read.
    #[test]
    fn an_explicit_backend_parses() {
        assert!(matches!(
            backend_choice_from_value(Some(OsString::from("memory")), "cloud-blobs"),
            Ok(BackendChoice::Memory)
        ));
    }

    /// A tunable returns its default only when unset; a set value that does
    /// not parse, an empty one included, is an error naming the variable and
    /// never the default.
    #[test]
    fn a_malformed_tunable_is_an_error_and_not_its_default() {
        assert_eq!(
            parse_or::<u16>("SCP_TEST_PORT", None, 9001).ok(),
            Some(9001)
        );
        assert_eq!(
            parse_or::<u16>("SCP_TEST_PORT", Some(OsString::from("8080")), 9001).ok(),
            Some(8080)
        );
        for bad in ["", "eighty", "70000"] {
            let result = parse_or::<u16>("SCP_TEST_PORT", Some(OsString::from(bad)), 9001);
            assert!(
                matches!(
                    result,
                    Err(StartupError::InvalidValue {
                        var: "SCP_TEST_PORT",
                        ..
                    })
                ),
                "{bad:?}: {result:?}"
            );
        }
    }

    /// The log filter and format accept their documented values and defaults,
    /// and reject anything else instead of falling back to `info` or `pretty`.
    #[test]
    fn a_malformed_log_setting_is_an_error() {
        assert!(log_filter(None, None).is_ok());
        assert!(log_filter(None, Some(OsString::from("debug"))).is_ok());
        assert!(log_filter(Some(OsString::from("scp_relay=info")), None).is_ok());
        assert!(matches!(
            log_filter(None, Some(OsString::from("info=info=info"))),
            Err(StartupError::InvalidValue {
                var: "SCP_RELAY_LOG_LEVEL",
                ..
            })
        ));
        assert!(matches!(
            log_filter(Some(OsString::from("info=info=info")), None),
            Err(StartupError::InvalidValue {
                var: "RUST_LOG",
                ..
            })
        ));
        assert_eq!(log_format_is_json(None).ok(), Some(false));
        assert_eq!(
            log_format_is_json(Some(OsString::from("json"))).ok(),
            Some(true)
        );
        assert_eq!(
            log_format_is_json(Some(OsString::from("pretty"))).ok(),
            Some(false)
        );
        assert!(matches!(
            log_format_is_json(Some(OsString::from("JSON "))),
            Err(StartupError::InvalidValue {
                var: "SCP_RELAY_LOG_FORMAT",
                ..
            })
        ));
    }

    /// `SCP_RELAY_STORAGE_PATH` has no default: unset, empty, and blank values
    /// are `MissingVar`, a relative path is `RelativePath`, and an absolute
    /// path comes back unchanged. Restoring the `./scp-relay.db` default makes
    /// the `None` case return a path and fail here.
    #[cfg(any(feature = "sqlite-blob", feature = "redb-blob"))]
    #[test]
    fn a_storage_path_must_be_set_and_absolute() {
        use super::storage_path;

        for raw in [None, Some(""), Some("  ")] {
            let result = storage_path("sqlite", raw.map(OsString::from));
            assert!(
                matches!(
                    result,
                    Err(StartupError::MissingVar {
                        backend: "sqlite",
                        var: "SCP_RELAY_STORAGE_PATH"
                    })
                ),
                "{raw:?}: {result:?}"
            );
        }
        for raw in ["./scp-relay.db", "scp-relay.redb", "data/relay.db"] {
            let result = storage_path("redb", Some(OsString::from(raw)));
            assert!(
                matches!(&result, Err(StartupError::RelativePath { .. })),
                "{raw} must be refused as relative; got {result:?}"
            );
            let message = result.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(message.contains("SCP_RELAY_STORAGE_PATH"), "{message}");
            assert!(message.contains("relative"), "{message}");
        }
        let path = std::env::temp_dir().join("relay.db");
        let resolved = storage_path("sqlite", Some(path.clone().into_os_string()));
        assert_eq!(resolved.ok(), Some(path));
    }

    /// A required cloud variable has no default: unset and blank values are
    /// `MissingVar` naming the variable.
    #[cfg(any(feature = "postgres-blob", feature = "s3-blob"))]
    #[test]
    fn a_required_cloud_variable_must_be_set() {
        use super::required_value;

        for raw in [None, Some(""), Some(" ")] {
            let result = required_value("s3", "SCP_RELAY_S3_BUCKET", raw.map(OsString::from));
            assert!(
                matches!(
                    result,
                    Err(StartupError::MissingVar {
                        backend: "s3",
                        var: "SCP_RELAY_S3_BUCKET"
                    })
                ),
                "{raw:?}: {result:?}"
            );
        }
        assert_eq!(
            required_value("s3", "SCP_RELAY_S3_BUCKET", Some(OsString::from("b"))).ok(),
            Some("b".to_owned())
        );
    }
}
