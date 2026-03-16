//! Configuration for the personal relay.
//!
//! All settings are loaded from environment variables with sensible defaults.
//! See the [`Config`] struct for the full list.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Personal relay configuration, loaded from environment variables.
pub struct Config {
    /// Domain name for TLS and DID document publication (e.g., `relay.example.com`).
    /// When set, ACME (Let's Encrypt) provisions a TLS certificate automatically.
    ///
    /// Env: `SCP_RELAY_DOMAIN`
    pub domain: Option<String>,

    /// Contact email for Let's Encrypt ACME account registration.
    /// Optional but recommended -- Let's Encrypt sends expiry warnings here.
    ///
    /// Env: `SCP_RELAY_ACME_EMAIL`
    pub acme_email: Option<String>,

    /// Public HTTP/HTTPS bind address. Clients connect here.
    /// Default: `0.0.0.0:443` when a domain is set, `0.0.0.0:9000` otherwise.
    ///
    /// Env: `SCP_RELAY_BIND_ADDR`
    pub bind_addr: SocketAddr,

    /// Use a self-signed TLS certificate instead of ACME (development only).
    /// Default: `false`.
    ///
    /// Env: `SCP_RELAY_TLS_SELF_SIGNED` (set to `1` or `true`)
    pub tls_self_signed: bool,

    /// Path to PEM-encoded TLS certificate chain (manual TLS mode).
    /// When both `tls_cert_path` and `tls_key_path` are set, ACME is skipped
    /// and these files are loaded directly.
    ///
    /// Env: `SCP_RELAY_TLS_CERT`
    pub tls_cert_path: Option<PathBuf>,

    /// Path to PEM-encoded TLS private key (manual TLS mode).
    ///
    /// Env: `SCP_RELAY_TLS_KEY`
    pub tls_key_path: Option<PathBuf>,

    /// Directory for SQLite databases (node storage + key custody).
    /// Default: `$XDG_DATA_HOME/scp/personal-relay` or `$HOME/.local/share/scp/personal-relay`.
    ///
    /// Env: `SCP_RELAY_STORAGE_PATH`
    pub storage_path: PathBuf,

    /// Hex-encoded 32-byte encryption key for SQLCipher storage.
    /// If unset, a random key is generated and persisted to `{storage_path}/.key`.
    ///
    /// Env: `SCP_RELAY_STORAGE_KEY`
    pub storage_key_hex: Option<String>,

    /// Comma-separated DHT HTTP gateway URLs for DID publication.
    /// Default: uses the pkarr client's built-in gateways.
    ///
    /// Env: `SCP_RELAY_DHT_GATEWAYS`
    pub dht_gateways: Vec<String>,

    /// Log level filter. Overridden by `RUST_LOG` when set.
    /// Default: `info`.
    ///
    /// Env: `SCP_RELAY_LOG_LEVEL`
    pub log_level: String,

    /// Log output format: `json` for structured output, anything else for
    /// human-readable output.
    /// Default: `pretty`.
    ///
    /// Env: `SCP_RELAY_LOG_FORMAT`
    pub log_format: String,
}

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// Missing variables use the defaults documented on each field.
    pub fn from_env() -> Self {
        let domain = non_empty_env("SCP_RELAY_DOMAIN");

        let default_addr = if domain.is_some() {
            SocketAddr::from(([0, 0, 0, 0], 443))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 9000))
        };

        let bind_addr = std::env::var("SCP_RELAY_BIND_ADDR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_addr);

        let tls_self_signed = std::env::var("SCP_RELAY_TLS_SELF_SIGNED")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

        let storage_path = std::env::var("SCP_RELAY_STORAGE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_storage_path());

        let dht_gateways = std::env::var("SCP_RELAY_DHT_GATEWAYS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        Self {
            domain,
            acme_email: non_empty_env("SCP_RELAY_ACME_EMAIL"),
            bind_addr,
            tls_self_signed,
            tls_cert_path: non_empty_env("SCP_RELAY_TLS_CERT").map(PathBuf::from),
            tls_key_path: non_empty_env("SCP_RELAY_TLS_KEY").map(PathBuf::from),
            storage_path,
            storage_key_hex: non_empty_env("SCP_RELAY_STORAGE_KEY"),
            dht_gateways,
            log_level: std::env::var("SCP_RELAY_LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            log_format: std::env::var("SCP_RELAY_LOG_FORMAT").unwrap_or_else(|_| "pretty".into()),
        }
    }
}

/// Returns `Some(value)` if the env var exists and is non-empty, `None` otherwise.
fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Default storage path following XDG Base Directory Specification.
fn default_storage_path() -> PathBuf {
    let data_home = std::env::var("XDG_DATA_HOME").map_or_else(
        |_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
            PathBuf::from(home).join(".local").join("share")
        },
        PathBuf::from,
    );
    data_home.join("scp").join("personal-relay")
}
