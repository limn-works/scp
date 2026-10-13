//! `NodeStartConfig`: the flat config that `server::node_start` reads to start a
//! production node from an existing `SCP` instance.
//!
//! `.docs/standards/construction.md` §"Node start — `NodeStartConfig`" defines
//! every field, type, arm and omission here (ADR-052, unified construction
//! pattern). Serde reads the config with `deny_unknown_fields`, so a misspelled
//! key fails instead of selecting a default, and every data enum carries the tag
//! `kind` with `snake_case` values (`{"kind": "nat_traversal"}`).
//!
//! The `PyO3` and napi-rs bridges read untyped input, so `tls`, `dht` and
//! `cors_origins` are required here although the core `NodeConfig` defaults
//! them: an optional field with a default would let a misspelled key select that
//! default.
//!
//! Gated behind the `server` feature.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::server::ServerError;

/// How the node is reached. Mirrors `scp_node::Reach` without `Tunnel`, because
/// the core does not thread `public_url` into the published relay URL.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FfiReach {
    /// The node serves a domain the operator controls.
    Domain {
        /// The DNS name, without a scheme, port or path.
        domain: String,
    },
    /// The node sits behind NAT and uses the NAT traversal tiers.
    NatTraversal {},
    /// The node serves the local machine only.
    Local {},
}

/// The relay's blob storage backend. Mirrors the durable and
/// durability-only arms of `BlobStorageBackend`, without S3 and Postgres.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FfiBlobBackend {
    /// The durability-only in-memory arm (spec §17.17, SCP-CAPSEL-8010): blobs
    /// die with the node, selected only by explicit choice.
    InMemory {},
    /// A redb database file at `path`.
    Redb {
        /// The database file path. `node_start` creates its parent directory.
        path: PathBuf,
    },
    /// A `SQLite` database file at `path`.
    Sqlite {
        /// The database file path. `node_start` creates its parent directory.
        path: PathBuf,
    },
}

/// TLS selection. Mirrors `scp_node::TlsMode` without `Custom`, whose trait
/// object cannot cross the FFI boundary.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FfiTlsMode {
    /// Serve a self-signed certificate for the reach's domain.
    SelfSigned {},
    /// Provision a certificate through ACME for the reach's domain.
    Acme {
        /// The ACME account contact address; absent selects headless ACME.
        #[serde(default)]
        email: Option<String>,
    },
    /// Serve plaintext. `Reach::Domain` with `Plaintext` is rejected.
    Plaintext {},
    /// TLS terminates upstream, at a tunnel or reverse proxy.
    Terminated {},
}

/// DID-document publication. keri's scope ruling of 2026-10-13 exposes
/// `Disabled` only: the node runs its relay and publishes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FfiDhtMode {
    /// Publish nothing.
    Disabled {},
}

/// CORS origins for the node's public endpoints. Required, because the core
/// `NodeConfig` reads an absent list as the permissive `*` origin.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FfiCorsOrigins {
    /// Allow every origin (`*`), only because the caller named it.
    AnyOrigin {},
    /// Allow exactly these origins.
    List {
        /// Each origin, such as `https://app.example.org`.
        origins: Vec<String>,
    },
}

/// NAT strategy. Mirrors `scp_node::NatSlot` without `Custom` and `Tuned`,
/// which carry `NatStrategy` trait objects.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FfiNat {
    /// The default NAT strategy.
    Auto {},
}

/// The flat config `server::node_start` converts into the core `NodeConfig`.
///
/// It has no storage field: `node_start` takes the `SCP` instance's own storage
/// handle (spec §17.6). `identity` names an operator identity already registered
/// on the same instance; nodes have no identity of their own.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeStartConfig {
    /// How the node is reached.
    pub reach: FfiReach,
    /// The operator's DID. The `UniFFI` bridge lowers its `Arc<Identity>` handle
    /// to this DID.
    pub identity: String,
    /// The relay's blob storage backend.
    pub blob_storage: FfiBlobBackend,
    /// TLS selection.
    pub tls: FfiTlsMode,
    /// DID-document publication.
    pub dht: FfiDhtMode,
    /// CORS origins for the public endpoints.
    pub cors_origins: FfiCorsOrigins,
    /// Relay bind address; absent binds `127.0.0.1:0`.
    #[serde(default)]
    pub bind_addr: Option<SocketAddr>,
    /// Public HTTP bind address; absent selects the core default.
    #[serde(default)]
    pub http_bind_addr: Option<SocketAddr>,
    /// NAT strategy; absent selects `Auto`.
    #[serde(default)]
    pub nat: Option<FfiNat>,
    /// Per-IP rate limit for broadcast projection endpoints, greater than 0;
    /// absent selects the core default.
    #[serde(default)]
    pub projection_rate_limit: Option<u32>,
}

impl NodeStartConfig {
    /// Parses a config from its JSON form.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::InvalidConfig`] when the JSON is malformed, names
    /// an unknown key or `kind`, or omits a required field.
    pub fn from_json(json: &str) -> Result<Self, ServerError> {
        serde_json::from_str(json).map_err(|e| ServerError::InvalidConfig(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
        "reach": {"kind": "domain", "domain": "node.example.org"},
        "identity": "did:dht:abc",
        "blob_storage": {"kind": "redb", "path": "/var/lib/scp/blobs.redb"},
        "tls": {"kind": "acme", "email": "ops@example.org"},
        "dht": {"kind": "disabled"},
        "cors_origins": {"kind": "list", "origins": ["https://app.example.org"]},
        "bind_addr": "127.0.0.1:0",
        "nat": {"kind": "auto"},
        "projection_rate_limit": 30
    }"#;

    fn invalid(json: &str) -> bool {
        matches!(
            NodeStartConfig::from_json(json),
            Err(ServerError::InvalidConfig(_))
        )
    }

    #[test]
    fn from_json_reads_every_field() {
        let cfg = NodeStartConfig::from_json(VALID).expect("valid config parses");
        assert_eq!(
            cfg,
            NodeStartConfig {
                reach: FfiReach::Domain {
                    domain: "node.example.org".to_owned()
                },
                identity: "did:dht:abc".to_owned(),
                blob_storage: FfiBlobBackend::Redb {
                    path: PathBuf::from("/var/lib/scp/blobs.redb")
                },
                tls: FfiTlsMode::Acme {
                    email: Some("ops@example.org".to_owned())
                },
                dht: FfiDhtMode::Disabled {},
                cors_origins: FfiCorsOrigins::List {
                    origins: vec!["https://app.example.org".to_owned()]
                },
                bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
                http_bind_addr: None,
                nat: Some(FfiNat::Auto {}),
                projection_rate_limit: Some(30),
            }
        );
    }

    #[test]
    fn from_json_leaves_optional_fields_absent() {
        let cfg = NodeStartConfig::from_json(
            r#"{"reach":{"kind":"local"},"identity":"did:dht:abc",
                "blob_storage":{"kind":"in_memory"},"tls":{"kind":"acme"},
                "dht":{"kind":"disabled"},"cors_origins":{"kind":"any_origin"}}"#,
        )
        .expect("minimal config parses");
        assert_eq!(cfg.reach, FfiReach::Local {});
        assert_eq!(cfg.blob_storage, FfiBlobBackend::InMemory {});
        assert_eq!(cfg.tls, FfiTlsMode::Acme { email: None });
        assert_eq!(cfg.cors_origins, FfiCorsOrigins::AnyOrigin {});
        assert_eq!(cfg.bind_addr, None);
        assert_eq!(cfg.http_bind_addr, None);
        assert_eq!(cfg.nat, None);
        assert_eq!(cfg.projection_rate_limit, None);
    }

    #[test]
    fn from_json_rejects_an_unknown_top_level_key() {
        let json = VALID.replacen("\"bind_addr\"", "\"bind_address\"", 1);
        assert!(invalid(&json));
    }

    #[test]
    fn from_json_rejects_an_unknown_key_inside_every_enum_arm() {
        // Each case swaps one object of `VALID` for an arm (`known`) and for the
        // same arm plus one unknown key (`unknown`): `known` must parse, so the
        // unknown key is the only reason `unknown` can fail.
        let reach = r#"{"kind": "domain", "domain": "node.example.org"}"#;
        let blob = r#"{"kind": "redb", "path": "/var/lib/scp/blobs.redb"}"#;
        for (from, known, unknown) in [
            (
                reach,
                reach,
                r#"{"kind": "domain", "domain": "node.example.org", "port": 1}"#,
            ),
            (
                reach,
                r#"{"kind": "local"}"#,
                r#"{"kind": "local", "x": 1}"#,
            ),
            (
                reach,
                r#"{"kind": "nat_traversal"}"#,
                r#"{"kind": "nat_traversal", "x": 1}"#,
            ),
            (
                blob,
                r#"{"kind": "in_memory"}"#,
                r#"{"kind": "in_memory", "x": 1}"#,
            ),
            (
                r#"{"kind": "disabled"}"#,
                r#"{"kind": "disabled"}"#,
                r#"{"kind": "disabled", "gateways": []}"#,
            ),
            (
                r#"{"kind": "auto"}"#,
                r#"{"kind": "auto"}"#,
                r#"{"kind": "auto", "stun": "x"}"#,
            ),
            (
                r#"{"kind": "acme", "email": "ops@example.org"}"#,
                r#"{"kind": "acme", "email": "ops@example.org"}"#,
                r#"{"kind": "acme", "emial": "ops@example.org"}"#,
            ),
        ] {
            let with_known = VALID.replacen(from, known, 1);
            let with_unknown = VALID.replacen(from, unknown, 1);
            assert_ne!(
                with_unknown, VALID,
                "fixture replacement must apply: {from}"
            );
            assert!(
                NodeStartConfig::from_json(&with_known).is_ok(),
                "arm without the unknown key rejected: {known}"
            );
            assert!(invalid(&with_unknown), "unknown key accepted in {unknown}");
        }
    }

    #[test]
    fn from_json_rejects_an_omitted_arm_and_a_missing_required_field() {
        // `Tunnel`, `Custom`, `Memory`/`Production` and `Tuned` are omitted arms.
        for (from, to) in [
            (r#""kind": "domain""#, r#""kind": "tunnel""#),
            (r#""kind": "acme""#, r#""kind": "custom""#),
            (r#""kind": "disabled""#, r#""kind": "production""#),
            (r#""kind": "auto""#, r#""kind": "tuned""#),
        ] {
            let json = VALID.replacen(from, to, 1);
            assert_ne!(json, VALID, "fixture replacement must apply: {from}");
            assert!(invalid(&json), "omitted arm accepted: {to}");
        }
        let without_tls = VALID.replacen(
            r#""tls": {"kind": "acme", "email": "ops@example.org"},"#,
            "",
            1,
        );
        assert_ne!(without_tls, VALID);
        assert!(invalid(&without_tls), "missing tls accepted");
        let without_cors = VALID.replacen(
            r#""cors_origins": {"kind": "list", "origins": ["https://app.example.org"]},"#,
            "",
            1,
        );
        assert_ne!(without_cors, VALID);
        assert!(invalid(&without_cors), "missing cors_origins accepted");
    }
}
