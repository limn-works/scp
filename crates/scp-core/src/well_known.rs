//! `.well-known/scp` document types and serialization.
//!
//! Implements the `.well-known/scp` JSON document format specified in
//! §18.3 of the SCP specification. This document enables web-based
//! discovery of SCP infrastructure associated with a domain.
//!
//! The document is an **optional web on-ramp** — an advisory,
//! HTTPS-dependent discovery mechanism. Clients MUST verify
//! `.well-known/scp` data against DHT-resolved DID documents before
//! trusting it (§18.3.2).
//!
//! # Privacy Constraints
//!
//! The document MUST NOT expose encrypted context IDs, membership
//! rosters, routing pseudonyms, or subscriber lists. It MAY expose
//! relay URLs, operator DID, protocol version, relay configuration,
//! and broadcast context IDs. See §18.3 for the full privacy model.

use serde::{Deserialize, Serialize};

/// The `.well-known/scp` JSON document.
///
/// Enables web-based discovery of SCP infrastructure associated with a
/// domain. Contains the operator's DID, primary relay URL, optional
/// publicly listed contexts, and optional relay configuration.
///
/// See §18.3.1 for the document format specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnownScp {
    /// Protocol version. Currently `1`.
    pub version: u32,

    /// The operator's DID (`did:dht` preferred).
    pub did: String,

    /// Primary relay URL (`wss://` scheme, `/scp/v1` path).
    pub relay: String,

    /// Publicly listed contexts. Only broadcast contexts may be listed
    /// (§18.3 privacy constraints).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contexts: Option<Vec<WellKnownContext>>,

    /// Relay operator configuration subset (§18.3.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_config: Option<RelayConfig>,
}

/// A publicly listed context entry in the `.well-known/scp` document.
///
/// Only broadcast contexts should appear here. Encrypted context IDs
/// MUST NOT be exposed (§18.3 privacy constraints).
///
/// See §18.3.1 context entry fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnownContext {
    /// Context ID (hex-encoded).
    pub id: String,

    /// Human-readable name (advisory, unverified).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Context mode: `"encrypted"` or `"broadcast"`. Defaults to
    /// `"encrypted"` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Full `scp://` URI for the context (§18.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// Relay operator configuration subset exposed in `.well-known/scp`.
///
/// These fields mirror the relay configuration table in ADR-004.
/// All fields are optional; absent fields indicate the relay uses
/// protocol defaults or has no limit.
///
/// See §18.3.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Maximum blob size the relay accepts, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_blob_size: Option<u64>,

    /// Maximum blob TTL the relay enforces, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_blob_ttl: Option<u64>,

    /// PUBLISH rate limit per connection, per minute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_publish: Option<u32>,

    /// Maximum concurrent subscriptions per connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_subscribe: Option<u32>,
}

/// Validation error for `.well-known/scp` documents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WellKnownValidationError {
    /// A listed context has a mode other than `"broadcast"`, or the
    /// mode field is absent (defaults to `"encrypted"`, which MUST NOT
    /// be listed).
    #[error(
        "context '{context_id}' has mode '{mode}' — only broadcast contexts \
         may be listed in .well-known/scp"
    )]
    NonBroadcastContext {
        /// The offending context ID.
        context_id: String,
        /// The mode value (or `"encrypted"` if absent/defaulted).
        mode: String,
    },
}

impl WellKnownScp {
    /// Validates the document against §18.3 privacy constraints.
    ///
    /// Returns an error if any listed context has a mode other than
    /// `"broadcast"`. Contexts without an explicit mode default to
    /// `"encrypted"` per §18.3.1 and are rejected — encrypted context
    /// IDs MUST NOT be exposed.
    ///
    /// # Errors
    ///
    /// Returns [`WellKnownValidationError::NonBroadcastContext`] if a
    /// context entry has `mode` absent or not equal to `"broadcast"`.
    pub fn validate(&self) -> Result<(), WellKnownValidationError> {
        if let Some(contexts) = &self.contexts {
            for ctx in contexts {
                let mode = ctx.mode.as_deref().unwrap_or("encrypted");
                if mode != "broadcast" {
                    return Err(WellKnownValidationError::NonBroadcastContext {
                        context_id: ctx.id.clone(),
                        mode: mode.to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Helper: a full document with all fields populated.
    fn full_document() -> WellKnownScp {
        WellKnownScp {
            version: 1,
            did: "did:dht:z6Mk...".to_owned(),
            relay: "wss://relay.example.com/scp/v1".to_owned(),
            contexts: Some(vec![WellKnownContext {
                id: "a1b2c3d4e5f6".to_owned(),
                name: Some("Example Community".to_owned()),
                mode: Some("broadcast".to_owned()),
                uri: Some(
                    "scp://context/a1b2c3d4e5f6?relay=wss://relay.example.com/scp/v1\
                     &mode=broadcast&name=Example+Community"
                        .to_owned(),
                ),
            }]),
            relay_config: Some(RelayConfig {
                max_blob_size: Some(262_144),
                max_blob_ttl: Some(86_400),
                rate_limit_publish: Some(100),
                rate_limit_subscribe: Some(50),
            }),
        }
    }

    /// Helper: a minimal document with only required fields.
    fn minimal_document() -> WellKnownScp {
        WellKnownScp {
            version: 1,
            did: "did:dht:z6Mk...".to_owned(),
            relay: "wss://relay.example.com/scp/v1".to_owned(),
            contexts: None,
            relay_config: None,
        }
    }

    #[test]
    fn full_document_serializes_to_expected_json() {
        let doc = full_document();
        let json = serde_json::to_value(&doc).expect("serialization failed");

        assert_eq!(json["version"], 1);
        assert_eq!(json["did"], "did:dht:z6Mk...");
        assert_eq!(json["relay"], "wss://relay.example.com/scp/v1");

        let ctx = &json["contexts"][0];
        assert_eq!(ctx["id"], "a1b2c3d4e5f6");
        assert_eq!(ctx["name"], "Example Community");
        assert_eq!(ctx["mode"], "broadcast");
        assert!(
            ctx["uri"]
                .as_str()
                .expect("uri is string")
                .starts_with("scp://context/")
        );

        let rc = &json["relay_config"];
        assert_eq!(rc["max_blob_size"], 262_144);
        assert_eq!(rc["max_blob_ttl"], 86_400);
        assert_eq!(rc["rate_limit_publish"], 100);
        assert_eq!(rc["rate_limit_subscribe"], 50);
    }

    #[test]
    fn minimal_document_serializes_without_optional_fields() {
        let doc = minimal_document();
        let json = serde_json::to_value(&doc).expect("serialization failed");

        assert_eq!(json["version"], 1);
        assert_eq!(json["did"], "did:dht:z6Mk...");
        assert_eq!(json["relay"], "wss://relay.example.com/scp/v1");

        // Optional fields must be absent, not null.
        assert!(json.get("contexts").is_none());
        assert!(json.get("relay_config").is_none());
    }

    #[test]
    fn deserialize_handles_missing_optional_fields() {
        let json =
            r#"{"version":1,"did":"did:dht:z6Mk...","relay":"wss://relay.example.com/scp/v1"}"#;
        let doc: WellKnownScp = serde_json::from_str(json).expect("deserialization failed");

        assert_eq!(doc.version, 1);
        assert_eq!(doc.did, "did:dht:z6Mk...");
        assert_eq!(doc.relay, "wss://relay.example.com/scp/v1");
        assert!(doc.contexts.is_none());
        assert!(doc.relay_config.is_none());
    }

    #[test]
    fn deserialize_handles_missing_optional_context_fields() {
        let json = r#"{
            "version": 1,
            "did": "did:dht:z6Mk...",
            "relay": "wss://relay.example.com/scp/v1",
            "contexts": [{"id": "abc123"}]
        }"#;
        let doc: WellKnownScp = serde_json::from_str(json).expect("deserialization failed");

        let ctx = &doc.contexts.expect("contexts present")[0];
        assert_eq!(ctx.id, "abc123");
        assert!(ctx.name.is_none());
        assert!(ctx.mode.is_none());
        assert!(ctx.uri.is_none());
    }

    #[test]
    fn serialize_deserialize_roundtrip_preserves_all_fields() {
        let original = full_document();
        let json = serde_json::to_string(&original).expect("serialization failed");
        let restored: WellKnownScp = serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(original, restored);
    }

    #[test]
    fn serialize_deserialize_roundtrip_minimal() {
        let original = minimal_document();
        let json = serde_json::to_string(&original).expect("serialization failed");
        let restored: WellKnownScp = serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(original, restored);
    }

    #[test]
    fn validate_accepts_broadcast_contexts() {
        let doc = full_document();
        assert!(doc.validate().is_ok());
    }

    #[test]
    fn validate_accepts_no_contexts() {
        let doc = minimal_document();
        assert!(doc.validate().is_ok());
    }

    #[test]
    fn validate_rejects_encrypted_context_mode() {
        let doc = WellKnownScp {
            version: 1,
            did: "did:dht:z6Mk...".to_owned(),
            relay: "wss://relay.example.com/scp/v1".to_owned(),
            contexts: Some(vec![WellKnownContext {
                id: "deadbeef".to_owned(),
                name: None,
                mode: Some("encrypted".to_owned()),
                uri: None,
            }]),
            relay_config: None,
        };

        let err = doc.validate().expect_err("should reject encrypted context");
        assert_eq!(
            err,
            WellKnownValidationError::NonBroadcastContext {
                context_id: "deadbeef".to_owned(),
                mode: "encrypted".to_owned(),
            }
        );
    }

    #[test]
    fn validate_rejects_absent_mode_as_encrypted_default() {
        let doc = WellKnownScp {
            version: 1,
            did: "did:dht:z6Mk...".to_owned(),
            relay: "wss://relay.example.com/scp/v1".to_owned(),
            contexts: Some(vec![WellKnownContext {
                id: "cafebabe".to_owned(),
                name: Some("Secret Context".to_owned()),
                mode: None,
                uri: None,
            }]),
            relay_config: None,
        };

        let err = doc.validate().expect_err("should reject absent mode");
        assert_eq!(
            err,
            WellKnownValidationError::NonBroadcastContext {
                context_id: "cafebabe".to_owned(),
                mode: "encrypted".to_owned(),
            }
        );
    }

    #[test]
    fn validate_rejects_unknown_mode() {
        let doc = WellKnownScp {
            version: 1,
            did: "did:dht:z6Mk...".to_owned(),
            relay: "wss://relay.example.com/scp/v1".to_owned(),
            contexts: Some(vec![WellKnownContext {
                id: "f00dcafe".to_owned(),
                name: None,
                mode: Some("private".to_owned()),
                uri: None,
            }]),
            relay_config: None,
        };

        let err = doc.validate().expect_err("should reject unknown mode");
        assert_eq!(
            err,
            WellKnownValidationError::NonBroadcastContext {
                context_id: "f00dcafe".to_owned(),
                mode: "private".to_owned(),
            }
        );
    }

    #[test]
    fn optional_relay_config_fields_omitted_when_none() {
        let config = RelayConfig {
            max_blob_size: Some(1024),
            max_blob_ttl: None,
            rate_limit_publish: None,
            rate_limit_subscribe: None,
        };
        let json = serde_json::to_value(&config).expect("serialization failed");

        assert_eq!(json["max_blob_size"], 1024);
        assert!(json.get("max_blob_ttl").is_none());
        assert!(json.get("rate_limit_publish").is_none());
        assert!(json.get("rate_limit_subscribe").is_none());
    }
}
