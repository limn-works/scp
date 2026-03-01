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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::economy::types::{Amount, CurrencyCode, PaymentAdapterRef};
use crate::identity::DidMethod;

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

    /// Human-readable handle mappings (§22.6.1). Keys are handle
    /// local-parts; values are resolution records pointing to an
    /// identity DID or a context ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handles: Option<HashMap<String, WellKnownHandle>>,
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

/// A handle resolution record in the `.well-known/scp` handles map.
///
/// Maps a human-readable local-part to either an identity DID or a
/// context ID with optional relay override. See §22.6.1.
///
/// Handle keys must match the address format (§22.2):
/// `[a-z0-9._-]`, max 64 characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WellKnownHandle {
    /// An identity handle that resolves to a DID.
    Identity {
        /// The identity's DID.
        did: String,
    },
    /// A context handle that resolves to a context ID.
    Context {
        /// Hex-encoded context ID.
        context_id: String,
        /// Override relay URL for this context. Defaults to the
        /// document-level `relay` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay: Option<String>,
    },
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

    /// Relay economic configuration (section 19.8). Optional. Absence = free
    /// relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic: Option<RelayEconomicConfig>,
}

/// Relay economic configuration exposed in `.well-known/scp`.
///
/// Declares per-action costs, accepted payment adapters, and the payee
/// DID for the relay operator. All `Amount` values are in the smallest
/// currency unit specified by `currency` (section 19.1.1). Absence of
/// this entire object means the relay is free.
///
/// See section 19.8 and ADR-033 acceptance criterion 12.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEconomicConfig {
    /// Currency code for all amounts in this economic config (e.g., `"USD"`).
    pub currency: CurrencyCode,

    /// Cost per PUBLISH operation as `Amount` in smallest currency unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_publish: Option<Amount>,

    /// Cost per byte stored as `Amount` in smallest currency unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_byte_stored: Option<Amount>,

    /// Accepted payment adapter IDs (e.g., `["x402", "lightning"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payment_adapters: Vec<PaymentAdapterRef>,

    /// Relay operator's DID for receiving payments.
    pub payee: String,
}

/// Validation error for `.well-known/scp` documents.
#[derive(Debug, thiserror::Error)]
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

    /// DID resolution via DHT failed during `.well-known/scp` verification.
    #[error("DID resolution failed for '{did}': {reason}")]
    DidResolutionFailed {
        /// The DID that could not be resolved.
        did: String,
        /// The underlying resolution error.
        reason: String,
    },

    /// The relay URL in `.well-known/scp` does not match any `SCPRelay`
    /// service entry in the resolved DID document (§18.3.2).
    #[error(
        "relay URL '{relay_url}' not found in DID document SCPRelay entries \
         for '{did}'"
    )]
    RelayMismatch {
        /// The relay URL from the `.well-known/scp` document.
        relay_url: String,
        /// The DID whose document was checked.
        did: String,
    },

    /// The operator DID in `.well-known/scp` does not match the resolved
    /// DID document's subject.
    #[error(
        "operator DID mismatch: .well-known/scp declares '{claimed}' but \
         resolved document subject is '{resolved}'"
    )]
    OperatorDidMismatch {
        /// The DID claimed in the `.well-known/scp` document.
        claimed: String,
        /// The DID subject in the resolved document.
        resolved: String,
    },
}

impl WellKnownScp {
    /// Verifies `.well-known/scp` data against a DHT-resolved DID document
    /// (§18.3.2).
    ///
    /// Resolves the operator DID via the provided [`DidMethod`] implementation
    /// and cross-references the relay URL, operator DID, and context listings.
    /// This MUST be called on every fetch — not cached from first use (no TOFU).
    ///
    /// # Verification Steps
    ///
    /// 1. Resolve the operator DID from `self.did` via `did_method.resolve()`.
    /// 2. Verify the resolved document's subject matches `self.did`.
    /// 3. Extract `SCPRelay` service entries from the resolved document.
    /// 4. Verify `self.relay` matches at least one `SCPRelay` service endpoint.
    ///
    /// # Errors
    ///
    /// - [`WellKnownValidationError::DidResolutionFailed`] if the DID cannot
    ///   be resolved.
    /// - [`WellKnownValidationError::OperatorDidMismatch`] if the resolved
    ///   document subject does not match the claimed operator DID.
    /// - [`WellKnownValidationError::RelayMismatch`] if the relay URL is not
    ///   found in any `SCPRelay` service entry.
    pub async fn verify_against_did<M: DidMethod>(
        &self,
        did_method: &M,
    ) -> Result<(), WellKnownValidationError> {
        // Step 1: Resolve the operator DID document via DHT.
        let document = did_method.resolve(&self.did).await.map_err(|e| {
            WellKnownValidationError::DidResolutionFailed {
                did: self.did.clone(),
                reason: e.to_string(),
            }
        })?;

        // Step 2: Verify the resolved document subject matches the claimed DID.
        if document.id != self.did {
            return Err(WellKnownValidationError::OperatorDidMismatch {
                claimed: self.did.clone(),
                resolved: document.id,
            });
        }

        // Step 3: Extract SCPRelay service endpoint URLs from the resolved document.
        let relay_urls = document.relay_service_urls();

        // Step 4: Verify the .well-known/scp relay URL matches at least one entry.
        if !relay_urls.iter().any(|url| url == &self.relay) {
            return Err(WellKnownValidationError::RelayMismatch {
                relay_url: self.relay.clone(),
                did: self.did.clone(),
            });
        }

        Ok(())
    }

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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unimplemented,
    clippy::manual_async_fn
)]
mod tests {
    use std::future::Future;
    use std::sync::Arc;

    use super::*;
    use crate::identity::document::{DidDocument, Service};
    use crate::identity::{DidMethod, IdentityError, ScpIdentity};

    use scp_platform::traits::KeyCustody;

    // -----------------------------------------------------------------------
    // Mock DidMethod
    // -----------------------------------------------------------------------

    /// Result type returned by the mock resolver.
    enum MockResolveResult {
        /// Return the given DID document on resolve.
        Ok(DidDocument),
        /// Return an error on resolve.
        Err(String),
    }

    /// A mock [`DidMethod`] implementation for testing `verify_against_did`.
    ///
    /// Only `resolve` is meaningful; all other trait methods panic.
    struct MockDidMethod {
        result: Arc<MockResolveResult>,
    }

    impl MockDidMethod {
        /// Creates a mock that resolves to the given DID document.
        fn resolves_to(doc: DidDocument) -> Self {
            Self {
                result: Arc::new(MockResolveResult::Ok(doc)),
            }
        }

        /// Creates a mock that fails DID resolution with the given message.
        fn fails_with(msg: &str) -> Self {
            Self {
                result: Arc::new(MockResolveResult::Err(msg.to_owned())),
            }
        }
    }

    impl DidMethod for MockDidMethod {
        fn create(
            &self,
            _key_custody: &impl KeyCustody,
        ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send
        {
            async { unimplemented!("not needed for well_known tests") }
        }

        fn verify(&self, _did_string: &str, _public_key: &[u8]) -> bool {
            unimplemented!("not needed for well_known tests")
        }

        fn publish(
            &self,
            _identity: &ScpIdentity,
            _document: &DidDocument,
        ) -> impl Future<Output = Result<(), IdentityError>> + Send {
            async { unimplemented!("not needed for well_known tests") }
        }

        fn resolve(
            &self,
            _did_string: &str,
        ) -> impl Future<Output = Result<DidDocument, IdentityError>> + Send {
            let result = Arc::clone(&self.result);
            async move {
                match &*result {
                    MockResolveResult::Ok(doc) => Ok(doc.clone()),
                    MockResolveResult::Err(msg) => {
                        Err(IdentityError::DhtResolveFailed(msg.clone()))
                    }
                }
            }
        }

        fn rotate(
            &self,
            _identity: &ScpIdentity,
            _key_custody: &impl KeyCustody,
        ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send
        {
            async { unimplemented!("not needed for well_known tests") }
        }
    }

    // -----------------------------------------------------------------------
    // DID document helpers
    // -----------------------------------------------------------------------

    /// Creates a DID document with the given DID and relay URLs.
    fn did_document_with_relays(did: &str, relay_urls: &[&str]) -> DidDocument {
        let mut services = vec![Service {
            id: format!("{did}#pre-rotation"),
            service_type: "PreRotationCommitment".to_owned(),
            service_endpoint: "sha256:0000000000000000000000000000000000000000\
                000000000000000000000000"
                .to_owned(),
        }];

        for (i, url) in relay_urls.iter().enumerate() {
            services.push(Service {
                id: format!("{did}#scp-relay-{}", i + 1),
                service_type: "SCPRelay".to_owned(),
                service_endpoint: (*url).to_owned(),
            });
        }

        DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_owned(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_owned(),
            ],
            id: did.to_owned(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            also_known_as: Vec::new(),
            service: services,
        }
    }

    // -----------------------------------------------------------------------
    // Existing helpers
    // -----------------------------------------------------------------------

    /// Helper: a full document with all fields populated.
    fn full_document() -> WellKnownScp {
        let mut handles = HashMap::new();
        handles.insert(
            "alice".to_owned(),
            WellKnownHandle::Identity {
                did: "did:dht:z6MkAlice...".to_owned(),
            },
        );
        handles.insert(
            "recipes".to_owned(),
            WellKnownHandle::Context {
                context_id: "a1b2c3d4e5f6".to_owned(),
                relay: Some("wss://relay.example.com/scp/v1".to_owned()),
            },
        );

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
                economic: None,
            }),
            handles: Some(handles),
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
            handles: None,
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
            handles: None,
        };

        let err = doc.validate().expect_err("should reject encrypted context");
        assert!(matches!(
            err,
            WellKnownValidationError::NonBroadcastContext {
                context_id,
                mode,
            } if context_id == "deadbeef" && mode == "encrypted"
        ));
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
            handles: None,
        };

        let err = doc.validate().expect_err("should reject absent mode");
        assert!(matches!(
            err,
            WellKnownValidationError::NonBroadcastContext {
                context_id,
                mode,
            } if context_id == "cafebabe" && mode == "encrypted"
        ));
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
            handles: None,
        };

        let err = doc.validate().expect_err("should reject unknown mode");
        assert!(matches!(
            err,
            WellKnownValidationError::NonBroadcastContext {
                context_id,
                mode,
            } if context_id == "f00dcafe" && mode == "private"
        ));
    }

    #[test]
    fn optional_relay_config_fields_omitted_when_none() {
        let config = RelayConfig {
            max_blob_size: Some(1024),
            max_blob_ttl: None,
            rate_limit_publish: None,
            rate_limit_subscribe: None,
            economic: None,
        };
        let json = serde_json::to_value(&config).expect("serialization failed");

        assert_eq!(json["max_blob_size"], 1024);
        assert!(json.get("max_blob_ttl").is_none());
        assert!(json.get("rate_limit_publish").is_none());
        assert!(json.get("rate_limit_subscribe").is_none());
    }

    // -- handles tests (§22.6.1) -------------------------------------------

    #[test]
    fn handles_serialize_with_tagged_type() {
        let mut handles = HashMap::new();
        handles.insert(
            "alice".to_owned(),
            WellKnownHandle::Identity {
                did: "did:dht:z6MkAlice".to_owned(),
            },
        );
        handles.insert(
            "recipes".to_owned(),
            WellKnownHandle::Context {
                context_id: "a1b2c3d4e5f6".to_owned(),
                relay: None,
            },
        );

        let doc = WellKnownScp {
            version: 1,
            did: "did:dht:z6Mk...".to_owned(),
            relay: "wss://relay.example.com/scp/v1".to_owned(),
            contexts: None,
            relay_config: None,
            handles: Some(handles),
        };

        let json = serde_json::to_value(&doc).expect("serialization failed");
        let handles_json = &json["handles"];

        let alice = &handles_json["alice"];
        assert_eq!(alice["type"], "identity");
        assert_eq!(alice["did"], "did:dht:z6MkAlice");

        let recipes = &handles_json["recipes"];
        assert_eq!(recipes["type"], "context");
        assert_eq!(recipes["context_id"], "a1b2c3d4e5f6");
        assert!(recipes.get("relay").is_none());
    }

    #[test]
    fn handles_roundtrip_preserves_all_fields() {
        let mut handles = HashMap::new();
        handles.insert(
            "bob".to_owned(),
            WellKnownHandle::Context {
                context_id: "deadbeef".to_owned(),
                relay: Some("wss://alt.example.com/scp/v1".to_owned()),
            },
        );

        let original = WellKnownScp {
            version: 1,
            did: "did:dht:z6Mk...".to_owned(),
            relay: "wss://relay.example.com/scp/v1".to_owned(),
            contexts: None,
            relay_config: None,
            handles: Some(handles),
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let restored: WellKnownScp = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
    }

    #[test]
    fn handles_absent_when_none() {
        let doc = minimal_document();
        let json = serde_json::to_value(&doc).expect("serialization failed");
        assert!(json.get("handles").is_none());
    }

    #[test]
    fn handles_deserialize_from_json() {
        let json = r#"{
            "version": 1,
            "did": "did:dht:z6Mk...",
            "relay": "wss://relay.example.com/scp/v1",
            "handles": {
                "alice": {
                    "type": "identity",
                    "did": "did:dht:z6MkAlice..."
                },
                "recipes": {
                    "type": "context",
                    "context_id": "a1b2c3d4e5f6",
                    "relay": "wss://relay.example.com/scp/v1"
                }
            }
        }"#;
        let doc: WellKnownScp = serde_json::from_str(json).expect("deserialization failed");
        let handles = doc.handles.expect("handles present");
        assert_eq!(handles.len(), 2);

        match &handles["alice"] {
            WellKnownHandle::Identity { did } => {
                assert_eq!(did, "did:dht:z6MkAlice...");
            }
            other => panic!("expected Identity, got: {other:?}"),
        }

        match &handles["recipes"] {
            WellKnownHandle::Context {
                context_id, relay, ..
            } => {
                assert_eq!(context_id, "a1b2c3d4e5f6");
                assert_eq!(
                    relay.as_deref(),
                    Some("wss://relay.example.com/scp/v1")
                );
            }
            other => panic!("expected Context, got: {other:?}"),
        }
    }

    // -- verify_against_did tests (SCP-188) --------------------------------

    #[tokio::test]
    async fn verify_against_did_passes_with_matching_relay() {
        let did = "did:dht:zOperator123";
        let relay_url = "wss://relay.example.com/scp/v1";

        let doc = did_document_with_relays(did, &[relay_url]);
        let mock = MockDidMethod::resolves_to(doc);

        let well_known = WellKnownScp {
            version: 1,
            did: did.to_owned(),
            relay: relay_url.to_owned(),
            contexts: None,
            relay_config: None,
            handles: None,
        };

        assert!(well_known.verify_against_did(&mock).await.is_ok());
    }

    #[tokio::test]
    async fn verify_against_did_passes_with_multiple_relays() {
        let did = "did:dht:zOperator123";
        let relay_url = "wss://relay2.example.com/scp/v1";

        let doc = did_document_with_relays(
            did,
            &[
                "wss://relay1.example.com/scp/v1",
                relay_url,
                "wss://relay3.example.com/scp/v1",
            ],
        );
        let mock = MockDidMethod::resolves_to(doc);

        let well_known = WellKnownScp {
            version: 1,
            did: did.to_owned(),
            relay: relay_url.to_owned(),
            contexts: None,
            relay_config: None,
            handles: None,
        };

        assert!(well_known.verify_against_did(&mock).await.is_ok());
    }

    #[tokio::test]
    async fn verify_against_did_fails_with_mismatched_relay() {
        let did = "did:dht:zOperator123";
        let claimed_relay = "wss://evil.example.com/scp/v1";
        let actual_relay = "wss://legit.example.com/scp/v1";

        let doc = did_document_with_relays(did, &[actual_relay]);
        let mock = MockDidMethod::resolves_to(doc);

        let well_known = WellKnownScp {
            version: 1,
            did: did.to_owned(),
            relay: claimed_relay.to_owned(),
            contexts: None,
            relay_config: None,
            handles: None,
        };

        let err = well_known
            .verify_against_did(&mock)
            .await
            .expect_err("should fail with relay mismatch");

        match err {
            WellKnownValidationError::RelayMismatch {
                relay_url,
                did: err_did,
            } => {
                assert_eq!(relay_url, claimed_relay);
                assert_eq!(err_did, did);
            }
            other => panic!("expected RelayMismatch, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_against_did_fails_when_did_resolution_fails() {
        let did = "did:dht:zUnresolvable";

        let mock = MockDidMethod::fails_with("network timeout");

        let well_known = WellKnownScp {
            version: 1,
            did: did.to_owned(),
            relay: "wss://relay.example.com/scp/v1".to_owned(),
            contexts: None,
            relay_config: None,
            handles: None,
        };

        let err = well_known
            .verify_against_did(&mock)
            .await
            .expect_err("should fail with resolution error");

        match err {
            WellKnownValidationError::DidResolutionFailed {
                did: err_did,
                reason,
            } => {
                assert_eq!(err_did, did);
                assert!(reason.contains("network timeout"));
            }
            other => panic!("expected DidResolutionFailed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_against_did_fails_with_operator_did_mismatch() {
        let claimed_did = "did:dht:zClaimedOperator";
        let actual_did = "did:dht:zActualOperator";
        let relay_url = "wss://relay.example.com/scp/v1";

        // The resolved document has a different subject DID.
        let doc = did_document_with_relays(actual_did, &[relay_url]);
        let mock = MockDidMethod::resolves_to(doc);

        let well_known = WellKnownScp {
            version: 1,
            did: claimed_did.to_owned(),
            relay: relay_url.to_owned(),
            contexts: None,
            relay_config: None,
            handles: None,
        };

        let err = well_known
            .verify_against_did(&mock)
            .await
            .expect_err("should fail with operator DID mismatch");

        match err {
            WellKnownValidationError::OperatorDidMismatch { claimed, resolved } => {
                assert_eq!(claimed, claimed_did);
                assert_eq!(resolved, actual_did);
            }
            other => panic!("expected OperatorDidMismatch, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_against_did_fails_with_no_relay_services() {
        let did = "did:dht:zOperator123";
        let relay_url = "wss://relay.example.com/scp/v1";

        // Document has no SCPRelay service entries.
        let doc = did_document_with_relays(did, &[]);
        let mock = MockDidMethod::resolves_to(doc);

        let well_known = WellKnownScp {
            version: 1,
            did: did.to_owned(),
            relay: relay_url.to_owned(),
            contexts: None,
            relay_config: None,
            handles: None,
        };

        let err = well_known
            .verify_against_did(&mock)
            .await
            .expect_err("should fail with relay mismatch");

        assert!(matches!(
            err,
            WellKnownValidationError::RelayMismatch { .. }
        ));
    }
}
