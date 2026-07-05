//! `.well-known/scp` economic config parsing for relay discovery.
//!
//! Extends the relay discovery layer with economic awareness. Parses the
//! optional `economic` field from `.well-known/scp` `relay_config`
//! (section 18.3.3, section 19.8) and provides helpers for relay
//! classification and bootstrap validation.
//!
//! # Parsing Rules
//!
//! - `.well-known/scp` JSON with an `economic` field in `relay_config`
//!   deserializes into a relay with economic parameters.
//! - Without the `economic` field, the relay is treated as free.
//! - `Amount` values are canonical base-10 decimal strings in the smallest
//!   currency unit (ADR-060, section 19.1.1).
//!
//! # Bootstrap Validation
//!
//! The SDK's fallback relay list (section 18.5) MUST include at least
//! one free relay. [`validate_bootstrap_has_free_relay`] enforces this
//! protocol invariant (section 19.14 invariant 8).
//!
//! See ADR-033 acceptance criteria 12, 14.

use scp_core::well_known::{RelayConfig, RelayEconomicConfig, WellKnownScp};

use crate::error::TransportError;

/// Extracts the relay economic config from a parsed `.well-known/scp`
/// document, if present.
///
/// Returns `None` when `relay_config` is absent or when `relay_config`
/// has no `economic` field — both cases indicate a free relay.
#[must_use]
pub fn relay_economic_config(doc: &WellKnownScp) -> Option<&RelayEconomicConfig> {
    doc.relay_config
        .as_ref()
        .and_then(|rc| rc.economic.as_ref())
}

/// Returns `true` if the `.well-known/scp` document describes a free
/// relay (no economic config).
#[must_use]
pub fn is_free_relay_doc(doc: &WellKnownScp) -> bool {
    relay_economic_config(doc).is_none()
}

/// A relay entry with its URL and optional economic config, used for
/// bootstrap validation and cost-aware selection.
#[derive(Debug, Clone)]
pub struct RelayEntry {
    /// The relay URL.
    pub url: String,
    /// Optional relay config (includes economic field if present).
    pub relay_config: Option<RelayConfig>,
}

impl RelayEntry {
    /// Returns the economic config for this relay entry, if any.
    #[must_use]
    pub fn economic_config(&self) -> Option<&RelayEconomicConfig> {
        self.relay_config
            .as_ref()
            .and_then(|rc| rc.economic.as_ref())
    }

    /// Returns `true` if this relay has no economic config (free relay).
    #[must_use]
    pub fn is_free(&self) -> bool {
        self.economic_config().is_none()
    }
}

/// Validates that a bootstrap relay list contains at least one free relay.
///
/// This enforces the protocol invariant from section 19.8 and section
/// 19.14 invariant 8: the SDK's fallback relay list MUST include at
/// least one free relay to prevent economic gatekeeping of basic
/// protocol operation.
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if no free relay exists
/// in the provided list.
pub fn validate_bootstrap_has_free_relay(relays: &[RelayEntry]) -> Result<(), TransportError> {
    let has_free = relays.iter().any(RelayEntry::is_free);
    if has_free {
        Ok(())
    } else {
        Err(TransportError::ProtocolError(
            "bootstrap relay list must include at least one free relay \
             (section 19.8, section 19.14 invariant 8)"
                .to_owned(),
        ))
    }
}

/// Parses a `.well-known/scp` JSON string into a [`WellKnownScp`]
/// document.
///
/// This is a thin wrapper over `serde_json::from_str` that converts
/// JSON parse errors into [`TransportError::ProtocolError`].
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if the JSON is malformed
/// or does not match the `.well-known/scp` schema.
pub fn parse_well_known(json: &str) -> Result<WellKnownScp, TransportError> {
    serde_json::from_str(json)
        .map_err(|e| TransportError::ProtocolError(format!("failed to parse .well-known/scp: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_core::economy::types::{Amount, CurrencyCode};

    /// JSON representing a `.well-known/scp` document with economic config.
    const WELL_KNOWN_WITH_ECONOMIC: &str = r#"{
        "version": 1,
        "did": "did:dht:z6Mk...",
        "relay": "wss://relay.example.com/scp/v1",
        "relay_config": {
            "max_blob_size": 262144,
            "max_blob_ttl": 86400,
            "rate_limit_publish": 100,
            "rate_limit_subscribe": 50,
            "economic": {
                "currency": [85, 83, 68, 0],
                "per_publish": "10",
                "per_byte_stored": "1",
                "payment_adapters": ["x402", "lightning"],
                "payee": "did:dht:z6MkRelay"
            }
        }
    }"#;

    /// JSON representing a `.well-known/scp` document without economic config.
    const WELL_KNOWN_WITHOUT_ECONOMIC: &str = r#"{
        "version": 1,
        "did": "did:dht:z6Mk...",
        "relay": "wss://relay.example.com/scp/v1",
        "relay_config": {
            "max_blob_size": 262144,
            "max_blob_ttl": 86400,
            "rate_limit_publish": 100
        }
    }"#;

    /// JSON with no `relay_config` at all.
    const WELL_KNOWN_MINIMAL: &str = r#"{
        "version": 1,
        "did": "did:dht:z6Mk...",
        "relay": "wss://relay.example.com/scp/v1"
    }"#;

    // -- Parsing tests -------------------------------------------------------

    #[test]
    fn parse_well_known_with_economic_field_succeeds() {
        let doc = parse_well_known(WELL_KNOWN_WITH_ECONOMIC)
            .expect("should parse .well-known/scp with economic field");

        let economic = relay_economic_config(&doc).expect("economic config should be present");

        assert_eq!(economic.currency, CurrencyCode::from("USD"));
        assert_eq!(economic.per_publish, Some(Amount::new(10)));
        assert_eq!(economic.per_byte_stored, Some(Amount::new(1)));
        assert_eq!(economic.payment_adapters, vec!["x402", "lightning"]);
        assert_eq!(economic.payee, "did:dht:z6MkRelay");
    }

    #[test]
    fn parse_well_known_without_economic_field_treated_as_free() {
        let doc = parse_well_known(WELL_KNOWN_WITHOUT_ECONOMIC)
            .expect("should parse .well-known/scp without economic field");

        assert!(relay_economic_config(&doc).is_none());
        assert!(is_free_relay_doc(&doc));
    }

    #[test]
    fn parse_well_known_minimal_treated_as_free() {
        let doc =
            parse_well_known(WELL_KNOWN_MINIMAL).expect("should parse minimal .well-known/scp");

        assert!(relay_economic_config(&doc).is_none());
        assert!(is_free_relay_doc(&doc));
    }

    #[test]
    fn parse_well_known_invalid_json_returns_error() {
        let result = parse_well_known("not valid json");
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::ProtocolError(msg) => {
                assert!(msg.contains("failed to parse .well-known/scp"));
            }
            other => panic!("expected ProtocolError, got: {other:?}"),
        }
    }

    // -- Relay entry tests ---------------------------------------------------

    #[test]
    fn relay_entry_is_free_when_no_config() {
        let entry = RelayEntry {
            url: "wss://free.example.com/scp/v1".to_owned(),
            relay_config: None,
        };
        assert!(entry.is_free());
        assert!(entry.economic_config().is_none());
    }

    #[test]
    fn relay_entry_is_free_when_config_has_no_economic() {
        let entry = RelayEntry {
            url: "wss://free.example.com/scp/v1".to_owned(),
            relay_config: Some(RelayConfig {
                max_blob_size: Some(262_144),
                max_blob_ttl: None,
                rate_limit_publish: None,
                rate_limit_subscribe: None,
                transports: None,
                economic: None,
            }),
        };
        assert!(entry.is_free());
    }

    #[test]
    fn relay_entry_is_not_free_when_economic_config_present() {
        let entry = RelayEntry {
            url: "wss://paid.example.com/scp/v1".to_owned(),
            relay_config: Some(RelayConfig {
                max_blob_size: None,
                max_blob_ttl: None,
                rate_limit_publish: None,
                rate_limit_subscribe: None,
                transports: None,
                economic: Some(RelayEconomicConfig {
                    currency: CurrencyCode::from("USD"),
                    per_publish: Some(Amount::new(10)),
                    per_byte_stored: None,
                    payment_adapters: vec!["x402".to_owned()],
                    payee: "did:dht:z6MkPaid".to_owned(),
                }),
            }),
        };
        assert!(!entry.is_free());
        assert!(entry.economic_config().is_some());
    }

    // -- Bootstrap validation tests ------------------------------------------

    #[test]
    fn validate_bootstrap_accepts_list_with_free_relay() {
        let relays = vec![
            RelayEntry {
                url: "wss://free.example.com/scp/v1".to_owned(),
                relay_config: None,
            },
            RelayEntry {
                url: "wss://paid.example.com/scp/v1".to_owned(),
                relay_config: Some(RelayConfig {
                    max_blob_size: None,
                    max_blob_ttl: None,
                    rate_limit_publish: None,
                    rate_limit_subscribe: None,
                    transports: None,
                    economic: Some(RelayEconomicConfig {
                        currency: CurrencyCode::from("USD"),
                        per_publish: Some(Amount::new(10)),
                        per_byte_stored: None,
                        payment_adapters: vec!["x402".to_owned()],
                        payee: "did:dht:z6MkPaid".to_owned(),
                    }),
                }),
            },
        ];
        assert!(validate_bootstrap_has_free_relay(&relays).is_ok());
    }

    #[test]
    fn validate_bootstrap_rejects_list_without_free_relay() {
        let relays = vec![RelayEntry {
            url: "wss://paid.example.com/scp/v1".to_owned(),
            relay_config: Some(RelayConfig {
                max_blob_size: None,
                max_blob_ttl: None,
                rate_limit_publish: None,
                rate_limit_subscribe: None,
                transports: None,
                economic: Some(RelayEconomicConfig {
                    currency: CurrencyCode::from("USD"),
                    per_publish: Some(Amount::new(10)),
                    per_byte_stored: None,
                    payment_adapters: vec!["x402".to_owned()],
                    payee: "did:dht:z6MkPaid".to_owned(),
                }),
            }),
        }];
        let err = validate_bootstrap_has_free_relay(&relays)
            .expect_err("should reject list without free relay");
        match err {
            TransportError::ProtocolError(msg) => {
                assert!(msg.contains("free relay"));
            }
            other => panic!("expected ProtocolError, got: {other:?}"),
        }
    }

    #[test]
    fn validate_bootstrap_accepts_empty_list() {
        // An empty list has no relays at all -- this is technically
        // a different validation concern. The free relay check should
        // fail because there are no free relays.
        let err = validate_bootstrap_has_free_relay(&[]).expect_err("should reject empty list");
        assert!(matches!(err, TransportError::ProtocolError(_)));
    }

    #[test]
    fn validate_bootstrap_accepts_all_free_relays() {
        let relays = vec![
            RelayEntry {
                url: "wss://free1.example.com/scp/v1".to_owned(),
                relay_config: None,
            },
            RelayEntry {
                url: "wss://free2.example.com/scp/v1".to_owned(),
                relay_config: Some(RelayConfig {
                    max_blob_size: Some(1024),
                    max_blob_ttl: None,
                    rate_limit_publish: None,
                    rate_limit_subscribe: None,
                    transports: None,
                    economic: None,
                }),
            },
        ];
        assert!(validate_bootstrap_has_free_relay(&relays).is_ok());
    }
}
