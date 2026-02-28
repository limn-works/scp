//! Relay economic configuration types for SCP transport.
//!
//! Defines [`RelayEconomicConfig`] — the economic parameters a relay
//! operator declares in `.well-known/scp` (section 19.8). This struct
//! carries per-action costs, accepted payment adapters, and the payee
//! DID. Absence of economic configuration means the relay is free.
//!
//! Re-exports the canonical type from `scp_core::well_known` and
//! provides transport-layer helpers for cost comparison and relay
//! classification.
//!
//! See ADR-033 acceptance criterion 12 and spec section 19.8.

pub use scp_core::well_known::RelayEconomicConfig;

use scp_core::economy::types::Amount;

/// Returns the estimated per-publish cost for a relay's economic config.
///
/// If the relay has no economic config or no `per_publish` cost, returns
/// `Amount(0)` — i.e., the relay is free for publishing.
#[must_use]
pub fn per_publish_cost(config: Option<&RelayEconomicConfig>) -> Amount {
    config.and_then(|c| c.per_publish).unwrap_or(Amount::new(0))
}

/// Returns `true` if the relay has no economic configuration (free relay).
///
/// A relay is considered free when it has no `economic` field in its
/// `relay_config` (section 19.8). This is the default — economic config
/// is entirely optional.
#[must_use]
pub const fn is_free_relay(config: Option<&RelayEconomicConfig>) -> bool {
    config.is_none()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_core::economy::types::CurrencyCode;

    fn sample_economic_config() -> RelayEconomicConfig {
        RelayEconomicConfig {
            currency: CurrencyCode::from("USD"),
            per_publish: Some(Amount::new(10)),
            per_byte_stored: Some(Amount::new(1)),
            payment_adapters: vec!["x402".to_owned(), "lightning".to_owned()],
            payee: "did:dht:z6MkRelay".to_owned(),
        }
    }

    #[test]
    fn per_publish_cost_returns_amount_when_present() {
        let config = sample_economic_config();
        assert_eq!(per_publish_cost(Some(&config)), Amount::new(10));
    }

    #[test]
    fn per_publish_cost_returns_zero_when_no_economic_config() {
        assert_eq!(per_publish_cost(None), Amount::new(0));
    }

    #[test]
    fn per_publish_cost_returns_zero_when_per_publish_absent() {
        let config = RelayEconomicConfig {
            currency: CurrencyCode::from("USD"),
            per_publish: None,
            per_byte_stored: Some(Amount::new(1)),
            payment_adapters: vec![],
            payee: "did:dht:z6MkRelay".to_owned(),
        };
        assert_eq!(per_publish_cost(Some(&config)), Amount::new(0));
    }

    #[test]
    fn is_free_relay_returns_true_when_no_config() {
        assert!(is_free_relay(None));
    }

    #[test]
    fn is_free_relay_returns_false_when_config_present() {
        let config = sample_economic_config();
        assert!(!is_free_relay(Some(&config)));
    }

    #[test]
    fn relay_economic_config_fields_match_spec() {
        let config = sample_economic_config();
        assert_eq!(config.currency, CurrencyCode::from("USD"));
        assert_eq!(config.per_publish, Some(Amount::new(10)));
        assert_eq!(config.per_byte_stored, Some(Amount::new(1)));
        assert_eq!(config.payment_adapters, vec!["x402", "lightning"]);
        assert_eq!(config.payee, "did:dht:z6MkRelay");
    }
}
