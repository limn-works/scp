//! `.well-known/scp` route handler.
//!
//! Dynamically generates the `.well-known/scp` JSON document from current
//! node state on each request. The response includes the operator's DID,
//! primary relay URL, and any registered broadcast contexts.
//!
//! See spec section 18.3 for the document format.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use scp_core::well_known::{RelayConfig, WellKnownContext, WellKnownScp};

/// Characters that must be percent-encoded when embedded as a query parameter
/// value.  Preserves URL-safe characters (`:`, `/`, `.`, `?`, `@`) so relay
/// URLs remain human-readable, while encoding delimiters that would break
/// query-string parsing.
const QUERY_VALUE: &AsciiSet = &CONTROLS
    .add(b'%')
    .add(b'&')
    .add(b'=')
    .add(b'#')
    .add(b'+')
    .add(b' ');

use crate::http::NodeState;

/// Returns the list of transports advertised in `.well-known/scp`.
///
/// WebSocket is always included (it is the baseline SCP transport).
/// Additional transports are included when their corresponding feature
/// flags are enabled at compile time:
///
/// - `quic` feature -> `"quic"`
/// - `http3` feature -> `"webtransport"`
/// - `udp` feature -> `"udp-dtls"`
///
/// See spec §10.5.1 and SCP-264.
#[must_use]
fn advertised_transports() -> Vec<String> {
    #[allow(unused_mut)]
    let mut transports = vec!["websocket".to_owned()];
    #[cfg(feature = "quic")]
    transports.push("quic".to_owned());
    #[cfg(feature = "http3")]
    transports.push("webtransport".to_owned());
    #[cfg(feature = "udp")]
    transports.push("udp-dtls".to_owned());
    #[cfg(feature = "coap")]
    transports.push("coap".to_owned());
    transports
}

/// Builds the complete [`WellKnownScp`] document from node state.
///
/// Shared between the Axum handler (HTTP/1.1 + HTTP/2) and the HTTP/3
/// request handler to guarantee identical responses across transports.
pub async fn build_well_known_scp(state: &NodeState) -> WellKnownScp {
    let contexts = {
        let guard = state.broadcast_contexts.read().await;
        if guard.is_empty() {
            None
        } else {
            Some(
                guard
                    .values()
                    .map(|ctx| {
                        let encoded_relay = utf8_percent_encode(&state.relay_url, QUERY_VALUE);
                        let name_param = ctx
                            .name
                            .as_ref()
                            .map(|n| {
                                let encoded = utf8_percent_encode(n, QUERY_VALUE);
                                format!("&name={encoded}")
                            })
                            .unwrap_or_default();
                        let uri = format!(
                            "scp://context/{}?relay={encoded_relay}&mode=broadcast{name_param}",
                            ctx.id,
                        );
                        WellKnownContext {
                            id: ctx.id.clone(),
                            name: ctx.name.clone(),
                            mode: Some("broadcast".to_owned()),
                            uri: Some(uri),
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        }
    };

    let rc = &state.relay_config;
    let relay_config = RelayConfig {
        max_blob_size: Some(rc.max_blob_size as u64),
        max_blob_ttl: Some(u64::from(rc.max_blob_ttl)),
        // Spec §18.3.3: unit is "per minute"; transport field is per-second.
        rate_limit_publish: Some(rc.rate_limit_publishes_per_second.saturating_mul(60)),
        // Spec §18.3.3: "Maximum concurrent subscriptions per connection."
        rate_limit_subscribe: Some(
            u32::try_from(rc.max_subscriptions_per_connection).unwrap_or(u32::MAX),
        ),
        transports: Some(advertised_transports()),
        economic: None,
    };

    WellKnownScp {
        version: 1,
        did: state.did.clone(),
        relay: state.relay_url.clone(),
        contexts,
        relay_config: Some(relay_config),
        handles: None,
    }
}

/// Axum handler for `GET /.well-known/scp`.
///
/// Reads the current node state (DID, relay URL, registered broadcast
/// contexts) and constructs a [`WellKnownScp`] response. The document
/// is generated fresh on every request -- never cached (spec section
/// 18.6.4: "dynamically generated from node state").
///
/// Returns `application/json` with the `WellKnownScp` payload.
pub async fn well_known_handler(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    let doc = build_well_known_scp(&state).await;
    (StatusCode::OK, Json(doc))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn advertised_transports_always_includes_websocket() {
        let transports = advertised_transports();
        assert!(
            transports.contains(&"websocket".to_owned()),
            "websocket must always be present in advertised transports"
        );
        // WebSocket is always the first entry.
        assert_eq!(transports[0], "websocket");
    }

    #[test]
    #[cfg(not(feature = "quic"))]
    fn advertised_transports_excludes_quic_without_feature() {
        let transports = advertised_transports();
        assert!(
            !transports.contains(&"quic".to_owned()),
            "quic must not be advertised without the quic feature flag"
        );
    }

    #[test]
    #[cfg(feature = "quic")]
    fn advertised_transports_includes_quic_with_feature() {
        let transports = advertised_transports();
        assert!(
            transports.contains(&"quic".to_owned()),
            "quic must be advertised when the quic feature flag is enabled"
        );
    }

    #[test]
    #[cfg(not(feature = "http3"))]
    fn advertised_transports_excludes_webtransport_without_feature() {
        let transports = advertised_transports();
        assert!(
            !transports.contains(&"webtransport".to_owned()),
            "webtransport must not be advertised without the http3 feature flag"
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn advertised_transports_includes_webtransport_with_feature() {
        let transports = advertised_transports();
        assert!(
            transports.contains(&"webtransport".to_owned()),
            "webtransport must be advertised when the http3 feature flag is enabled"
        );
    }

    #[test]
    #[cfg(not(feature = "udp"))]
    fn advertised_transports_excludes_udp_dtls_without_feature() {
        let transports = advertised_transports();
        assert!(
            !transports.contains(&"udp-dtls".to_owned()),
            "udp-dtls must not be advertised without the udp feature flag"
        );
    }

    #[test]
    #[cfg(feature = "udp")]
    fn advertised_transports_includes_udp_dtls_with_feature() {
        let transports = advertised_transports();
        assert!(
            transports.contains(&"udp-dtls".to_owned()),
            "udp-dtls must be advertised when the udp feature flag is enabled"
        );
    }

    #[test]
    #[cfg(not(any(feature = "quic", feature = "http3", feature = "udp")))]
    fn advertised_transports_default_is_websocket_only() {
        let transports = advertised_transports();
        assert_eq!(
            transports,
            vec!["websocket".to_owned()],
            "without any transport feature flags, only websocket should be advertised"
        );
    }
}
