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
/// Additional transports are advertised only when this node actually serves
/// them, so the document never advertises a transport the binary does not run:
///
/// - `"quic"` -> advertised only when a QUIC listener is started, i.e. the
///   `quic` feature is enabled **and** a TLS certificate was provisioned
///   (`quic_listening == true`). In no-domain (plaintext) mode QUIC is not
///   served, so it is not advertised — closing the advertise-but-don't-serve
///   gap (spec §10.14.3 item 1).
/// - `http3` feature -> `"webtransport"`
/// - `udp` feature -> `"udp-dtls"`
///
/// See spec §10.5.1 and §10.14.3.
#[must_use]
fn advertised_transports(quic_listening: bool) -> Vec<String> {
    #[allow(unused_mut)]
    let mut transports = vec!["websocket".to_owned()];
    // `quic_listening` is only ever `true` when the `quic` feature is enabled
    // (the field that feeds it is gated), so this reflects the running listener.
    if quic_listening {
        transports.push("quic".to_owned());
    }
    #[cfg(feature = "http3")]
    transports.push("webtransport".to_owned());
    #[cfg(feature = "udp")]
    transports.push("udp-dtls".to_owned());
    #[cfg(feature = "coap")]
    transports.push("coap".to_owned());
    transports
}

/// Returns whether this node serves a relay-side QUIC listener.
///
/// `true` only when the `quic` feature is enabled and the QUIC listener
/// actually bound and started (set by [`ApplicationNode::serve`] after a
/// successful UDP bind, not merely when the QUIC server config was built).
/// Always `false` without the feature. Reading the *running* state rather than
/// the config-built state ensures `.well-known/scp` does not advertise `"quic"`
/// when the bind failed and the node degraded to WebSocket-only.
///
/// [`ApplicationNode::serve`]: crate::ApplicationNode::serve
//
// Not `const fn`: with the `quic` feature the body performs an atomic load,
// which is not permitted in a const context. Without the feature the body is
// trivially const-able, so silence the lint on that build only.
#[cfg_attr(not(feature = "quic"), allow(clippy::missing_const_for_fn))]
#[must_use]
fn quic_listening(state: &NodeState) -> bool {
    #[cfg(feature = "quic")]
    {
        state
            .quic_listening
            .load(std::sync::atomic::Ordering::Acquire)
    }
    #[cfg(not(feature = "quic"))]
    {
        let _ = state;
        false
    }
}

/// Builds the complete [`WellKnownScp`] document from node state.
///
/// Shared between the Axum handler (HTTP/1.1 + HTTP/2) and the HTTP/3
/// request handler to guarantee identical responses across transports.
pub async fn build_well_known_scp(state: &NodeState) -> WellKnownScp {
    // Read the node's live slot ONCE for the whole document. Every address in
    // this response — the top-level `relay` field and the `relay=` parameter of
    // every `scp://context/…` invite URI — is then the node's single current
    // address, so a NAT tier change landing mid-build cannot produce a document
    // that advertises two different endpoints. See
    // [`LiveSlot`](crate::LiveSlot).
    let relay_url = state.live_state.get().relay_url;

    let contexts = {
        let guard = state.broadcast_contexts.read().await;
        if guard.is_empty() {
            None
        } else {
            Some(
                guard
                    .values()
                    .map(|ctx| {
                        let encoded_relay = utf8_percent_encode(&relay_url, QUERY_VALUE);
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
        transports: Some(advertised_transports(quic_listening(state))),
        economic: None,
    };

    WellKnownScp {
        version: 1,
        did: state.did.clone(),
        relay: relay_url,
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
        let transports = advertised_transports(false);
        assert!(
            transports.contains(&"websocket".to_owned()),
            "websocket must always be present in advertised transports"
        );
        // WebSocket is always the first entry.
        assert_eq!(transports[0], "websocket");
    }

    #[test]
    fn advertised_transports_excludes_quic_when_not_listening() {
        // Regardless of the compile-time feature, a node that is not running a
        // QUIC listener must not advertise quic (§10.14.3 item 1: no
        // advertise-but-don't-serve).
        let transports = advertised_transports(false);
        assert!(
            !transports.contains(&"quic".to_owned()),
            "quic must not be advertised when no QUIC listener is running"
        );
    }

    #[test]
    fn advertised_transports_includes_quic_when_listening() {
        // When a QUIC listener is running, quic must be advertised so clients
        // can discover and prefer it (§10.5.1).
        let transports = advertised_transports(true);
        assert!(
            transports.contains(&"quic".to_owned()),
            "quic must be advertised when a QUIC listener is running"
        );
    }

    #[test]
    #[cfg(not(feature = "http3"))]
    fn advertised_transports_excludes_webtransport_without_feature() {
        let transports = advertised_transports(false);
        assert!(
            !transports.contains(&"webtransport".to_owned()),
            "webtransport must not be advertised without the http3 feature flag"
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn advertised_transports_includes_webtransport_with_feature() {
        let transports = advertised_transports(false);
        assert!(
            transports.contains(&"webtransport".to_owned()),
            "webtransport must be advertised when the http3 feature flag is enabled"
        );
    }

    #[test]
    #[cfg(not(feature = "udp"))]
    fn advertised_transports_excludes_udp_dtls_without_feature() {
        let transports = advertised_transports(false);
        assert!(
            !transports.contains(&"udp-dtls".to_owned()),
            "udp-dtls must not be advertised without the udp feature flag"
        );
    }

    #[test]
    #[cfg(feature = "udp")]
    fn advertised_transports_includes_udp_dtls_with_feature() {
        let transports = advertised_transports(false);
        assert!(
            transports.contains(&"udp-dtls".to_owned()),
            "udp-dtls must be advertised when the udp feature flag is enabled"
        );
    }

    #[test]
    #[cfg(not(any(feature = "http3", feature = "udp", feature = "coap")))]
    fn advertised_transports_not_listening_is_websocket_only() {
        // With no other transport features and no QUIC listener, only websocket
        // should be advertised.
        let transports = advertised_transports(false);
        assert_eq!(
            transports,
            vec!["websocket".to_owned()],
            "without any transport features and no QUIC listener, only websocket should be advertised"
        );
    }
}
