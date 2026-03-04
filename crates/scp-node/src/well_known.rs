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

/// Axum handler for `GET /.well-known/scp`.
///
/// Reads the current node state (DID, relay URL, registered broadcast
/// contexts) and constructs a [`WellKnownScp`] response. The document
/// is generated fresh on every request -- never cached (spec section
/// 18.6.4: "dynamically generated from node state").
///
/// Returns `application/json` with the `WellKnownScp` payload.
pub async fn well_known_handler(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
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
        economic: None,
    };

    let doc = WellKnownScp {
        version: 1,
        did: state.did.clone(),
        relay: state.relay_url.clone(),
        contexts,
        relay_config: Some(relay_config),
        handles: None,
    };

    (StatusCode::OK, Json(doc))
}
