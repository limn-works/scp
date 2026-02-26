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

use scp_core::well_known::{WellKnownContext, WellKnownScp};

use crate::http::NodeState;

/// Axum handler for `GET /.well-known/scp`.
///
/// Reads the current node state (DID, relay URL, registered broadcast
/// contexts) and constructs a [`WellKnownScp`] response. The document
/// is generated fresh on every request -- never cached (spec section
/// 18.6.4: "dynamically generated from node state").
///
/// Returns `application/json` with the `WellKnownScp` payload.
pub(crate) async fn well_known_handler(
    State(state): State<Arc<NodeState>>,
) -> impl IntoResponse {
    let contexts = {
        let guard = state.broadcast_contexts.read().await;
        if guard.is_empty() {
            None
        } else {
            Some(
                guard
                    .iter()
                    .map(|ctx| {
                        let uri = format!(
                            "scp://context/{}?relay={}&mode=broadcast{}",
                            ctx.id,
                            state.relay_url,
                            ctx.name
                                .as_ref()
                                .map(|n| format!("&name={n}"))
                                .unwrap_or_default(),
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

    let doc = WellKnownScp {
        version: 1,
        did: state.did.clone(),
        relay: state.relay_url.clone(),
        contexts,
        relay_config: None,
    };

    (StatusCode::OK, Json(doc))
}
