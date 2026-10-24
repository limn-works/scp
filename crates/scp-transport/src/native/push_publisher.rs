//! Production [`PushRelayPublisher`] over live relay connections.
//!
//! It carries a push registrar's messages to each relay
//! (`10-infrastructure-and-self-hosting.md` §10.7.1, ADR-004 **Push
//! registration interception**). [`TransportPushPublisher`] sends one blob to one relay, named by its
//! canonical URL, at the routing ID the registrar chose (the relay's reserved
//! push routing ID). It never fans out: each push message is signed over one
//! relay's URL, and a copy sent to any other relay is refused there with
//! `4060`.
//!
//! Connections are bound after construction through
//! [`bind`](TransportPushPublisher::bind), as with
//! [`TransportRelayPublisher`](crate::native::TransportRelayPublisher). A
//! relay with no bound connection fails closed with
//! [`PushPublishError::Unreachable`], so an unconnected registrar never sees
//! a success it did not get. A relay `ERR` arrives as
//! [`TransportError::RelayRejected`] and leaves as
//! [`PushPublishError::Rejected`] with its code intact, which is what lets the
//! registrar tell a `4060`, `4061`, `4063` or `4064` refusal (never retried)
//! from a `4062` stale timestamp or a `5xxx` failure (retried after the
//! backoff, a `4062` with a newer `timestamp`). A connection whose transport has no raw-blob path
//! answers [`TransportError::NotSupported`] and leaves as
//! [`PushPublishError::Unsupported`], which the registrar does not retry.
//! Node wiring is PUSH-015.

use std::sync::Arc;

use futures::future::BoxFuture;
use scp_core::push::{PushPublishError, PushRelayPublisher};
use scp_did::{RelayUrlError, canonical_relay_url};
use scp_relay_client::{MIN_BLOB_TTL, sanitize_relay_text};

use crate::error::TransportError;
use crate::native::BoundRelays;
use crate::traits::{RoutingId, TransportAdapter};

/// The `blob_ttl` a push message carries in its `PUBLISH`.
///
/// A push-enabled relay intercepts a `PUBLISH` at its reserved push routing
/// ID and never stores the blob (ADR-004 **Push registration interception**,
/// spec 10 §10.7.1), so the TTL governs nothing there. The message still
/// carries the smallest TTL the relay accepts, so a relay that does not
/// intercept keeps the blob for as short a time as the protocol allows.
pub const PUSH_MESSAGE_BLOB_TTL_SECS: u32 = MIN_BLOB_TTL;

/// Sends push registrations and deregistrations to relays over bound
/// connections. See the module docs.
#[derive(Debug, Default)]
pub struct TransportPushPublisher {
    relays: BoundRelays,
}

impl TransportPushPublisher {
    /// Creates a publisher with no bound connections.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds a live connection to the relay at `relay_url`, keyed by the
    /// URL's canonical form, so the registrar's canonical URL finds it. A
    /// later bind for the same relay replaces the earlier connection.
    ///
    /// # Errors
    ///
    /// [`RelayUrlError`] when `relay_url` is not a valid relay URL; nothing
    /// is bound.
    pub fn bind(
        &self,
        relay_url: &str,
        adapter: Arc<dyn TransportAdapter>,
    ) -> Result<(), RelayUrlError> {
        self.relays.bind(canonical_relay_url(relay_url)?, adapter);
        Ok(())
    }

    /// Removes the connection bound to the relay at `relay_url`. An unbound
    /// relay is left as it is.
    ///
    /// # Errors
    ///
    /// [`RelayUrlError`] when `relay_url` is not a valid relay URL.
    pub fn unbind(&self, relay_url: &str) -> Result<(), RelayUrlError> {
        self.relays.unbind(&canonical_relay_url(relay_url)?);
        Ok(())
    }
}

impl PushRelayPublisher for TransportPushPublisher {
    fn publish<'a>(
        &'a self,
        relay_url: &'a str,
        routing_id: [u8; 32],
        blob: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), PushPublishError>> {
        Box::pin(async move {
            let canonical =
                canonical_relay_url(relay_url).map_err(|err| PushPublishError::Unreachable {
                    reason: format!("invalid relay URL: {err}"),
                })?;
            let adapter =
                self.relays
                    .get(&canonical)
                    .ok_or_else(|| PushPublishError::Unreachable {
                        reason: format!("no connection is bound for {canonical}"),
                    })?;
            adapter
                .publish_raw(
                    &RoutingId::new(routing_id),
                    u64::from(PUSH_MESSAGE_BLOB_TTL_SECS),
                    blob,
                )
                .await
                .map_err(publish_error)
        })
    }
}

/// A relay `ERR` keeps its code; a connection with no raw-blob path is
/// [`PushPublishError::Unsupported`], which no retry heals; every other
/// transport failure means the message did not reach a relay that answered.
fn publish_error(err: TransportError) -> PushPublishError {
    match err {
        TransportError::RelayRejected { code, msg } => PushPublishError::Rejected { code, msg },
        TransportError::NotSupported(reason) => PushPublishError::Unsupported {
            reason: sanitize_relay_text(&reason),
        },
        other => PushPublishError::Unreachable {
            reason: sanitize_relay_text(&other.to_string()),
        },
    }
}

#[cfg(test)]
mod tests;
