//! SCP native relay -- server, adapters, and blob storage.
//!
//! This module implements the SCP native relay -- a purpose-built,
//! WebSocket-based store-and-forward relay for SCP envelopes. The relay is
//! deliberately simple: accept opaque blobs, hold them for a TTL, deliver to
//! subscribers, delete on expiry or request. The wire types it speaks
//! ([`scp_relay_client::ClientMessage`] / [`scp_relay_client::RelayMessage`])
//! live in the wasm-safe `scp-relay-client` leaf, shared with the in-browser
//! client (ADR-057 Slice 3, Decision D5).
//!
//! # Wire format
//!
//! All messages are serialized as `MessagePack` maps over WebSocket binary
//! frames. Each message has a required `op` field (string) identifying the
//! operation, plus operation-specific fields. Unknown fields MUST be ignored
//! for forward compatibility.
//!
//! Binary fields (`routing_id`, `blob_id`, `recipient_hint`, `blob`) use
//! `MessagePack`'s native `bin` type -- no Base64 or hex encoding.
//!
//! # Connection
//!
//! Connection URL: `wss://<host>/scp/v1`. TLS 1.3 required. The URL path
//! encodes the protocol version -- no in-band version negotiation.
//!
//! # Keepalive
//!
//! Client MUST send `PING` every 30 seconds. Relay MAY close idle connections
//! after 90 seconds of no messages. WebSocket-level pings (opcode 0x9) are
//! independent TCP-level liveness checks.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.

pub mod adapter;
pub mod cert_pin;
pub(crate) mod client;
#[cfg(feature = "combined")]
pub mod combined;
pub mod did_slot;
#[cfg(feature = "local-cache")]
pub mod local_cache;
#[cfg(feature = "postgres-blob")]
pub mod postgres_blob;
#[cfg(feature = "redb-blob")]
pub mod redb_blob;
pub mod relay_persistence;
pub mod relay_publisher;
pub mod relay_querier;
#[cfg(feature = "s3-blob")]
pub mod s3_blob;
pub mod server;
#[cfg(feature = "sqlite-blob")]
pub mod sqlite_blob;
pub mod storage;

// Re-export primary types for convenience.
//
// The relay wire types (`ClientMessage`, `RelayMessage`, the constants, and
// `RelayProtocolError` / `code`) now live in the wasm-safe `scp-relay-client`
// leaf so the native relay and the in-browser client share ONE definition
// (ADR-057 Slice 3, Decision D5). Import them directly from `scp_relay_client`;
// they are deliberately NOT re-exported here (a shim re-export is forbidden by
// the ADR-057 Amendment — see `scripts/check-no-shim-reexports.sh`).
pub use adapter::NativeRelayAdapter;
pub use cert_pin::{CertPinResult, CertificatePin};
pub use relay_publisher::TransportRelayPublisher;
pub use relay_querier::TransportRelayQuerier;

// ---------------------------------------------------------------------------
// Late-bound relay set — shared by the DID-resolution READ and WRITE halves
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::traits::TransportAdapter;

/// A late-bound `relay_url -> adapter` set.
///
/// Both halves of Model B relay DID resolution — [`TransportRelayQuerier`]
/// (READ, §3.10.4) and [`TransportRelayPublisher`] (WRITE, §3.10.5) — are
/// constructed at FFI init, **before** any relay connection exists, so they hold
/// their transports behind exactly this late-binding map. It lives here, once,
/// rather than being duplicated in each: the two halves await the *same* relay
/// connection set, so a divergence in how they hold it (locking, poisoning,
/// rebind semantics) would be a divergence in when DID resolution and DID
/// publishing are live.
///
/// # Locking discipline
///
/// A synchronous [`RwLock`], never held across an `.await`: every accessor
/// clones the `Arc` handles out and drops the guard before returning, so a
/// caller physically cannot await while holding it. A **poisoned** lock is
/// treated as "no binding" — reads yield nothing and writes are dropped — so a
/// panic elsewhere degrades to the fail-closed path (an unbound publisher errors;
/// an unbound querier returns no candidates) rather than propagating a panic
/// into the resolution path.
#[derive(Default)]
pub(crate) struct BoundRelays {
    relays: RwLock<HashMap<String, Arc<dyn TransportAdapter>>>,
}

impl std::fmt::Debug for BoundRelays {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundRelays")
            .field("bound_relays", &self.len())
            .finish()
    }
}

impl BoundRelays {
    /// Creates an empty set.
    pub(crate) fn new() -> Self {
        Self {
            relays: RwLock::new(HashMap::new()),
        }
    }

    /// Late-binds a live transport adapter for a relay URL.
    ///
    /// Idempotent: a subsequent bind for the same URL replaces the prior
    /// adapter (reconnects rebind rather than accumulate).
    pub(crate) fn bind(&self, relay_url: impl Into<String>, adapter: Arc<dyn TransportAdapter>) {
        if let Ok(mut relays) = self.relays.write() {
            relays.insert(relay_url.into(), adapter);
        }
    }

    /// Removes the binding for a relay URL (e.g. on disconnect). Absent
    /// bindings are ignored.
    pub(crate) fn unbind(&self, relay_url: &str) {
        if let Ok(mut relays) = self.relays.write() {
            relays.remove(relay_url);
        }
    }

    /// The adapter bound for `relay_url`, cloned out under a short lock.
    pub(crate) fn get(&self, relay_url: &str) -> Option<Arc<dyn TransportAdapter>> {
        self.relays.read().ok()?.get(relay_url).cloned()
    }

    /// Every currently-bound `(relay_url, adapter)` pair, cloned out under a
    /// short lock so the guard never crosses an `.await`.
    pub(crate) fn snapshot(&self) -> Vec<(String, Arc<dyn TransportAdapter>)> {
        self.relays.read().map_or_else(
            |_| Vec::new(),
            |m| {
                m.iter()
                    .map(|(url, a)| (url.clone(), Arc::clone(a)))
                    .collect()
            },
        )
    }

    /// Number of relays currently bound.
    pub(crate) fn len(&self) -> usize {
        self.relays.read().map_or(0, |m| m.len())
    }
}
