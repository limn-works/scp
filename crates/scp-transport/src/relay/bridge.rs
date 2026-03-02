//! BRIDGE relay operation for symmetric NAT fallback (spec section 10.12.4).
//!
//! When a self-hosted relay is behind symmetric NAT (~15% of consumer internet
//! connections), neither `UPnP` nor STUN hole punching can establish direct
//! reachability. The BRIDGE operation allows a willing SCP relay to act as a
//! transparent proxy, forwarding blobs bidirectionally between peers and the
//! self-hosted relay.
//!
//! # Architecture
//!
//! ```text
//!  Peer ──wss──▶ Bridge Relay ◀──ws/outbound── Self-Hosted Relay (behind NAT)
//!                    │                              ▲
//!                    │  BRIDGE_REGISTER              │
//!                    │  (routing_id registration)    │
//!                    └──────────────────────────────►┘
//! ```
//!
//! 1. The self-hosted relay connects **outbound** to the bridge relay
//!    (outbound connections are not blocked by NAT).
//! 2. The self-hosted relay registers its `routing_id` via `BRIDGE_REGISTER`.
//! 3. Peers connect to the bridge relay URL (from the DID document) and send
//!    standard relay operations (`PUBLISH`, `SUBSCRIBE`, etc.).
//! 4. The bridge relay forwards all traffic for registered `routing_id`s to
//!    the self-hosted relay over the existing outbound connection.
//!
//! # Properties
//!
//! - **Transparent.** The bridge does NOT inspect, modify, decrypt, or cache
//!   proxied blobs. It sees the same metadata as any relay (section 9.9.1).
//! - **Substitutable.** If a bridge fails, the self-hosted relay discovers
//!   another and re-registers. Peers re-resolve the DID document.
//! - **Multiple bridges.** A self-hosted relay MAY register with multiple
//!   bridge relays simultaneously for availability.
//!
//! # URL format (section 10.12.7)
//!
//! Bridge URLs in DID documents use the format:
//! `wss://bridge.example.com/scp/v1?bridge_target=<hex-routing-hint>`
//!
//! See ADR-004 and spec section 10.12.4 for the full specification.

use std::collections::HashMap;

use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info, warn};

use crate::error::TransportError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Query parameter name used in bridge relay URLs (section 10.12.7).
///
/// Example: `wss://bridge.example.com/scp/v1?bridge_target=deadbeef...`
pub const BRIDGE_TARGET_PARAM: &str = "bridge_target";

/// Maximum number of simultaneous bridge registrations per connection.
/// Prevents a single connection from consuming excessive registry space.
const MAX_REGISTRATIONS_PER_CONNECTION: usize = 64;

// ---------------------------------------------------------------------------
// BridgeRequest — wire-level operation type
// ---------------------------------------------------------------------------

/// The BRIDGE operation sent by peers to a bridge relay to reach a
/// self-hosted relay behind symmetric NAT (spec section 10.12.4).
///
/// This is a higher-level routing hint — peers include this information
/// via the `bridge_target` query parameter in the relay URL. The bridge
/// relay uses `target_routing_id` to look up the registered self-hosted
/// relay connection and proxies traffic to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRequest {
    /// Routing ID of the bridged (self-hosted) relay.
    pub target_routing_id: [u8; 32],

    /// URL hint for reaching the target relay. Used by the bridge for
    /// initial connection establishment if the target is not yet
    /// registered.
    pub target_relay_hint: String,
}

// ---------------------------------------------------------------------------
// BridgeRegistration — self-hosted relay registers with a bridge
// ---------------------------------------------------------------------------

/// Registration message sent by a self-hosted relay to a bridge relay.
///
/// The self-hosted relay connects outbound to the bridge and registers
/// its `routing_id` so the bridge knows to forward traffic for that ID
/// over this connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRegistration {
    /// The routing ID this self-hosted relay is responsible for.
    pub routing_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// BridgeRegistry — server-side state tracking registered bridges
// ---------------------------------------------------------------------------

/// A channel for forwarding bytes to a registered self-hosted relay.
pub type BridgeForwardSender = mpsc::Sender<Vec<u8>>;

/// A receiver for bytes forwarded from the bridge relay.
pub type BridgeForwardReceiver = mpsc::Receiver<Vec<u8>>;

/// Entry in the bridge registry for a single registered routing ID.
#[derive(Debug)]
struct BridgeRegistryEntry {
    /// Connection ID of the self-hosted relay's outbound connection.
    connection_id: u64,

    /// Channel to send proxied blobs to the self-hosted relay.
    forward_tx: BridgeForwardSender,
}

/// Server-side registry tracking which routing IDs are bridged to which
/// self-hosted relay connections.
///
/// Thread-safe via `RwLock` — reads (proxy lookups) are frequent and
/// concurrent, writes (registrations/deregistrations) are infrequent.
#[derive(Debug)]
pub struct BridgeRegistry {
    /// Map from routing ID to the registered self-hosted relay's forwarding channel.
    entries: RwLock<HashMap<[u8; 32], BridgeRegistryEntry>>,

    /// Track how many registrations each connection has (for limits).
    connection_counts: RwLock<HashMap<u64, usize>>,
}

impl BridgeRegistry {
    /// Creates a new, empty bridge registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            connection_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a routing ID as bridged to a self-hosted relay connection.
    ///
    /// Returns a [`BridgeForwardReceiver`] that the connection handler should
    /// read from and forward to the self-hosted relay's WebSocket.
    ///
    /// If the routing ID is already registered, the old registration is
    /// replaced (the self-hosted relay re-registered, possibly after
    /// reconnect).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the connection has
    /// exceeded [`MAX_REGISTRATIONS_PER_CONNECTION`].
    pub async fn register(
        &self,
        routing_id: [u8; 32],
        connection_id: u64,
    ) -> Result<BridgeForwardReceiver, TransportError> {
        // Check per-connection limit.
        let count = self
            .connection_counts
            .read()
            .await
            .get(&connection_id)
            .copied()
            .unwrap_or(0);
        if count >= MAX_REGISTRATIONS_PER_CONNECTION {
            return Err(TransportError::ProtocolError(format!(
                "bridge registration limit exceeded: max {MAX_REGISTRATIONS_PER_CONNECTION} \
                 registrations per connection"
            )));
        }

        let (tx, rx) = mpsc::channel(256);

        // Check if we're replacing an existing registration for this routing_id.
        let old_entry = self.entries.write().await.insert(
            routing_id,
            BridgeRegistryEntry {
                connection_id,
                forward_tx: tx,
            },
        );

        // Update connection counts.
        let mut counts = self.connection_counts.write().await;
        if let Some(old) = &old_entry {
            // Decrement old connection's count if it was a different connection.
            if old.connection_id != connection_id
                && let Some(c) = counts.get_mut(&old.connection_id)
            {
                *c = c.saturating_sub(1);
            }
        }
        if old_entry
            .as_ref()
            .is_none_or(|e| e.connection_id != connection_id)
        {
            *counts.entry(connection_id).or_insert(0) += 1;
        }

        let replaced = old_entry.is_some();
        drop(counts);

        info!(
            routing_id = hex::encode(routing_id),
            connection_id, replaced, "bridge registration"
        );

        Ok(rx)
    }

    /// Removes a specific routing ID registration.
    pub async fn deregister(&self, routing_id: &[u8; 32]) {
        let entry = self.entries.write().await.remove(routing_id);
        if let Some(entry) = entry {
            let mut counts = self.connection_counts.write().await;
            if let Some(c) = counts.get_mut(&entry.connection_id) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    counts.remove(&entry.connection_id);
                }
            }
            drop(counts);
            debug!(
                routing_id = hex::encode(routing_id),
                connection_id = entry.connection_id,
                "bridge deregistration"
            );
        }
    }

    /// Removes all registrations for a given connection (on disconnect).
    pub async fn deregister_connection(&self, connection_id: u64) {
        let routing_ids: Vec<[u8; 32]> = {
            let entries = self.entries.read().await;
            entries
                .iter()
                .filter(|(_, e)| e.connection_id == connection_id)
                .map(|(id, _)| *id)
                .collect()
        };

        if !routing_ids.is_empty() {
            let mut entries = self.entries.write().await;
            for id in &routing_ids {
                entries.remove(id);
            }
        }

        self.connection_counts.write().await.remove(&connection_id);

        if !routing_ids.is_empty() {
            debug!(
                connection_id,
                count = routing_ids.len(),
                "bridge deregistration (connection closed)"
            );
        }
    }

    /// Looks up the forwarding channel for a bridged routing ID.
    ///
    /// Returns `None` if the routing ID is not registered (not bridged).
    pub async fn lookup(&self, routing_id: &[u8; 32]) -> Option<BridgeForwardSender> {
        let entries = self.entries.read().await;
        entries.get(routing_id).map(|e| e.forward_tx.clone())
    }

    /// Returns the number of currently registered bridge entries.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns `true` if the registry has no entries.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

impl Default for BridgeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BridgeConfig — server-side configuration
// ---------------------------------------------------------------------------

/// Configuration for the bridge relay service (spec section 10.12.4).
///
/// Any SCP relay MAY offer bridge service. When `enabled` is true, the
/// relay accepts `BRIDGE_REGISTER` operations and proxies traffic for
/// registered routing IDs.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Whether this relay supports the BRIDGE operation.
    /// Corresponds to the `supports_bridge` configuration flag.
    pub enabled: bool,

    /// Maximum number of concurrent bridge registrations across all
    /// connections. Prevents unbounded registry growth.
    pub max_registrations: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_registrations: 1000,
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge URL parsing (section 10.12.7)
// ---------------------------------------------------------------------------

/// Parses a bridge relay URL and extracts the `bridge_target` routing hint.
///
/// Bridge URLs follow the format specified in section 10.12.7:
/// `wss://bridge.example.com/scp/v1?bridge_target=<hex-routing-hint>`
///
/// Returns `None` if the URL does not contain a `bridge_target` parameter
/// or if the hex encoding is invalid.
#[must_use]
pub fn parse_bridge_target(url: &str) -> Option<Vec<u8>> {
    let query_start = url.find('?')?;
    let query = &url[query_start + 1..];

    for param in query.split('&') {
        if let Some(value) = param.strip_prefix("bridge_target=") {
            return hex::decode(value).ok();
        }
    }

    None
}

/// Returns `true` if the given relay URL is a bridge URL (contains
/// `bridge_target` query parameter).
#[must_use]
pub fn is_bridge_url(url: &str) -> bool {
    url.contains("bridge_target=")
}

// ---------------------------------------------------------------------------
// BridgeDiscovery — client-side bridge discovery and failover
// ---------------------------------------------------------------------------

/// A discovered bridge relay that can be used for registration.
#[derive(Debug, Clone)]
pub struct BridgeRelay {
    /// The bridge relay's WebSocket URL.
    pub url: String,

    /// Whether this bridge is currently active (has a live registration).
    pub active: bool,
}

/// Client-side bridge discovery and failover manager.
///
/// When a self-hosted relay behind symmetric NAT needs bridge service,
/// this manager handles:
/// 1. Discovering available bridge relays (from bootstrap list, DHT, etc.).
/// 2. Registering with one or more bridges.
/// 3. Detecting bridge failures and re-registering with alternatives.
///
/// The bridge is **substitutable** (spec section 10.12.4): if one bridge
/// fails, the manager discovers another and re-registers. No session
/// state is lost because MLS sessions survive relay changes.
#[derive(Debug)]
pub struct BridgeDiscovery {
    /// Known bridge relays, ordered by preference.
    relays: RwLock<Vec<BridgeRelay>>,

    /// The routing ID this self-hosted relay wants to register.
    routing_id: [u8; 32],
}

impl BridgeDiscovery {
    /// Creates a new bridge discovery manager for the given routing ID.
    #[must_use]
    pub fn new(routing_id: [u8; 32]) -> Self {
        Self {
            relays: RwLock::new(Vec::new()),
            routing_id,
        }
    }

    /// Returns the routing ID being registered with bridges.
    #[must_use]
    pub const fn routing_id(&self) -> &[u8; 32] {
        &self.routing_id
    }

    /// Adds a bridge relay to the list of known bridges.
    pub async fn add_relay(&self, url: String) {
        let mut relays = self.relays.write().await;
        // Avoid duplicates.
        if !relays.iter().any(|r| r.url == url) {
            relays.push(BridgeRelay { url, active: false });
        }
    }

    /// Marks a bridge relay as active (successfully registered).
    pub async fn mark_active(&self, url: &str) {
        let mut relays = self.relays.write().await;
        if let Some(relay) = relays.iter_mut().find(|r| r.url == url) {
            relay.active = true;
        }
    }

    /// Marks a bridge relay as failed and returns the next available
    /// alternative for failover.
    ///
    /// Returns `None` if no alternative bridges are available.
    pub async fn failover(&self, failed_url: &str) -> Option<String> {
        let mut relays = self.relays.write().await;

        // Mark the failed relay as inactive.
        if let Some(relay) = relays.iter_mut().find(|r| r.url == failed_url) {
            relay.active = false;
            warn!(url = failed_url, "bridge relay failed, attempting failover");
        }

        // Find the first inactive relay that isn't the failed one.
        relays
            .iter()
            .find(|r| !r.active && r.url != failed_url)
            .map(|r| r.url.clone())
    }

    /// Returns a list of all currently active bridge relays.
    pub async fn active_relays(&self) -> Vec<String> {
        let relays = self.relays.read().await;
        relays
            .iter()
            .filter(|r| r.active)
            .map(|r| r.url.clone())
            .collect()
    }

    /// Returns the number of known bridge relays (active and inactive).
    pub async fn relay_count(&self) -> usize {
        self.relays.read().await.len()
    }
}

// ---------------------------------------------------------------------------
// hex encoding helpers (no external dep beyond what's in scope)
// ---------------------------------------------------------------------------

/// Minimal hex encoding/decoding for bridge target routing hints.
///
/// Avoids pulling in the `hex` crate — bridge targets are 32 bytes max
/// and hex operations are infrequent.
mod hex {
    use std::fmt::Write;

    /// Encodes bytes as a lowercase hex string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Decodes a hex string to bytes.
    ///
    /// Returns `Err` if the string contains non-hex characters or has
    /// odd length.
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- BridgeRequest --

    #[test]
    fn bridge_request_construction() {
        let req = BridgeRequest {
            target_routing_id: [0xAA; 32],
            target_relay_hint: "wss://bridge.example.com/scp/v1".to_string(),
        };
        assert_eq!(req.target_routing_id, [0xAA; 32]);
        assert_eq!(req.target_relay_hint, "wss://bridge.example.com/scp/v1");
    }

    #[test]
    fn bridge_request_equality() {
        let a = BridgeRequest {
            target_routing_id: [0x11; 32],
            target_relay_hint: "wss://a.example.com/scp/v1".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- BridgeRegistration --

    #[test]
    fn bridge_registration_construction() {
        let reg = BridgeRegistration {
            routing_id: [0xBB; 32],
        };
        assert_eq!(reg.routing_id, [0xBB; 32]);
    }

    // -- BridgeRegistry --

    #[tokio::test]
    async fn registry_register_and_lookup() {
        let registry = BridgeRegistry::new();
        let routing_id = [0x01; 32];

        let _rx = registry.register(routing_id, 1).await.unwrap();
        let sender = registry.lookup(&routing_id).await;
        assert!(sender.is_some());
    }

    #[tokio::test]
    async fn registry_lookup_unregistered_returns_none() {
        let registry = BridgeRegistry::new();
        let result = registry.lookup(&[0xFF; 32]).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn registry_deregister_removes_entry() {
        let registry = BridgeRegistry::new();
        let routing_id = [0x02; 32];

        let _rx = registry.register(routing_id, 1).await.unwrap();
        assert!(!registry.is_empty().await);

        registry.deregister(&routing_id).await;
        assert!(registry.is_empty().await);
        assert!(registry.lookup(&routing_id).await.is_none());
    }

    #[tokio::test]
    async fn registry_deregister_connection_removes_all() {
        let registry = BridgeRegistry::new();
        let conn_id = 42;

        let _rx1 = registry.register([0x01; 32], conn_id).await.unwrap();
        let _rx2 = registry.register([0x02; 32], conn_id).await.unwrap();
        let _rx3 = registry.register([0x03; 32], 99).await.unwrap();

        assert_eq!(registry.len().await, 3);

        registry.deregister_connection(conn_id).await;

        assert_eq!(registry.len().await, 1);
        assert!(registry.lookup(&[0x01; 32]).await.is_none());
        assert!(registry.lookup(&[0x02; 32]).await.is_none());
        assert!(registry.lookup(&[0x03; 32]).await.is_some());
    }

    #[tokio::test]
    async fn registry_re_register_replaces_entry() {
        let registry = BridgeRegistry::new();
        let routing_id = [0x04; 32];

        let _rx1 = registry.register(routing_id, 1).await.unwrap();
        let _rx2 = registry.register(routing_id, 2).await.unwrap();

        // Should still have exactly one entry.
        assert_eq!(registry.len().await, 1);

        // The new connection's channel should be returned.
        let sender = registry.lookup(&routing_id).await.unwrap();
        // Verify we can send (old rx1 would be dropped, new rx2 is alive).
        assert!(sender.try_send(vec![0x42]).is_ok());
    }

    #[tokio::test]
    async fn registry_per_connection_limit() {
        let registry = BridgeRegistry::new();
        let conn_id = 1;

        // Register up to the limit.
        #[allow(clippy::cast_possible_truncation)]
        for i in 0..MAX_REGISTRATIONS_PER_CONNECTION {
            let mut routing_id = [0u8; 32];
            routing_id[0] = (i & 0xFF) as u8;
            routing_id[1] = ((i >> 8) & 0xFF) as u8;
            let _rx = registry.register(routing_id, conn_id).await.unwrap();
        }

        // One more should fail.
        let result = registry.register([0xFF; 32], conn_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn registry_forward_blob_through_channel() {
        let registry = BridgeRegistry::new();
        let routing_id = [0x05; 32];

        let mut rx = registry.register(routing_id, 1).await.unwrap();
        let sender = registry.lookup(&routing_id).await.unwrap();

        // Simulate proxying a blob.
        let blob = vec![0xDE, 0xAD, 0xBE, 0xEF];
        sender.send(blob.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received, blob);
    }

    // -- BridgeConfig --

    #[test]
    fn bridge_config_default_is_disabled() {
        let config = BridgeConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_registrations, 1000);
    }

    // -- URL parsing --

    #[test]
    fn parse_bridge_target_valid() {
        let url = "wss://bridge.example.com/scp/v1?bridge_target=aabbccdd";
        let target = parse_bridge_target(url).unwrap();
        assert_eq!(target, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn parse_bridge_target_full_routing_id() {
        let routing_id = [0x42; 32];
        let hex_id = hex::encode(routing_id);
        let url = format!("wss://bridge.example.com/scp/v1?bridge_target={hex_id}");
        let target = parse_bridge_target(&url).unwrap();
        assert_eq!(target, routing_id.to_vec());
    }

    #[test]
    fn parse_bridge_target_no_param() {
        let url = "wss://bridge.example.com/scp/v1";
        assert!(parse_bridge_target(url).is_none());
    }

    #[test]
    fn parse_bridge_target_invalid_hex() {
        let url = "wss://bridge.example.com/scp/v1?bridge_target=xyz";
        assert!(parse_bridge_target(url).is_none());
    }

    #[test]
    fn parse_bridge_target_with_other_params() {
        let url = "wss://bridge.example.com/scp/v1?foo=bar&bridge_target=deadbeef&baz=1";
        let target = parse_bridge_target(url).unwrap();
        assert_eq!(target, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn is_bridge_url_true() {
        assert!(is_bridge_url(
            "wss://bridge.example.com/scp/v1?bridge_target=aabb"
        ));
    }

    #[test]
    fn is_bridge_url_false() {
        assert!(!is_bridge_url("wss://relay.example.com/scp/v1"));
    }

    // -- BridgeDiscovery --

    #[tokio::test]
    async fn discovery_add_and_count() {
        let discovery = BridgeDiscovery::new([0x01; 32]);
        assert_eq!(discovery.relay_count().await, 0);

        discovery
            .add_relay("wss://bridge1.example.com/scp/v1".to_string())
            .await;
        discovery
            .add_relay("wss://bridge2.example.com/scp/v1".to_string())
            .await;
        assert_eq!(discovery.relay_count().await, 2);
    }

    #[tokio::test]
    async fn discovery_no_duplicates() {
        let discovery = BridgeDiscovery::new([0x01; 32]);

        discovery
            .add_relay("wss://bridge1.example.com/scp/v1".to_string())
            .await;
        discovery
            .add_relay("wss://bridge1.example.com/scp/v1".to_string())
            .await;
        assert_eq!(discovery.relay_count().await, 1);
    }

    #[tokio::test]
    async fn discovery_mark_active() {
        let discovery = BridgeDiscovery::new([0x01; 32]);
        let url = "wss://bridge1.example.com/scp/v1".to_string();

        discovery.add_relay(url.clone()).await;
        assert!(discovery.active_relays().await.is_empty());

        discovery.mark_active(&url).await;
        assert_eq!(discovery.active_relays().await, vec![url]);
    }

    #[tokio::test]
    async fn discovery_failover_returns_alternative() {
        let discovery = BridgeDiscovery::new([0x01; 32]);

        let url1 = "wss://bridge1.example.com/scp/v1".to_string();
        let url2 = "wss://bridge2.example.com/scp/v1".to_string();

        discovery.add_relay(url1.clone()).await;
        discovery.add_relay(url2.clone()).await;
        discovery.mark_active(&url1).await;

        // Failover from url1 should return url2.
        let alt = discovery.failover(&url1).await;
        assert_eq!(alt, Some(url2));
    }

    #[tokio::test]
    async fn discovery_failover_no_alternatives() {
        let discovery = BridgeDiscovery::new([0x01; 32]);

        let url1 = "wss://bridge1.example.com/scp/v1".to_string();
        discovery.add_relay(url1.clone()).await;
        discovery.mark_active(&url1).await;

        // No alternative bridges available.
        let alt = discovery.failover(&url1).await;
        assert!(alt.is_none());
    }

    #[tokio::test]
    async fn discovery_routing_id() {
        let routing_id = [0xAB; 32];
        let discovery = BridgeDiscovery::new(routing_id);
        assert_eq!(discovery.routing_id(), &routing_id);
    }

    // -- hex helpers --

    #[test]
    fn hex_encode_decode_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let encoded = hex::encode(&data);
        assert_eq!(encoded, "deadbeef00ff");
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_odd_length_fails() {
        assert!(hex::decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars_fails() {
        assert!(hex::decode("zzzz").is_err());
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex::encode(Vec::<u8>::new()), "");
    }
}
