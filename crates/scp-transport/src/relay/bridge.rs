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
//! # Authentication (SCP-247, §10.12.4)
//!
//! `BRIDGE_REGISTER` requires an Ed25519 signature proving the sender owns
//! the DID that maps to the claimed `routing_id`. The signature covers a
//! domain-separated payload: `"SCP-BRIDGE-REGISTER-V1:" || routing_id || timestamp`.
//! The bridge verifies:
//!
//! 1. The Ed25519 signature is valid for the provided `public_key`.
//! 2. The DID derived from `public_key` maps to the claimed `routing_id`
//!    via `SHA-256("scp:did:" || did_string)` (§3.10.2).
//! 3. The `timestamp` is within 60 seconds of the server's current time
//!    (replay window).
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
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
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

/// Maximum allowed timestamp skew in seconds between the `BRIDGE_REGISTER`
/// timestamp and the server's current time. Prevents replay attacks while
/// allowing reasonable clock drift between peers (SCP-247).
const BRIDGE_REGISTER_REPLAY_WINDOW_SECS: u64 = 60;

/// Domain separator for DID routing IDs (same as §3.10.2 in scp-identity).
///
/// This is intentionally duplicated from `scp-identity::resolution` to avoid
/// adding a cross-crate dependency. The value MUST match
/// `scp_identity::resolution::DID_ROUTING_DOMAIN_SEPARATOR`.
const DID_ROUTING_DOMAIN_SEPARATOR: &[u8] = b"scp:did:";

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
///
/// # Authentication (SCP-247)
///
/// The registration MUST include an Ed25519 signature proving the sender
/// owns the DID that maps to the claimed `routing_id`. The signature
/// covers `routing_id || timestamp` (concatenated bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRegistration {
    /// The routing ID this self-hosted relay is responsible for.
    pub routing_id: [u8; 32],

    /// Ed25519 public key of the DID owner (32 bytes). The bridge derives
    /// the DID string from this key and verifies that
    /// `SHA-256("scp:did:" || did_string) == routing_id`.
    pub public_key: [u8; 32],

    /// Ed25519 signature over `routing_id || timestamp` (64 bytes).
    /// Proves the sender holds the private key corresponding to `public_key`.
    pub signature: [u8; 64],

    /// Unix timestamp (seconds since epoch) included in the signed payload.
    /// Must be within [`BRIDGE_REGISTER_REPLAY_WINDOW_SECS`] of the server's
    /// current time to prevent replay attacks.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Authentication helpers (SCP-247)
// ---------------------------------------------------------------------------

/// Derives a `did:dht:z...` string from a raw Ed25519 public key.
///
/// Uses z-base-32 encoding per the did:dht method specification:
/// `did:dht:z` + zbase32-encode(public_key_bytes).
fn did_from_ed25519_public_key(public_key: &[u8; 32]) -> String {
    format!("did:dht:z{}", zbase32::encode(public_key))
}

/// Computes the DID routing ID: `SHA-256("scp:did:" || did_string)`.
///
/// This matches `scp_identity::resolution::did_routing_id` (§3.10.2).
fn compute_did_routing_id(did_string: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DID_ROUTING_DOMAIN_SEPARATOR);
    hasher.update(did_string.as_bytes());
    hasher.finalize().into()
}

/// Domain separator prefix for `BRIDGE_REGISTER` signable payloads.
///
/// Prevents cross-protocol signature confusion by binding signatures to
/// this specific operation.
const BRIDGE_REGISTER_SIGN_PREFIX: &[u8] = b"SCP-BRIDGE-REGISTER-V1:";

/// Constructs the signable payload for a `BRIDGE_REGISTER` operation.
///
/// The payload is `"SCP-BRIDGE-REGISTER-V1:" || routing_id || big-endian-u64(timestamp)`.
/// The domain separator prevents cross-protocol signature confusion.
#[must_use]
pub fn bridge_register_signable(routing_id: &[u8; 32], timestamp: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BRIDGE_REGISTER_SIGN_PREFIX.len() + 32 + 8);
    buf.extend_from_slice(BRIDGE_REGISTER_SIGN_PREFIX);
    buf.extend_from_slice(routing_id);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf
}

/// Reason a `BRIDGE_REGISTER` authentication check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeAuthError {
    /// The Ed25519 signature is invalid or the public key is malformed.
    InvalidSignature(String),
    /// The DID derived from the public key does not produce the claimed
    /// `routing_id` via `SHA-256("scp:did:" || did_string)`.
    RoutingIdMismatch {
        /// The routing ID claimed in the registration.
        claimed: [u8; 32],
        /// The routing ID derived from the public key's DID.
        derived: [u8; 32],
    },
    /// The timestamp is outside the replay window.
    TimestampExpired {
        /// The timestamp in the registration message.
        registration_ts: u64,
        /// The server's current time.
        server_ts: u64,
    },
}

impl std::fmt::Display for BridgeAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {msg}"),
            Self::RoutingIdMismatch { claimed, derived } => {
                write!(
                    f,
                    "routing ID mismatch: claimed {}, derived {}",
                    hex::encode(claimed),
                    hex::encode(derived)
                )
            }
            Self::TimestampExpired {
                registration_ts,
                server_ts,
            } => {
                write!(
                    f,
                    "timestamp expired: registration_ts={registration_ts}, \
                     server_ts={server_ts}, window={BRIDGE_REGISTER_REPLAY_WINDOW_SECS}s"
                )
            }
        }
    }
}

impl std::error::Error for BridgeAuthError {}

/// Verifies a `BRIDGE_REGISTER` authentication proof (SCP-247).
///
/// Checks:
/// 1. The Ed25519 signature over the domain-separated payload is valid.
/// 2. The DID derived from `public_key` produces the claimed `routing_id`
///    via `SHA-256("scp:did:" || did_string)`.
/// 3. The `timestamp` is within `BRIDGE_REGISTER_REPLAY_WINDOW_SECS` of
///    `server_time_secs`.
///
/// # Errors
///
/// Returns [`BridgeAuthError`] describing the specific authentication failure.
pub fn verify_bridge_registration(
    registration: &BridgeRegistration,
    server_time_secs: u64,
) -> Result<(), BridgeAuthError> {
    // Step 1: Verify timestamp is within replay window.
    let diff = server_time_secs.abs_diff(registration.timestamp);
    if diff > BRIDGE_REGISTER_REPLAY_WINDOW_SECS {
        return Err(BridgeAuthError::TimestampExpired {
            registration_ts: registration.timestamp,
            server_ts: server_time_secs,
        });
    }

    // Step 2: Verify Ed25519 signature over routing_id || timestamp.
    let verifying_key = VerifyingKey::from_bytes(&registration.public_key)
        .map_err(|e| BridgeAuthError::InvalidSignature(format!("malformed public key: {e}")))?;

    let signable = bridge_register_signable(&registration.routing_id, registration.timestamp);
    let signature = ed25519_dalek::Signature::from_bytes(&registration.signature);
    verifying_key
        .verify_strict(&signable, &signature)
        .map_err(|e| {
            BridgeAuthError::InvalidSignature(format!("signature verification failed: {e}"))
        })?;

    // Step 3: Verify routing_id == SHA-256("scp:did:" || did_string).
    let did_string = did_from_ed25519_public_key(&registration.public_key);
    let derived_routing_id = compute_did_routing_id(&did_string);
    if derived_routing_id != registration.routing_id {
        return Err(BridgeAuthError::RoutingIdMismatch {
            claimed: registration.routing_id,
            derived: derived_routing_id,
        });
    }

    Ok(())
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

    /// Maximum number of total registrations across all connections.
    max_registrations: usize,
}

impl BridgeRegistry {
    /// Creates a new, empty bridge registry with a default limit of 1000 registrations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            connection_counts: RwLock::new(HashMap::new()),
            max_registrations: 1000,
        }
    }

    /// Creates a new bridge registry with the given maximum registration limit.
    #[must_use]
    pub fn with_max_registrations(max_registrations: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            connection_counts: RwLock::new(HashMap::new()),
            max_registrations,
        }
    }

    /// Registers a routing ID as bridged to a self-hosted relay connection.
    ///
    /// Verifies the Ed25519 ownership proof before accepting the registration
    /// (SCP-247). The signature must cover the domain-separated payload, the
    /// public key must derive to the claimed routing ID, and the timestamp
    /// must be within 60 seconds of the server's current time.
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
    /// Returns [`TransportError::ProtocolError`] if:
    /// - The authentication proof is missing or invalid (SCP-247).
    /// - The connection has exceeded [`MAX_REGISTRATIONS_PER_CONNECTION`].
    /// - The global `max_registrations` limit has been reached.
    pub async fn register(
        &self,
        registration: &BridgeRegistration,
        connection_id: u64,
    ) -> Result<BridgeForwardReceiver, TransportError> {
        // Step 1: Authenticate the registration (SCP-247).
        let server_time_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| TransportError::ProtocolError("system clock error".into()))?;

        verify_bridge_registration(registration, server_time_secs).map_err(|e| {
            warn!(
                routing_id = hex::encode(registration.routing_id),
                error = %e,
                "bridge registration authentication failed"
            );
            TransportError::ProtocolError("BRIDGE_AUTH_FAILED".to_string())
        })?;

        // Step 2: Check limits and register (same logic as before).
        let routing_id = registration.routing_id;

        // Acquire BOTH write locks up front to prevent TOCTOU races:
        // a concurrent register() between our read-check and write-insert
        // could violate limits.
        let mut entries = self.entries.write().await;
        let mut counts = self.connection_counts.write().await;

        // Check global registration limit (replacements don't increase count).
        let is_replacement = entries.contains_key(&routing_id);
        if !is_replacement && entries.len() >= self.max_registrations {
            return Err(TransportError::ProtocolError(format!(
                "bridge global registration limit exceeded: max {} registrations",
                self.max_registrations
            )));
        }

        // Check per-connection limit. For replacements where the old entry
        // belongs to a *different* connection, the new connection still needs
        // a slot — enforce the limit to prevent bypass via re-registration.
        let conn_count = counts.get(&connection_id).copied().unwrap_or(0);
        let needs_new_slot = !is_replacement
            || entries
                .get(&routing_id)
                .is_some_and(|e| e.connection_id != connection_id);
        if needs_new_slot && conn_count >= MAX_REGISTRATIONS_PER_CONNECTION {
            return Err(TransportError::ProtocolError(format!(
                "bridge registration limit exceeded: max {MAX_REGISTRATIONS_PER_CONNECTION} \
                 registrations per connection"
            )));
        }

        let (tx, rx) = mpsc::channel(256);

        // Insert (or replace) the entry.
        let old_entry = entries.insert(
            routing_id,
            BridgeRegistryEntry {
                connection_id,
                forward_tx: tx,
            },
        );

        // Update connection counts.
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
        drop(entries);

        info!(
            routing_id = hex::encode(routing_id),
            connection_id, replaced, "bridge registration"
        );

        Ok(rx)
    }

    /// Removes a specific routing ID registration.
    ///
    /// Only succeeds if the routing ID is currently registered by the given
    /// `connection_id`. Returns `true` if the entry was removed. Callers
    /// that operate on behalf of a connection must provide their connection ID
    /// to prevent unauthorized deregistration of another connection's entries.
    pub async fn deregister(&self, routing_id: &[u8; 32], connection_id: u64) -> bool {
        let mut entries = self.entries.write().await;
        let Some(entry) = entries.get(routing_id) else {
            return false;
        };
        if entry.connection_id != connection_id {
            warn!(
                routing_id = hex::encode(routing_id),
                claimed_connection = connection_id,
                actual_connection = entry.connection_id,
                "bridge deregistration rejected: connection mismatch"
            );
            return false;
        }
        // Safe: we just confirmed the key exists via get() above.
        let Some(entry) = entries.remove(routing_id) else {
            return false;
        };
        let mut counts = self.connection_counts.write().await;
        if let Some(c) = counts.get_mut(&entry.connection_id) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                counts.remove(&entry.connection_id);
            }
        }
        drop(counts);
        drop(entries);
        debug!(
            routing_id = hex::encode(routing_id),
            connection_id = entry.connection_id,
            "bridge deregistration"
        );
        true
    }

    /// Removes all registrations for a given connection (on disconnect).
    pub async fn deregister_connection(&self, connection_id: u64) {
        // Hold a single write lock throughout to prevent TOCTOU races:
        // a concurrent register() between a read-check and write-remove
        // could be wrongly removed.
        let mut entries = self.entries.write().await;
        let routing_ids: Vec<[u8; 32]> = entries
            .iter()
            .filter(|(_, e)| e.connection_id == connection_id)
            .map(|(id, _)| *id)
            .collect();

        for id in &routing_ids {
            entries.remove(id);
        }
        drop(entries);

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
/// `bridge_target` query parameter in the query string).
#[must_use]
pub fn is_bridge_url(url: &str) -> bool {
    // Only match bridge_target= in the query string portion (after '?'),
    // not in the path, fragment, or userinfo components.
    url.find('?')
        .is_some_and(|pos| url[pos..].contains("bridge_target="))
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    // -- Test helpers --

    /// Creates a valid `BridgeRegistration` for the given signing key at the
    /// given timestamp.
    fn make_registration(signing_key: &SigningKey, timestamp: u64) -> BridgeRegistration {
        let public_key = signing_key.verifying_key().to_bytes();
        let did_string = did_from_ed25519_public_key(&public_key);
        let routing_id = compute_did_routing_id(&did_string);
        let signable = bridge_register_signable(&routing_id, timestamp);
        let signature = signing_key.sign(&signable);
        BridgeRegistration {
            routing_id,
            public_key,
            signature: signature.to_bytes(),
            timestamp,
        }
    }

    /// Returns the current unix timestamp in seconds.
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs()
    }

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
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let reg = make_registration(&signing_key, 1_700_000_000);
        assert_eq!(reg.public_key, signing_key.verifying_key().to_bytes());
        assert_eq!(reg.timestamp, 1_700_000_000);
    }

    // -- Authentication verification (SCP-247) --

    #[test]
    fn verify_valid_registration_succeeds() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let now = 1_700_000_000_u64;
        let reg = make_registration(&signing_key, now);
        assert!(verify_bridge_registration(&reg, now).is_ok());
    }

    #[test]
    fn verify_valid_registration_within_window() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let reg_ts = 1_700_000_000_u64;
        let reg = make_registration(&signing_key, reg_ts);

        // Server time is 59 seconds after registration — within 60s window.
        assert!(verify_bridge_registration(&reg, reg_ts + 59).is_ok());

        // Server time is 59 seconds before registration — within 60s window.
        assert!(verify_bridge_registration(&reg, reg_ts - 59).is_ok());

        // Exactly at the boundary (60 seconds).
        assert!(verify_bridge_registration(&reg, reg_ts + 60).is_ok());
    }

    #[test]
    fn verify_expired_timestamp_rejected() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let reg_ts = 1_700_000_000_u64;
        let reg = make_registration(&signing_key, reg_ts);

        // Server time is 61 seconds after — outside the 60s window.
        let result = verify_bridge_registration(&reg, reg_ts + 61);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BridgeAuthError::TimestampExpired { .. }),
            "expected TimestampExpired, got: {err:?}"
        );
    }

    #[test]
    fn verify_future_timestamp_rejected() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let reg_ts = 1_700_000_100_u64;
        let reg = make_registration(&signing_key, reg_ts);

        // Server time is 61 seconds before the registration timestamp.
        let result = verify_bridge_registration(&reg, reg_ts - 61);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BridgeAuthError::TimestampExpired { .. }
        ));
    }

    #[test]
    fn verify_invalid_signature_rejected() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let now = 1_700_000_000_u64;
        let mut reg = make_registration(&signing_key, now);

        // Corrupt the signature.
        reg.signature[0] ^= 0xFF;

        let result = verify_bridge_registration(&reg, now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BridgeAuthError::InvalidSignature(_)),
            "expected InvalidSignature, got: {err:?}"
        );
    }

    #[test]
    fn verify_wrong_key_rejected() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let other_key = SigningKey::from_bytes(&[99u8; 32]);
        let now = 1_700_000_000_u64;
        let mut reg = make_registration(&signing_key, now);

        // Replace the public key with a different key (signature won't match).
        reg.public_key = other_key.verifying_key().to_bytes();

        let result = verify_bridge_registration(&reg, now);
        assert!(result.is_err());
        // Could be InvalidSignature or RoutingIdMismatch depending on order.
        // Since we verify signature before routing ID, it should be InvalidSignature.
        let err = result.unwrap_err();
        assert!(
            matches!(err, BridgeAuthError::InvalidSignature(_)),
            "expected InvalidSignature, got: {err:?}"
        );
    }

    #[test]
    fn verify_routing_id_mismatch_rejected() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let now = 1_700_000_000_u64;
        let mut reg = make_registration(&signing_key, now);

        // Tamper with the routing_id (but re-sign with the correct key so
        // the signature over the tampered routing_id is valid).
        let fake_routing_id = [0xFFu8; 32];
        let signable = bridge_register_signable(&fake_routing_id, now);
        let sig = signing_key.sign(&signable);
        reg.routing_id = fake_routing_id;
        reg.signature = sig.to_bytes();

        let result = verify_bridge_registration(&reg, now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BridgeAuthError::RoutingIdMismatch { .. }),
            "expected RoutingIdMismatch, got: {err:?}"
        );
    }

    #[test]
    fn verify_malformed_public_key_rejected() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let now = 1_700_000_000_u64;
        let mut reg = make_registration(&signing_key, now);

        // Set public key to all zeros (not a valid Ed25519 point).
        reg.public_key = [0u8; 32];

        let result = verify_bridge_registration(&reg, now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BridgeAuthError::InvalidSignature(_)),
            "expected InvalidSignature, got: {err:?}"
        );
    }

    #[test]
    fn bridge_register_signable_format() {
        let routing_id = [0xAA; 32];
        let timestamp = 0x0102_0304_0506_0708_u64;
        let signable = bridge_register_signable(&routing_id, timestamp);

        let prefix = BRIDGE_REGISTER_SIGN_PREFIX;
        let prefix_len = prefix.len(); // 23 bytes: "SCP-BRIDGE-REGISTER-V1:"
        assert_eq!(signable.len(), prefix_len + 32 + 8);
        assert_eq!(&signable[..prefix_len], prefix);
        assert_eq!(&signable[prefix_len..prefix_len + 32], &routing_id);
        assert_eq!(
            &signable[prefix_len + 32..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn did_from_public_key_format() {
        let key = [42u8; 32];
        let did = did_from_ed25519_public_key(&key);
        assert!(did.starts_with("did:dht:z"));
    }

    #[test]
    fn compute_did_routing_id_matches_identity_crate() {
        // Verify our local computation matches the canonical derivation.
        let did = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let expected: [u8; 32] = [
            0xad, 0xb8, 0x0e, 0x64, 0xa5, 0x91, 0xa0, 0x4b, 0x2e, 0xbd, 0x6b, 0x8d, 0xcb, 0x71,
            0xd8, 0xdf, 0x2b, 0x55, 0x38, 0x10, 0x92, 0xf6, 0x23, 0x96, 0xdb, 0x81, 0x1e, 0xd5,
            0xe2, 0x5f, 0xf7, 0x1b,
        ];
        assert_eq!(compute_did_routing_id(did), expected);
    }

    // -- BridgeRegistry with authentication --

    #[tokio::test]
    async fn registry_register_valid_signature_succeeds() {
        let registry = BridgeRegistry::new();
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let reg = make_registration(&signing_key, current_timestamp());

        let result = registry.register(&reg, 1).await;
        assert!(result.is_ok());

        let sender = registry.lookup(&reg.routing_id).await;
        assert!(sender.is_some());
    }

    #[tokio::test]
    async fn registry_register_invalid_signature_fails() {
        let registry = BridgeRegistry::new();
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let mut reg = make_registration(&signing_key, current_timestamp());

        // Corrupt signature.
        reg.signature[0] ^= 0xFF;

        let result = registry.register(&reg, 1).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("BRIDGE_AUTH_FAILED"),
            "expected BRIDGE_AUTH_FAILED, got: {err_msg}"
        );

        // Registry should be empty.
        assert!(registry.is_empty().await);
    }

    #[tokio::test]
    async fn registry_register_expired_timestamp_fails() {
        let registry = BridgeRegistry::new();
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);

        // Use a timestamp far in the past.
        let old_timestamp = current_timestamp().saturating_sub(120);
        let reg = make_registration(&signing_key, old_timestamp);

        let result = registry.register(&reg, 1).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("BRIDGE_AUTH_FAILED"),
            "expected BRIDGE_AUTH_FAILED, got: {err_msg}"
        );

        assert!(registry.is_empty().await);
    }

    #[tokio::test]
    async fn registry_register_routing_id_mismatch_fails() {
        let registry = BridgeRegistry::new();
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let now = current_timestamp();

        // Create a registration with a fake routing_id (re-signed).
        let fake_routing_id = [0xFFu8; 32];
        let signable = bridge_register_signable(&fake_routing_id, now);
        let sig = signing_key.sign(&signable);
        let reg = BridgeRegistration {
            routing_id: fake_routing_id,
            public_key: signing_key.verifying_key().to_bytes(),
            signature: sig.to_bytes(),
            timestamp: now,
        };

        let result = registry.register(&reg, 1).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("BRIDGE_AUTH_FAILED"),
            "expected BRIDGE_AUTH_FAILED, got: {err_msg}"
        );

        assert!(registry.is_empty().await);
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
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let reg = make_registration(&signing_key, current_timestamp());
        let routing_id = reg.routing_id;

        let _rx = registry.register(&reg, 1).await.unwrap();
        assert!(!registry.is_empty().await);

        assert!(registry.deregister(&routing_id, 1).await);
        assert!(registry.is_empty().await);
        assert!(registry.lookup(&routing_id).await.is_none());
    }

    #[tokio::test]
    async fn registry_deregister_connection_removes_all() {
        let registry = BridgeRegistry::new();
        let conn_id = 42;

        let key1 = SigningKey::from_bytes(&[1u8; 32]);
        let key2 = SigningKey::from_bytes(&[2u8; 32]);
        let key3 = SigningKey::from_bytes(&[3u8; 32]);
        let now = current_timestamp();

        let reg1 = make_registration(&key1, now);
        let reg2 = make_registration(&key2, now);
        let reg3 = make_registration(&key3, now);

        let rid1 = reg1.routing_id;
        let rid2 = reg2.routing_id;
        let rid3 = reg3.routing_id;

        let _rx1 = registry.register(&reg1, conn_id).await.unwrap();
        let _rx2 = registry.register(&reg2, conn_id).await.unwrap();
        let _rx3 = registry.register(&reg3, 99).await.unwrap();

        assert_eq!(registry.len().await, 3);

        registry.deregister_connection(conn_id).await;

        assert_eq!(registry.len().await, 1);
        assert!(registry.lookup(&rid1).await.is_none());
        assert!(registry.lookup(&rid2).await.is_none());
        assert!(registry.lookup(&rid3).await.is_some());
    }

    #[tokio::test]
    async fn registry_re_register_replaces_entry() {
        let registry = BridgeRegistry::new();
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let now = current_timestamp();

        let reg1 = make_registration(&signing_key, now);
        let routing_id = reg1.routing_id;

        let _rx1 = registry.register(&reg1, 1).await.unwrap();

        // Re-register with a different connection (new timestamp to get fresh signature).
        let reg2 = make_registration(&signing_key, now);
        let _rx2 = registry.register(&reg2, 2).await.unwrap();

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
        let now = current_timestamp();

        // Register up to the limit.
        for i in 0..MAX_REGISTRATIONS_PER_CONNECTION {
            #[allow(clippy::cast_possible_truncation)]
            let key_bytes = {
                let mut b = [0u8; 32];
                b[0] = (i & 0xFF) as u8;
                b[1] = ((i >> 8) & 0xFF) as u8;
                // Ensure different keys produce valid Ed25519 points.
                b[31] = 0x01;
                b
            };
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let reg = make_registration(&signing_key, now);
            let _rx = registry.register(&reg, conn_id).await.unwrap();
        }

        // One more should fail.
        let extra_key = SigningKey::from_bytes(&[0xFFu8; 32]);
        let extra_reg = make_registration(&extra_key, now);
        let result = registry.register(&extra_reg, conn_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn registry_forward_blob_through_channel() {
        let registry = BridgeRegistry::new();
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let reg = make_registration(&signing_key, current_timestamp());
        let routing_id = reg.routing_id;

        let mut rx = registry.register(&reg, 1).await.unwrap();
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

    #[tokio::test]
    async fn registry_global_limit_enforced() {
        let registry = BridgeRegistry::with_max_registrations(2);

        let key1 = SigningKey::from_bytes(&[1u8; 32]);
        let key2 = SigningKey::from_bytes(&[2u8; 32]);
        let key3 = SigningKey::from_bytes(&[3u8; 32]);
        let now = current_timestamp();

        let reg1 = make_registration(&key1, now);
        let reg2 = make_registration(&key2, now);
        let reg3 = make_registration(&key3, now);

        // Two registrations from different connections — both succeed.
        let _rx1 = registry.register(&reg1, 1).await.unwrap();
        let _rx2 = registry.register(&reg2, 2).await.unwrap();

        // Third registration from yet another connection — must fail.
        let result = registry.register(&reg3, 3).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("global registration limit"),
            "expected global limit error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn registry_per_connection_limit_atomic() {
        let registry = BridgeRegistry::new();
        let conn_id = 1;
        let now = current_timestamp();

        // Register up to the per-connection limit.
        for i in 0..MAX_REGISTRATIONS_PER_CONNECTION {
            #[allow(clippy::cast_possible_truncation)]
            let key_bytes = {
                let mut b = [0u8; 32];
                b[0] = (i & 0xFF) as u8;
                b[1] = ((i >> 8) & 0xFF) as u8;
                b[31] = 0x01;
                b
            };
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let reg = make_registration(&signing_key, now);
            let _rx = registry.register(&reg, conn_id).await.unwrap();
        }

        // One more on the same connection should fail (per-connection limit).
        let extra_key = SigningKey::from_bytes(&[0xFFu8; 32]);
        let extra_reg = make_registration(&extra_key, now);
        let result = registry.register(&extra_reg, conn_id).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("registrations per connection"),
            "expected per-connection limit error, got: {err_msg}"
        );

        // A different connection should still succeed (global limit is 1000).
        let other_key = SigningKey::from_bytes(&[0xFEu8; 32]);
        let other_reg = make_registration(&other_key, now);
        let result2 = registry.register(&other_reg, 2).await;
        assert!(result2.is_ok());
    }
}
