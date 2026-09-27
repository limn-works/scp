//! QUIC connection lifecycle management (section 10.14.2).
//!
//! This module implements the full QUIC connection lifecycle per spec
//! section 10.14.2 and ADR-037:
//!
//! - **TLS 1.3 session resumption (1-RTT)** via stored session tickets.
//!   Session tickets are persisted across adapter restarts using
//!   [`SessionTicketStore`], letting clients abbreviate the handshake on
//!   reconnection (RFC 8446 section 2.2). 0-RTT early data is deliberately
//!   NOT enabled — application data is only sent after the handshake
//!   completes, so non-idempotent SCP operations cannot ride 0-RTT and be
//!   replayed. See [`QuicAdapter::connect_url`](super::QuicAdapter::connect_url)
//!   for the 0-RTT safety rationale.
//!
//! - **Connection migration** when the client's IP address changes
//!   (e.g., Wi-Fi to cellular). QUIC migrates the connection without
//!   closing it; active subscription streams continue uninterrupted.
//!   [`ConnectionMigrationEvent`] reports migration events for logging
//!   and metrics.
//!
//! - **QUIC-native keepalive** via PING frames (RFC 9000 section 19.2),
//!   replacing application-level PING/PONG. [`QuicKeepaliveConfig`]
//!   configures the keepalive interval.
//!
//! - **Reconnection with exponential backoff** using profile-derived
//!   parameters. [`ReconnectBackoff`] (re-exported from [`crate::backoff`])
//!   implements the exponential backoff strategy with min/max bounds
//!   from [`TransportProfile`](crate::TransportProfile).
//!
//! See spec section 10.14.2, ADR-037, and ADR-004 for full details.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::NamedGroup;
use rustls::client::ClientSessionStore;
use rustls::pki_types::ServerName;
use zeroize::Zeroizing;

use crate::profile::TransportProfile;

// ---------------------------------------------------------------------------
// Session Ticket Store (TLS 1.3 session resumption, 1-RTT)
// ---------------------------------------------------------------------------

/// Opaque session ticket data for TLS 1.3 session resumption (1-RTT).
///
/// Wraps the raw bytes of a TLS 1.3 session ticket (`NewSessionTicket`
/// message). The ticket is issued by the server at the end of the QUIC
/// handshake and stored by the client to abbreviate future handshakes.
///
/// Session tickets are opaque to the client -- only the server can
/// validate them. The client stores them by relay URL and presents them
/// on reconnection to resume the TLS session (1-RTT). 0-RTT early data is
/// not enabled (see the module docs), so resumption speeds up the
/// handshake but does not let application data ride the first flight.
///
/// # Security
///
/// 0-RTT early data has no forward secrecy and is vulnerable to replay
/// attacks (RFC 9001 section 9.2). Because SCP does not enable 0-RTT, no
/// application data is exposed to that replay window; every operation runs
/// only after the resumed handshake completes.
#[derive(Debug, Clone)]
pub struct SessionTicket {
    /// The raw session ticket bytes (opaque TLS 1.3 `NewSessionTicket`).
    ///
    /// Wrapped in [`Zeroizing`] so that the key material is securely
    /// erased from memory when this ticket is dropped (CRYPTO-004a).
    data: Zeroizing<Vec<u8>>,

    /// When this ticket was received from the server.
    received_at: Instant,

    /// Maximum lifetime of the ticket as declared by the server.
    /// After this duration, the ticket MUST NOT be used for resumption.
    max_lifetime: Duration,
}

impl SessionTicket {
    /// Creates a new session ticket from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `data` -- raw session ticket bytes from the TLS 1.3 handshake.
    /// * `max_lifetime` -- server-declared maximum ticket lifetime.
    #[must_use]
    pub fn new(data: Vec<u8>, max_lifetime: Duration) -> Self {
        Self {
            data: Zeroizing::new(data),
            received_at: Instant::now(),
            max_lifetime,
        }
    }

    /// Returns `true` if this ticket has expired.
    ///
    /// A ticket expires when `elapsed_since_received >= max_lifetime`.
    /// Expired tickets MUST NOT be used for session resumption.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.received_at.elapsed() >= self.max_lifetime
    }

    /// Returns the raw session ticket bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the time this ticket was received.
    #[must_use]
    pub const fn received_at(&self) -> Instant {
        self.received_at
    }

    /// Returns the server-declared maximum lifetime.
    #[must_use]
    pub const fn max_lifetime(&self) -> Duration {
        self.max_lifetime
    }
}

/// Persistent session ticket store for TLS 1.3 session resumption (1-RTT)
/// across adapter restarts (section 10.14.2).
///
/// Stores session tickets keyed by relay URL. When a QUIC connection
/// completes a handshake and the server issues a session ticket, the
/// client stores it here. On reconnection, the client retrieves the
/// stored ticket for the target relay and uses it to resume the TLS
/// session, abbreviating the handshake. 0-RTT early data is not enabled.
///
/// The store is thread-safe (`Send + Sync`) via interior mutability so
/// it can be shared across adapter instances and tokio tasks.
///
/// # Persistence
///
/// The store supports serialization to/from bytes for persistence across
/// process restarts. Callers are responsible for the actual I/O -- the
/// store provides [`export`](Self::export) and
/// [`import`](Self::import) methods for the data.
///
/// # Capacity
///
/// The store evicts the oldest ticket when capacity is reached. Default
/// capacity is 256 relay entries, which covers typical deployment
/// scenarios.
#[derive(Debug, Clone)]
pub struct SessionTicketStore {
    inner: Arc<Mutex<SessionTicketStoreInner>>,
}

/// Inner state of the session ticket store, protected by a mutex.
struct SessionTicketStoreInner {
    /// Application-layer session tickets keyed by relay URL (for
    /// persistence across restarts via [`SessionTicketStore::export`]).
    tickets: HashMap<String, SessionTicket>,

    /// Maximum number of relay entries to store.
    capacity: usize,

    /// TLS 1.3 session tickets keyed by server name, used by rustls
    /// via the [`ClientSessionStore`] trait for session resumption (1-RTT).
    /// Each server may have multiple valid tickets (FIFO queue).
    tls13_tickets: HashMap<ServerName<'static>, Vec<rustls::client::Tls13ClientSessionValue>>,

    /// Key exchange group hints keyed by server name.
    kx_hints: HashMap<ServerName<'static>, NamedGroup>,
}

impl fmt::Debug for SessionTicketStoreInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTicketStoreInner")
            .field("tickets", &self.tickets)
            .field("capacity", &self.capacity)
            .field(
                "tls13_tickets_count",
                &self.tls13_tickets.values().map(Vec::len).sum::<usize>(),
            )
            .field("kx_hints_count", &self.kx_hints.len())
            .finish()
    }
}

/// Default capacity for the session ticket store.
const DEFAULT_TICKET_STORE_CAPACITY: usize = 256;

impl SessionTicketStore {
    /// Creates a new empty session ticket store with default capacity (256).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_TICKET_STORE_CAPACITY)
    }

    /// Creates a new empty session ticket store with the specified capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero. A zero-capacity store cannot store any
    /// tickets but the eviction logic cannot enforce this constraint.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "session ticket store capacity must be at least 1"
        );
        Self {
            inner: Arc::new(Mutex::new(SessionTicketStoreInner {
                tickets: HashMap::with_capacity(capacity.min(256)),
                capacity,
                tls13_tickets: HashMap::new(),
                kx_hints: HashMap::new(),
            })),
        }
    }

    /// Stores a session ticket for a relay URL.
    ///
    /// If the store is at capacity, the oldest ticket (by `received_at`)
    /// is evicted. If a ticket already exists for this relay, it is
    /// replaced.
    pub fn store(&self, relay_url: &str, ticket: SessionTicket) {
        let Ok(mut inner) = self.inner.lock() else {
            // Mutex poisoned -- silently drop the ticket.
            // This can only happen if a panic occurred while holding the
            // lock, which is a catastrophic failure mode. Losing session
            // tickets is acceptable in this case.
            return;
        };

        // If at capacity and this is a new key, evict the oldest.
        if inner.tickets.len() >= inner.capacity && !inner.tickets.contains_key(relay_url) {
            evict_oldest(&mut inner.tickets);
        }

        inner.tickets.insert(relay_url.to_owned(), ticket);
    }

    /// Retrieves the session ticket for a relay URL, if one exists and
    /// has not expired.
    ///
    /// Expired tickets are removed from the store and `None` is returned.
    #[must_use]
    pub fn get(&self, relay_url: &str) -> Option<SessionTicket> {
        let Ok(mut inner) = self.inner.lock() else {
            return None;
        };

        if let Some(ticket) = inner.tickets.get(relay_url) {
            if ticket.is_expired() {
                inner.tickets.remove(relay_url);
                return None;
            }
            return Some(ticket.clone());
        }

        None
    }

    /// Removes the session ticket for a relay URL.
    ///
    /// Returns `true` if a ticket was removed, `false` if no ticket
    /// existed for this relay.
    #[must_use]
    pub fn remove(&self, relay_url: &str) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        inner.tickets.remove(relay_url).is_some()
    }

    /// Returns the number of stored tickets (including expired ones that
    /// have not yet been lazily cleaned).
    #[must_use]
    pub fn len(&self) -> usize {
        let Ok(inner) = self.inner.lock() else {
            return 0;
        };
        inner.tickets.len()
    }

    /// Returns `true` if the store contains no tickets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes all expired tickets from the store.
    ///
    /// Returns the number of tickets removed.
    #[must_use]
    pub fn prune_expired(&self) -> usize {
        let Ok(mut inner) = self.inner.lock() else {
            return 0;
        };
        let before = inner.tickets.len();
        inner.tickets.retain(|_, ticket| !ticket.is_expired());
        before - inner.tickets.len()
    }

    /// Exports all non-expired tickets as `(relay_url, ticket_data, max_lifetime_secs)` tuples.
    ///
    /// Callers can serialize these for persistence across restarts.
    /// The `received_at` field is reset to `Instant::now()` minus the
    /// elapsed time -- callers should persist the remaining lifetime.
    #[must_use]
    pub fn export(&self) -> Vec<(String, Vec<u8>, u64)> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };

        inner
            .tickets
            .iter()
            .filter(|(_, ticket)| !ticket.is_expired())
            .map(|(url, ticket)| {
                let elapsed = ticket.received_at.elapsed();
                let remaining = ticket.max_lifetime.saturating_sub(elapsed);
                (url.clone(), (*ticket.data).clone(), remaining.as_secs())
            })
            .collect()
    }

    /// Imports tickets from `(relay_url, ticket_data, remaining_lifetime_secs)` tuples.
    ///
    /// Tickets with zero remaining lifetime are skipped. This is the
    /// counterpart to [`export`](Self::export) for restoring tickets
    /// from persistent storage.
    pub fn import(&self, tickets: &[(String, Vec<u8>, u64)]) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };

        for (url, data, remaining_secs) in tickets {
            if *remaining_secs == 0 {
                continue;
            }

            // Evict oldest if at capacity and this is a new key.
            if inner.tickets.len() >= inner.capacity && !inner.tickets.contains_key(url.as_str()) {
                evict_oldest(&mut inner.tickets);
            }

            let ticket = SessionTicket {
                data: Zeroizing::new(data.clone()),
                received_at: Instant::now(),
                max_lifetime: Duration::from_secs(*remaining_secs),
            };
            inner.tickets.insert(url.clone(), ticket);
        }
    }
}

impl Default for SessionTicketStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Evicts the oldest ticket (by `received_at`) from the map.
fn evict_oldest(tickets: &mut HashMap<String, SessionTicket>) {
    if tickets.is_empty() {
        return;
    }

    let oldest_key = tickets
        .iter()
        .min_by_key(|(_, ticket)| ticket.received_at)
        .map(|(key, _)| key.clone());

    if let Some(key) = oldest_key {
        tickets.remove(&key);
    }
}

// ---------------------------------------------------------------------------
// rustls ClientSessionStore integration
// ---------------------------------------------------------------------------

/// Maximum number of TLS 1.3 tickets stored per server name.
///
/// Rustls may issue multiple tickets per connection; we keep a bounded
/// queue to prevent unbounded growth.
const MAX_TLS13_TICKETS_PER_SERVER: usize = 8;

impl ClientSessionStore for SessionTicketStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.kx_hints.insert(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        let Ok(inner) = self.inner.lock() else {
            return None;
        };
        inner.kx_hints.get(server_name).copied()
    }

    fn set_tls12_session(
        &self,
        _server_name: ServerName<'static>,
        _value: rustls::client::Tls12ClientSessionValue,
    ) {
        // QUIC mandates TLS 1.3 (RFC 9001 §4.1); TLS 1.2 sessions are
        // not applicable. Silently ignore.
    }

    fn tls12_session(
        &self,
        _server_name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        // QUIC mandates TLS 1.3.
        None
    }

    fn remove_tls12_session(&self, _server_name: &ServerName<'static>) {
        // QUIC mandates TLS 1.3.
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let tickets = inner.tls13_tickets.entry(server_name).or_default();
        // Evict oldest if at per-server capacity.
        if tickets.len() >= MAX_TLS13_TICKETS_PER_SERVER {
            tickets.remove(0);
        }
        tickets.push(value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        let Ok(mut inner) = self.inner.lock() else {
            return None;
        };
        let tickets = inner.tls13_tickets.get_mut(server_name)?;
        if tickets.is_empty() {
            return None;
        }
        // Return the most recent ticket (LIFO — last inserted is freshest).
        tickets.pop()
    }
}

// ---------------------------------------------------------------------------
// Connection Migration
// ---------------------------------------------------------------------------

/// Event emitted when a QUIC connection migrates to a new network path.
///
/// QUIC connections survive IP address changes (e.g., Wi-Fi to cellular)
/// without closing. Active subscription streams continue uninterrupted.
/// This event is emitted for logging and metrics purposes.
///
/// See spec section 10.14.2 point 3 (connection migration).
#[derive(Debug, Clone)]
pub struct ConnectionMigrationEvent {
    /// The relay URL whose connection migrated.
    pub relay_url: String,

    /// When the migration was detected.
    pub detected_at: Instant,

    /// Whether active streams survived the migration.
    ///
    /// In QUIC, streams survive migration by default. This is `false`
    /// only if the migration failed and the connection was reset.
    pub streams_preserved: bool,
}

impl ConnectionMigrationEvent {
    /// Creates a new migration event indicating successful stream preservation.
    #[must_use]
    pub fn success(relay_url: String) -> Self {
        Self {
            relay_url,
            detected_at: Instant::now(),
            streams_preserved: true,
        }
    }

    /// Creates a new migration event indicating streams were lost.
    #[must_use]
    pub fn failed(relay_url: String) -> Self {
        Self {
            relay_url,
            detected_at: Instant::now(),
            streams_preserved: false,
        }
    }
}

// ---------------------------------------------------------------------------
// QUIC Keepalive Configuration
// ---------------------------------------------------------------------------

/// Configuration for QUIC-native keepalive via PING frames.
///
/// QUIC's native PING frame mechanism (RFC 9000 section 19.2) replaces
/// WebSocket PING/PONG. PING frames are ack-eliciting, resetting the
/// idle timeout. No application-level keepalive is needed.
///
/// See spec section 10.14.2 point 5 (keepalive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicKeepaliveConfig {
    /// Interval at which QUIC PING frames are sent.
    ///
    /// This should be less than the server's idle timeout to prevent
    /// the connection from being closed. quinn's `keep_alive_interval`
    /// maps directly to this.
    ///
    /// Default: 15 seconds (half of a typical 30-second idle timeout).
    interval: Duration,
}

/// Default keepalive interval: 15 seconds.
///
/// This is half of the typical relay idle timeout (30s per ADR-004).
/// Sending PINGs at half the idle timeout provides a comfortable margin
/// for network jitter while keeping the connection alive.
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

impl QuicKeepaliveConfig {
    /// Creates a new keepalive config with the specified interval.
    ///
    /// # Arguments
    ///
    /// * `interval` -- interval between QUIC PING frames. Must be
    ///   greater than zero.
    ///
    /// # Panics
    ///
    /// Panics if `interval` is zero. A zero interval causes quinn to send
    /// PING frames in a tight loop, consuming CPU and flooding the connection.
    #[must_use]
    pub const fn new(interval: Duration) -> Self {
        assert!(
            interval.as_nanos() > 0,
            "keepalive interval must be greater than zero"
        );
        Self { interval }
    }

    /// Returns the keepalive interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Applies this keepalive configuration to a quinn transport config.
    ///
    /// Sets `keep_alive_interval` on the quinn transport config, which
    /// causes quinn to send QUIC PING frames at the specified interval.
    /// This replaces application-level PING/PONG entirely (section 10.14.2
    /// point 5).
    pub fn apply_to_transport_config(&self, config: &mut quinn::TransportConfig) {
        config.keep_alive_interval(Some(self.interval));
    }
}

impl Default for QuicKeepaliveConfig {
    fn default() -> Self {
        Self::new(DEFAULT_KEEPALIVE_INTERVAL)
    }
}

// ---------------------------------------------------------------------------
// Reconnect Backoff (re-export from shared module)
// ---------------------------------------------------------------------------

// Re-exported from the shared `backoff` module so existing code that
// imports `crate::quic::lifecycle::ReconnectBackoff` continues to compile.
// New code should import from `crate::backoff::ReconnectBackoff` or the
// crate-level re-export `scp_transport::ReconnectBackoff`.
pub use crate::backoff::ReconnectBackoff;

// ---------------------------------------------------------------------------
// Lifecycle Manager
// ---------------------------------------------------------------------------

/// Gap-fill overlap duration for re-subscribing after reconnection.
///
/// After reconnecting, subscription streams are re-opened with
/// `since = last_received_stored_at - RECONNECT_GAP_FILL_OVERLAP`.
/// This 5-second overlap ensures no messages are lost during the
/// transition, at the cost of potential duplicates (deduplicated
/// by `BlobId`). Same strategy as WebSocket reconnection per ADR-004.
const RECONNECT_GAP_FILL_OVERLAP: Duration = Duration::from_secs(5);

/// QUIC connection lifecycle manager (section 10.14.2).
///
/// Coordinates all aspects of QUIC connection lifecycle:
///
/// 1. **Session resumption (1-RTT):** Stores and retrieves TLS 1.3 session
///    tickets via [`SessionTicketStore`] to abbreviate the reconnection
///    handshake. 0-RTT early data is not enabled.
/// 2. **Connection migration:** Monitors for IP address changes and
///    reports migration events.
/// 3. **Keepalive:** Configures QUIC-native PING frames via
///    [`QuicKeepaliveConfig`].
/// 4. **Reconnection:** Uses [`ReconnectBackoff`] for profile-aware
///    exponential backoff on connection loss.
///
/// # Usage
///
/// The lifecycle manager is owned by the [`QuicAdapter`](super::QuicAdapter)
/// and configured at initialization. It does not manage the connection
/// directly -- it provides the parameters and state that the adapter
/// uses when establishing, maintaining, and re-establishing connections.
///
/// ```rust,ignore
/// use scp_transport::quic::lifecycle::{QuicLifecycleManager, SessionTicketStore};
/// use scp_transport::profile::TransportProfile;
///
/// let store = SessionTicketStore::new();
/// let manager = QuicLifecycleManager::new(TransportProfile::Desktop, store);
/// ```
#[derive(Debug)]
pub struct QuicLifecycleManager {
    /// Transport profile driving reconnection and keepalive behavior.
    profile: TransportProfile,

    /// Session ticket store for TLS 1.3 session resumption (1-RTT).
    ticket_store: SessionTicketStore,

    /// Keepalive configuration for QUIC PING frames.
    keepalive: QuicKeepaliveConfig,

    /// Reconnection backoff state.
    ///
    /// `None` for `Constrained` profile (poll-based, no reconnect).
    backoff: Option<ReconnectBackoff>,

    /// Gap-fill overlap duration for re-subscribing after reconnection.
    gap_fill_overlap: Duration,
}

impl QuicLifecycleManager {
    /// Creates a new lifecycle manager for the given profile and ticket store.
    ///
    /// Configures keepalive and reconnection parameters based on the
    /// profile. Uses default keepalive interval (15 seconds).
    #[must_use]
    pub fn new(profile: TransportProfile, ticket_store: SessionTicketStore) -> Self {
        let backoff = ReconnectBackoff::from_profile(&profile);
        Self {
            profile,
            ticket_store,
            keepalive: QuicKeepaliveConfig::default(),
            backoff,
            gap_fill_overlap: RECONNECT_GAP_FILL_OVERLAP,
        }
    }

    /// Creates a new lifecycle manager with a custom keepalive config.
    #[must_use]
    pub fn with_keepalive(
        profile: TransportProfile,
        ticket_store: SessionTicketStore,
        keepalive: QuicKeepaliveConfig,
    ) -> Self {
        let backoff = ReconnectBackoff::from_profile(&profile);
        Self {
            profile,
            ticket_store,
            keepalive,
            backoff,
            gap_fill_overlap: RECONNECT_GAP_FILL_OVERLAP,
        }
    }

    /// Returns the transport profile.
    #[must_use]
    pub const fn profile(&self) -> TransportProfile {
        self.profile
    }

    /// Returns a reference to the session ticket store.
    #[must_use]
    pub const fn ticket_store(&self) -> &SessionTicketStore {
        &self.ticket_store
    }

    /// Returns the keepalive configuration.
    #[must_use]
    pub const fn keepalive(&self) -> &QuicKeepaliveConfig {
        &self.keepalive
    }

    /// Returns the gap-fill overlap duration.
    #[must_use]
    pub const fn gap_fill_overlap(&self) -> Duration {
        self.gap_fill_overlap
    }

    /// Applies lifecycle-related configuration to a quinn transport config.
    ///
    /// Sets the keepalive interval for QUIC-native PING frames. This
    /// replaces application-level PING/PONG entirely (section 10.14.2
    /// point 5).
    pub fn configure_transport(&self, config: &mut quinn::TransportConfig) {
        self.keepalive.apply_to_transport_config(config);
    }

    /// Stores a session ticket for future session resumption (1-RTT).
    ///
    /// Called when the server issues a session ticket after a successful
    /// QUIC handshake. The ticket is stored by relay URL for use on
    /// subsequent connections.
    pub fn store_session_ticket(
        &self,
        relay_url: &str,
        ticket_data: Vec<u8>,
        max_lifetime: Duration,
    ) {
        let ticket = SessionTicket::new(ticket_data, max_lifetime);
        self.ticket_store.store(relay_url, ticket);
    }

    /// Retrieves a stored session ticket for session resumption (1-RTT).
    ///
    /// Returns `None` if no valid (non-expired) ticket exists for the
    /// relay URL.
    #[must_use]
    pub fn get_session_ticket(&self, relay_url: &str) -> Option<SessionTicket> {
        self.ticket_store.get(relay_url)
    }

    /// Returns the delay to wait before the next reconnection attempt.
    ///
    /// Returns `None` if the profile is `Constrained` (poll-based, no
    /// reconnect) or if no backoff is configured.
    #[must_use]
    pub fn next_reconnect_delay(&mut self) -> Option<Duration> {
        self.backoff.as_mut().map(ReconnectBackoff::next_delay)
    }

    /// Resets the reconnection backoff after a successful connection.
    pub const fn reset_backoff(&mut self) {
        if let Some(backoff) = &mut self.backoff {
            backoff.reset();
        }
    }

    /// Returns the number of consecutive failed reconnection attempts.
    #[must_use]
    pub fn reconnect_attempts(&self) -> u32 {
        self.backoff.as_ref().map_or(0, ReconnectBackoff::attempts)
    }

    /// Computes the `since` timestamp for re-subscribing after reconnection.
    ///
    /// Returns `last_received_stored_at - gap_fill_overlap` to ensure
    /// no messages are lost during the transition. The 5-second overlap
    /// is the same strategy as WebSocket reconnection per ADR-004.
    ///
    /// # Arguments
    ///
    /// * `last_received_stored_at` -- epoch seconds of the last received
    ///   envelope's `stored_at` timestamp.
    #[must_use]
    pub const fn gap_fill_since(&self, last_received_stored_at: u64) -> u64 {
        let overlap_secs = self.gap_fill_overlap.as_secs();
        last_received_stored_at.saturating_sub(overlap_secs)
    }

    /// Creates a QUIC transport config with lifecycle-appropriate parameters.
    ///
    /// Configures keepalive intervals, idle timeout, and other transport
    /// parameters appropriate for the lifecycle manager's profile. The
    /// returned config should be applied to a `quinn::ClientConfig`.
    #[must_use]
    pub fn build_client_config(&self) -> quinn::TransportConfig {
        let mut transport_config = quinn::TransportConfig::default();
        self.configure_transport(&mut transport_config);
        transport_config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- SessionTicket --

    #[test]
    fn session_ticket_not_expired_when_fresh() {
        let ticket = SessionTicket::new(vec![1, 2, 3], Duration::from_hours(1));
        assert!(!ticket.is_expired());
    }

    #[test]
    fn session_ticket_data_roundtrip() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let ticket = SessionTicket::new(data.clone(), Duration::from_mins(1));
        assert_eq!(ticket.data(), &data);
    }

    #[test]
    fn session_ticket_max_lifetime_accessor() {
        let lifetime = Duration::from_hours(2);
        let ticket = SessionTicket::new(vec![], lifetime);
        assert_eq!(ticket.max_lifetime(), lifetime);
    }

    #[test]
    fn session_ticket_expired_when_zero_lifetime() {
        let ticket = SessionTicket::new(vec![], Duration::ZERO);
        assert!(ticket.is_expired());
    }

    // -- SessionTicketStore --

    #[test]
    fn store_and_retrieve_ticket() {
        let store = SessionTicketStore::new();
        let ticket = SessionTicket::new(vec![1, 2, 3], Duration::from_hours(1));

        store.store("wss://relay1.example.com/scp/v1", ticket);

        let retrieved = store.get("wss://relay1.example.com/scp/v1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data(), &[1, 2, 3]);
    }

    #[test]
    fn store_returns_none_for_unknown_relay() {
        let store = SessionTicketStore::new();
        assert!(store.get("wss://unknown.example.com/scp/v1").is_none());
    }

    #[test]
    fn store_returns_none_for_expired_ticket() {
        let store = SessionTicketStore::new();
        // Zero lifetime = immediately expired.
        let ticket = SessionTicket::new(vec![1], Duration::ZERO);
        store.store("wss://relay1.example.com/scp/v1", ticket);

        assert!(store.get("wss://relay1.example.com/scp/v1").is_none());
    }

    #[test]
    fn store_replaces_existing_ticket() {
        let store = SessionTicketStore::new();
        let ticket1 = SessionTicket::new(vec![1], Duration::from_hours(1));
        let ticket2 = SessionTicket::new(vec![2], Duration::from_hours(1));

        store.store("wss://relay1.example.com/scp/v1", ticket1);
        store.store("wss://relay1.example.com/scp/v1", ticket2);

        let retrieved = store.get("wss://relay1.example.com/scp/v1");
        assert_eq!(retrieved.unwrap().data(), &[2]);
    }

    #[test]
    fn store_len_and_is_empty() {
        let store = SessionTicketStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store.store(
            "wss://relay1.example.com/scp/v1",
            SessionTicket::new(vec![1], Duration::from_hours(1)),
        );
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_remove() {
        let store = SessionTicketStore::new();
        store.store(
            "wss://relay1.example.com/scp/v1",
            SessionTicket::new(vec![1], Duration::from_hours(1)),
        );

        assert!(store.remove("wss://relay1.example.com/scp/v1"));
        assert!(!store.remove("wss://relay1.example.com/scp/v1"));
        assert!(store.is_empty());
    }

    #[test]
    fn store_evicts_oldest_at_capacity() {
        let store = SessionTicketStore::with_capacity(2);

        store.store(
            "wss://relay1.example.com/scp/v1",
            SessionTicket::new(vec![1], Duration::from_hours(1)),
        );
        store.store(
            "wss://relay2.example.com/scp/v1",
            SessionTicket::new(vec![2], Duration::from_hours(1)),
        );
        // At capacity. Adding a third should evict the oldest.
        store.store(
            "wss://relay3.example.com/scp/v1",
            SessionTicket::new(vec![3], Duration::from_hours(1)),
        );

        assert_eq!(store.len(), 2);
        // relay3 should be present.
        assert!(store.get("wss://relay3.example.com/scp/v1").is_some());
        // relay2 should also be present (it was stored after relay1).
        assert!(store.get("wss://relay2.example.com/scp/v1").is_some());
    }

    #[test]
    fn store_prune_expired() {
        let store = SessionTicketStore::new();

        // One expired, one valid.
        store.store(
            "wss://expired.example.com/scp/v1",
            SessionTicket::new(vec![1], Duration::ZERO),
        );
        store.store(
            "wss://valid.example.com/scp/v1",
            SessionTicket::new(vec![2], Duration::from_hours(1)),
        );

        let pruned = store.prune_expired();
        assert_eq!(pruned, 1);
        assert_eq!(store.len(), 1);
        assert!(store.get("wss://valid.example.com/scp/v1").is_some());
    }

    #[test]
    fn store_export_and_import() {
        let store = SessionTicketStore::new();
        store.store(
            "wss://relay1.example.com/scp/v1",
            SessionTicket::new(vec![0xAA, 0xBB], Duration::from_hours(1)),
        );

        let exported = store.export();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].0, "wss://relay1.example.com/scp/v1");
        assert_eq!(exported[0].1, vec![0xAA, 0xBB]);
        assert!(exported[0].2 > 0); // Remaining lifetime > 0.

        // Import into a new store.
        let store2 = SessionTicketStore::new();
        store2.import(&exported);
        assert_eq!(store2.len(), 1);

        let retrieved = store2.get("wss://relay1.example.com/scp/v1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().data(), &[0xAA, 0xBB]);
    }

    #[test]
    fn store_import_skips_zero_lifetime() {
        let store = SessionTicketStore::new();
        let tickets = vec![("wss://relay.example.com/scp/v1".to_owned(), vec![1], 0u64)];
        store.import(&tickets);
        assert!(store.is_empty());
    }

    #[test]
    fn store_default_creates_empty() {
        let store = SessionTicketStore::default();
        assert!(store.is_empty());
    }

    // -- ConnectionMigrationEvent --

    #[test]
    fn migration_event_success() {
        let event = ConnectionMigrationEvent::success("wss://relay.example.com/scp/v1".to_owned());
        assert!(event.streams_preserved);
        assert_eq!(event.relay_url, "wss://relay.example.com/scp/v1");
    }

    #[test]
    fn migration_event_failed() {
        let event = ConnectionMigrationEvent::failed("wss://relay.example.com/scp/v1".to_owned());
        assert!(!event.streams_preserved);
    }

    // -- QuicKeepaliveConfig --

    #[test]
    fn keepalive_default_interval() {
        let config = QuicKeepaliveConfig::default();
        assert_eq!(config.interval(), Duration::from_secs(15));
    }

    #[test]
    fn keepalive_custom_interval() {
        let config = QuicKeepaliveConfig::new(Duration::from_secs(10));
        assert_eq!(config.interval(), Duration::from_secs(10));
    }

    // -- ReconnectBackoff tests are in crate::backoff::tests --

    // -- QuicLifecycleManager --

    #[test]
    fn lifecycle_manager_construction() {
        let store = SessionTicketStore::new();
        let manager = QuicLifecycleManager::new(TransportProfile::Desktop, store);

        assert_eq!(manager.profile(), TransportProfile::Desktop);
        assert_eq!(manager.keepalive().interval(), Duration::from_secs(15));
        assert_eq!(manager.gap_fill_overlap(), Duration::from_secs(5));
    }

    #[test]
    fn lifecycle_manager_with_custom_keepalive() {
        let store = SessionTicketStore::new();
        let keepalive = QuicKeepaliveConfig::new(Duration::from_secs(10));
        let manager =
            QuicLifecycleManager::with_keepalive(TransportProfile::Server, store, keepalive);

        assert_eq!(manager.keepalive().interval(), Duration::from_secs(10));
    }

    #[test]
    fn lifecycle_manager_session_ticket_roundtrip() {
        let store = SessionTicketStore::new();
        let manager = QuicLifecycleManager::new(TransportProfile::Desktop, store);

        manager.store_session_ticket(
            "wss://relay.example.com/scp/v1",
            vec![0xDE, 0xAD],
            Duration::from_hours(1),
        );

        let ticket = manager.get_session_ticket("wss://relay.example.com/scp/v1");
        assert!(ticket.is_some());
        assert_eq!(ticket.unwrap().data(), &[0xDE, 0xAD]);
    }

    #[test]
    fn lifecycle_manager_reconnect_backoff() {
        let store = SessionTicketStore::new();
        let mut manager = QuicLifecycleManager::new(TransportProfile::Desktop, store);

        // Desktop: aggressive backoff (1-30s).
        let delay = manager.next_reconnect_delay();
        assert!(delay.is_some());
        let delay = delay.unwrap();
        assert!(delay >= Duration::from_secs(1));
        assert!(delay < Duration::from_secs(2));
    }

    #[test]
    fn lifecycle_manager_constrained_no_reconnect() {
        let store = SessionTicketStore::new();
        let mut manager = QuicLifecycleManager::new(TransportProfile::Constrained, store);

        assert!(manager.next_reconnect_delay().is_none());
        assert_eq!(manager.reconnect_attempts(), 0);
    }

    #[test]
    fn lifecycle_manager_reset_backoff() {
        let store = SessionTicketStore::new();
        let mut manager = QuicLifecycleManager::new(TransportProfile::Server, store);

        let _ = manager.next_reconnect_delay();
        let _ = manager.next_reconnect_delay();
        assert!(manager.reconnect_attempts() >= 2);

        manager.reset_backoff();
        assert_eq!(manager.reconnect_attempts(), 0);
    }

    #[test]
    fn lifecycle_manager_gap_fill_since() {
        let store = SessionTicketStore::new();
        let manager = QuicLifecycleManager::new(TransportProfile::Desktop, store);

        // last_received at epoch 100 -> gap_fill_since = 100 - 5 = 95.
        assert_eq!(manager.gap_fill_since(100), 95);

        // Edge case: last_received at epoch 3 -> gap_fill_since = 0 (saturating).
        assert_eq!(manager.gap_fill_since(3), 0);

        // Edge case: last_received at epoch 0 -> gap_fill_since = 0.
        assert_eq!(manager.gap_fill_since(0), 0);
    }

    #[test]
    fn lifecycle_manager_build_client_config() {
        let store = SessionTicketStore::new();
        let manager = QuicLifecycleManager::new(TransportProfile::Desktop, store);

        // `build_client_config` applies this manager's keepalive interval,
        // which `quinn::TransportConfig::default()` leaves unset, so both
        // configs must differ. An earlier version bound that result to
        // `_config` and asserted nothing, so a body returning quinn's default
        // config would have passed.
        let config = manager.build_client_config();
        assert_ne!(
            format!("{config:?}"),
            format!("{:?}", quinn::TransportConfig::default()),
            "build_client_config must apply its keepalive interval rather than \
             return quinn's default transport config"
        );
    }

    #[test]
    fn lifecycle_manager_ticket_store_accessor() {
        let store = SessionTicketStore::new();
        store.store(
            "wss://relay.example.com/scp/v1",
            SessionTicket::new(vec![1, 2], Duration::from_hours(1)),
        );

        let manager = QuicLifecycleManager::new(TransportProfile::Desktop, store);

        // Access the store through the manager.
        assert_eq!(manager.ticket_store().len(), 1);
    }
}
