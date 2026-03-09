//! QUIC connection lifecycle management (section 10.14.2).
//!
//! This module implements the full QUIC connection lifecycle per spec
//! section 10.14.2 and ADR-037:
//!
//! - **0-RTT session resumption** via stored session tickets. Session
//!   tickets are persisted across adapter restarts using
//!   [`SessionTicketStore`], enabling clients to send application data
//!   immediately on reconnection without waiting for the handshake to
//!   complete (RFC 9001 section 4.6.1).
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
/// 1. **0-RTT resumption:** Stores and retrieves session tickets via
///    [`SessionTicketStore`] for instant reconnection.
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

    /// Session ticket store for 0-RTT resumption.
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

    /// Stores a session ticket for future 0-RTT resumption.
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

    /// Retrieves a stored session ticket for 0-RTT resumption.
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
        let ticket = SessionTicket::new(vec![1, 2, 3], Duration::from_secs(3600));
        assert!(!ticket.is_expired());
    }

    #[test]
    fn session_ticket_data_roundtrip() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let ticket = SessionTicket::new(data.clone(), Duration::from_secs(60));
        assert_eq!(ticket.data(), &data);
    }

    #[test]
    fn session_ticket_max_lifetime_accessor() {
        let lifetime = Duration::from_secs(7200);
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
        let ticket = SessionTicket::new(vec![1, 2, 3], Duration::from_secs(3600));

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
        let ticket1 = SessionTicket::new(vec![1], Duration::from_secs(3600));
        let ticket2 = SessionTicket::new(vec![2], Duration::from_secs(3600));

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
            SessionTicket::new(vec![1], Duration::from_secs(3600)),
        );
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_remove() {
        let store = SessionTicketStore::new();
        store.store(
            "wss://relay1.example.com/scp/v1",
            SessionTicket::new(vec![1], Duration::from_secs(3600)),
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
            SessionTicket::new(vec![1], Duration::from_secs(3600)),
        );
        store.store(
            "wss://relay2.example.com/scp/v1",
            SessionTicket::new(vec![2], Duration::from_secs(3600)),
        );
        // At capacity. Adding a third should evict the oldest.
        store.store(
            "wss://relay3.example.com/scp/v1",
            SessionTicket::new(vec![3], Duration::from_secs(3600)),
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
            SessionTicket::new(vec![2], Duration::from_secs(3600)),
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
            SessionTicket::new(vec![0xAA, 0xBB], Duration::from_secs(3600)),
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
            Duration::from_secs(3600),
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

        // Should not panic -- just verify the config is created.
        let _config = manager.build_client_config();
    }

    #[test]
    fn lifecycle_manager_ticket_store_accessor() {
        let store = SessionTicketStore::new();
        store.store(
            "wss://relay.example.com/scp/v1",
            SessionTicket::new(vec![1, 2], Duration::from_secs(3600)),
        );

        let manager = QuicLifecycleManager::new(TransportProfile::Desktop, store);

        // Access the store through the manager.
        assert_eq!(manager.ticket_store().len(), 1);
    }
}
