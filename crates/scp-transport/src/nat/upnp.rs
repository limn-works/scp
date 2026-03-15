//! UPnP-IGD and NAT-PMP/PCP port mapping for Tier 1 NAT traversal.
//!
//! Implements the Tier 1 reachability mechanism described in spec section 10.12.2.
//! On relay startup, the SDK attempts to open a port mapping on the local gateway
//! using UPnP-IGD or NAT-PMP/PCP. If successful, the router's external IP and
//! assigned port become the relay's advertised address.
//!
//! This module defines:
//!
//! - [`PortMapper`] -- trait for port mapping backends (UPnP-IGD, NAT-PMP/PCP).
//!   Production implementations use `igd-next` and `natpmp` crates; the trait
//!   enables mock implementations for testing.
//! - [`PortMappingManager`] -- orchestrates the `UPnP` -> NAT-PMP fallback sequence,
//!   manages lease renewal at 50% TTL, and emits [`NatTierChange`] events.
//! - [`PortMappingResult`], [`MappingProtocol`], [`PortMappingError`] -- supporting types.
//!
//! See spec section 10.12.2 (Tier 1: UPnP/NAT-PMP Port Mapping) for the full design.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fraction of the mapping TTL at which renewal is attempted.
/// Per spec 10.12.2: "The SDK renews at 50% TTL."
const RENEWAL_FRACTION: f64 = 0.5;

/// Minimum renewal interval to prevent tight loops on very short TTLs.
const MIN_RENEWAL_INTERVAL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// MappingProtocol
// ---------------------------------------------------------------------------

/// The protocol used to obtain a port mapping.
///
/// Spec 10.12.2 describes UPnP-IGD as the primary attempt, with NAT-PMP/PCP
/// as fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingProtocol {
    /// `UPnP` Internet Gateway Device protocol (SSDP discovery + port mapping).
    UpnpIgd,
    /// NAT Port Mapping Protocol (RFC 6886).
    NatPmp,
    /// Port Control Protocol (RFC 6887), the successor to NAT-PMP.
    Pcp,
}

impl std::fmt::Display for MappingProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UpnpIgd => write!(f, "UPnP-IGD"),
            Self::NatPmp => write!(f, "NAT-PMP"),
            Self::Pcp => write!(f, "PCP"),
        }
    }
}

// ---------------------------------------------------------------------------
// PortMappingResult
// ---------------------------------------------------------------------------

/// Result of a successful port mapping attempt.
///
/// Contains the external address that peers can use to reach the relay,
/// the time-to-live of the mapping lease, and which protocol was used.
///
/// Per spec 10.12.2: "the gateway's external IP and assigned port become the
/// relay's reachable address."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMappingResult {
    /// The external IP and port assigned by the gateway.
    pub external_addr: SocketAddr,
    /// Time-to-live of the mapping. `UPnP` typically 10-60 minutes,
    /// NAT-PMP/PCP has explicit lifetimes (spec 10.12.2).
    pub ttl: Duration,
    /// Which mapping protocol was used.
    pub protocol: MappingProtocol,
}

// ---------------------------------------------------------------------------
// PortMappingError
// ---------------------------------------------------------------------------

/// Errors that can occur during port mapping operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PortMappingError {
    /// Gateway discovery failed (SSDP timeout, no default gateway, etc.).
    #[error("gateway discovery failed: {0}")]
    DiscoveryFailed(String),

    /// The gateway rejected the port mapping request.
    #[error("mapping request rejected: {0}")]
    MappingRejected(String),

    /// The mapping operation timed out.
    #[error("mapping operation timed out")]
    Timeout,

    /// The mapping protocol is not supported by the gateway.
    #[error("protocol not supported: {0}")]
    NotSupported(String),

    /// An internal or unexpected error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// NatTierChange
// ---------------------------------------------------------------------------

/// Events emitted when the NAT mapping or reachability tier state changes.
///
/// Consumers should listen for these events to update the relay's advertised
/// address in the DID document (spec 10.12.2: "Mapping loss triggers immediate
/// DID document update if the tier changes").
///
/// The `TierChanged` variant is emitted by the periodic re-evaluation loop
/// (spec 10.12.1, SCP-243) when the reachability tier changes during a
/// 30-minute re-evaluation cycle or on a network change event.
#[derive(Debug, Clone)]
pub enum NatTierChange {
    /// A port mapping was successfully acquired.
    MappingAcquired(PortMappingResult),

    /// A previously held port mapping was lost. The reason string describes
    /// whether renewal failed, the gateway became unreachable, etc.
    /// Per spec 10.12.2: the SDK re-probes and falls through to Tier 2 if
    /// re-mapping fails.
    MappingLost {
        /// Human-readable description of why the mapping was lost.
        reason: String,
    },

    /// A port mapping lease was successfully renewed.
    MappingRenewed(PortMappingResult),

    /// The reachability tier changed during periodic re-evaluation (§10.12.1,
    /// SCP-243). The `previous_relay_url` is the URL that was previously
    /// published in the DID document. The `new_relay_url` is the URL that
    /// should replace it. The `reason` describes what triggered the change
    /// (periodic 30-minute cycle or network change event).
    TierChanged {
        /// The relay URL previously published in the DID document.
        previous_relay_url: String,
        /// The new relay URL to publish.
        new_relay_url: String,
        /// Human-readable reason for the tier change.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// PortMapper trait
// ---------------------------------------------------------------------------

/// Trait for port mapping backends.
///
/// Production implementations wrap `igd-next` (for UPnP-IGD) or `natpmp`
/// (for NAT-PMP/PCP). The trait enables mock implementations for testing
/// without real network access.
///
/// All methods are async and return pinned futures to enable use in trait
/// objects (`dyn PortMapper`).
pub trait PortMapper: Send + Sync {
    /// Attempt to create a port mapping for the given internal port.
    ///
    /// Returns the external address, TTL, and protocol on success.
    fn map_port(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>>;

    /// Renew an existing port mapping for the given internal port.
    ///
    /// Implementations may re-request the same mapping. The returned TTL
    /// may differ from the original.
    fn renew(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>>;

    /// Remove (unmap) a previously created port mapping.
    fn remove(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<(), PortMappingError>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// PortMappingManager
// ---------------------------------------------------------------------------

/// Orchestrates Tier 1 NAT traversal: UPnP-IGD with NAT-PMP/PCP fallback.
///
/// On [`start`](Self::start), the manager tries the `UPnP` mapper first. If it
/// fails, it falls back to the NAT-PMP/PCP mapper. On success it schedules
/// lease renewal at 50% TTL (spec 10.12.2). Events are emitted on the
/// [`NatTierChange`] channel.
///
/// The manager runs as a background task and can be stopped via
/// [`stop`](Self::stop).
pub struct PortMappingManager {
    /// UPnP-IGD mapper (tried first).
    upnp_mapper: Arc<dyn PortMapper>,
    /// NAT-PMP/PCP mapper (fallback).
    natpmp_mapper: Arc<dyn PortMapper>,
    /// The internal port to map.
    internal_port: u16,
    /// Channel sender for tier-change events.
    event_tx: mpsc::Sender<NatTierChange>,
    /// Handle to the background renewal task, if running.
    task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Cancellation token for the background task.
    cancel_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl PortMappingManager {
    /// Creates a new `PortMappingManager`.
    ///
    /// # Arguments
    ///
    /// * `upnp_mapper` -- UPnP-IGD port mapper (tried first).
    /// * `natpmp_mapper` -- NAT-PMP/PCP port mapper (tried if `UPnP` fails).
    /// * `internal_port` -- The relay's local listening port to map.
    /// * `event_tx` -- Channel for emitting [`NatTierChange`] events.
    #[must_use]
    pub fn new(
        upnp_mapper: Arc<dyn PortMapper>,
        natpmp_mapper: Arc<dyn PortMapper>,
        internal_port: u16,
        event_tx: mpsc::Sender<NatTierChange>,
    ) -> Self {
        Self {
            upnp_mapper,
            natpmp_mapper,
            internal_port,
            event_tx,
            task_handle: None,
            cancel_tx: None,
        }
    }

    /// Attempts to acquire a port mapping using `UPnP` first, then NAT-PMP/PCP.
    ///
    /// Returns the mapping result on success, or the last error if both fail.
    /// Per spec 10.12.2: "Discover local gateway via `UPnP` SSDP multicast or
    /// NAT-PMP default gateway."
    ///
    /// # Errors
    ///
    /// Returns [`PortMappingError`] if both `UPnP` and NAT-PMP/PCP mapping fail.
    pub async fn try_acquire(&self) -> Result<PortMappingResult, PortMappingError> {
        // Try UPnP-IGD first (spec 10.12.2 procedure step 1-3).
        info!(
            "attempting UPnP-IGD port mapping for internal port {}",
            self.internal_port
        );
        match self.upnp_mapper.map_port(self.internal_port).await {
            Ok(result) => {
                info!(
                    protocol = %result.protocol,
                    external_addr = %result.external_addr,
                    ttl_secs = result.ttl.as_secs(),
                    "UPnP-IGD port mapping acquired"
                );
                return Ok(result);
            }
            Err(e) => {
                warn!(error = %e, "UPnP-IGD mapping failed, falling back to NAT-PMP/PCP");
            }
        }

        // Fall back to NAT-PMP/PCP (spec 10.12.2: NAT-PMP/PCP as fallback).
        info!(
            "attempting NAT-PMP/PCP port mapping for internal port {}",
            self.internal_port
        );
        match self.natpmp_mapper.map_port(self.internal_port).await {
            Ok(result) => {
                info!(
                    protocol = %result.protocol,
                    external_addr = %result.external_addr,
                    ttl_secs = result.ttl.as_secs(),
                    "NAT-PMP/PCP port mapping acquired"
                );
                Ok(result)
            }
            Err(e) => {
                warn!(error = %e, "NAT-PMP/PCP mapping also failed");
                Err(e)
            }
        }
    }

    /// Starts the port mapping manager: acquires a mapping and spawns a
    /// background renewal task.
    ///
    /// On success, emits [`NatTierChange::MappingAcquired`] and schedules
    /// renewal at 50% TTL. On failure, returns the error (caller should
    /// fall through to Tier 2 per spec 10.12.2).
    ///
    /// # Errors
    ///
    /// Returns [`PortMappingError`] if both `UPnP` and NAT-PMP/PCP fail.
    pub async fn start(&mut self) -> Result<PortMappingResult, PortMappingError> {
        let result = self.try_acquire().await?;

        // Emit the acquired event.
        let _ = self
            .event_tx
            .send(NatTierChange::MappingAcquired(result.clone()))
            .await;

        // Spawn the renewal loop.
        self.spawn_renewal_loop(&result);

        Ok(result)
    }

    /// Stops the background renewal task and removes the port mapping.
    pub async fn stop(&mut self) {
        // Signal cancellation.
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(true);
        }

        // Wait for the task to finish.
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }

        // Best-effort removal of the mapping. Use whichever mapper might work.
        let port = self.internal_port;
        let _ = self.upnp_mapper.remove(port).await;
        let _ = self.natpmp_mapper.remove(port).await;

        debug!("port mapping manager stopped for internal port {port}");
    }

    /// Spawns the background renewal loop.
    ///
    /// Per spec 10.12.2: "The SDK renews at 50% TTL." If renewal fails,
    /// the manager re-attempts acquisition. If both protocols fail on
    /// re-attempt, [`NatTierChange::MappingLost`] is emitted.
    fn spawn_renewal_loop(&mut self, initial: &PortMappingResult) {
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        self.cancel_tx = Some(cancel_tx);

        let upnp = Arc::clone(&self.upnp_mapper);
        let natpmp = Arc::clone(&self.natpmp_mapper);
        let port = self.internal_port;
        let event_tx = self.event_tx.clone();
        let initial_ttl = initial.ttl;
        let initial_protocol = initial.protocol;

        let handle = tokio::spawn(async move {
            let mut cancel_rx = cancel_rx;
            let mut current_ttl = initial_ttl;
            let mut active_protocol = initial_protocol;

            loop {
                let renewal_delay = renewal_interval(current_ttl);
                debug!(
                    ttl_secs = current_ttl.as_secs(),
                    renewal_secs = renewal_delay.as_secs(),
                    "scheduling next lease renewal"
                );

                // Wait for the renewal interval or cancellation.
                tokio::select! {
                    () = tokio::time::sleep(renewal_delay) => {}
                    _ = cancel_rx.changed() => {
                        debug!("renewal loop cancelled");
                        return;
                    }
                }

                // Attempt renewal with the active mapper.
                let mapper: &dyn PortMapper = match active_protocol {
                    MappingProtocol::UpnpIgd => upnp.as_ref(),
                    MappingProtocol::NatPmp | MappingProtocol::Pcp => natpmp.as_ref(),
                };

                match mapper.renew(port).await {
                    Ok(result) => {
                        info!(
                            protocol = %result.protocol,
                            external_addr = %result.external_addr,
                            ttl_secs = result.ttl.as_secs(),
                            "port mapping renewed"
                        );
                        current_ttl = result.ttl;
                        active_protocol = result.protocol;
                        let _ = event_tx.send(NatTierChange::MappingRenewed(result)).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "renewal failed, attempting full re-acquisition");

                        // Re-attempt: UPnP first, then NAT-PMP (same fallback order).
                        let reacquire =
                            try_acquire_with(upnp.as_ref(), natpmp.as_ref(), port).await;

                        match reacquire {
                            Ok(result) => {
                                info!(
                                    protocol = %result.protocol,
                                    external_addr = %result.external_addr,
                                    "re-acquired port mapping after renewal failure"
                                );
                                current_ttl = result.ttl;
                                active_protocol = result.protocol;
                                // Re-acquisition after failure is semantically a new
                                // acquisition, not a renewal of an existing mapping.
                                let _ = event_tx.send(NatTierChange::MappingAcquired(result)).await;
                            }
                            Err(final_err) => {
                                warn!(
                                    error = %final_err,
                                    "both UPnP and NAT-PMP re-acquisition failed, mapping lost"
                                );
                                let _ = event_tx
                                    .send(NatTierChange::MappingLost {
                                        reason: format!(
                                            "renewal and re-acquisition failed: {final_err}"
                                        ),
                                    })
                                    .await;
                                return;
                            }
                        }
                    }
                }
            }
        });

        self.task_handle = Some(handle);
    }
}

impl Drop for PortMappingManager {
    fn drop(&mut self) {
        // Signal cancellation so the renewal loop exits promptly.
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(true);
        }
        // Abort the background task. We cannot await it in Drop, but aborting
        // ensures the spawned future is cancelled and resources are released.
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Computes the renewal interval as 50% of the TTL, clamped to a minimum.
///
/// Per spec 10.12.2: "The SDK renews at 50% TTL" for both `UPnP` and NAT-PMP/PCP.
fn renewal_interval(ttl: Duration) -> Duration {
    let half = ttl.mul_f64(RENEWAL_FRACTION);
    if half < MIN_RENEWAL_INTERVAL {
        MIN_RENEWAL_INTERVAL
    } else {
        half
    }
}

/// Standalone helper for the `UPnP` -> NAT-PMP fallback sequence.
/// Used by both `PortMappingManager::try_acquire` and the renewal loop.
async fn try_acquire_with(
    upnp: &dyn PortMapper,
    natpmp: &dyn PortMapper,
    internal_port: u16,
) -> Result<PortMappingResult, PortMappingError> {
    match upnp.map_port(internal_port).await {
        Ok(result) => return Ok(result),
        Err(e) => {
            debug!(error = %e, "UPnP re-acquisition failed, trying NAT-PMP");
        }
    }
    natpmp.map_port(internal_port).await
}

// ---------------------------------------------------------------------------
// Production PortMapper implementations (feature = "upnp")
// ---------------------------------------------------------------------------

/// Default lease duration for `UPnP` port mappings (seconds).
///
/// Per spec 10.12.2: typical `UPnP` leases are 10-60 minutes. We request
/// 30 minutes (1800s); the gateway may grant a shorter TTL.
#[cfg(feature = "upnp")]
const DEFAULT_UPNP_LEASE_SECS: u32 = 1800;

/// Default lease duration for NAT-PMP port mappings (seconds).
///
/// NAT-PMP/PCP uses explicit lifetimes (RFC 6886 section 3.3 recommends
/// 7200s = 2 hours). We request 3600s (1 hour) as a reasonable default.
#[cfg(feature = "upnp")]
const DEFAULT_NATPMP_LEASE_SECS: u32 = 3600;

/// Discovery timeout for `UPnP` SSDP gateway search.
#[cfg(feature = "upnp")]
const UPNP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for NAT-PMP request/response cycles.
#[cfg(feature = "upnp")]
const NATPMP_TIMEOUT: Duration = Duration::from_secs(5);

/// UPnP-IGD port mapper using the `igd-next` crate.
///
/// Discovers the local UPnP-IGD gateway via SSDP multicast, then uses
/// the gateway's SOAP API to add/renew/remove TCP port mappings.
///
/// Per spec 10.12.2: "Discover local gateway via `UPnP` SSDP multicast."
///
/// # Feature gate
///
/// Requires the `upnp` feature on `scp-transport`.
#[cfg(feature = "upnp")]
pub struct UpnpPortMapper {
    /// Lease duration to request from the gateway (seconds).
    lease_duration: u32,
    /// Discovery timeout for SSDP search.
    discovery_timeout: Duration,
}

#[cfg(feature = "upnp")]
impl UpnpPortMapper {
    /// Creates a new UPnP-IGD port mapper with default settings.
    ///
    /// Default lease: 1800 seconds (30 minutes).
    /// Default discovery timeout: 5 seconds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lease_duration: DEFAULT_UPNP_LEASE_SECS,
            discovery_timeout: UPNP_DISCOVERY_TIMEOUT,
        }
    }

    /// Creates a new UPnP-IGD port mapper with custom settings.
    ///
    /// # Arguments
    ///
    /// * `lease_duration` -- Lease duration in seconds to request from the
    ///   gateway. The gateway may grant a shorter TTL.
    /// * `discovery_timeout` -- Timeout for the SSDP discovery phase.
    #[must_use]
    pub const fn with_options(lease_duration: u32, discovery_timeout: Duration) -> Self {
        Self {
            lease_duration,
            discovery_timeout,
        }
    }

    /// Discovers the UPnP-IGD gateway on the local network.
    async fn discover_gateway(
        &self,
    ) -> Result<igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>, PortMappingError> {
        let options = igd_next::SearchOptions {
            timeout: Some(self.discovery_timeout),
            ..Default::default()
        };
        igd_next::aio::tokio::search_gateway(options)
            .await
            .map_err(|e| PortMappingError::DiscoveryFailed(format!("UPnP SSDP discovery: {e}")))
    }

    /// Resolves the local address to bind for port mapping requests.
    ///
    /// The local address is needed by `igd-next` to tell the gateway where
    /// to forward traffic. We discover it by connecting a UDP socket to the
    /// gateway and reading the local endpoint.
    fn resolve_local_addr(
        gateway_addr: std::net::SocketAddr,
        internal_port: u16,
    ) -> Result<std::net::SocketAddr, PortMappingError> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| PortMappingError::Internal(format!("UDP bind for local addr: {e}")))?;
        socket.connect(gateway_addr).map_err(|e| {
            PortMappingError::Internal(format!("UDP connect to gateway for local addr: {e}"))
        })?;
        let local_ip = socket
            .local_addr()
            .map_err(|e| PortMappingError::Internal(format!("read local addr after connect: {e}")))?
            .ip();
        Ok(std::net::SocketAddr::new(local_ip, internal_port))
    }
}

#[cfg(feature = "upnp")]
impl Default for UpnpPortMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "upnp")]
impl PortMapper for UpnpPortMapper {
    fn map_port(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>>
    {
        Box::pin(async move {
            let gateway = self.discover_gateway().await?;
            let local_addr = Self::resolve_local_addr(gateway.addr, internal_port)?;

            debug!(
                gateway = %gateway.addr,
                local_addr = %local_addr,
                lease_secs = self.lease_duration,
                "requesting UPnP-IGD port mapping"
            );

            let external_addr = gateway
                .get_any_address(
                    igd_next::PortMappingProtocol::TCP,
                    local_addr,
                    self.lease_duration,
                    "SCP relay",
                )
                .await
                .map_err(|e| {
                    PortMappingError::MappingRejected(format!("UPnP add_any_port: {e}"))
                })?;

            info!(
                external_addr = %external_addr,
                lease_secs = self.lease_duration,
                "UPnP-IGD port mapping created"
            );

            Ok(PortMappingResult {
                external_addr,
                ttl: Duration::from_secs(u64::from(self.lease_duration)),
                protocol: MappingProtocol::UpnpIgd,
            })
        })
    }

    fn renew(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>>
    {
        // UPnP-IGD renewal is implemented as a fresh mapping request.
        // Per the UPnP-IGD spec, re-adding the same mapping refreshes
        // the lease without creating a duplicate entry.
        self.map_port(internal_port)
    }

    fn remove(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<(), PortMappingError>> + Send + '_>> {
        Box::pin(async move {
            let gateway = self.discover_gateway().await?;
            let local_addr = Self::resolve_local_addr(gateway.addr, internal_port)?;

            // To remove we need the external port. We request the same mapping
            // to find it, but since we used add_any_port we need to know the
            // external port. Use internal_port as the best guess -- routers
            // commonly assign the same port when available.
            //
            // Try removing internal_port first. If that fails, it's best-effort.
            debug!(
                gateway = %gateway.addr,
                external_port = internal_port,
                "attempting UPnP-IGD port mapping removal"
            );

            // Best-effort: try the internal port as the external port.
            // get_any_address may have assigned a different port, but we
            // don't persist state across calls. The PortMappingManager
            // calls remove on both mappers as best-effort cleanup.
            let _ = gateway
                .remove_port(igd_next::PortMappingProtocol::TCP, local_addr.port())
                .await;

            Ok(())
        })
    }
}

/// NAT-PMP/PCP port mapper using the `natpmp` crate.
///
/// Discovers the default gateway and sends NAT-PMP (RFC 6886) port mapping
/// requests. Falls back to this when UPnP-IGD is not available.
///
/// Per spec 10.12.2: "NAT-PMP/PCP as fallback" after UPnP-IGD.
///
/// # Feature gate
///
/// Requires the `upnp` feature on `scp-transport`.
#[cfg(feature = "upnp")]
pub struct NatPmpPortMapper {
    /// Lease duration to request (seconds).
    lease_duration: u32,
    /// Timeout for NAT-PMP request/response cycles.
    timeout: Duration,
}

#[cfg(feature = "upnp")]
impl NatPmpPortMapper {
    /// Creates a new NAT-PMP port mapper with default settings.
    ///
    /// Default lease: 3600 seconds (1 hour).
    /// Default timeout: 5 seconds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lease_duration: DEFAULT_NATPMP_LEASE_SECS,
            timeout: NATPMP_TIMEOUT,
        }
    }

    /// Creates a new NAT-PMP port mapper with custom settings.
    #[must_use]
    pub const fn with_options(lease_duration: u32, timeout: Duration) -> Self {
        Self {
            lease_duration,
            timeout,
        }
    }

    /// Sends a port mapping request and reads the response.
    ///
    /// The NAT-PMP protocol is a simple request/response over UDP to the
    /// default gateway on port 5351.
    async fn request_mapping(
        &self,
        internal_port: u16,
        lifetime: u32,
    ) -> Result<PortMappingResult, PortMappingError> {
        let client = natpmp::new_tokio_natpmp()
            .await
            .map_err(|e| PortMappingError::DiscoveryFailed(format!("NAT-PMP gateway: {e}")))?;

        let gateway_ip = *client.gateway();

        // First, get the external IP via a public address request.
        // We need a mutable reference for `send_public_address_request`.
        // The natpmp crate's async API requires &mut for address requests
        // but &self for port mapping (quirk of the crate API).
        //
        // We work around this by creating a separate client for the
        // address request.
        let mut addr_client = natpmp::new_tokio_natpmp().await.map_err(|e| {
            PortMappingError::DiscoveryFailed(format!("NAT-PMP gateway (addr): {e}"))
        })?;

        addr_client
            .send_public_address_request()
            .await
            .map_err(|e| {
                PortMappingError::Internal(format!("NAT-PMP public address request: {e}"))
            })?;

        let external_ip = tokio::time::timeout(self.timeout, addr_client.read_response_or_retry())
            .await
            .map_err(|_| PortMappingError::Timeout)?
            .map_err(|e| {
                PortMappingError::Internal(format!("NAT-PMP public address response: {e}"))
            })
            .and_then(|resp| match resp {
                natpmp::Response::Gateway(gw) => Ok(std::net::IpAddr::V4(*gw.public_address())),
                other => Err(PortMappingError::Internal(format!(
                    "unexpected NAT-PMP response type: {other:?}"
                ))),
            })?;

        debug!(
            gateway = %gateway_ip,
            external_ip = %external_ip,
            internal_port,
            lifetime,
            "sending NAT-PMP port mapping request"
        );

        // Send the TCP port mapping request.
        // Request the same external port as the internal port (NAT-PMP
        // convention). The gateway may assign a different port.
        client
            .send_port_mapping_request(
                natpmp::Protocol::TCP,
                internal_port,
                internal_port,
                lifetime,
            )
            .await
            .map_err(|e| {
                PortMappingError::MappingRejected(format!("NAT-PMP mapping request: {e}"))
            })?;

        let mapping = tokio::time::timeout(self.timeout, client.read_response_or_retry())
            .await
            .map_err(|_| PortMappingError::Timeout)?
            .map_err(|e| {
                PortMappingError::MappingRejected(format!("NAT-PMP mapping response: {e}"))
            })?;

        match mapping {
            natpmp::Response::TCP(m) | natpmp::Response::UDP(m) => {
                let external_addr = std::net::SocketAddr::new(external_ip, m.public_port());
                let ttl = *m.lifetime();

                info!(
                    external_addr = %external_addr,
                    ttl_secs = ttl.as_secs(),
                    "NAT-PMP port mapping created"
                );

                Ok(PortMappingResult {
                    external_addr,
                    ttl,
                    protocol: MappingProtocol::NatPmp,
                })
            }
            natpmp::Response::Gateway(_) => Err(PortMappingError::Internal(
                "unexpected gateway response to mapping request".into(),
            )),
        }
    }
}

#[cfg(feature = "upnp")]
impl Default for NatPmpPortMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "upnp")]
impl PortMapper for NatPmpPortMapper {
    fn map_port(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>>
    {
        Box::pin(async move {
            self.request_mapping(internal_port, self.lease_duration)
                .await
        })
    }

    fn renew(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>>
    {
        // NAT-PMP renewal is a fresh mapping request with the same parameters.
        // Per RFC 6886 section 3.3: "To refresh a mapping, the client sends
        // a new mapping request."
        Box::pin(async move {
            self.request_mapping(internal_port, self.lease_duration)
                .await
        })
    }

    fn remove(
        &self,
        internal_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<(), PortMappingError>> + Send + '_>> {
        Box::pin(async move {
            // Per RFC 6886 section 3.4: "To destroy a mapping, the client
            // sends a mapping request with a lifetime of zero."
            debug!(
                internal_port,
                "sending NAT-PMP mapping removal (lifetime=0)"
            );
            let _ = self.request_mapping(internal_port, 0).await;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::Mutex;

    // -- Mock mapper ---------------------------------------------------------

    /// A configurable mock `PortMapper` for testing.
    struct MockMapper {
        /// Results returned by `map_port`, consumed in order.
        map_results: Mutex<Vec<Result<PortMappingResult, PortMappingError>>>,
        /// Results returned by `renew`, consumed in order.
        renew_results: Mutex<Vec<Result<PortMappingResult, PortMappingError>>>,
        /// Call counter for `map_port`.
        map_calls: AtomicU32,
        /// Call counter for `renew`.
        renew_calls: AtomicU32,
        /// Call counter for `remove`.
        remove_calls: AtomicU32,
    }

    impl MockMapper {
        fn new(
            map_results: Vec<Result<PortMappingResult, PortMappingError>>,
            renew_results: Vec<Result<PortMappingResult, PortMappingError>>,
        ) -> Self {
            Self {
                map_results: Mutex::new(map_results),
                renew_results: Mutex::new(renew_results),
                map_calls: AtomicU32::new(0),
                renew_calls: AtomicU32::new(0),
                remove_calls: AtomicU32::new(0),
            }
        }

        /// Creates a mapper that always succeeds with the given address and TTL.
        fn always_ok(addr: SocketAddr, ttl: Duration, protocol: MappingProtocol) -> Self {
            // Provide enough results for repeated calls.
            let result = PortMappingResult {
                external_addr: addr,
                ttl,
                protocol,
            };
            Self::new(
                vec![Ok(result.clone()), Ok(result.clone()), Ok(result.clone())],
                vec![Ok(result.clone()), Ok(result.clone()), Ok(result)],
            )
        }

        /// Creates a mapper that always fails with the given error message.
        fn always_fail(msg: &str) -> Self {
            let err = PortMappingError::DiscoveryFailed(msg.to_owned());
            Self::new(
                vec![Err(err.clone()), Err(err.clone()), Err(err.clone())],
                vec![Err(err.clone()), Err(err.clone()), Err(err)],
            )
        }
    }

    impl PortMapper for MockMapper {
        fn map_port(
            &self,
            _internal_port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>>
        {
            Box::pin(async {
                self.map_calls.fetch_add(1, Ordering::Relaxed);
                let mut results = self.map_results.lock().await;
                if results.is_empty() {
                    return Err(PortMappingError::Internal(
                        "no more mock map results".to_owned(),
                    ));
                }
                results.remove(0)
            })
        }

        fn renew(
            &self,
            _internal_port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<PortMappingResult, PortMappingError>> + Send + '_>>
        {
            Box::pin(async {
                self.renew_calls.fetch_add(1, Ordering::Relaxed);
                let mut results = self.renew_results.lock().await;
                if results.is_empty() {
                    return Err(PortMappingError::Internal(
                        "no more mock renew results".to_owned(),
                    ));
                }
                results.remove(0)
            })
        }

        fn remove(
            &self,
            _internal_port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<(), PortMappingError>> + Send + '_>> {
            Box::pin(async {
                self.remove_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
        }
    }

    // -- Helper functions ----------------------------------------------------

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8443)
    }

    fn alt_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 9443)
    }

    // -- Unit tests ----------------------------------------------------------

    #[tokio::test]
    async fn upnp_mapping_returns_correct_external_address() {
        let addr = test_addr();
        let ttl = Duration::from_secs(600);
        let upnp = Arc::new(MockMapper::always_ok(addr, ttl, MappingProtocol::UpnpIgd));
        let natpmp = Arc::new(MockMapper::always_fail("unused"));
        let (tx, mut rx) = mpsc::channel(16);

        let mut mgr = PortMappingManager::new(upnp.clone(), natpmp, 4000, tx);
        let result = mgr.start().await.expect("should succeed");

        assert_eq!(result.external_addr, addr);
        assert_eq!(result.ttl, ttl);
        assert_eq!(result.protocol, MappingProtocol::UpnpIgd);

        // Verify MappingAcquired event was emitted.
        let event = rx.recv().await.expect("should receive event");
        assert!(matches!(event, NatTierChange::MappingAcquired(ref r) if r.external_addr == addr));

        mgr.stop().await;
    }

    #[tokio::test]
    async fn upnp_failure_falls_back_to_natpmp() {
        let addr = alt_addr();
        let ttl = Duration::from_secs(300);
        let upnp = Arc::new(MockMapper::always_fail("no UPnP gateway"));
        let natpmp = Arc::new(MockMapper::always_ok(addr, ttl, MappingProtocol::NatPmp));
        let (tx, mut rx) = mpsc::channel(16);

        let mut mgr = PortMappingManager::new(upnp.clone(), natpmp.clone(), 5000, tx);
        let result = mgr.start().await.expect("NAT-PMP should succeed");

        assert_eq!(result.external_addr, addr);
        assert_eq!(result.protocol, MappingProtocol::NatPmp);

        // UPnP was tried first.
        assert_eq!(upnp.map_calls.load(Ordering::Relaxed), 1);
        // NAT-PMP was the fallback.
        assert_eq!(natpmp.map_calls.load(Ordering::Relaxed), 1);

        let event = rx.recv().await.expect("should receive event");
        assert!(matches!(event, NatTierChange::MappingAcquired(_)));

        mgr.stop().await;
    }

    #[tokio::test]
    async fn both_protocols_fail_returns_error() {
        let upnp = Arc::new(MockMapper::always_fail("no UPnP gateway"));
        let natpmp = Arc::new(MockMapper::always_fail("no NAT-PMP gateway"));
        let (tx, _rx) = mpsc::channel(16);

        let mut mgr = PortMappingManager::new(upnp, natpmp, 6000, tx);
        let result = mgr.start().await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn lease_renewal_fires_at_50_percent_ttl() {
        // Use tokio's time pausing to control time precisely.
        tokio::time::pause();

        let addr = test_addr();
        // Use a TTL of 100 seconds so renewal fires at 50 seconds.
        let ttl = Duration::from_secs(100);
        let renewal_ttl = Duration::from_secs(80);

        let renewed_result = PortMappingResult {
            external_addr: addr,
            ttl: renewal_ttl,
            protocol: MappingProtocol::UpnpIgd,
        };

        let upnp = Arc::new(MockMapper::new(
            vec![Ok(PortMappingResult {
                external_addr: addr,
                ttl,
                protocol: MappingProtocol::UpnpIgd,
            })],
            vec![Ok(renewed_result)],
        ));
        let natpmp = Arc::new(MockMapper::always_fail("unused"));
        let (tx, mut rx) = mpsc::channel(16);

        let mut mgr = PortMappingManager::new(upnp.clone(), natpmp, 7000, tx);
        let result = mgr.start().await.expect("should succeed");
        assert_eq!(result.ttl, ttl);

        // Consume the MappingAcquired event.
        let event = rx.recv().await.expect("should receive acquired event");
        assert!(matches!(event, NatTierChange::MappingAcquired(_)));

        // Advance time to 50% of TTL (50 seconds).
        tokio::time::advance(Duration::from_secs(50)).await;
        // Yield to let the renewal task run.
        tokio::task::yield_now().await;
        // Small additional advance to ensure the sleep completes.
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        // Should have received a MappingRenewed event.
        let event = rx.recv().await.expect("should receive renewed event");
        match event {
            NatTierChange::MappingRenewed(r) => {
                assert_eq!(r.external_addr, addr);
                assert_eq!(r.ttl, renewal_ttl);
            }
            other => panic!("expected MappingRenewed, got {other:?}"),
        }

        // Verify the renew was actually called.
        assert_eq!(upnp.renew_calls.load(Ordering::Relaxed), 1);

        mgr.stop().await;
    }

    #[tokio::test]
    async fn mapping_loss_emitted_when_renewal_and_reacquisition_fail() {
        tokio::time::pause();

        let addr = test_addr();
        let ttl = Duration::from_secs(20);

        // Initial map succeeds, but renewal and re-acquisition both fail.
        let upnp = Arc::new(MockMapper::new(
            vec![
                Ok(PortMappingResult {
                    external_addr: addr,
                    ttl,
                    protocol: MappingProtocol::UpnpIgd,
                }),
                // Re-acquisition attempt fails.
                Err(PortMappingError::DiscoveryFailed("gateway gone".to_owned())),
            ],
            vec![
                // Renewal fails.
                Err(PortMappingError::Timeout),
            ],
        ));
        let natpmp = Arc::new(MockMapper::new(
            vec![
                // NAT-PMP re-acquisition also fails.
                Err(PortMappingError::DiscoveryFailed("no natpmp".to_owned())),
            ],
            vec![],
        ));
        let (tx, mut rx) = mpsc::channel(16);

        let mut mgr = PortMappingManager::new(upnp, natpmp, 8000, tx);
        mgr.start().await.expect("initial mapping should succeed");

        // Consume MappingAcquired.
        let event = rx.recv().await.expect("should receive acquired event");
        assert!(matches!(event, NatTierChange::MappingAcquired(_)));

        // Advance to 50% TTL (10 seconds) to trigger renewal.
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        // Should receive MappingLost because both renewal and re-acquisition failed.
        let event = rx.recv().await.expect("should receive lost event");
        match event {
            NatTierChange::MappingLost { reason } => {
                assert!(
                    reason.contains("failed"),
                    "reason should describe failure: {reason}"
                );
            }
            other => panic!("expected MappingLost, got {other:?}"),
        }

        mgr.stop().await;
    }

    #[tokio::test]
    async fn reacquisition_after_renewal_failure_emits_mapping_acquired() {
        tokio::time::pause();

        let addr = test_addr();
        let reacquired_addr = alt_addr();
        let ttl = Duration::from_secs(20);
        let reacquired_ttl = Duration::from_secs(40);

        // Initial map succeeds, renewal fails, but UPnP re-acquisition succeeds.
        let upnp = Arc::new(MockMapper::new(
            vec![
                // Initial acquisition.
                Ok(PortMappingResult {
                    external_addr: addr,
                    ttl,
                    protocol: MappingProtocol::UpnpIgd,
                }),
                // Re-acquisition after renewal failure succeeds (possibly new addr).
                Ok(PortMappingResult {
                    external_addr: reacquired_addr,
                    ttl: reacquired_ttl,
                    protocol: MappingProtocol::UpnpIgd,
                }),
            ],
            vec![
                // Renewal fails.
                Err(PortMappingError::Timeout),
            ],
        ));
        let natpmp = Arc::new(MockMapper::always_fail("unused"));
        let (tx, mut rx) = mpsc::channel(16);

        let mut mgr = PortMappingManager::new(upnp, natpmp, 8001, tx);
        mgr.start().await.expect("initial mapping should succeed");

        // Consume MappingAcquired from initial start().
        let event = rx.recv().await.expect("should receive acquired event");
        assert!(matches!(event, NatTierChange::MappingAcquired(_)));

        // Advance to 50% TTL (10 seconds) to trigger renewal.
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;

        // Re-acquisition after renewal failure should emit MappingAcquired, not MappingRenewed.
        let event = rx.recv().await.expect("should receive re-acquired event");
        match event {
            NatTierChange::MappingAcquired(r) => {
                assert_eq!(r.external_addr, reacquired_addr);
                assert_eq!(r.ttl, reacquired_ttl);
            }
            other => panic!("expected MappingAcquired on re-acquisition, got {other:?}"),
        }

        mgr.stop().await;
    }

    #[tokio::test]
    async fn renewal_interval_is_50_percent_of_ttl() {
        assert_eq!(
            renewal_interval(Duration::from_secs(600)),
            Duration::from_secs(300),
        );
        assert_eq!(
            renewal_interval(Duration::from_secs(100)),
            Duration::from_secs(50),
        );
    }

    #[tokio::test]
    async fn renewal_interval_has_minimum_floor() {
        // For a 4-second TTL, 50% = 2s, but minimum is 5s.
        assert_eq!(
            renewal_interval(Duration::from_secs(4)),
            MIN_RENEWAL_INTERVAL,
        );
        // For a 0-second TTL, still returns minimum.
        assert_eq!(renewal_interval(Duration::ZERO), MIN_RENEWAL_INTERVAL,);
    }

    #[tokio::test]
    async fn stop_calls_remove_on_mappers() {
        let addr = test_addr();
        let upnp = Arc::new(MockMapper::always_ok(
            addr,
            Duration::from_secs(600),
            MappingProtocol::UpnpIgd,
        ));
        let natpmp = Arc::new(MockMapper::always_fail("unused"));
        let (tx, _rx) = mpsc::channel(16);

        let mut mgr = PortMappingManager::new(upnp.clone(), natpmp.clone(), 9000, tx);
        mgr.start().await.expect("should succeed");
        mgr.stop().await;

        // remove should have been called on both mappers (best-effort cleanup).
        assert_eq!(upnp.remove_calls.load(Ordering::Relaxed), 1);
        assert_eq!(natpmp.remove_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn mapping_protocol_display() {
        assert_eq!(format!("{}", MappingProtocol::UpnpIgd), "UPnP-IGD");
        assert_eq!(format!("{}", MappingProtocol::NatPmp), "NAT-PMP");
        assert_eq!(format!("{}", MappingProtocol::Pcp), "PCP");
    }

    #[test]
    fn port_mapping_error_display() {
        let err = PortMappingError::DiscoveryFailed("timeout".to_owned());
        assert_eq!(err.to_string(), "gateway discovery failed: timeout");

        let err = PortMappingError::Timeout;
        assert_eq!(err.to_string(), "mapping operation timed out");

        let err = PortMappingError::MappingRejected("conflict".to_owned());
        assert_eq!(err.to_string(), "mapping request rejected: conflict");
    }

    #[tokio::test]
    async fn try_acquire_prefers_upnp_over_natpmp() {
        let upnp_addr = test_addr();
        let natpmp_addr = alt_addr();
        let ttl = Duration::from_secs(300);

        let upnp = Arc::new(MockMapper::always_ok(
            upnp_addr,
            ttl,
            MappingProtocol::UpnpIgd,
        ));
        let natpmp = Arc::new(MockMapper::always_ok(
            natpmp_addr,
            ttl,
            MappingProtocol::NatPmp,
        ));
        let (tx, _rx) = mpsc::channel(16);

        let mgr = PortMappingManager::new(upnp.clone(), natpmp.clone(), 4000, tx);
        let result = mgr.try_acquire().await.expect("should succeed");

        // Should use UPnP, not NAT-PMP.
        assert_eq!(result.external_addr, upnp_addr);
        assert_eq!(result.protocol, MappingProtocol::UpnpIgd);
        // NAT-PMP should NOT have been called.
        assert_eq!(natpmp.map_calls.load(Ordering::Relaxed), 0);
    }
}
