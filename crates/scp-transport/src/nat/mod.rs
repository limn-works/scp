//! NAT traversal for relay reachability (spec section 10.12).
//!
//! This module implements the layered reachability strategy described in spec
//! section 10.12. Each tier is a separate submodule:
//!
//! - [`stun`] / [`types`] -- NAT type detection via STUN probing (§10.12.3).
//! - [`upnp`] -- Tier 1: UPnP-IGD and NAT-PMP/PCP port mapping (§10.12.2).
//!
//! The classification algorithm (SCP-244: multi-STUN divergence detection)
//! sends STUN Binding Requests to ALL configured endpoints sequentially from
//! the same local socket and compares the external mappings:
//!
//! - All responding servers report the same external IP:port → non-symmetric
//!   (cone NAT, classified as `AddressRestricted`).
//! - Any server reports a different external IP or port → `Symmetric`
//!   (§10.12.9 threat model: divergence indicates symmetric NAT or STUN
//!   server manipulation).
//! - Only one server responds → single-STUN fallback using port-mapping
//!   heuristics (defaults to `AddressRestricted`).
//!
//! Probes are sequential on a shared socket because symmetric NAT detection
//! requires the same local port across all requests. Concurrent `recv_from`
//! calls on a shared socket would cause packet-steal races.
//!
//! A 25-second keepalive maintains the NAT mapping for non-symmetric NATs
//! (spec 10.12.3).
//!
//! Tier selection is automatic: the SDK tries each tier in order and uses the
//! first that produces a reachable external address.
//!
//! - [`ReachabilityProbe`] / [`DefaultReachabilityProbe`] -- self-test to verify
//!   external reachability before publishing (§10.12.2 step 4, §10.12.3).
//! - [`NetworkChangeDetector`] / [`ChannelNetworkChangeDetector`] -- network
//!   change event detection for triggering tier re-evaluation (§10.12.1).
//!
//! See spec section 10.12.3 "Tier 2: STUN Hole Punching" for the full design.

pub mod stun;
pub mod types;
pub mod upnp;

pub use stun::{
    NatKeepalive, StunBindingResponse, encode_binding_indication, encode_binding_request,
    run_keepalive_loop, stun_binding_request,
};
pub use types::{NatProbeResult, NatType, StunEndpoint};
#[cfg(feature = "upnp")]
pub use upnp::UpnpPortMapper;
pub use upnp::{
    MappingProtocol, NatTierChange, PortMapper, PortMappingError, PortMappingManager,
    PortMappingResult,
};

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::TransportError;

// ---------------------------------------------------------------------------
// NatProber
// ---------------------------------------------------------------------------

/// Probes NAT type by sending STUN Binding Requests to multiple endpoints
/// and comparing the external address mappings (spec 10.12.3, SCP-244).
///
/// # Multi-STUN Divergence Detection Algorithm (SCP-244)
///
/// 1. Send a Binding Request to **every** configured endpoint sequentially
///    from the same local UDP socket.
/// 2. Collect all successful responses (endpoints that time out or error are
///    skipped with a warning).
/// 3. If 2+ endpoints responded and all report the **same** external IP:port
///    → non-symmetric (cone NAT). Classified as `AddressRestricted` by
///    default (differentiating full-cone from restricted-cone requires the
///    server to respond from an alternate address, which is not part of this
///    implementation).
/// 4. If 2+ endpoints responded and **any** external address differs →
///    `Symmetric` (§10.12.9: divergence indicates symmetric NAT or STUN
///    server manipulation).
/// 5. If only 1 endpoint responded → single-STUN fallback: classification
///    uses port-mapping heuristics (defaults to `AddressRestricted`, the
///    most common cone NAT type at ~30% prevalence).
///
/// # Fallback Signal
///
/// When `NatType::Symmetric` is detected, the caller should skip Tier 2
/// and proceed to Tier 3 (relay bridging).
///
/// # Why Sequential, Not Parallel
///
/// Symmetric NAT detection requires comparing external mappings from the
/// **same local socket** to different servers. Concurrent `recv_from` calls
/// on a shared `UdpSocket` would race and steal packets, so probes are
/// sequential. This is correct: each probe takes at most `timeout` duration
/// (default 3s), and typical deployments have 2-3 STUN endpoints.
pub struct NatProber {
    /// STUN endpoints to probe (at least one, ideally two or more).
    endpoints: Vec<StunEndpoint>,
    /// Timeout per STUN request.
    timeout: Duration,
}

impl NatProber {
    /// Creates a new prober with the given STUN endpoints.
    ///
    /// At least one endpoint is required. Two or more endpoints enable
    /// multi-STUN divergence detection for symmetric NAT classification
    /// (SCP-244, §10.12.9). With a single endpoint, only external address
    /// discovery is performed and the NAT type defaults to
    /// `AddressRestricted` (port-mapping heuristic fallback).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if `endpoints` is empty.
    pub fn new(
        endpoints: Vec<StunEndpoint>,
        timeout: Option<Duration>,
    ) -> Result<Self, TransportError> {
        if endpoints.is_empty() {
            return Err(TransportError::ProtocolError(
                "at least one STUN endpoint is required for NAT probing".into(),
            ));
        }
        Ok(Self {
            endpoints,
            timeout: timeout.unwrap_or(Duration::from_secs(3)),
        })
    }

    /// Returns the configured STUN endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[StunEndpoint] {
        &self.endpoints
    }

    /// Probes NAT type and discovers the external address.
    ///
    /// Binds a local **IPv4** UDP socket (`0.0.0.0:0`) and sends STUN
    /// Binding Requests to the configured endpoints. Compares responses
    /// to classify the NAT type.
    ///
    /// On IPv6-only networks this method will fail with
    /// [`TransportError::ConnectionFailed`]. Use [`probe_with_socket`](Self::probe_with_socket)
    /// with an appropriately bound `[::]` socket instead.
    ///
    /// Returns [`NatProbeResult`] with the NAT type and external address.
    /// For symmetric NATs, `external_addr` is still populated (it is the
    /// address seen by the primary STUN server) but should not be used
    /// for hole punching.
    ///
    /// # Errors
    ///
    /// Returns an error if all STUN endpoints fail to respond.
    pub async fn probe(&self) -> Result<NatProbeResult, TransportError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("UDP bind failed: {e}")))?;

        self.probe_with_socket(&socket).await
    }

    /// Probes NAT type using the provided UDP socket.
    ///
    /// This variant is useful when the caller already has a bound socket
    /// (e.g., the relay's listen socket) and wants to discover the external
    /// mapping for that specific local port.
    ///
    /// **Address family:** All configured STUN endpoints should use the same
    /// address family (IPv4 or IPv6) as the provided socket. Mixing address
    /// families (e.g., IPv4 socket with IPv6 STUN servers) will cause send
    /// failures. Using endpoints from different families with a dual-stack
    /// socket may produce false symmetric NAT classifications because the
    /// source address legitimately differs across families.
    ///
    /// # Multi-STUN Divergence Detection (SCP-244)
    ///
    /// Queries **all** configured STUN endpoints sequentially from the same
    /// socket. If 2+ respond and any report a different external address,
    /// the NAT is classified as symmetric. If only 1 responds, falls back
    /// to port-mapping heuristics (`AddressRestricted`).
    ///
    /// # Errors
    ///
    /// Returns an error if **no** STUN endpoint responds.
    pub async fn probe_with_socket(
        &self,
        socket: &UdpSocket,
    ) -> Result<NatProbeResult, TransportError> {
        // SCP-244: Query ALL configured STUN endpoints and collect responses.
        // Sequential on a shared socket to ensure the same local port is used
        // for every request (required for symmetric NAT detection).
        let mut responses: Vec<(SocketAddr, String)> = Vec::with_capacity(self.endpoints.len());
        let mut first_error: Option<TransportError> = None;

        for (i, endpoint) in self.endpoints.iter().enumerate() {
            info!(
                server = %endpoint.addr,
                label = %endpoint.label,
                index = i,
                total = self.endpoints.len(),
                "sending STUN binding request"
            );

            match stun::stun_binding_request(socket, endpoint.addr, Some(self.timeout)).await {
                Ok(response) => {
                    debug!(
                        external = %response.mapped_addr,
                        server = %endpoint.label,
                        "STUN response received"
                    );
                    responses.push((response.mapped_addr, endpoint.label.clone()));
                }
                Err(e) => {
                    warn!(
                        server = %endpoint.label,
                        error = %e,
                        "STUN probe failed"
                    );
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }

        // No responses at all: propagate the first error (or a generic one).
        if responses.is_empty() {
            return Err(first_error.unwrap_or_else(|| {
                TransportError::ProtocolError("all STUN endpoints failed to respond".into())
            }));
        }

        let (primary_addr, primary_label) = responses[0].clone();

        // SCP-244: Multi-STUN divergence detection.
        // If 2+ endpoints responded, compare all external addresses.
        if responses.len() >= 2 {
            let nat_type = classify_from_multiple_responses(&responses)?;

            info!(
                nat_type = %nat_type,
                external = %primary_addr,
                responding_servers = responses.len(),
                "NAT type classified via multi-STUN divergence detection (SCP-244)"
            );

            return Ok(NatProbeResult {
                nat_type,
                external_addr: Some(primary_addr),
                stun_server: primary_label,
            });
        }

        // Single-STUN fallback (SCP-244 AC4): only 1 endpoint responded.
        // Cannot detect symmetric NAT — use port-mapping heuristic.
        // Default to AddressRestricted (most common cone NAT type, ~30%
        // prevalence per spec 10.12.3).
        info!(
            nat_type = %NatType::AddressRestricted,
            external = %primary_addr,
            "NAT type defaulted via single-STUN fallback (SCP-244 AC4)"
        );

        Ok(NatProbeResult {
            nat_type: NatType::AddressRestricted,
            external_addr: Some(primary_addr),
            stun_server: primary_label,
        })
    }
}

// ---------------------------------------------------------------------------
// ReachabilityProbe
// ---------------------------------------------------------------------------

/// Trait for verifying external reachability of a NAT-mapped address.
///
/// After obtaining an external address via `UPnP` (Tier 1, spec 10.12.2 step 4)
/// or STUN (Tier 2, spec 10.12.3), the SDK must perform a self-test before
/// publishing the address in the DID document. If the self-test fails, the
/// mapping is considered unreliable and the SDK falls through to the next tier.
///
/// The probe uses an intermediary (STUN server) to verify the mapping is
/// valid. The caller provides the UDP socket that holds the NAT mapping;
/// the probe sends a STUN Binding Request from that socket to the configured
/// STUN server and compares the returned external address against the expected
/// address.
///
/// # Security
///
/// The STUN transaction ID is a 96-bit CSPRNG value (per RFC 8489 section 6).
/// The STUN server must echo this exact transaction ID in its response, and
/// the response is validated against the expected source address. A local
/// MITM would need to guess the 96-bit transaction ID to spoof the response,
/// providing sufficient anti-spoofing protection for self-test purposes.
///
/// Abstracted as a trait to enable mock implementations for testing.
pub trait ReachabilityProbe: Send + Sync {
    /// Verifies that `external_addr` is reachable from the public internet.
    ///
    /// The `socket` parameter must be the same UDP socket that holds the NAT
    /// mapping (i.e., the socket from which the original STUN probe or `UPnP`
    /// mapping was obtained). The probe sends from this socket to ensure the
    /// NAT mapping is exercised.
    ///
    /// Returns `true` if the external address is verified reachable, `false`
    /// otherwise.
    fn probe_reachability<'a>(
        &'a self,
        socket: &'a UdpSocket,
        external_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<bool, TransportError>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// DefaultReachabilityProbe
// ---------------------------------------------------------------------------

/// Default reachability probe that verifies a NAT mapping via a STUN server.
///
/// Sends a STUN Binding Request from the same socket that holds the NAT
/// mapping to the configured STUN server. If the STUN server's response
/// reports the same external address as `expected_addr`, the mapping is
/// confirmed valid and reachable.
///
/// This works because the STUN server is an external intermediary: if the
/// NAT mapping allows the STUN server to reach us (and respond), and the
/// STUN server sees the same external address we expect, then other external
/// hosts will see the same mapping (for non-symmetric NATs).
///
/// # Security
///
/// Anti-spoofing protection is provided by the STUN transaction ID: a
/// 96-bit CSPRNG value that must be echoed in the response. Additionally,
/// responses from unexpected source addresses are rejected. See
/// [`stun::stun_binding_request`] for the full validation logic.
pub struct DefaultReachabilityProbe {
    /// STUN server to use as the intermediary for the self-test.
    stun_server: SocketAddr,
    /// Timeout for the STUN round-trip.
    timeout: Duration,
}

impl DefaultReachabilityProbe {
    /// Creates a new reachability probe.
    ///
    /// # Arguments
    ///
    /// * `stun_server` -- The STUN server to use as the intermediary.
    /// * `timeout` -- Timeout for the STUN round-trip (default: 3 seconds).
    #[must_use]
    pub fn new(stun_server: SocketAddr, timeout: Option<Duration>) -> Self {
        Self {
            stun_server,
            timeout: timeout.unwrap_or(Duration::from_secs(3)),
        }
    }

    /// Returns the configured STUN server address.
    #[must_use]
    pub const fn stun_server(&self) -> SocketAddr {
        self.stun_server
    }
}

impl ReachabilityProbe for DefaultReachabilityProbe {
    /// Sends a STUN Binding Request from `socket` to the configured STUN
    /// server. Returns `true` if the server reports the same external address
    /// as `external_addr`, confirming the NAT mapping is still valid.
    ///
    /// The 96-bit CSPRNG transaction ID in the STUN request serves as an
    /// anti-spoofing challenge (spec 10.12.9: STUN server manipulation
    /// threat). A local MITM would need to guess this value to forge a
    /// response.
    fn probe_reachability<'a>(
        &'a self,
        socket: &'a UdpSocket,
        external_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<bool, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            info!(
                stun_server = %self.stun_server,
                expected_addr = %external_addr,
                "performing reachability self-test via STUN intermediary (SCP-242)"
            );

            match stun::stun_binding_request(socket, self.stun_server, Some(self.timeout)).await {
                Ok(response) => {
                    let matches = response.mapped_addr == external_addr;
                    if matches {
                        info!(
                            external_addr = %external_addr,
                            stun_server = %self.stun_server,
                            "reachability self-test passed: STUN server confirms expected address"
                        );
                    } else {
                        warn!(
                            expected = %external_addr,
                            actual = %response.mapped_addr,
                            stun_server = %self.stun_server,
                            "reachability self-test failed: STUN server reports different address \
                             (NAT mapping may have changed)"
                        );
                    }
                    Ok(matches)
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        stun_server = %self.stun_server,
                        "reachability self-test failed: STUN request to intermediary failed"
                    );
                    Ok(false)
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// NetworkChangeDetector (SCP-243)
// ---------------------------------------------------------------------------

/// Trait for detecting network change events (IP change, interface up/down).
///
/// Network changes trigger immediate NAT tier re-evaluation per spec
/// §10.12.1: "The SDK re-evaluates periodically (recommended: every 30
/// minutes) and on network change events (IP change, interface up/down)."
///
/// Abstracted as a trait to enable mock implementations in tests and
/// platform-specific implementations in production.
pub trait NetworkChangeDetector: Send + Sync {
    /// Waits until a network change event is detected.
    ///
    /// Returns `Ok(())` when a network change occurs. Returns `Err` if the
    /// detector encounters an unrecoverable error (e.g., the platform API
    /// is unavailable). After returning `Ok(())`, the detector is ready to
    /// be polled again for the next event.
    fn wait_for_change(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>>;
}

/// A network change detector that receives events via a channel.
///
/// Production code sends notifications on IP change or interface up/down.
/// Tests can send events directly to trigger immediate re-evaluation.
pub struct ChannelNetworkChangeDetector {
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<()>>,
}

impl ChannelNetworkChangeDetector {
    /// Creates a new detector and returns the sender for injecting events.
    #[must_use]
    pub fn new(rx: tokio::sync::mpsc::Receiver<()>) -> Self {
        Self {
            rx: tokio::sync::Mutex::new(rx),
        }
    }
}

impl NetworkChangeDetector for ChannelNetworkChangeDetector {
    fn wait_for_change(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
        Box::pin(async {
            let mut rx = self.rx.lock().await;
            rx.recv().await.ok_or_else(|| {
                TransportError::ConnectionFailed(
                    "network change detector channel closed".to_owned(),
                )
            })
        })
    }
}

// ---------------------------------------------------------------------------
// NAT type classification
// ---------------------------------------------------------------------------

/// Classifies NAT type by comparing external mappings from multiple STUN
/// servers (spec 10.12.3, SCP-244 multi-STUN divergence detection).
///
/// Requires at least 2 responses. Returns an error if fewer than 2 are
/// provided (callers should use the single-STUN fallback path instead).
///
/// - All servers report the same external IP and port → non-symmetric.
///   Classified as `AddressRestricted` (differentiating full-cone from
///   restricted requires server cooperation not in this implementation).
/// - Any server reports a different external IP or port → `Symmetric`
///   (§10.12.9: divergence indicates symmetric NAT or STUN server
///   manipulation).
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if `responses` has fewer
/// than 2 entries.
fn classify_from_multiple_responses(
    responses: &[(SocketAddr, String)],
) -> Result<NatType, TransportError> {
    if responses.len() < 2 {
        return Err(TransportError::ProtocolError(
            "multi-STUN classification requires at least 2 responses".into(),
        ));
    }

    let reference_addr = responses[0].0;

    for (addr, label) in &responses[1..] {
        if *addr != reference_addr {
            // Divergence detected: different external mapping per
            // destination → symmetric NAT (or STUN server manipulation
            // per §10.12.9 threat model).
            debug!(
                reference = %reference_addr,
                divergent = %addr,
                divergent_server = %label,
                "multi-STUN divergence detected — symmetric NAT (SCP-244)"
            );
            return Ok(NatType::Symmetric);
        }
    }

    // All responses match → cone NAT. Full-cone vs. restricted
    // differentiation requires the server to respond from an alternate
    // address. Default to AddressRestricted as the most common cone type
    // (~30% prevalence per spec 10.12.3).
    Ok(NatType::AddressRestricted)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::task::JoinHandle;

    /// Spawns a mock STUN server that responds to one Binding Request with
    /// the given `external_addr`. Returns the server's local address and a
    /// join handle for cleanup.
    async fn spawn_mock_stun(external_addr: SocketAddr) -> (SocketAddr, JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = sock.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_len, from) = sock.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external_addr, &txn_id);
            sock.send_to(&response, from).await.expect("send");
        });
        (addr, handle)
    }

    /// Test-only convenience wrapper: classifies NAT type from two addresses.
    fn classify_nat_type(
        primary: SocketAddr,
        secondary: SocketAddr,
    ) -> Result<NatType, TransportError> {
        classify_from_multiple_responses(&[(primary, String::new()), (secondary, String::new())])
    }

    // -- classify_nat_type (two-server convenience wrapper) --------------------

    #[test]
    fn classify_same_mapping_is_address_restricted() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        assert_eq!(
            classify_nat_type(addr, addr).expect("classify"),
            NatType::AddressRestricted
        );
    }

    #[test]
    fn classify_different_port_is_symmetric() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32892));
        assert_eq!(
            classify_nat_type(a, b).expect("classify"),
            NatType::Symmetric
        );
    }

    #[test]
    fn classify_different_ip_is_symmetric() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 32891));
        assert_eq!(
            classify_nat_type(a, b).expect("classify"),
            NatType::Symmetric
        );
    }

    // -- classify_from_multiple_responses (SCP-244 multi-STUN) ----------------

    #[test]
    fn multi_stun_all_same_is_non_symmetric() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let responses = vec![
            (addr, "server1".into()),
            (addr, "server2".into()),
            (addr, "server3".into()),
        ];
        assert_eq!(
            classify_from_multiple_responses(&responses).expect("classify"),
            NatType::AddressRestricted
        );
    }

    #[test]
    fn multi_stun_any_divergent_is_symmetric() {
        let same = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let different = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32892));
        let responses = vec![
            (same, "server1".into()),
            (same, "server2".into()),
            (different, "server3".into()),
        ];
        assert_eq!(
            classify_from_multiple_responses(&responses).expect("classify"),
            NatType::Symmetric
        );
    }

    #[test]
    fn multi_stun_first_divergent_is_symmetric() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 32891));
        let responses = vec![(a, "server1".into()), (b, "server2".into())];
        assert_eq!(
            classify_from_multiple_responses(&responses).expect("classify"),
            NatType::Symmetric
        );
    }

    #[test]
    fn multi_stun_rejects_fewer_than_two_responses() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let responses = vec![(addr, "server1".into())];
        assert!(classify_from_multiple_responses(&responses).is_err());
        assert!(classify_from_multiple_responses(&[]).is_err());
    }

    // -- NatProber construction -----------------------------------------------

    #[test]
    fn prober_rejects_empty_endpoints() {
        let result = NatProber::new(vec![], None);
        assert!(result.is_err());
    }

    #[test]
    fn prober_accepts_single_endpoint() {
        let ep = StunEndpoint {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478)),
            label: "test".into(),
        };
        let prober = NatProber::new(vec![ep], None);
        assert!(prober.is_ok());
    }

    #[test]
    fn prober_accepts_two_endpoints() {
        let ep1 = StunEndpoint {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478)),
            label: "server1".into(),
        };
        let ep2 = StunEndpoint {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 3478)),
            label: "server2".into(),
        };
        let prober = NatProber::new(vec![ep1, ep2], None);
        assert!(prober.is_ok());
    }

    // -- Single-STUN fallback (SCP-244 AC4) -----------------------------------

    #[tokio::test]
    async fn probe_single_endpoint_uses_heuristic_fallback() {
        let external_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 32891));

        let (server1_addr, handle) = spawn_mock_stun(external_addr).await;

        let ep = StunEndpoint {
            addr: server1_addr,
            label: "mock1".into(),
        };
        let prober = NatProber::new(vec![ep], Some(Duration::from_secs(5))).expect("prober");
        let result = prober.probe().await.expect("probe");

        assert_eq!(result.external_addr, Some(external_addr));
        assert_eq!(result.stun_server, "mock1");
        // SCP-244 AC4: Single endpoint → heuristic fallback to AddressRestricted.
        assert_eq!(result.nat_type, NatType::AddressRestricted);

        handle.await.expect("server");
    }

    // -- SCP-244 AC5/AC6: Two STUN servers, divergence detection --------------

    /// SCP-244 AC5: Two STUN servers return the same address → non-symmetric.
    #[tokio::test]
    async fn probe_two_servers_same_addr_classified_non_symmetric() {
        let server1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server2 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server1_addr = server1.local_addr().expect("addr");
        let server2_addr = server2.local_addr().expect("addr");

        // Both servers report the SAME external address → cone NAT.
        let external = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));

        let h1 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server1.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external, &txn_id);
            server1.send_to(&response, from).await.expect("send");
        });

        let h2 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server2.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external, &txn_id);
            server2.send_to(&response, from).await.expect("send");
        });

        let prober = NatProber::new(
            vec![
                StunEndpoint {
                    addr: server1_addr,
                    label: "mock1".into(),
                },
                StunEndpoint {
                    addr: server2_addr,
                    label: "mock2".into(),
                },
            ],
            Some(Duration::from_secs(5)),
        )
        .expect("prober");

        let result = prober.probe().await.expect("probe");
        // SCP-244 AC2: 2+ STUN servers match → non-symmetric.
        assert_eq!(result.nat_type, NatType::AddressRestricted);
        assert!(result.nat_type.is_hole_punchable());

        h1.await.expect("server1");
        h2.await.expect("server2");
    }

    /// SCP-244 AC6: Two STUN servers return different addresses → symmetric.
    #[tokio::test]
    async fn probe_two_servers_different_addr_classified_symmetric() {
        let server1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server2 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server1_addr = server1.local_addr().expect("addr");
        let server2_addr = server2.local_addr().expect("addr");

        // Server 1 reports one external address.
        let external1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 10001));
        // Server 2 reports a DIFFERENT port → symmetric NAT.
        let external2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 10002));

        let h1 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server1.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external1, &txn_id);
            server1.send_to(&response, from).await.expect("send");
        });

        let h2 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server2.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external2, &txn_id);
            server2.send_to(&response, from).await.expect("send");
        });

        let prober = NatProber::new(
            vec![
                StunEndpoint {
                    addr: server1_addr,
                    label: "mock1".into(),
                },
                StunEndpoint {
                    addr: server2_addr,
                    label: "mock2".into(),
                },
            ],
            Some(Duration::from_secs(5)),
        )
        .expect("prober");

        let result = prober.probe().await.expect("probe");
        // SCP-244 AC3: 2+ STUN servers diverge → symmetric.
        assert_eq!(result.nat_type, NatType::Symmetric);
        assert!(!result.nat_type.is_hole_punchable());

        h1.await.expect("server1");
        h2.await.expect("server2");
    }

    // -- Multi-STUN (3+ servers) divergence detection -------------------------

    /// SCP-244 AC1: Queries all configured STUN endpoints (3 servers).
    #[tokio::test]
    async fn probe_three_servers_all_match_non_symmetric() {
        let server1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server2 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server3 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server1_addr = server1.local_addr().expect("addr");
        let server2_addr = server2.local_addr().expect("addr");
        let server3_addr = server3.local_addr().expect("addr");

        // All three servers report the SAME external address.
        let external = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));

        let h1 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server1.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external, &txn_id);
            server1.send_to(&response, from).await.expect("send");
        });

        let h2 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server2.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external, &txn_id);
            server2.send_to(&response, from).await.expect("send");
        });

        let h3 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server3.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external, &txn_id);
            server3.send_to(&response, from).await.expect("send");
        });

        let prober = NatProber::new(
            vec![
                StunEndpoint {
                    addr: server1_addr,
                    label: "mock1".into(),
                },
                StunEndpoint {
                    addr: server2_addr,
                    label: "mock2".into(),
                },
                StunEndpoint {
                    addr: server3_addr,
                    label: "mock3".into(),
                },
            ],
            Some(Duration::from_secs(5)),
        )
        .expect("prober");

        let result = prober.probe().await.expect("probe");
        assert_eq!(result.nat_type, NatType::AddressRestricted);
        assert!(result.nat_type.is_hole_punchable());

        h1.await.expect("server1");
        h2.await.expect("server2");
        h3.await.expect("server3");
    }

    /// SCP-244: Third server diverges among 3 servers → symmetric.
    #[tokio::test]
    async fn probe_three_servers_third_diverges_symmetric() {
        let server1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server2 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server3 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server1_addr = server1.local_addr().expect("addr");
        let server2_addr = server2.local_addr().expect("addr");
        let server3_addr = server3.local_addr().expect("addr");

        let matching = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        // Third server reports a different IP → symmetric NAT.
        let divergent = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 99), 32891));

        let h1 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server1.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(matching, &txn_id);
            server1.send_to(&response, from).await.expect("send");
        });

        let h2 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server2.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(matching, &txn_id);
            server2.send_to(&response, from).await.expect("send");
        });

        let h3 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server3.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(divergent, &txn_id);
            server3.send_to(&response, from).await.expect("send");
        });

        let prober = NatProber::new(
            vec![
                StunEndpoint {
                    addr: server1_addr,
                    label: "mock1".into(),
                },
                StunEndpoint {
                    addr: server2_addr,
                    label: "mock2".into(),
                },
                StunEndpoint {
                    addr: server3_addr,
                    label: "mock3".into(),
                },
            ],
            Some(Duration::from_secs(5)),
        )
        .expect("prober");

        let result = prober.probe().await.expect("probe");
        assert_eq!(result.nat_type, NatType::Symmetric);
        assert!(!result.nat_type.is_hole_punchable());

        h1.await.expect("server1");
        h2.await.expect("server2");
        h3.await.expect("server3");
    }

    // -- Partial failure scenarios ---------------------------------------------

    /// SCP-244 AC4: Two endpoints configured but only one responds →
    /// single-STUN fallback uses port-mapping heuristics.
    #[tokio::test]
    async fn probe_second_endpoint_fails_uses_single_stun_fallback() {
        let server1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server1_addr = server1.local_addr().expect("addr");
        // Server 2 is bound but never responds → will time out.
        let server2 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server2_addr = server2.local_addr().expect("addr");

        let external_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));

        let h1 = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = server1.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(external_addr, &txn_id);
            server1.send_to(&response, from).await.expect("send");
        });

        // Keep server2 socket alive so it accepts the packet but never responds.
        let _server2_keepalive = server2;

        let prober = NatProber::new(
            vec![
                StunEndpoint {
                    addr: server1_addr,
                    label: "mock1".into(),
                },
                StunEndpoint {
                    addr: server2_addr,
                    label: "mock2-unresponsive".into(),
                },
            ],
            // Short timeout to keep test fast.
            Some(Duration::from_millis(200)),
        )
        .expect("prober");

        let result = prober.probe().await.expect("probe");

        // Only 1 response → single-STUN fallback (SCP-244 AC4).
        assert_eq!(result.nat_type, NatType::AddressRestricted);
        assert_eq!(result.external_addr, Some(external_addr));
        assert_eq!(result.stun_server, "mock1");

        h1.await.expect("server1");
    }

    // -- ReachabilityProbe (SCP-242) self-test via STUN intermediary -----------

    /// SCP-242 AC5/AC6: Self-test passes when STUN server confirms expected address.
    /// Uses loopback with mock STUN server — validates protocol logic, not real NAT traversal.
    #[tokio::test]
    async fn reachability_self_test_passes_when_stun_confirms_address_loopback() {
        let stun_server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let stun_server_addr = stun_server.local_addr().expect("addr");

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let expected_external =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));

        // Mock STUN server: returns the expected external address.
        let h = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = stun_server.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(expected_external, &txn_id);
            stun_server.send_to(&response, from).await.expect("send");
        });

        let probe = DefaultReachabilityProbe::new(stun_server_addr, Some(Duration::from_secs(5)));
        let result = probe
            .probe_reachability(&client_socket, expected_external)
            .await
            .expect("probe");

        assert!(
            result,
            "self-test should pass when STUN confirms expected address"
        );
        h.await.expect("server");
    }

    /// SCP-242 AC7: Self-test fails when STUN server reports different address.
    /// Uses loopback with mock STUN server — validates protocol logic, not real NAT traversal.
    #[tokio::test]
    async fn reachability_self_test_fails_when_stun_reports_different_address_loopback() {
        let stun_server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let stun_server_addr = stun_server.local_addr().expect("addr");

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let expected_external =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        // STUN server reports a DIFFERENT address (mapping changed).
        let actual_external =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 99), 12345));

        let h = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = stun_server.recv_from(&mut buf).await.expect("recv");
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(actual_external, &txn_id);
            stun_server.send_to(&response, from).await.expect("send");
        });

        let probe = DefaultReachabilityProbe::new(stun_server_addr, Some(Duration::from_secs(5)));
        let result = probe
            .probe_reachability(&client_socket, expected_external)
            .await
            .expect("probe");

        assert!(
            !result,
            "self-test should fail when STUN reports different address"
        );
        h.await.expect("server");
    }

    /// SCP-242: Self-test returns false (not error) when STUN server is unreachable.
    /// Uses loopback with silent server — validates timeout behavior, not real NAT traversal.
    #[tokio::test]
    async fn reachability_self_test_returns_false_on_stun_timeout_loopback() {
        // Bind a STUN server socket but never respond -- will time out.
        let stun_server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let stun_server_addr = stun_server.local_addr().expect("addr");
        let _keepalive = stun_server;

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let expected_external =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));

        let probe =
            DefaultReachabilityProbe::new(stun_server_addr, Some(Duration::from_millis(100)));
        let result = probe
            .probe_reachability(&client_socket, expected_external)
            .await
            .expect("probe should not return Err, just false");

        assert!(!result, "self-test should return false on STUN timeout");
    }

    /// SCP-242: `DefaultReachabilityProbe` uses the same socket (NAT mapping preserved).
    /// Uses loopback with mock STUN server — validates socket identity, not real NAT traversal.
    #[tokio::test]
    async fn reachability_self_test_uses_provided_socket_loopback() {
        let stun_server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let stun_server_addr = stun_server.local_addr().expect("addr");

        // Bind a specific socket -- this is the "NAT-mapped" socket.
        let nat_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let nat_local_addr = nat_socket.local_addr().expect("addr");

        let expected_external =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));

        // The mock STUN server verifies the request comes from nat_socket's address.
        let h = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_, from) = stun_server.recv_from(&mut buf).await.expect("recv");
            // Verify the packet came from the specific socket we provided.
            assert_eq!(
                from, nat_local_addr,
                "STUN request should come from the provided socket"
            );
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = stun::tests_helper::build_binding_response(expected_external, &txn_id);
            stun_server.send_to(&response, from).await.expect("send");
        });

        let probe = DefaultReachabilityProbe::new(stun_server_addr, Some(Duration::from_secs(5)));
        let result = probe
            .probe_reachability(&nat_socket, expected_external)
            .await
            .expect("probe");

        assert!(result, "self-test should pass");
        h.await.expect("server");
    }

    /// SCP-242: Verify `DefaultReachabilityProbe` constructor stores correct values.
    #[test]
    fn default_reachability_probe_construction() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478));
        let probe = DefaultReachabilityProbe::new(addr, Some(Duration::from_secs(10)));
        assert_eq!(probe.stun_server(), addr);
    }
}
