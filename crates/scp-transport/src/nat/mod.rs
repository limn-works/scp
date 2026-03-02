//! NAT traversal for relay reachability (spec section 10.12).
//!
//! This module implements the layered reachability strategy described in spec
//! section 10.12. Each tier is a separate submodule:
//!
//! - [`stun`] / [`types`] -- NAT type detection via STUN probing (§10.12.3).
//! - [`upnp`] -- Tier 1: UPnP-IGD and NAT-PMP/PCP port mapping (§10.12.2).
//!
//! The classification algorithm sends STUN Binding Requests to two endpoints
//! and compares the external mappings:
//!
//! - Same external IP:port from both servers → non-symmetric (cone NAT).
//! - Different external ports → symmetric NAT.
//!
//! A 25-second keepalive maintains the NAT mapping for non-symmetric NATs
//! (spec 10.12.3).
//!
//! Tier selection is automatic: the SDK tries each tier in order and uses the
//! first that produces a reachable external address.
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
pub use upnp::{
    MappingProtocol, NatTierChange, PortMapper, PortMappingError, PortMappingManager,
    PortMappingResult,
};

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::TransportError;

// ---------------------------------------------------------------------------
// NatProber
// ---------------------------------------------------------------------------

/// Probes NAT type by sending STUN Binding Requests to multiple endpoints
/// and comparing the external address mappings (spec 10.12.3).
///
/// # NAT Classification Algorithm
///
/// 1. Send a Binding Request to `endpoints[0]` (primary).
/// 2. Send a Binding Request to `endpoints[1]` (secondary, different IP or
///    port).
/// 3. If both return the same external IP:port → non-symmetric (cone NAT).
///    Classified as `AddressRestricted` by default (differentiating full-cone
///    from restricted-cone requires the server to respond from an alternate
///    address, which is not part of this initial implementation).
/// 4. If external ports differ → `Symmetric`.
///
/// # Fallback Signal
///
/// When `NatType::Symmetric` is detected, the caller should skip Tier 2
/// and proceed to Tier 3 (relay bridging).
pub struct NatProber {
    /// STUN endpoints to probe (at least one, ideally two).
    endpoints: Vec<StunEndpoint>,
    /// Timeout per STUN request.
    timeout: Duration,
}

impl NatProber {
    /// Creates a new prober with the given STUN endpoints.
    ///
    /// At least one endpoint is required. Two endpoints enable NAT type
    /// classification (symmetric vs. cone). With a single endpoint, only
    /// external address discovery is performed and the NAT type defaults
    /// to `AddressRestricted`.
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
    /// Binds a local UDP socket and sends STUN Binding Requests to the
    /// configured endpoints. Compares responses to classify the NAT type.
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
    /// # Errors
    ///
    /// Returns an error if all STUN endpoints fail to respond.
    pub async fn probe_with_socket(
        &self,
        socket: &UdpSocket,
    ) -> Result<NatProbeResult, TransportError> {
        // Step 1: Send to primary endpoint.
        let primary = &self.endpoints[0];
        info!(server = %primary.addr, label = %primary.label, "sending STUN binding request to primary");

        let primary_response =
            stun::stun_binding_request(socket, primary.addr, Some(self.timeout)).await?;

        let primary_addr = primary_response.mapped_addr;
        debug!(external = %primary_addr, server = %primary.label, "primary STUN response");

        // Step 2: If we have a second endpoint, classify NAT type.
        if self.endpoints.len() >= 2 {
            let secondary = &self.endpoints[1];
            info!(server = %secondary.addr, label = %secondary.label, "sending STUN binding request to secondary");

            match stun::stun_binding_request(socket, secondary.addr, Some(self.timeout)).await {
                Ok(secondary_response) => {
                    let secondary_addr = secondary_response.mapped_addr;
                    debug!(external = %secondary_addr, server = %secondary.label, "secondary STUN response");

                    let nat_type = classify_nat_type(primary_addr, secondary_addr);
                    info!(nat_type = %nat_type, external = %primary_addr, "NAT type classified");

                    return Ok(NatProbeResult {
                        nat_type,
                        external_addr: Some(primary_addr),
                        stun_server: primary.label.clone(),
                    });
                }
                Err(e) => {
                    warn!(
                        server = %secondary.label,
                        error = %e,
                        "secondary STUN probe failed, defaulting to AddressRestricted"
                    );
                }
            }
        }

        // Single endpoint or secondary failed: cannot fully classify.
        // Default to AddressRestricted (most common cone NAT type).
        info!(
            nat_type = %NatType::AddressRestricted,
            external = %primary_addr,
            "NAT type defaulted (single endpoint)"
        );

        Ok(NatProbeResult {
            nat_type: NatType::AddressRestricted,
            external_addr: Some(primary_addr),
            stun_server: primary.label.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// NAT type classification
// ---------------------------------------------------------------------------

/// Classifies NAT type by comparing external mappings from two different
/// STUN servers (spec 10.12.3).
///
/// - Same external IP and port → non-symmetric. Classified as
///   `AddressRestricted` (differentiating full-cone from restricted requires
///   server cooperation not in this implementation).
/// - Same external IP, different port → `Symmetric`.
/// - Different external IP → `Symmetric`.
fn classify_nat_type(primary: SocketAddr, secondary: SocketAddr) -> NatType {
    if primary.ip() == secondary.ip() && primary.port() == secondary.port() {
        // Same mapping to different servers → cone NAT.
        // Full-cone vs. restricted differentiation requires the server to
        // send from an alternate address. Default to AddressRestricted as
        // the most common cone type (~30% prevalence per spec 10.12.3).
        NatType::AddressRestricted
    } else {
        // Different mapping per destination → symmetric NAT.
        NatType::Symmetric
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn classify_same_mapping_is_address_restricted() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        assert_eq!(classify_nat_type(addr, addr), NatType::AddressRestricted);
    }

    #[test]
    fn classify_different_port_is_symmetric() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32892));
        assert_eq!(classify_nat_type(a, b), NatType::Symmetric);
    }

    #[test]
    fn classify_different_ip_is_symmetric() {
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 32891));
        assert_eq!(classify_nat_type(a, b), NatType::Symmetric);
    }

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

    #[tokio::test]
    async fn probe_with_mock_stun_server_returns_external_addr() {
        let server1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server1_addr = server1.local_addr().expect("addr");

        let external_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 32891));

        // Spawn mock STUN server.
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 576];
            let (_len, from) = server1.recv_from(&mut buf).await.expect("recv");

            // Extract transaction ID.
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);

            // Build response with known external address.
            let response = stun::tests_helper::build_binding_response(external_addr, &txn_id);
            server1.send_to(&response, from).await.expect("send");
        });

        let ep = StunEndpoint {
            addr: server1_addr,
            label: "mock1".into(),
        };
        let prober = NatProber::new(vec![ep], Some(Duration::from_secs(5))).expect("prober");
        let result = prober.probe().await.expect("probe");

        assert_eq!(result.external_addr, Some(external_addr));
        assert_eq!(result.stun_server, "mock1");
        // Single endpoint → default to AddressRestricted.
        assert_eq!(result.nat_type, NatType::AddressRestricted);

        handle.await.expect("server");
    }

    #[tokio::test]
    async fn probe_classifies_symmetric_nat() {
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
        assert_eq!(result.nat_type, NatType::Symmetric);
        assert!(!result.nat_type.is_hole_punchable());

        h1.await.expect("server1");
        h2.await.expect("server2");
    }

    #[tokio::test]
    async fn probe_classifies_cone_nat() {
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
        assert_eq!(result.nat_type, NatType::AddressRestricted);
        assert!(result.nat_type.is_hole_punchable());

        h1.await.expect("server1");
        h2.await.expect("server2");
    }
}
