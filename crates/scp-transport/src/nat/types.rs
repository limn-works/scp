//! NAT type classification and STUN probe result types.
//!
//! Spec section 10.12.1 defines four NAT types that determine which
//! reachability tier is viable. Section 10.12.3 specifies STUN-based
//! classification. This module provides the type definitions used by
//! [`super::NatProber`] and [`super::stun`].

use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// NatType
// ---------------------------------------------------------------------------

/// NAT type as classified by STUN probing (spec 10.12.3).
///
/// The classification determines whether STUN hole punching (Tier 2) is
/// viable or whether relay bridging (Tier 3) is required.
///
/// | Type              | Prevalence | Hole punchable |
/// |-------------------|-----------|----------------|
/// | FullCone          | ~20%      | Yes            |
/// | AddressRestricted | ~30%      | Yes            |
/// | PortRestricted    | ~35%      | Yes            |
/// | Symmetric         | ~15%      | No             |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatType {
    /// Any external host can send to the mapped address.
    FullCone,
    /// Only hosts the internal endpoint has contacted can send back.
    AddressRestricted,
    /// Only the specific host:port the internal endpoint has contacted.
    PortRestricted,
    /// Different mapping per destination -- external address unpredictable.
    /// Falls through to Tier 3 (bridge).
    Symmetric,
}

impl NatType {
    /// Returns `true` if this NAT type supports hole punching (Tier 2).
    ///
    /// Symmetric NATs assign a different external mapping per destination,
    /// making the STUN-discovered address unusable for other peers (spec
    /// 10.12.3).
    #[must_use]
    pub const fn is_hole_punchable(&self) -> bool {
        !matches!(self, Self::Symmetric)
    }
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullCone => write!(f, "full-cone"),
            Self::AddressRestricted => write!(f, "address-restricted"),
            Self::PortRestricted => write!(f, "port-restricted"),
            Self::Symmetric => write!(f, "symmetric"),
        }
    }
}

// ---------------------------------------------------------------------------
// StunEndpoint
// ---------------------------------------------------------------------------

/// A STUN-capable endpoint used for NAT type probing (spec 10.12.3).
///
/// STUN service coexists with SCP relay WebSocket endpoints. Bootstrap
/// relays MUST include at least one STUN-capable relay (spec 10.12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunEndpoint {
    /// UDP socket address of the STUN server.
    pub addr: SocketAddr,
    /// Human-readable label for logging (e.g., relay URL or name).
    pub label: String,
}

// ---------------------------------------------------------------------------
// NatProbeResult
// ---------------------------------------------------------------------------

/// Result of a STUN-based NAT type probe (spec 10.12.3).
///
/// Contains the classified NAT type and, for non-symmetric NATs, the
/// external address that can be published in the DID document (spec
/// 10.12.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatProbeResult {
    /// Classified NAT type.
    pub nat_type: NatType,
    /// External IP and port as seen by the STUN server. `None` only when
    /// probing fails entirely (no response from any server).
    pub external_addr: Option<SocketAddr>,
    /// Label of the STUN server that provided the primary response.
    pub stun_server: String,
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
    fn hole_punchable_for_cone_nats() {
        assert!(NatType::FullCone.is_hole_punchable());
        assert!(NatType::AddressRestricted.is_hole_punchable());
        assert!(NatType::PortRestricted.is_hole_punchable());
    }

    #[test]
    fn not_hole_punchable_for_symmetric() {
        assert!(!NatType::Symmetric.is_hole_punchable());
    }

    #[test]
    fn display_formats() {
        assert_eq!(NatType::FullCone.to_string(), "full-cone");
        assert_eq!(NatType::AddressRestricted.to_string(), "address-restricted");
        assert_eq!(NatType::PortRestricted.to_string(), "port-restricted");
        assert_eq!(NatType::Symmetric.to_string(), "symmetric");
    }

    #[test]
    fn probe_result_with_external_addr() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 32891));
        let result = NatProbeResult {
            nat_type: NatType::FullCone,
            external_addr: Some(addr),
            stun_server: "stun.example.com".into(),
        };
        assert_eq!(result.nat_type, NatType::FullCone);
        assert_eq!(result.external_addr, Some(addr));
    }

    #[test]
    fn probe_result_without_external_addr() {
        let result = NatProbeResult {
            nat_type: NatType::Symmetric,
            external_addr: None,
            stun_server: "stun.example.com".into(),
        };
        assert!(result.external_addr.is_none());
        assert!(!result.nat_type.is_hole_punchable());
    }

    #[test]
    fn stun_endpoint_equality() {
        let a = StunEndpoint {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478)),
            label: "server1".into(),
        };
        let b = StunEndpoint {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 3478)),
            label: "server1".into(),
        };
        assert_eq!(a, b);
    }
}
