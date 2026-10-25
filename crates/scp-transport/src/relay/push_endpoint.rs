//! The ADR-004 `WebPush` endpoint refusal rule (PUSH-022).
//!
//! A `WebPush` registrant chooses the URL the relay sends its wakes to, so the
//! relay refuses an endpoint that would aim a request anywhere but a public
//! host (ADR-004 **Endpoint refusal**, spec 10 §10.7.1 **`WebPush` endpoint**):
//!
//! - [`parse_endpoint`] parses the endpoint, requires it to equal its WHATWG
//!   URL serialization (spec 22 §22.11.4) with scheme `https`, no userinfo and
//!   no fragment, and derives the VAPID `aud`, the RFC 6454 origin.
//! - [`check_address`] judges one address: it refuses each address the IANA
//!   IPv4 and IPv6 Special-Purpose Address Registries (both as last updated
//!   2025-10-09) mark not globally reachable, N/A or blank, every IPv6
//!   address outside `2000::/3`, multicast, unspecified, 6to4, and the
//!   relay's [`OwnAddresses`]. It judges an IPv4-mapped address, a NAT64
//!   address under the well-known prefix (`64:ff9b::/96`), and an address
//!   under one of the operator's [`Nat64Prefixes`] by the IPv4 address it
//!   embeds.
//! - [`CheckedResolver`] resolves a host name and refuses the whole lookup
//!   when any address it returns is refused. The `WebPush` sender's HTTP client
//!   resolves through it, so a request connects only to addresses that
//!   passed, at the moment of the send. The client never consults a resolver
//!   for an IP-literal host, so [`CheckedResolver::check_literal`] judges a
//!   literal before any request. Every system lookup holds a permit from one
//!   bounded pool until the lookup itself ends, so lookups that outlive their
//!   deadline cannot pile up blocking threads.
//!
//! - [`track_own_addresses`] keeps a relay's [`OwnAddresses`] current: it
//!   resolves the host of every URL the relay reserves, adds each specific
//!   listener bind, and resolves again on every change of the reserved URL
//!   set and every [`OWN_ADDRESS_REFRESH`]. While a resolution fails, the set
//!   is unresolved and every endpoint check fails without sending.
//!
//! No error or log line in this module carries the endpoint, its host or an
//! address: the endpoint is a per-device capability URL.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock, Weak};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use url::{Host, Url};

use super::push_gate::{LiveRelayUrl, ReservedRelayUrls};

/// The longest a registration-time or send-time DNS lookup may take
/// (indicator: 5 s, the connect deadline of every push sender).
pub(crate) const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The system lookups one [`CheckedResolver`] and its clones run at once
/// (indicator: 16). A lookup that outlives [`RESOLVE_TIMEOUT`] keeps its
/// blocking thread, and its permit, until the operating system answers, so
/// this bounds the blocking threads hostile endpoints can hold.
pub(crate) const DNS_LOOKUP_PERMITS: usize = 16;

/// The share of [`DNS_LOOKUP_PERMITS`] registration-time lookups may hold
/// (indicator: 4), so registrations cannot starve wakes of lookups.
pub(crate) const REGISTRATION_LOOKUP_PERMITS: usize = 4;

/// How often [`track_own_addresses`] resolves the relay's own hosts again.
///
/// The value, 300 s, is an indicator. ADR-004 **Endpoint refusal** has the
/// relay resolve them again at an interval it chooses while the reserved URL
/// set stays the same, because a DNS change can move the relay's host to a
/// new address while its URL stays the same.
pub const OWN_ADDRESS_REFRESH: Duration = Duration::from_secs(300);

/// Why [`check_address`] refused an address. No variant carries the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AddressRefusal {
    /// The address is one of the relay's own.
    #[error("the address is one of the relay's own addresses")]
    OwnAddress,
    /// The address is unspecified (`0.0.0.0` or `::`).
    #[error("the address is unspecified")]
    Unspecified,
    /// The address is multicast (`224.0.0.0/4` or `ff00::/8`).
    #[error("the address is multicast")]
    Multicast,
    /// The most specific special-purpose registry row that contains the
    /// address marks it not globally reachable.
    #[error("the special-purpose address registry marks the address not globally reachable")]
    NotGloballyReachable,
    /// The most specific special-purpose registry row that contains the
    /// address marks global reachability N/A or leaves it blank.
    #[error("the special-purpose address registry gives the address no global reachability")]
    ReachabilityUndefined,
    /// The IPv6 address lies outside `2000::/3`.
    #[error("the IPv6 address lies outside the global unicast block 2000::/3")]
    OutsideGlobalUnicast,
    /// The address is a 6to4 address (`2002::/16`), which RFC 7526
    /// deprecates.
    #[error("the address is a deprecated 6to4 address")]
    SixToFour,
}

/// Why an endpoint was refused. No variant carries the endpoint, its host or
/// an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    /// The endpoint is not a URL.
    #[error("the WebPush endpoint is not a URL: {0}")]
    NotUrl(url::ParseError),
    /// The endpoint differs from its WHATWG URL serialization.
    #[error("the WebPush endpoint is not in its canonical URL serialization")]
    NotCanonical,
    /// The endpoint's scheme is not `https`.
    #[error("the WebPush endpoint scheme is not https")]
    NotHttps,
    /// The endpoint carries a user name or password.
    #[error("the WebPush endpoint carries userinfo")]
    HasUserinfo,
    /// The endpoint carries a fragment.
    #[error("the WebPush endpoint carries a fragment")]
    HasFragment,
    /// The endpoint has no host.
    #[error("the WebPush endpoint has no host")]
    NoHost,
    /// The endpoint's host is, or resolves to, a refused address.
    #[error("the WebPush endpoint host is refused: {0}")]
    Refused(#[source] AddressRefusal),
    /// The endpoint's host name resolves to no address.
    #[error("the WebPush endpoint host resolves to no address")]
    DoesNotResolve,
    /// The lookup took longer than [`RESOLVE_TIMEOUT`].
    #[error("the WebPush endpoint host lookup timed out")]
    ResolveTimeout,
    /// Every permit of the relay's bounded lookup pool was taken, so no
    /// lookup started. The relay's own pool was full and nothing is known
    /// about the endpoint: a send neither goes out nor counts, and the
    /// dispatcher holds the wake until a permit frees.
    #[error("the relay's endpoint lookup pool is full; no lookup started")]
    LookupPoolFull,
    /// The lookup failed.
    #[error("the WebPush endpoint host lookup failed: {0:?}")]
    Resolve(std::io::ErrorKind),
    /// The relay could not resolve its own hosts, so it cannot tell which
    /// address is its own and checks no endpoint (ADR-004 **Endpoint
    /// refusal**). Nothing is known about the endpoint: a send goes out to
    /// no address and counts toward no removal.
    #[error("the relay's own addresses are unresolved; no endpoint is checked")]
    OwnAddressesUnresolved,
}

impl EndpointError {
    /// Whether the endpoint itself is refused, as opposed to a lookup that
    /// found no address, failed, timed out or never started, which a later
    /// attempt may pass. A send counts only a refusal toward removal (spec 10
    /// §10.7.1 **Unreachable `WebPush` push service** keeps DNS failure
    /// transient).
    #[must_use]
    pub const fn is_refusal(self) -> bool {
        !matches!(
            self,
            Self::ResolveTimeout
                | Self::Resolve(_)
                | Self::DoesNotResolve
                | Self::LookupPoolFull
                | Self::OwnAddressesUnresolved
        )
    }
}

/// One resolved set of the relay's own addresses, which [`check_address`]
/// refuses.
///
/// No `Default`: an empty set is a choice the caller makes by name.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnAddressSet(Arc<[IpAddr]>);

impl OwnAddressSet {
    /// The set of `addresses`, each held in its canonical form, so an
    /// IPv4-mapped IPv6 address matches the IPv4 address it embeds.
    pub fn new(addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        let mut held: Vec<IpAddr> = addresses.into_iter().map(|ip| ip.to_canonical()).collect();
        held.sort_unstable();
        held.dedup();
        Self(held.into())
    }

    /// Whether `ip`, in canonical form, is one of the relay's own addresses.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&ip.to_canonical())
    }

    /// How many addresses the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set holds no address.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for OwnAddressSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnAddressSet")
            .field("count", &self.0.len())
            .finish()
    }
}

/// The relay's own addresses, which the ADR-004 rule refuses: a shared handle
/// whose every clone sees each replacement.
///
/// They are each address the host of every URL the relay reserves resolves
/// to, and each specific address a relay listener binds to. The handle is
/// either a known [`OwnAddressSet`] or unresolved; while it is unresolved,
/// [`CheckedResolver`] checks no endpoint and returns
/// [`EndpointError::OwnAddressesUnresolved`]. A relay that reaches endpoints
/// through `WebPush` keeps the handle current with [`track_own_addresses`].
/// No `Default`: the caller names the starting state.
#[derive(Clone)]
pub struct OwnAddresses(Arc<RwLock<Option<OwnAddressSet>>>);

impl OwnAddresses {
    /// A handle that holds the known set of `addresses`.
    pub fn new(addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        Self(Arc::new(RwLock::new(Some(OwnAddressSet::new(addresses)))))
    }

    /// A handle that holds no set yet, so every endpoint check fails until
    /// [`track_own_addresses`] resolves one.
    #[must_use]
    pub fn unresolved() -> Self {
        Self(Arc::new(RwLock::new(None)))
    }

    /// The current set, or `None` while it is unresolved.
    #[must_use]
    pub fn known(&self) -> Option<OwnAddressSet> {
        // Each write replaces the whole value, so a poisoned lock still holds
        // a consistent one.
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replaces the set every clone reads; `None` marks it unresolved.
    pub(crate) fn replace(&self, set: Option<OwnAddressSet>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = set;
    }

    fn downgrade(&self) -> Weak<RwLock<Option<OwnAddressSet>>> {
        Arc::downgrade(&self.0)
    }
}

impl fmt::Debug for OwnAddresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.known() {
            Some(set) => f
                .debug_struct("OwnAddresses")
                .field("count", &set.len())
                .finish(),
            None => f.write_str("OwnAddresses(unresolved)"),
        }
    }
}

/// The length of an RFC 6052 §2.2 NAT64 prefix, which fixes where the
/// embedded IPv4 address sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nat64PrefixLen {
    /// A `/32` prefix.
    Bits32,
    /// A `/40` prefix.
    Bits40,
    /// A `/48` prefix.
    Bits48,
    /// A `/56` prefix.
    Bits56,
    /// A `/64` prefix.
    Bits64,
    /// A `/96` prefix.
    Bits96,
}

impl Nat64PrefixLen {
    const fn bits(self) -> u8 {
        match self {
            Self::Bits32 => 32,
            Self::Bits40 => 40,
            Self::Bits48 => 48,
            Self::Bits56 => 56,
            Self::Bits64 => 64,
            Self::Bits96 => 96,
        }
    }

    /// The indexes of the four IPv4 octets in the IPv6 address (RFC 6052
    /// §2.2 figure 1). Octet 8, bits 64 to 71, is the `u` octet, which never
    /// carries IPv4 bits.
    const fn octets(self) -> [usize; 4] {
        match self {
            Self::Bits32 => [4, 5, 6, 7],
            Self::Bits40 => [5, 6, 7, 9],
            Self::Bits48 => [6, 7, 9, 10],
            Self::Bits56 => [7, 9, 10, 11],
            Self::Bits64 => [9, 10, 11, 12],
            Self::Bits96 => [12, 13, 14, 15],
        }
    }
}

/// Why [`Nat64Prefix::new`] refused a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Nat64PrefixError {
    /// RFC 6052 §2.2 allows only lengths 32, 40, 48, 56, 64 and 96.
    #[error("a NAT64 prefix length must be 32, 40, 48, 56, 64 or 96, not {0}")]
    Length(u8),
    /// The network address sets bits past the prefix length.
    #[error("the NAT64 prefix sets bits past its length")]
    HostBits,
}

/// One NAT64 network-specific prefix the relay's network translates (RFC 6052
/// §2.2).
///
/// ADR-004 **Endpoint refusal** judges an address under it by the IPv4
/// address it embeds, because the translator delivers the packet there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nat64Prefix {
    network: u128,
    len: Nat64PrefixLen,
}

impl Nat64Prefix {
    /// The prefix `network/len`.
    ///
    /// # Errors
    ///
    /// [`Nat64PrefixError::Length`] for a length RFC 6052 does not allow, and
    /// [`Nat64PrefixError::HostBits`] when `network` sets a bit past `len`.
    pub const fn new(network: Ipv6Addr, len: u8) -> Result<Self, Nat64PrefixError> {
        let len = match len {
            32 => Nat64PrefixLen::Bits32,
            40 => Nat64PrefixLen::Bits40,
            48 => Nat64PrefixLen::Bits48,
            56 => Nat64PrefixLen::Bits56,
            64 => Nat64PrefixLen::Bits64,
            96 => Nat64PrefixLen::Bits96,
            other => return Err(Nat64PrefixError::Length(other)),
        };
        let network = network.to_bits();
        if network << len.bits() != 0 {
            return Err(Nat64PrefixError::HostBits);
        }
        Ok(Self { network, len })
    }

    /// The IPv4 address `ip` embeds when it lies under this prefix. The `u`
    /// octet is not checked: a translator that ignores it still delivers the
    /// packet to the embedded address.
    const fn embedded(self, ip: Ipv6Addr) -> Option<Ipv4Addr> {
        if !prefix_matches(ip.to_bits(), self.network, self.len.bits()) {
            return None;
        }
        let octets = ip.octets();
        let [a, b, c, d] = self.len.octets();
        Some(Ipv4Addr::new(octets[a], octets[b], octets[c], octets[d]))
    }
}

/// The NAT64 network-specific prefixes the relay operator lists (ADR-004
/// **Endpoint refusal**, PUSH-023).
///
/// The list is empty when the relay's network has no NAT64 translator. No
/// `Default`: the empty list is a choice the operator
/// makes by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nat64Prefixes(Arc<[Nat64Prefix]>);

impl Nat64Prefixes {
    /// The list `prefixes`.
    pub fn new(prefixes: impl IntoIterator<Item = Nat64Prefix>) -> Self {
        Self(prefixes.into_iter().collect())
    }

    /// The IPv4 address `ip` embeds under the first listed prefix that
    /// contains it.
    fn embedded(&self, ip: Ipv6Addr) -> Option<Ipv4Addr> {
        self.0.iter().find_map(|prefix| prefix.embedded(ip))
    }
}

/// What a special-purpose registry row says about global reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    Global,
    NotGlobal,
    Undefined,
}

/// The IANA IPv4 Special-Purpose Address Registry, as IANA last updated it on
/// 2025-10-09: `(network, prefix length, Globally Reachable)`.
const IPV4_REGISTRY: &[(Ipv4Addr, u8, Reach)] = &[
    (Ipv4Addr::UNSPECIFIED, 8, Reach::NotGlobal),
    (Ipv4Addr::UNSPECIFIED, 32, Reach::NotGlobal),
    (Ipv4Addr::new(10, 0, 0, 0), 8, Reach::NotGlobal),
    (Ipv4Addr::new(100, 64, 0, 0), 10, Reach::NotGlobal),
    (Ipv4Addr::new(127, 0, 0, 0), 8, Reach::NotGlobal),
    (Ipv4Addr::new(169, 254, 0, 0), 16, Reach::NotGlobal),
    (Ipv4Addr::new(172, 16, 0, 0), 12, Reach::NotGlobal),
    (Ipv4Addr::new(192, 0, 0, 0), 24, Reach::NotGlobal),
    (Ipv4Addr::new(192, 0, 0, 0), 29, Reach::NotGlobal),
    (Ipv4Addr::new(192, 0, 0, 8), 32, Reach::NotGlobal),
    (Ipv4Addr::new(192, 0, 0, 9), 32, Reach::Global),
    (Ipv4Addr::new(192, 0, 0, 10), 32, Reach::Global),
    (Ipv4Addr::new(192, 0, 0, 170), 32, Reach::NotGlobal),
    (Ipv4Addr::new(192, 0, 0, 171), 32, Reach::NotGlobal),
    (Ipv4Addr::new(192, 0, 2, 0), 24, Reach::NotGlobal),
    (Ipv4Addr::new(192, 31, 196, 0), 24, Reach::Global),
    (Ipv4Addr::new(192, 52, 193, 0), 24, Reach::Global),
    (Ipv4Addr::new(192, 88, 99, 0), 24, Reach::Undefined),
    (Ipv4Addr::new(192, 88, 99, 2), 32, Reach::NotGlobal),
    (Ipv4Addr::new(192, 168, 0, 0), 16, Reach::NotGlobal),
    (Ipv4Addr::new(192, 175, 48, 0), 24, Reach::Global),
    (Ipv4Addr::new(198, 18, 0, 0), 15, Reach::NotGlobal),
    (Ipv4Addr::new(198, 51, 100, 0), 24, Reach::NotGlobal),
    (Ipv4Addr::new(203, 0, 113, 0), 24, Reach::NotGlobal),
    (Ipv4Addr::new(240, 0, 0, 0), 4, Reach::NotGlobal),
    (Ipv4Addr::BROADCAST, 32, Reach::NotGlobal),
];

/// The IANA IPv6 Special-Purpose Address Registry, as IANA last updated it on
/// 2025-10-09: `(network, prefix length, Globally Reachable)`. The
/// `::ffff:0:0/96` and `64:ff9b::/96` rows are absent, because
/// [`check_address`] judges those addresses by the IPv4 address they embed,
/// and `2002::/16` is absent because every 6to4 address is refused.
const IPV6_REGISTRY: &[(Ipv6Addr, u8, Reach)] = &[
    (Ipv6Addr::LOCALHOST, 128, Reach::NotGlobal),
    (Ipv6Addr::UNSPECIFIED, 128, Reach::NotGlobal),
    (
        Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0),
        48,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0),
        64,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0x100, 0, 0, 1, 0, 0, 0, 0),
        64,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        23,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        32,
        Reach::Undefined,
    ),
    (
        Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1),
        128,
        Reach::Global,
    ),
    (
        Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2),
        128,
        Reach::Global,
    ),
    (
        Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 3),
        128,
        Reach::Global,
    ),
    (
        Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0),
        48,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0),
        32,
        Reach::Global,
    ),
    (
        Ipv6Addr::new(0x2001, 4, 0x112, 0, 0, 0, 0, 0),
        48,
        Reach::Global,
    ),
    (
        Ipv6Addr::new(0x2001, 0x10, 0, 0, 0, 0, 0, 0),
        28,
        Reach::Undefined,
    ),
    (
        Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0),
        28,
        Reach::Global,
    ),
    (
        Ipv6Addr::new(0x2001, 0x30, 0, 0, 0, 0, 0, 0),
        28,
        Reach::Global,
    ),
    (
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        32,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0),
        48,
        Reach::Global,
    ),
    (
        Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
        20,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0),
        16,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
        7,
        Reach::NotGlobal,
    ),
    (
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        10,
        Reach::NotGlobal,
    ),
];

/// The NAT64 well-known prefix `64:ff9b::/96` (RFC 6052).
const NAT64_PREFIX: u128 = 0x0064_ff9b_0000_0000_0000_0000_0000_0000;

/// Whether the top `len` bits of `addr` equal those of `network`.
const fn prefix_matches(addr: u128, network: u128, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    let shift = 128 - len as u32;
    (addr >> shift) == (network >> shift)
}

/// The reachability of the most specific row of `rows` that contains `addr`,
/// widened to 128 bits with `width` the address length in bits; `None` when
/// no row contains it.
fn most_specific<A: Copy>(
    rows: &[(A, u8, Reach)],
    addr: u128,
    width: u8,
    bits: impl Fn(A) -> u128,
) -> Option<Reach> {
    let shift = 128 - u32::from(width);
    rows.iter()
        .filter(|(network, len, _)| prefix_matches(addr << shift, bits(*network) << shift, *len))
        .max_by_key(|(_, len, _)| *len)
        .map(|(_, _, reach)| *reach)
}

const fn reach_to_result(reach: Option<Reach>) -> Result<(), AddressRefusal> {
    match reach {
        None | Some(Reach::Global) => Ok(()),
        Some(Reach::NotGlobal) => Err(AddressRefusal::NotGloballyReachable),
        Some(Reach::Undefined) => Err(AddressRefusal::ReachabilityUndefined),
    }
}

fn check_ipv4(ip: Ipv4Addr, own: &OwnAddressSet) -> Result<(), AddressRefusal> {
    if own.contains(IpAddr::V4(ip)) {
        return Err(AddressRefusal::OwnAddress);
    }
    if ip.is_unspecified() {
        return Err(AddressRefusal::Unspecified);
    }
    if ip.is_multicast() {
        return Err(AddressRefusal::Multicast);
    }
    reach_to_result(most_specific(
        IPV4_REGISTRY,
        u128::from(ip.to_bits()),
        32,
        |a: Ipv4Addr| u128::from(a.to_bits()),
    ))
}

fn check_ipv6(
    ip: Ipv6Addr,
    own: &OwnAddressSet,
    nat64: &Nat64Prefixes,
) -> Result<(), AddressRefusal> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return check_ipv4(v4, own);
    }
    let bits = ip.to_bits();
    if prefix_matches(bits, NAT64_PREFIX, 96) {
        // The low 32 bits are the embedded IPv4 address; the mask keeps the
        // conversion lossless.
        let embedded = u32::try_from(bits & u128::from(u32::MAX)).unwrap_or(u32::MAX);
        return check_ipv4(Ipv4Addr::from_bits(embedded), own);
    }
    if let Some(v4) = nat64.embedded(ip) {
        return check_ipv4(v4, own);
    }
    if own.contains(IpAddr::V6(ip)) {
        return Err(AddressRefusal::OwnAddress);
    }
    if ip.is_unspecified() {
        return Err(AddressRefusal::Unspecified);
    }
    if ip.is_multicast() {
        return Err(AddressRefusal::Multicast);
    }
    if ip.segments()[0] == 0x2002 {
        return Err(AddressRefusal::SixToFour);
    }
    reach_to_result(most_specific(IPV6_REGISTRY, bits, 128, Ipv6Addr::to_bits))?;
    if !prefix_matches(bits, 0x2000 << 112, 3) {
        return Err(AddressRefusal::OutsideGlobalUnicast);
    }
    Ok(())
}

/// Applies the ADR-004 address rule to `ip`, with the relay's own addresses
/// `own` and its network's NAT64 prefixes `nat64`.
///
/// # Errors
///
/// The [`AddressRefusal`] naming why `ip` is not a global unicast address the
/// relay may send to.
pub fn check_address(
    ip: IpAddr,
    own: &OwnAddressSet,
    nat64: &Nat64Prefixes,
) -> Result<(), AddressRefusal> {
    match ip {
        IpAddr::V4(v4) => check_ipv4(v4, own),
        IpAddr::V6(v6) => check_ipv6(v6, own, nat64),
    }
}

/// An endpoint that passed [`parse_endpoint`].
///
/// `Debug` prints nothing of the URL.
#[derive(Clone)]
pub struct ParsedEndpoint {
    url: Url,
    aud: String,
}

impl fmt::Debug for ParsedEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedEndpoint").finish_non_exhaustive()
    }
}

impl ParsedEndpoint {
    /// The request target, equal byte for byte to the registered endpoint.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// The endpoint's origin in the RFC 6454 §6.1 serialization: the VAPID
    /// `aud` claim and the key of the per-origin sender state.
    #[must_use]
    pub fn aud(&self) -> &str {
        &self.aud
    }

    /// The host as an IP address, when the endpoint names an IP literal.
    #[must_use]
    pub fn ip_literal(&self) -> Option<IpAddr> {
        match self.url.host()? {
            Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
            Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
            Host::Domain(_) => None,
        }
    }

    /// The host name, when the endpoint names a domain.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.url.domain()
    }
}

/// Parses `endpoint` under the §22.11.4 URL rules: it must equal its WHATWG
/// URL serialization, with scheme `https`, a host, no userinfo and no
/// fragment.
///
/// # Errors
///
/// The [`EndpointError`] naming the first rule `endpoint` breaks.
pub fn parse_endpoint(endpoint: &str) -> Result<ParsedEndpoint, EndpointError> {
    let url = Url::parse(endpoint).map_err(EndpointError::NotUrl)?;
    if url.scheme() != "https" {
        return Err(EndpointError::NotHttps);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(EndpointError::HasUserinfo);
    }
    if url.fragment().is_some() {
        return Err(EndpointError::HasFragment);
    }
    if url.host().is_none() {
        return Err(EndpointError::NoHost);
    }
    if url.as_str() != endpoint {
        return Err(EndpointError::NotCanonical);
    }
    let aud = url.origin().ascii_serialization();
    Ok(ParsedEndpoint { url, aud })
}

/// Who asked for a lookup, which decides the permits it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupPurpose {
    /// A wake's connection.
    Send,
    /// A registration-time check, which may hold only
    /// [`REGISTRATION_LOOKUP_PERMITS`] of the pool.
    Registration,
}

/// The permits one lookup holds until the lookup itself ends, even after its
/// caller stopped waiting. Dropping it returns the permits to the pool and
/// then signals the pool's `freed`.
pub(crate) struct LookupPermit {
    all: Option<OwnedSemaphorePermit>,
    registration: Option<OwnedSemaphorePermit>,
    freed: Arc<Notify>,
}

impl Drop for LookupPermit {
    fn drop(&mut self) {
        // The permits go back before the signal, so a woken waiter finds
        // them free.
        drop(self.registration.take());
        drop(self.all.take());
        self.freed.notify_one();
    }
}

/// The bounded lookup pool a [`CheckedResolver`] and its clones share.
#[derive(Clone)]
struct LookupPermits {
    all: Arc<Semaphore>,
    registration: Arc<Semaphore>,
    /// Signalled each time a lookup returns its permits. `notify_one` keeps
    /// one signal for a waiter that has not started waiting, so a permit
    /// freed between a full-pool refusal and the wait is not missed.
    freed: Arc<Notify>,
}

impl LookupPermits {
    fn new() -> Self {
        Self {
            all: Arc::new(Semaphore::new(DNS_LOOKUP_PERMITS)),
            registration: Arc::new(Semaphore::new(REGISTRATION_LOOKUP_PERMITS)),
            freed: Arc::new(Notify::new()),
        }
    }

    /// Takes the permits a lookup for `purpose` needs, or fails fast with
    /// [`EndpointError::LookupPoolFull`] when the pool is full, before any
    /// lookup starts.
    fn try_acquire(&self, purpose: LookupPurpose) -> Result<LookupPermit, EndpointError> {
        let registration = match purpose {
            LookupPurpose::Send => None,
            LookupPurpose::Registration => Some(
                Arc::clone(&self.registration)
                    .try_acquire_owned()
                    .map_err(|_| EndpointError::LookupPoolFull)?,
            ),
        };
        let all = Arc::clone(&self.all)
            .try_acquire_owned()
            .map_err(|_| EndpointError::LookupPoolFull)?;
        Ok(LookupPermit {
            all: Some(all),
            registration,
            freed: Arc::clone(&self.freed),
        })
    }
}

/// How a [`CheckedResolver`] looks a name up.
#[derive(Clone)]
enum Lookup {
    /// The operating system's resolver.
    System,
    /// A fixed table, so a test can point a name at any address. A name the
    /// table lacks fails as the system resolver fails for NXDOMAIN; a name
    /// mapped to no address resolves to none. `started` counts the lookups
    /// that ran.
    #[cfg(test)]
    Fixed {
        table: FixedTable,
        started: Arc<std::sync::atomic::AtomicUsize>,
    },
}

/// The answers of a [`Lookup::Fixed`], which a test may change while a
/// resolver holds them.
#[cfg(test)]
pub(crate) type FixedTable = Arc<RwLock<std::collections::HashMap<String, Vec<IpAddr>>>>;

impl Lookup {
    /// Looks `host` up while holding `permit`. The system lookup runs on a
    /// blocking thread that keeps the permit until the operating system
    /// answers, however long the caller waits.
    async fn lookup(&self, host: &str, permit: LookupPermit) -> Result<Vec<IpAddr>, EndpointError> {
        match self {
            Self::System => {
                let host = host.to_owned();
                tokio::task::spawn_blocking(move || {
                    let found = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0))
                        .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
                        .map_err(|e| EndpointError::Resolve(e.kind()));
                    drop(permit);
                    found
                })
                .await
                // The blocking task panicked or the runtime is shutting down.
                .map_err(|_| EndpointError::Resolve(std::io::ErrorKind::Other))?
            }
            #[cfg(test)]
            Self::Fixed { table, started } => {
                started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(permit);
                table
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(host)
                    .cloned()
                    .ok_or(EndpointError::Resolve(std::io::ErrorKind::NotFound))
            }
        }
    }
}

/// A resolver that refuses a whole lookup when [`check_address`] refuses any
/// address it returns.
///
/// ADR-004 refuses an endpoint whose name resolves to any refused address,
/// even when its other addresses pass.
///
/// The `WebPush` sender's HTTP client resolves every host through it, so the
/// rule holds at the moment of each connection, not only at registration.
#[derive(Clone)]
pub struct CheckedResolver {
    own: OwnAddresses,
    nat64: Nat64Prefixes,
    lookup: Lookup,
    permits: LookupPermits,
    /// Lets a test reach its loopback server. Absent from every non-test
    /// build.
    #[cfg(test)]
    allow_loopback: bool,
}

impl fmt::Debug for CheckedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedResolver")
            .field("own", &self.own)
            .field("nat64", &self.nat64)
            .finish_non_exhaustive()
    }
}

impl CheckedResolver {
    /// A resolver that looks names up through the operating system, refuses
    /// `own` along with every other refused address, and judges an address
    /// under one of `nat64` by the IPv4 address it embeds.
    #[must_use]
    pub fn new(own: OwnAddresses, nat64: Nat64Prefixes) -> Self {
        Self {
            own,
            nat64,
            lookup: Lookup::System,
            permits: LookupPermits::new(),
            #[cfg(test)]
            allow_loopback: false,
        }
    }

    /// A resolver that answers from `table` and, when `allow_loopback`, lets
    /// loopback addresses through.
    #[cfg(test)]
    pub(crate) fn for_tests(
        own: OwnAddresses,
        table: std::collections::HashMap<String, Vec<IpAddr>>,
        allow_loopback: bool,
    ) -> Self {
        Self {
            own,
            nat64: Nat64Prefixes::new([]),
            lookup: Lookup::Fixed {
                table: Arc::new(RwLock::new(table)),
                started: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            },
            permits: LookupPermits::new(),
            allow_loopback,
        }
    }

    /// How many table lookups this resolver and its clones started.
    #[cfg(test)]
    pub(crate) fn lookups_started(&self) -> usize {
        match &self.lookup {
            Lookup::Fixed { started, .. } => started.load(std::sync::atomic::Ordering::SeqCst),
            Lookup::System => 0,
        }
    }

    /// Takes every lookup permit, as lookups stuck past their deadline would,
    /// until the returned permits are dropped.
    #[cfg(test)]
    pub(crate) fn exhaust_permits(&self) -> Result<Vec<LookupPermit>, EndpointError> {
        (0..DNS_LOOKUP_PERMITS)
            .map(|_| self.permits.try_acquire(LookupPurpose::Send))
            .collect()
    }

    /// Completes once a lookup of this resolver or a clone returns its
    /// permits, at once when one did since the last completed wait, with the
    /// number of permits a wake's lookup can take then. Several permits that
    /// free before the wait completes complete it once, so the count, not the
    /// completion, says how many held wakes may retry. The `WebPush`
    /// dispatcher waits on it to retry a wake whose send found the pool full.
    #[cfg(any(test, feature = "push-store"))]
    pub(crate) async fn lookup_permit_freed(&self) -> usize {
        self.permits.freed.notified().await;
        self.free_lookup_permits()
    }

    /// The permits a wake's lookup can take now.
    #[cfg(any(test, feature = "push-store"))]
    pub(crate) fn free_lookup_permits(&self) -> usize {
        self.permits.all.available_permits()
    }

    fn check(&self, ip: IpAddr) -> Result<(), EndpointError> {
        let own = self
            .own
            .known()
            .ok_or(EndpointError::OwnAddressesUnresolved)?;
        // The own-address rule runs before the test loopback allowance, so a
        // test can name its loopback server as an own address.
        #[cfg(test)]
        if self.allow_loopback && ip.to_canonical().is_loopback() {
            if own.contains(ip) {
                return Err(EndpointError::Refused(AddressRefusal::OwnAddress));
            }
            return Ok(());
        }
        check_address(ip, &own, &self.nat64).map_err(EndpointError::Refused)
    }

    /// The relay's own-address handle this resolver checks against; every
    /// clone shares it.
    #[must_use]
    pub fn own_addresses(&self) -> OwnAddresses {
        self.own.clone()
    }

    /// Judges an IP-literal host, which the HTTP client connects to without
    /// consulting any resolver. A domain host passes here and is judged when
    /// it is resolved.
    ///
    /// # Errors
    ///
    /// [`EndpointError::Refused`] when the literal is refused.
    pub fn check_literal(&self, endpoint: &ParsedEndpoint) -> Result<(), EndpointError> {
        endpoint.ip_literal().map_or(Ok(()), |ip| self.check(ip))
    }

    /// Resolves `host` for a wake within [`RESOLVE_TIMEOUT`] and returns its
    /// addresses when every one of them passes.
    ///
    /// # Errors
    ///
    /// [`EndpointError::Refused`] when any address is refused,
    /// [`EndpointError::DoesNotResolve`] when there is none,
    /// [`EndpointError::ResolveTimeout`] or [`EndpointError::Resolve`] when
    /// the lookup times out or fails, and [`EndpointError::LookupPoolFull`]
    /// when the lookup pool is full and no lookup started.
    pub async fn resolve_checked(&self, host: &str) -> Result<Vec<IpAddr>, EndpointError> {
        self.resolve_for(host, LookupPurpose::Send).await
    }

    async fn resolve_for(
        &self,
        host: &str,
        purpose: LookupPurpose,
    ) -> Result<Vec<IpAddr>, EndpointError> {
        // An unresolved own-address set refuses every address, so no lookup
        // is spent on a host that cannot pass.
        self.own
            .known()
            .ok_or(EndpointError::OwnAddressesUnresolved)?;
        // The permit moves into the lookup, which holds it until the lookup
        // itself ends, even past the timeout below.
        let lookup = self.lookup.lookup(host, self.permits.try_acquire(purpose)?);
        let addresses = tokio::time::timeout(RESOLVE_TIMEOUT, lookup)
            .await
            .map_err(|_| EndpointError::ResolveTimeout)??;
        if addresses.is_empty() {
            return Err(EndpointError::DoesNotResolve);
        }
        for ip in &addresses {
            self.check(*ip)?;
        }
        Ok(addresses)
    }

    /// The registration-time check (ADR-004): parses `endpoint`, then judges
    /// its IP literal or every address its host name resolves to.
    ///
    /// # Errors
    ///
    /// The [`EndpointError`] that refuses the endpoint or reports the failed
    /// lookup.
    pub async fn check_registration_endpoint(&self, endpoint: &str) -> Result<(), EndpointError> {
        let parsed = parse_endpoint(endpoint)?;
        self.check_literal(&parsed)?;
        if let Some(domain) = parsed.domain() {
            self.resolve_for(domain, LookupPurpose::Registration)
                .await?;
        }
        Ok(())
    }
}

impl reqwest::dns::Resolve for CheckedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = resolver
                .resolve_checked(&host)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            let addrs: reqwest::dns::Addrs =
                Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

/// How soon [`track_own_addresses`] tries again after a failed resolution.
///
/// A failure leaves the own-address set unresolved. The value, 10 s, is an
/// indicator: a short DNS failure stops `WebPush` wakes for seconds, not for
/// a whole [`OWN_ADDRESS_REFRESH`].
pub const OWN_ADDRESS_RETRY: Duration = Duration::from_secs(10);

/// Why [`track_own_addresses`] could not resolve the relay's own addresses.
///
/// The variants name the relay's own URL and host, which the relay publishes;
/// none names an endpoint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OwnAddressError {
    /// A reserved relay URL has no host to resolve.
    #[error("the reserved relay URL {url} has no host")]
    NoHost {
        /// The URL in §9.18.2 canonical form.
        url: String,
    },
    /// The lookup of a reserved relay URL's host failed, timed out, found no
    /// address, or found the tracker's lookup pool full.
    #[error("the relay host {host} did not resolve: {error}")]
    Lookup {
        /// The host that did not resolve.
        host: String,
        /// Why the lookup failed.
        #[source]
        error: EndpointError,
    },
    /// The call ran outside a tokio runtime, so the refresh task had nowhere
    /// to run.
    #[error("own-address tracking must start inside a tokio runtime")]
    NoRuntime,
}

/// The running own-address refresh task that [`track_own_addresses`]
/// started. Dropping it stops the task; the handle keeps its last set.
#[derive(Debug)]
pub struct OwnAddressTracker {
    task: tokio::task::AbortHandle,
}

impl OwnAddressTracker {
    /// Stops the refresh task; the handle keeps its last set.
    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for OwnAddressTracker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Resolves the relay's own addresses into `own` and keeps them current
/// (ADR-004 **Endpoint refusal**).
///
/// The set holds each address the host of every URL in `urls` resolves to,
/// each IP-literal host, and the address of each bind in `binds` that is not
/// a wildcard (`0.0.0.0` or `::`), because a wildcard bind names no specific
/// address. The returned task resolves the hosts again whenever `urls`
/// changes, after first marking `own` unresolved, and every
/// [`OWN_ADDRESS_REFRESH`] while `urls` stays the same. A resolution that
/// fails marks `own` unresolved, logs a warning, and is tried again after
/// [`OWN_ADDRESS_RETRY`]. The task ends when it is dropped, when every
/// [`LiveRelayUrl`] clone is gone, or when every [`OwnAddresses`] clone is
/// gone.
///
/// # Errors
///
/// [`OwnAddressError`] when a host does not resolve now, which leaves `own`
/// as it was, or outside a tokio runtime.
pub async fn track_own_addresses(
    own: &OwnAddresses,
    urls: &LiveRelayUrl,
    binds: &[SocketAddr],
) -> Result<OwnAddressTracker, OwnAddressError> {
    track_with(own, urls, binds, Lookup::System, OWN_ADDRESS_REFRESH).await
}

async fn track_with(
    own: &OwnAddresses,
    urls: &LiveRelayUrl,
    binds: &[SocketAddr],
    lookup: Lookup,
    refresh: Duration,
) -> Result<OwnAddressTracker, OwnAddressError> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| OwnAddressError::NoRuntime)?;
    let binds: Arc<[IpAddr]> = binds
        .iter()
        .map(SocketAddr::ip)
        .filter(|ip| !ip.is_unspecified())
        .collect();
    let permits = LookupPermits::new();
    let mut reserved = urls.subscribe();
    let set = resolve_own(&reserved.current(), &binds, &lookup, &permits).await?;
    own.replace(Some(set));
    let weak = own.downgrade();
    let task = runtime.spawn(async move {
        let mut wait = refresh;
        loop {
            let url_changed = tokio::select! {
                changed = reserved.changed() => {
                    if !changed {
                        return;
                    }
                    true
                }
                () = tokio::time::sleep(wait) => false,
            };
            let Some(cell) = weak.upgrade() else {
                return;
            };
            let own = OwnAddresses(cell);
            if url_changed {
                // The old set may omit the new host's addresses, so nothing
                // is checked against it while the new one resolves.
                own.replace(None);
            }
            match resolve_own(&reserved.current(), &binds, &lookup, &permits).await {
                Ok(set) => {
                    own.replace(Some(set));
                    wait = refresh;
                }
                Err(error) => {
                    own.replace(None);
                    tracing::warn!(
                        %error,
                        "relay own addresses unresolved; WebPush checks no endpoint until they resolve"
                    );
                    wait = OWN_ADDRESS_RETRY;
                }
            }
        }
    });
    Ok(OwnAddressTracker {
        task: task.abort_handle(),
    })
}

/// One resolution of the own-address set: every reserved URL's host, then
/// the specific binds.
async fn resolve_own(
    urls: &ReservedRelayUrls,
    binds: &[IpAddr],
    lookup: &Lookup,
    permits: &LookupPermits,
) -> Result<OwnAddressSet, OwnAddressError> {
    let mut addresses = binds.to_vec();
    for entry in urls.as_slice() {
        let canonical = entry.canonical();
        let no_host = || OwnAddressError::NoHost {
            url: canonical.to_owned(),
        };
        let url = Url::parse(canonical).map_err(|_| no_host())?;
        match url.host().ok_or_else(no_host)? {
            Host::Ipv4(v4) => addresses.push(IpAddr::V4(v4)),
            Host::Ipv6(v6) => addresses.push(IpAddr::V6(v6)),
            Host::Domain(domain) => {
                let failed = |error| OwnAddressError::Lookup {
                    host: domain.to_owned(),
                    error,
                };
                let found = tokio::time::timeout(
                    RESOLVE_TIMEOUT,
                    lookup.lookup(
                        domain,
                        permits.try_acquire(LookupPurpose::Send).map_err(failed)?,
                    ),
                )
                .await
                .map_err(|_| failed(EndpointError::ResolveTimeout))?
                .map_err(failed)?;
                if found.is_empty() {
                    return Err(failed(EndpointError::DoesNotResolve));
                }
                addresses.extend(found);
            }
        }
    }
    Ok(OwnAddressSet::new(addresses))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ip(text: &str) -> Result<IpAddr, std::net::AddrParseError> {
        IpAddr::from_str(text)
    }

    /// A fixed lookup whose answers a test can change, and the table behind
    /// it.
    fn fixed(entries: &[(&str, &[IpAddr])]) -> (Lookup, FixedTable) {
        let table: FixedTable = Arc::new(RwLock::new(
            entries
                .iter()
                .map(|(host, ips)| ((*host).to_owned(), ips.to_vec()))
                .collect(),
        ));
        let lookup = Lookup::Fixed {
            table: Arc::clone(&table),
            started: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        (lookup, table)
    }

    fn relay_url(
        url: &str,
    ) -> Result<crate::relay::push_gate::RelayUrl, Box<dyn std::error::Error>> {
        Ok(crate::relay::push_gate::RelayUrl::new(url)?)
    }

    /// Lets the refresh task run until `done` holds, moving the paused clock
    /// by at most 1 ms per step, so no refresh timer fires on the way.
    async fn settle(
        own: &OwnAddresses,
        done: impl Fn(Option<&OwnAddressSet>) -> bool,
    ) -> Result<(), String> {
        for _ in 0..1000 {
            if done(own.known().as_ref()) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Err("the own-address set never reached the expected state".to_owned())
    }

    /// The handle every clone shares: a replacement is seen by a resolver
    /// built before it, and an unresolved set checks no endpoint.
    #[test]
    fn own_addresses_replace_is_seen_by_existing_resolver_clone() -> TestResult {
        let own = OwnAddresses::new([]);
        let resolver = CheckedResolver::new(own.clone(), Nat64Prefixes::new([]));
        let clone = resolver.clone();
        let endpoint = parse_endpoint("https://1.1.1.1/p")?;
        clone.check_literal(&endpoint)?;
        own.replace(Some(OwnAddressSet::new([ip("1.1.1.1")?])));
        assert_eq!(
            clone.check_literal(&endpoint),
            Err(EndpointError::Refused(AddressRefusal::OwnAddress))
        );
        resolver.check_literal(&parse_endpoint("https://8.8.8.8/p")?)?;
        Ok(())
    }

    /// An unresolved set refuses a global address it would otherwise pass,
    /// with a typed error that counts toward no removal, both at a send and
    /// at registration, and before any lookup starts.
    #[tokio::test]
    async fn unresolved_own_set_refuses_global_address() -> TestResult {
        let resolver = CheckedResolver::new(OwnAddresses::unresolved(), Nat64Prefixes::new([]));
        assert_eq!(
            resolver.check_literal(&parse_endpoint("https://1.1.1.1/p")?),
            Err(EndpointError::OwnAddressesUnresolved)
        );
        assert_eq!(
            resolver
                .check_registration_endpoint("https://1.1.1.1/p")
                .await,
            Err(EndpointError::OwnAddressesUnresolved)
        );
        assert!(!EndpointError::OwnAddressesUnresolved.is_refusal());
        assert_eq!(
            format!("{:?}", OwnAddresses::unresolved()),
            "OwnAddresses(unresolved)"
        );
        let table_resolver = CheckedResolver::for_tests(
            OwnAddresses::unresolved(),
            HashMap::from([("push.example".to_owned(), vec![ip("1.1.1.1")?])]),
            false,
        );
        assert_eq!(
            table_resolver.resolve_checked("push.example").await,
            Err(EndpointError::OwnAddressesUnresolved)
        );
        assert_eq!(table_resolver.lookups_started(), 0);
        Ok(())
    }

    /// The set follows the reserved URL set: after a switch to a URL whose
    /// host resolves elsewhere, the new host's address is refused and the
    /// old one passes. It holds every reserved URL's host at once.
    #[tokio::test(start_paused = true)]
    async fn own_addresses_follow_tier_change() -> TestResult {
        let (lookup, _table) = fixed(&[
            ("a.example", &[ip("8.8.8.8")?]),
            ("b.example", &[ip("1.1.1.1")?, ip("2606:4700::1111")?]),
        ]);
        let urls = LiveRelayUrl::new(relay_url("wss://a.example/scp/v1")?);
        let own = OwnAddresses::unresolved();
        let resolver = CheckedResolver::new(own.clone(), Nat64Prefixes::new([]));
        let _tracker = track_with(&own, &urls, &[], lookup, OWN_ADDRESS_REFRESH).await?;
        let a = parse_endpoint("https://8.8.8.8/p")?;
        let b = parse_endpoint("https://1.1.1.1/p")?;
        assert_eq!(
            resolver.check_literal(&a),
            Err(EndpointError::Refused(AddressRefusal::OwnAddress))
        );
        resolver.check_literal(&b)?;

        urls.set(relay_url("wss://b.example/scp/v1")?);
        let b_ip = ip("1.1.1.1")?;
        settle(&own, move |set| set.is_some_and(|s| s.contains(b_ip))).await?;
        resolver.check_literal(&a)?;
        assert_eq!(
            resolver.check_literal(&b),
            Err(EndpointError::Refused(AddressRefusal::OwnAddress))
        );
        assert_eq!(own.known().map(|s| s.len()), Some(2));

        urls.set(crate::relay::push_gate::ReservedRelayUrls::new(
            relay_url("wss://a.example/scp/v1")?,
            [relay_url("wss://b.example/scp/v1")?],
        ));
        settle(&own, |set| set.is_some_and(|s| s.len() == 3)).await?;
        assert_eq!(
            resolver.check_literal(&a),
            Err(EndpointError::Refused(AddressRefusal::OwnAddress))
        );
        Ok(())
    }

    /// The refresh timer: a DNS change with no URL change reaches the set
    /// after [`OWN_ADDRESS_REFRESH`] and not before. A refresh that fails
    /// marks the set unresolved, and the retry after [`OWN_ADDRESS_RETRY`]
    /// resolves it again.
    #[tokio::test(start_paused = true)]
    async fn own_addresses_refresh_on_the_timer() -> TestResult {
        let (lookup, table) = fixed(&[("a.example", &[ip("8.8.8.8")?])]);
        let urls = LiveRelayUrl::new(relay_url("wss://a.example/scp/v1")?);
        let own = OwnAddresses::unresolved();
        let _tracker = track_with(&own, &urls, &[], lookup, OWN_ADDRESS_REFRESH).await?;
        let set_table = |ips: Vec<IpAddr>| {
            let mut table = table.write().unwrap_or_else(PoisonError::into_inner);
            table.clear();
            if !ips.is_empty() {
                table.insert("a.example".to_owned(), ips);
            }
        };
        set_table(vec![ip("9.9.9.9")?]);
        tokio::time::sleep(OWN_ADDRESS_REFRESH.saturating_sub(Duration::from_secs(1))).await;
        let want = ip("8.8.8.8")?;
        assert!(own.known().is_some_and(|s| s.contains(want)));
        tokio::time::sleep(Duration::from_secs(2)).await;
        let old = ip("8.8.8.8")?;
        settle(&own, move |set| set.is_some_and(|s| !s.contains(old))).await?;
        let want = ip("9.9.9.9")?;
        assert!(own.known().is_some_and(|s| s.contains(want)));

        set_table(Vec::new());
        tokio::time::sleep(OWN_ADDRESS_REFRESH + Duration::from_secs(1)).await;
        settle(&own, |set| set.is_none()).await?;

        set_table(vec![ip("8.8.4.4")?]);
        tokio::time::sleep(OWN_ADDRESS_RETRY + Duration::from_secs(1)).await;
        settle(&own, |set| set.is_some()).await?;
        let want = ip("8.8.4.4")?;
        assert!(own.known().is_some_and(|s| s.contains(want)));
        Ok(())
    }

    /// A reserved host that does not resolve, or resolves to no address,
    /// fails tracking with a typed error naming the host, and the handle
    /// stays unresolved.
    #[tokio::test(start_paused = true)]
    async fn unresolvable_host_fails_tracking() -> TestResult {
        let (lookup, _table) = fixed(&[("empty.example", &[])]);
        let own = OwnAddresses::unresolved();
        for (host, want) in [
            (
                "absent.example",
                EndpointError::Resolve(std::io::ErrorKind::NotFound),
            ),
            ("empty.example", EndpointError::DoesNotResolve),
        ] {
            let urls = LiveRelayUrl::new(relay_url(&format!("wss://{host}/scp/v1"))?);
            let result = track_with(&own, &urls, &[], lookup.clone(), OWN_ADDRESS_REFRESH).await;
            assert_eq!(
                result.err(),
                Some(OwnAddressError::Lookup {
                    host: host.to_owned(),
                    error: want,
                })
            );
            assert!(own.known().is_none());
        }
        Ok(())
    }

    /// A wildcard bind names no specific address and adds none; a specific
    /// bind and an IP-literal URL host are added as they are.
    #[tokio::test(start_paused = true)]
    async fn wildcard_bind_adds_no_own_address() -> TestResult {
        let (lookup, _table) = fixed(&[]);
        let urls = LiveRelayUrl::new(relay_url("wss://203.0.114.5/scp/v1")?);
        let own = OwnAddresses::unresolved();
        let binds: [SocketAddr; 3] = [
            "0.0.0.0:443".parse()?,
            "[::]:443".parse()?,
            "198.18.7.7:8443".parse()?,
        ];
        let _tracker = track_with(&own, &urls, &binds, lookup, OWN_ADDRESS_REFRESH).await?;
        let set = own.known().ok_or("the set is unresolved")?;
        assert_eq!(set.len(), 2);
        assert!(set.contains(ip("203.0.114.5")?));
        assert!(set.contains(ip("198.18.7.7")?));
        assert!(!set.contains(ip("0.0.0.0")?));
        assert!(!set.contains(ip("::")?));
        Ok(())
    }

    /// Dropping the tracker stops the refresh: a DNS change after the drop
    /// never reaches the set.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_tracker_stops_the_refresh() -> TestResult {
        let (lookup, table) = fixed(&[("a.example", &[ip("8.8.8.8")?])]);
        let urls = LiveRelayUrl::new(relay_url("wss://a.example/scp/v1")?);
        let own = OwnAddresses::unresolved();
        let tracker = track_with(&own, &urls, &[], lookup, OWN_ADDRESS_REFRESH).await?;
        drop(tracker);
        table
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert("a.example".to_owned(), vec![ip("9.9.9.9")?]);
        tokio::time::sleep(OWN_ADDRESS_REFRESH * 3).await;
        let want = ip("8.8.8.8")?;
        assert!(own.known().is_some_and(|s| s.contains(want)));
        Ok(())
    }

    /// One address in each registry row, and the outcome the rule gives it.
    #[test]
    fn each_registry_row_and_rule_is_judged() -> TestResult {
        use AddressRefusal::{
            Multicast, NotGloballyReachable as Not, OutsideGlobalUnicast, ReachabilityUndefined,
            SixToFour, Unspecified,
        };
        let cases: &[(&str, Result<(), AddressRefusal>)] = &[
            // IPv4 rows.
            ("0.1.2.3", Err(Not)),
            ("0.0.0.0", Err(Unspecified)),
            ("10.1.2.3", Err(Not)),
            ("100.64.0.1", Err(Not)),
            ("100.127.255.254", Err(Not)),
            ("127.0.0.1", Err(Not)),
            ("169.254.1.1", Err(Not)),
            ("172.16.0.1", Err(Not)),
            ("172.31.255.255", Err(Not)),
            ("192.0.0.100", Err(Not)),
            ("192.0.0.1", Err(Not)),
            ("192.0.0.8", Err(Not)),
            ("192.0.0.9", Ok(())),
            ("192.0.0.10", Ok(())),
            ("192.0.0.170", Err(Not)),
            ("192.0.0.171", Err(Not)),
            ("192.0.2.1", Err(Not)),
            ("192.31.196.1", Ok(())),
            ("192.52.193.1", Ok(())),
            ("192.88.99.1", Err(ReachabilityUndefined)),
            ("192.88.99.2", Err(Not)),
            ("192.168.1.1", Err(Not)),
            ("192.175.48.1", Ok(())),
            ("198.18.0.1", Err(Not)),
            ("198.19.255.255", Err(Not)),
            ("198.51.100.1", Err(Not)),
            ("203.0.113.1", Err(Not)),
            ("240.0.0.1", Err(Not)),
            ("255.255.255.255", Err(Not)),
            ("224.0.0.1", Err(Multicast)),
            ("239.255.255.255", Err(Multicast)),
            // IPv4 neighbours of the rows, outside every one.
            ("8.8.8.8", Ok(())),
            ("100.63.255.255", Ok(())),
            ("100.128.0.0", Ok(())),
            ("172.32.0.0", Ok(())),
            ("198.20.0.0", Ok(())),
            ("223.255.255.255", Ok(())),
            // IPv6 rows.
            ("::1", Err(Not)),
            ("::", Err(Unspecified)),
            ("64:ff9b:1::1", Err(Not)),
            ("100::1", Err(Not)),
            ("100:0:0:1::1", Err(Not)),
            (
                "2001:0:4136:e378:8000:63bf:3fff:fdd2",
                Err(ReachabilityUndefined),
            ),
            ("2001:1::1", Ok(())),
            ("2001:1::2", Ok(())),
            ("2001:1::3", Ok(())),
            ("2001:1::4", Err(Not)),
            ("2001:2::1", Err(Not)),
            ("2001:3::1", Ok(())),
            ("2001:4:112::1", Ok(())),
            ("2001:10::1", Err(ReachabilityUndefined)),
            ("2001:20::1", Ok(())),
            ("2001:30::1", Ok(())),
            ("2001:100::1", Err(Not)),
            ("2001:db8::1", Err(Not)),
            ("2002:c000:0201::1", Err(SixToFour)),
            ("2002:808:808::1", Err(SixToFour)),
            ("2620:4f:8000::1", Ok(())),
            ("3fff::1", Err(Not)),
            ("5f00::1", Err(Not)),
            ("fc00::1", Err(Not)),
            ("fd12:3456::1", Err(Not)),
            ("fe80::1", Err(Not)),
            ("ff02::1", Err(Multicast)),
            // Outside 2000::/3 and in no row.
            ("4000::1", Err(OutsideGlobalUnicast)),
            ("1::1", Err(OutsideGlobalUnicast)),
            ("::2", Err(OutsideGlobalUnicast)),
            // Global unicast.
            ("2001:4860:4860::8888", Ok(())),
            ("2606:4700::1111", Ok(())),
            // Embedded IPv4, judged by the IPv4 address.
            ("::ffff:127.0.0.1", Err(Not)),
            ("::ffff:10.0.0.1", Err(Not)),
            ("::ffff:8.8.8.8", Ok(())),
            ("64:ff9b::7f00:1", Err(Not)),
            ("64:ff9b::a9fe:a9fe", Err(Not)),
            ("64:ff9b::808:808", Ok(())),
        ];
        let own = OwnAddressSet::new([]);
        let nat64 = Nat64Prefixes::new([]);
        for (i, (text, want)) in cases.iter().enumerate() {
            assert_eq!(
                check_address(ip(text)?, &own, &nat64),
                *want,
                "address #{i}"
            );
        }
        Ok(())
    }

    /// An address under an operator-listed NAT64 network-specific prefix is
    /// judged by the IPv4 address RFC 6052 §2.2 places under it, at every
    /// allowed prefix length.
    #[test]
    fn an_address_under_a_listed_nat64_prefix_is_judged_by_its_ipv4() -> TestResult {
        let own = OwnAddressSet::new([ip("203.0.114.7")?]);
        let none = Nat64Prefixes::new([]);
        // (prefix, length, 127.0.0.1 embedded, 8.8.8.8 embedded, 203.0.114.7 embedded)
        let cases: &[(&str, u8, &str, &str, &str)] = &[
            (
                "2001:db8::",
                32,
                "2001:db8:7f00:1::",
                "2001:db8:808:808::",
                "2001:db8:cb00:7207::",
            ),
            (
                "2001:db8:100::",
                40,
                "2001:db8:17f:0:1::",
                "2001:db8:108:808:8::",
                "2001:db8:1cb:72:7::",
            ),
            (
                "2001:db8:122::",
                48,
                "2001:db8:122:7f00:0:100::",
                "2001:db8:122:808:8:800::",
                "2001:db8:122:cb00:72:700::",
            ),
            (
                "2001:db8:122:300::",
                56,
                "2001:db8:122:37f:0:1::",
                "2001:db8:122:308:8:808::",
                "2001:db8:122:3cb:0:7207::",
            ),
            (
                "2001:db8:122:344::",
                64,
                "2001:db8:122:344:7f:0:100:0",
                "2001:db8:122:344:8:808:800:0",
                "2001:db8:122:344:cb:72:700:0",
            ),
            (
                "2001:db8:122:344::",
                96,
                "2001:db8:122:344::7f00:1",
                "2001:db8:122:344::808:808",
                "2001:db8:122:344::cb00:7207",
            ),
        ];
        for (i, (prefix, len, loopback, public, own_v4)) in cases.iter().enumerate() {
            let listed = Nat64Prefixes::new([Nat64Prefix::new(Ipv6Addr::from_str(prefix)?, *len)?]);
            assert_eq!(
                check_address(ip(loopback)?, &own, &listed),
                Err(AddressRefusal::NotGloballyReachable),
                "prefix #{i}, loopback"
            );
            assert_eq!(
                check_address(ip(own_v4)?, &own, &listed),
                Err(AddressRefusal::OwnAddress),
                "prefix #{i}, own address"
            );
            assert_eq!(
                check_address(ip(public)?, &own, &listed),
                Ok(()),
                "prefix #{i}, public"
            );
            // Unlisted, the documentation prefix is refused as such.
            assert_eq!(
                check_address(ip(public)?, &own, &none),
                Err(AddressRefusal::NotGloballyReachable),
                "prefix #{i}, public, unlisted"
            );
        }
        // A listed prefix inside global unicast space makes a public-looking
        // address carrying a loopback IPv4 refused.
        let global =
            Nat64Prefixes::new([Nat64Prefix::new(Ipv6Addr::from_str("2606:4700:64::")?, 96)?]);
        assert_eq!(
            check_address(ip("2606:4700:64::808:808")?, &own, &none),
            Ok(())
        );
        assert_eq!(
            check_address(ip("2606:4700:64::7f00:1")?, &own, &global),
            Err(AddressRefusal::NotGloballyReachable)
        );
        Ok(())
    }

    #[test]
    fn nat64_prefix_new_refuses_bad_lengths_and_host_bits() -> TestResult {
        let net = Ipv6Addr::from_str("2001:db8::")?;
        for len in [0, 8, 33, 63, 95, 128] {
            assert_eq!(
                Nat64Prefix::new(net, len),
                Err(Nat64PrefixError::Length(len))
            );
        }
        assert_eq!(
            Nat64Prefix::new(Ipv6Addr::from_str("2001:db8::1")?, 96),
            Err(Nat64PrefixError::HostBits)
        );
        assert_eq!(
            Nat64Prefix::new(Ipv6Addr::from_str("2001:db8:0:1::")?, 48),
            Err(Nat64PrefixError::HostBits)
        );
        Ok(())
    }

    /// The relay's own public addresses are refused in every form.
    #[test]
    fn own_addresses_are_refused() -> TestResult {
        let own = OwnAddressSet::new([ip("203.0.114.7")?, ip("2001:4860::7")?]);
        for (i, text) in [
            "203.0.114.7",
            "::ffff:203.0.114.7",
            "64:ff9b::cb00:7207",
            "2001:4860::7",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                check_address(ip(text)?, &own, &Nat64Prefixes::new([])),
                Err(AddressRefusal::OwnAddress),
                "address #{i}"
            );
        }
        assert_eq!(
            check_address(ip("203.0.114.8")?, &own, &Nat64Prefixes::new([])),
            Ok(())
        );
        // An own address given in mapped form matches its IPv4 address.
        let mapped = OwnAddressSet::new([ip("::ffff:203.0.114.9")?]);
        assert_eq!(
            check_address(ip("203.0.114.9")?, &mapped, &Nat64Prefixes::new([])),
            Err(AddressRefusal::OwnAddress)
        );
        Ok(())
    }

    #[test]
    fn parse_endpoint_gives_the_rfc_6454_origin() -> TestResult {
        let default_port = parse_endpoint("https://push.example.net/p/abc")?;
        assert_eq!(default_port.aud(), "https://push.example.net");
        assert_eq!(default_port.domain(), Some("push.example.net"));
        assert_eq!(default_port.ip_literal(), None);
        let other_port = parse_endpoint("https://push.example.net:8443/p/abc")?;
        assert_eq!(other_port.aud(), "https://push.example.net:8443");
        let literal = parse_endpoint("https://[2001:db8::1]/p")?;
        assert_eq!(literal.ip_literal(), Some(ip("2001:db8::1")?));
        assert_eq!(literal.aud(), "https://[2001:db8::1]");
        Ok(())
    }

    #[test]
    fn parse_endpoint_refuses_each_url_rule() {
        let cases: &[(&str, EndpointError)] = &[
            (
                "not a url",
                EndpointError::NotUrl(url::ParseError::RelativeUrlWithoutBase),
            ),
            ("http://push.example.net/p", EndpointError::NotHttps),
            ("https://u:p@push.example.net/p", EndpointError::HasUserinfo),
            ("https://u@push.example.net/p", EndpointError::HasUserinfo),
            ("https://push.example.net/p#f", EndpointError::HasFragment),
            // Each differs from its WHATWG serialization.
            ("https://PUSH.example.net/p", EndpointError::NotCanonical),
            ("https://push.example.net", EndpointError::NotCanonical),
            (
                "https://push.example.net:443/p",
                EndpointError::NotCanonical,
            ),
            (
                "https://push.example.net/a/../p",
                EndpointError::NotCanonical,
            ),
            ("https://0x7f.1/p", EndpointError::NotCanonical),
            ("https://push.example.net\\p", EndpointError::NotCanonical),
            (
                "https://xn--bcher-kva.example/p\u{e9}",
                EndpointError::NotCanonical,
            ),
        ];
        for (i, (endpoint, want)) in cases.iter().enumerate() {
            assert_eq!(
                parse_endpoint(endpoint).map(|_| ()),
                Err(*want),
                "endpoint #{i}"
            );
        }
    }

    #[test]
    fn check_literal_judges_only_literals() -> TestResult {
        let resolver = CheckedResolver::new(OwnAddresses::new([]), Nat64Prefixes::new([]));
        assert_eq!(
            resolver.check_literal(&parse_endpoint("https://127.0.0.1/p")?),
            Err(EndpointError::Refused(AddressRefusal::NotGloballyReachable))
        );
        assert_eq!(
            resolver.check_literal(&parse_endpoint("https://[::1]/p")?),
            Err(EndpointError::Refused(AddressRefusal::NotGloballyReachable))
        );
        resolver.check_literal(&parse_endpoint("https://8.8.8.8/p")?)?;
        resolver.check_literal(&parse_endpoint("https://push.example.net/p")?)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_name_with_any_refused_address_is_refused() -> TestResult {
        let table = HashMap::from([
            (
                "public.example".to_owned(),
                vec![ip("8.8.8.8")?, ip("2001:4860:4860::8888")?],
            ),
            (
                "mixed.example".to_owned(),
                vec![ip("8.8.8.8")?, ip("10.0.0.1")?],
            ),
            ("loop.example".to_owned(), vec![ip("::1")?]),
            ("empty.example".to_owned(), vec![]),
        ]);
        let resolver = CheckedResolver::for_tests(OwnAddresses::new([]), table, false);
        assert_eq!(resolver.resolve_checked("public.example").await?.len(), 2);
        assert_eq!(
            resolver.resolve_checked("mixed.example").await,
            Err(EndpointError::Refused(AddressRefusal::NotGloballyReachable))
        );
        assert_eq!(
            resolver.resolve_checked("loop.example").await,
            Err(EndpointError::Refused(AddressRefusal::NotGloballyReachable))
        );
        // A name the table lacks fails as NXDOMAIN does through the system
        // resolver; a name with no address resolves to none.
        assert_eq!(
            resolver.resolve_checked("absent.example").await,
            Err(EndpointError::Resolve(std::io::ErrorKind::NotFound))
        );
        assert_eq!(
            resolver.resolve_checked("empty.example").await,
            Err(EndpointError::DoesNotResolve)
        );
        resolver
            .check_registration_endpoint("https://public.example/p")
            .await?;
        assert_eq!(
            resolver
                .check_registration_endpoint("https://mixed.example/p")
                .await,
            Err(EndpointError::Refused(AddressRefusal::NotGloballyReachable))
        );
        assert_eq!(
            resolver
                .check_registration_endpoint("https://10.0.0.1/p")
                .await,
            Err(EndpointError::Refused(AddressRefusal::NotGloballyReachable))
        );
        Ok(())
    }

    /// With every lookup permit taken, a lookup fails fast as a full pool,
    /// never as a timeout or a failure of the endpoint, and starts no lookup;
    /// a freed permit signals the waiter with the number of permits free.
    #[tokio::test]
    async fn a_full_lookup_pool_refuses_without_starting_a_lookup() -> TestResult {
        let table = HashMap::from([("public.example".to_owned(), vec![ip("8.8.8.8")?])]);
        let resolver = CheckedResolver::for_tests(OwnAddresses::new([]), table, false);
        let mut held = resolver.exhaust_permits()?;
        assert_eq!(
            resolver.resolve_checked("public.example").await,
            Err(EndpointError::LookupPoolFull)
        );
        assert_eq!(
            resolver
                .check_registration_endpoint("https://public.example/p")
                .await,
            Err(EndpointError::LookupPoolFull)
        );
        // A clone shares the pool.
        assert_eq!(
            resolver.clone().resolve_checked("public.example").await,
            Err(EndpointError::LookupPoolFull)
        );
        assert_eq!(resolver.lookups_started(), 0);
        assert!(!EndpointError::LookupPoolFull.is_refusal());
        let freed = resolver.lookup_permit_freed();
        drop(held.pop());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), freed).await?,
            1
        );
        drop(held);
        assert_eq!(resolver.resolve_checked("public.example").await?.len(), 1);
        assert_eq!(resolver.lookups_started(), 1);
        Ok(())
    }

    /// Registration lookups hold at most their share of the pool, so the
    /// rest stays free for wakes.
    #[test]
    fn registration_lookups_hold_only_their_share() -> TestResult {
        let permits = LookupPermits::new();
        let held: Vec<LookupPermit> = (0..REGISTRATION_LOOKUP_PERMITS)
            .map(|_| permits.try_acquire(LookupPurpose::Registration))
            .collect::<Result<_, _>>()?;
        assert!(matches!(
            permits.try_acquire(LookupPurpose::Registration),
            Err(EndpointError::LookupPoolFull)
        ));
        let sends: Vec<LookupPermit> = (0..DNS_LOOKUP_PERMITS - REGISTRATION_LOOKUP_PERMITS)
            .map(|_| permits.try_acquire(LookupPurpose::Send))
            .collect::<Result<_, _>>()?;
        assert!(matches!(
            permits.try_acquire(LookupPurpose::Send),
            Err(EndpointError::LookupPoolFull)
        ));
        drop((held, sends));
        Ok(())
    }

    /// The system resolver also fails fast when the pool is full.
    #[tokio::test]
    async fn a_full_pool_refuses_a_system_lookup_at_once() -> TestResult {
        let resolver = CheckedResolver::new(OwnAddresses::new([]), Nat64Prefixes::new([]));
        let held = resolver.exhaust_permits()?;
        let started = std::time::Instant::now();
        assert_eq!(
            resolver.resolve_checked("localhost").await,
            Err(EndpointError::LookupPoolFull)
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(held);
        Ok(())
    }

    /// The production resolver refuses `localhost`, which every system
    /// resolver maps to loopback.
    #[tokio::test]
    async fn the_system_resolver_refuses_localhost() {
        let resolver = CheckedResolver::new(OwnAddresses::new([]), Nat64Prefixes::new([]));
        assert_eq!(
            resolver.resolve_checked("localhost").await,
            Err(EndpointError::Refused(AddressRefusal::NotGloballyReachable))
        );
    }

    #[test]
    fn errors_and_debug_carry_no_endpoint() -> TestResult {
        let parsed = parse_endpoint("https://push.example.net/p/secret")?;
        assert!(!format!("{parsed:?}").contains("push.example"));
        let own = OwnAddresses::new([ip("203.0.114.7")?]);
        assert!(!format!("{own:?}").contains("203.0"));
        let shown = EndpointError::Refused(AddressRefusal::OwnAddress).to_string();
        assert!(!shown.contains("203.0"), "the error names the address");
        Ok(())
    }
}
