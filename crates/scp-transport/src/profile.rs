//! Transport profiles for device-class-aware connection behavior.
//!
//! A transport profile bundles connection strategy, cover traffic tier,
//! relay count, reconnect behavior, and connection budget for a device class.
//! The SDK infers a profile from the platform and exposes it as a configurable
//! parameter on [`TransportConfig`](crate::TransportConfig).
//!
//! # Profiles
//!
//! | Profile | Min relays | Max connections | Cover traffic | Reconnect backoff |
//! |---------|-----------|----------------|---------------|-------------------|
//! | Server | 3 | unlimited | full | 1-30s |
//! | Desktop | 3 | 50 | full | 1-30s |
//! | Mobile | 2 | 10 | reduced | 5-60s |
//! | Constrained | 1 | 2 | off | none (poll-based) |
//!
//! # Platform Inference
//!
//! The SDK selects a default profile using a two-stage strategy:
//! compile-time target narrows the candidate set, then optional runtime
//! heuristics refine within that set. See [`TransportProfile::platform_default`].
//!
//! See spec section 10.13, 10.13.1, and ADR-036 in `.docs/adrs/phase-2.md`.

use std::time::Duration;

// ---------------------------------------------------------------------------
// CoverTrafficTier
// ---------------------------------------------------------------------------

/// Cover traffic tier controlling interval and padding size per spec §9.10.6
/// as amended by ADR-036.
///
/// The tier determines the interval between dummy messages and the padding
/// size for each dummy on a per-connection basis. Tiers are mapped from
/// transport profiles via [`CoverTrafficTier::from_profile`].
///
/// | Tier | Interval | Padding size | Use case |
/// |------|----------|-------------|----------|
/// | `Full` | 30s | 1024 bytes | Desktop/server — maximum metadata privacy |
/// | `Reduced` | 120s | 256 bytes | Mobile — battery-conscious |
/// | `Off` | — | — | Constrained devices, push-wake connections |
/// | `Custom` | user | user | Advanced configuration |
///
/// See spec section 9.10.6 and ADR-036.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoverTrafficTier {
    /// Maximum metadata privacy: 30-second interval, 1024-byte padding.
    /// Used by Server and Desktop profiles.
    Full,
    /// Battery-conscious: 120-second interval, 256-byte padding.
    /// Used by Mobile profile.
    Reduced,
    /// No cover traffic. Used by Constrained profile.
    Off,
    /// User-specified interval and padding size for advanced configuration.
    /// Allows fine-grained control when the predefined tiers don't fit.
    Custom {
        /// Interval between cover traffic dummy messages.
        interval: Duration,
        /// Target size for dummy message payloads in bytes.
        padding_bytes: usize,
    },
}

/// Default cover traffic interval for the Full tier per spec §9.10.6:
/// one padded message every 30 seconds per relay connection.
const FULL_TIER_INTERVAL: Duration = Duration::from_secs(30);

/// Default padding target size for the Full tier: 1024 bytes.
/// ~15MB/day for 5 relay connections (spec §9.10.6).
const FULL_TIER_PADDING: usize = 1024;

/// Cover traffic interval for the Reduced tier per spec §9.10.6:
/// one padded message every 120 seconds per relay connection.
const REDUCED_TIER_INTERVAL: Duration = Duration::from_secs(120);

/// Padding target size for the Reduced tier: 256 bytes.
/// ~1.8MB/day for 5 relay connections (spec §9.10.6).
const REDUCED_TIER_PADDING: usize = 256;

impl CoverTrafficTier {
    /// Returns the interval between cover traffic messages for this tier.
    ///
    /// Returns `None` for the `Off` tier (no cover traffic).
    #[must_use]
    pub const fn interval(&self) -> Option<Duration> {
        match self {
            Self::Full => Some(FULL_TIER_INTERVAL),
            Self::Reduced => Some(REDUCED_TIER_INTERVAL),
            Self::Off => None,
            Self::Custom { interval, .. } => Some(*interval),
        }
    }

    /// Returns the padding size in bytes for this tier.
    ///
    /// Returns `None` for the `Off` tier (no cover traffic).
    #[must_use]
    pub const fn padding_bytes(&self) -> Option<usize> {
        match self {
            Self::Full => Some(FULL_TIER_PADDING),
            Self::Reduced => Some(REDUCED_TIER_PADDING),
            Self::Off => None,
            Self::Custom { padding_bytes, .. } => Some(*padding_bytes),
        }
    }

    /// Returns `true` if cover traffic is enabled for this tier.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Returns `(interval, padding_bytes)` for this tier, or `None` for `Off`.
    ///
    /// This combines [`interval()`](Self::interval) and
    /// [`padding_bytes()`](Self::padding_bytes) into a single accessor,
    /// making the invariant that both are always paired structurally
    /// impossible to violate. Prefer this over calling the two accessors
    /// separately.
    #[must_use]
    pub const fn traffic_params(&self) -> Option<(Duration, usize)> {
        match self {
            Self::Full => Some((FULL_TIER_INTERVAL, FULL_TIER_PADDING)),
            Self::Reduced => Some((REDUCED_TIER_INTERVAL, REDUCED_TIER_PADDING)),
            Self::Off => None,
            Self::Custom {
                interval,
                padding_bytes,
            } => Some((*interval, *padding_bytes)),
        }
    }

    /// Maps a [`TransportProfile`] to its default cover traffic tier.
    ///
    /// - `Server` / `Desktop` -> `Full` (30s/1024B)
    /// - `Mobile` -> `Reduced` (120s/256B)
    /// - `Constrained` -> `Off`
    ///
    /// Per spec §9.10.6 as amended by ADR-036.
    #[must_use]
    pub const fn from_profile(profile: TransportProfile) -> Self {
        match profile {
            TransportProfile::Server | TransportProfile::Desktop => Self::Full,
            TransportProfile::Mobile => Self::Reduced,
            TransportProfile::Constrained => Self::Off,
        }
    }
}

// ---------------------------------------------------------------------------
// TransportProfile
// ---------------------------------------------------------------------------

/// Transport profile defining device-class-aware connection behavior.
///
/// Each variant bundles default values for minimum relay count, maximum
/// connection count, reconnect backoff range, and cover traffic tier.
/// The SDK infers a profile from the platform at initialization via
/// [`platform_default`](Self::platform_default), but applications can
/// override it explicitly via
/// [`TransportConfig`](crate::TransportConfig).
///
/// # Spec References
///
/// - Section 10.13: Transport Profiles
/// - Section 10.13.1: Profile Definitions
/// - ADR-036: Transport Profiles and Adaptive Resource Management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProfile {
    /// Persistent connections to all assigned relays. Full cover traffic.
    /// Aggressive reconnect (1-30s backoff). Unlimited connections.
    ///
    /// Intended for headless servers, cloud VMs, containers, and dedicated
    /// relay infrastructure.
    Server,

    /// Persistent connections to all assigned relays. Full cover traffic.
    /// Aggressive reconnect (1-30s backoff). Up to 50 connections.
    ///
    /// Intended for desktop operating systems (macOS, Windows, Linux with
    /// display server).
    Desktop,

    /// Active contexts only; push bridge for inactive. Reduced cover traffic.
    /// Conservative reconnect (5-60s backoff). Up to 10 connections.
    ///
    /// Intended for iOS and Android devices where battery life and radio
    /// power state matter.
    Mobile,

    /// On-demand only; poll via QUERY. No cover traffic. No reconnect
    /// (poll-based). Up to 2 connections.
    ///
    /// Intended for `IoT`, embedded, and other resource-constrained devices
    /// (Raspberry Pi Zero-class, <256 MB RAM, small architectures).
    Constrained,
}

impl TransportProfile {
    /// Returns the minimum number of relays for suppression resistance.
    ///
    /// - Server: 3
    /// - Desktop: 3
    /// - Mobile: 2 (reduced suppression detection, see §10.13.1)
    /// - Constrained: 1 (no suppression detection)
    #[must_use]
    pub const fn min_relays(&self) -> usize {
        match self {
            Self::Server | Self::Desktop => 3,
            Self::Mobile => 2,
            Self::Constrained => 1,
        }
    }

    /// Returns the minimum number of successful relay deliveries required
    /// for a send to succeed.
    ///
    /// Derived from [`min_relays`](Self::min_relays): a majority of the
    /// relay set must accept the envelope for the send to be considered
    /// sufficiently redundant. For single-relay profiles (`Constrained`),
    /// the minimum is 1 since no redundancy is available.
    ///
    /// - Server: 2 (majority of 3)
    /// - Desktop: 2 (majority of 3)
    /// - Mobile: 1 (at least 1 of 2; see §10.13.1 suppression trade-offs)
    /// - Constrained: 1 (single relay, no redundancy)
    #[must_use]
    pub const fn min_successful_sends(&self) -> usize {
        self.min_relays().div_ceil(2)
    }

    /// Returns the maximum total connection count across all adapters.
    ///
    /// - Server: `usize::MAX` (unlimited)
    /// - Desktop: 50
    /// - Mobile: 10
    /// - Constrained: 2
    ///
    /// These are soft limits; the SDK may temporarily exceed the budget
    /// during relay set reassignment or context join operations, then
    /// converge back within 30 seconds (§10.13.3).
    #[must_use]
    pub const fn max_connections(&self) -> usize {
        match self {
            Self::Server => usize::MAX,
            Self::Desktop => 50,
            Self::Mobile => 10,
            Self::Constrained => 2,
        }
    }

    /// Returns the reconnect backoff range as `(min_backoff, max_backoff)`.
    ///
    /// - Server: 1-30s (aggressive exponential backoff)
    /// - Desktop: 1-30s (aggressive exponential backoff)
    /// - Mobile: 5-60s (conservative exponential backoff)
    /// - Constrained: `None` (poll-based, no reconnect)
    ///
    /// When `Some`, the SDK uses exponential backoff starting at the
    /// minimum and capping at the maximum. When `None`, the profile uses
    /// poll-based operation (QUERY at application-defined intervals).
    #[must_use]
    pub const fn reconnect_backoff_range(&self) -> Option<(Duration, Duration)> {
        match self {
            Self::Server | Self::Desktop => Some((Duration::from_secs(1), Duration::from_secs(30))),
            Self::Mobile => Some((Duration::from_secs(5), Duration::from_secs(60))),
            Self::Constrained => None,
        }
    }

    /// Returns the cover traffic tier for this profile.
    ///
    /// - Server: `Full` (30s/1024B)
    /// - Desktop: `Full` (30s/1024B)
    /// - Mobile: `Reduced` (120s/256B)
    /// - Constrained: `Off`
    ///
    /// See spec section 9.10.6 as amended by ADR-036.
    #[must_use]
    pub const fn cover_traffic_tier(&self) -> CoverTrafficTier {
        CoverTrafficTier::from_profile(*self)
    }

    /// Returns the transport profile for the current platform.
    ///
    /// Checks the `SCP_TRANSPORT_PROFILE` environment variable first. If set,
    /// the value must be one of `server`, `desktop`, `mobile`, `constrained`
    /// (case-insensitive). This allows operators to override profile inference
    /// in containers or other environments where automatic detection is
    /// unreliable.
    ///
    /// Falls back to compile-time platform inference with runtime refinement:
    ///
    /// 1. **Compile-time:** `#[cfg(target_os)]` narrows the candidate set.
    ///    - iOS / Android -> `Mobile`
    ///    - macOS / Windows -> `Desktop`
    ///    - `wasm32` -> `Desktop` (browser tabs behave like desktop)
    ///    - Linux -> runtime refinement (stage 2)
    ///
    /// 2. **Runtime refinement (Linux only):**
    ///    - Headless (no `$DISPLAY`, no `$WAYLAND_DISPLAY`) AND >2 GB RAM -> `Server`
    ///    - <256 MB RAM OR small architecture (arm, riscv32, mips) -> `Constrained`
    ///    - Fallback -> `Desktop`
    // Cannot be const: reads env vars and (on Linux) /proc/meminfo.
    #[must_use]
    pub fn platform_default() -> Self {
        // Environment variable override for containers/CI/explicit configuration.
        if let Ok(val) = std::env::var("SCP_TRANSPORT_PROFILE") {
            if let Some(profile) = parse_profile_env_value(&val) {
                return profile;
            }
            tracing::warn!(
                value = %val,
                "unrecognized SCP_TRANSPORT_PROFILE value, falling back to platform inference"
            );
        }

        platform_default_impl()
    }
}

// ---------------------------------------------------------------------------
// Environment variable parsing
// ---------------------------------------------------------------------------

/// Parses a `SCP_TRANSPORT_PROFILE` environment variable value into a
/// [`TransportProfile`].
///
/// Case-insensitive. Returns `None` for unrecognized values.
fn parse_profile_env_value(val: &str) -> Option<TransportProfile> {
    match val.to_ascii_lowercase().as_str() {
        "server" => Some(TransportProfile::Server),
        "desktop" => Some(TransportProfile::Desktop),
        "mobile" => Some(TransportProfile::Mobile),
        "constrained" => Some(TransportProfile::Constrained),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Platform inference — compile-time dispatch
// ---------------------------------------------------------------------------

/// iOS -> Mobile
#[cfg(target_os = "ios")]
const fn platform_default_impl() -> TransportProfile {
    TransportProfile::Mobile
}

/// Android -> Mobile
#[cfg(target_os = "android")]
const fn platform_default_impl() -> TransportProfile {
    TransportProfile::Mobile
}

/// macOS -> Desktop
#[cfg(target_os = "macos")]
const fn platform_default_impl() -> TransportProfile {
    TransportProfile::Desktop
}

/// Windows -> Desktop
#[cfg(target_os = "windows")]
const fn platform_default_impl() -> TransportProfile {
    TransportProfile::Desktop
}

/// wasm32 -> Desktop (browser tabs behave like desktop)
#[cfg(target_arch = "wasm32")]
const fn platform_default_impl() -> TransportProfile {
    TransportProfile::Desktop
}

/// Linux -> runtime refinement
#[cfg(all(target_os = "linux", not(target_arch = "wasm32")))]
fn platform_default_impl() -> TransportProfile {
    linux_runtime_refinement()
}

/// Fallback for any other target OS not covered above.
#[cfg(not(any(
    target_os = "ios",
    target_os = "android",
    target_os = "macos",
    target_os = "windows",
    target_os = "linux",
    target_arch = "wasm32",
)))]
const fn platform_default_impl() -> TransportProfile {
    TransportProfile::Desktop
}

// ---------------------------------------------------------------------------
// Linux runtime refinement
// ---------------------------------------------------------------------------

/// Runtime heuristics for Linux platform inference per §10.13.1.
///
/// 1. Small architecture (arm 32-bit, riscv32, mips) -> Constrained (always).
/// 2. If `/proc/meminfo` available:
///    a. Headless AND >2 GB RAM -> Server
///    b. <256 MB RAM -> Constrained
/// 3. If `/proc/meminfo` unavailable (containers, exotic setups) -> Desktop
///    (skip memory heuristics entirely rather than defaulting to Constrained).
/// 4. Fallback -> Desktop
#[cfg(target_os = "linux")]
fn linux_runtime_refinement() -> TransportProfile {
    const TWO_GB: u64 = 2 * 1024 * 1024 * 1024;
    const TWO_HUNDRED_FIFTY_SIX_MB: u64 = 256 * 1024 * 1024;

    let is_small_arch = is_small_architecture();

    // Small arch is always Constrained regardless of memory.
    if is_small_arch {
        return TransportProfile::Constrained;
    }

    let is_headless = is_headless_linux();
    let total_memory = total_system_memory_bytes();

    // If memory info is available, use it for server/constrained detection.
    // If unavailable (e.g. containers without /proc/meminfo), skip memory
    // heuristics and fall through to Desktop instead of wrongly selecting
    // Constrained.
    if let Some(total_memory_bytes) = total_memory {
        if is_headless && total_memory_bytes > TWO_GB {
            return TransportProfile::Server;
        }
        if total_memory_bytes < TWO_HUNDRED_FIFTY_SIX_MB {
            return TransportProfile::Constrained;
        }
    }

    // Fallback
    TransportProfile::Desktop
}

/// Returns `true` if neither `$DISPLAY` nor `$WAYLAND_DISPLAY` is set,
/// indicating a headless Linux environment.
#[cfg(target_os = "linux")]
fn is_headless_linux() -> bool {
    std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err()
}

/// Returns total system memory in bytes by reading `/proc/meminfo`.
///
/// Returns `None` if `/proc/meminfo` is unavailable or unparseable (e.g.
/// in containers without procfs). Callers should skip memory-based
/// heuristics when `None` rather than defaulting to Constrained.
#[cfg(target_os = "linux")]
fn total_system_memory_bytes() -> Option<u64> {
    // Read /proc/meminfo and parse MemTotal line
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;

    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // Format: "MemTotal:       16384000 kB"
            let trimmed = rest.trim();
            // Extract the numeric part (value in kB)
            if let Some(Ok(kb)) = trimmed.split_whitespace().next().map(str::parse::<u64>) {
                return Some(kb * 1024); // Convert kB to bytes
            }
        }
    }

    None
}

/// Returns `true` if the current target architecture is considered "small"
/// per §10.13.1: arm (32-bit), riscv32, or mips.
#[cfg(target_os = "linux")]
const fn is_small_architecture() -> bool {
    // 32-bit ARM (not aarch64)
    cfg!(target_arch = "arm") || cfg!(target_arch = "riscv32") || cfg!(target_arch = "mips")
}

// ---------------------------------------------------------------------------
// Display impl
// ---------------------------------------------------------------------------

impl std::fmt::Display for TransportProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server => write!(f, "server"),
            Self::Desktop => write!(f, "desktop"),
            Self::Mobile => write!(f, "mobile"),
            Self::Constrained => write!(f, "constrained"),
        }
    }
}

impl std::fmt::Display for CoverTrafficTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Reduced => write!(f, "reduced"),
            Self::Off => write!(f, "off"),
            Self::Custom {
                interval,
                padding_bytes,
            } => {
                write!(f, "custom({}s/{}B)", interval.as_secs(), padding_bytes)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- Profile default values per §10.13.1 --

    #[test]
    fn server_min_relays() {
        assert_eq!(TransportProfile::Server.min_relays(), 3);
    }

    #[test]
    fn desktop_min_relays() {
        assert_eq!(TransportProfile::Desktop.min_relays(), 3);
    }

    #[test]
    fn mobile_min_relays() {
        assert_eq!(TransportProfile::Mobile.min_relays(), 2);
    }

    #[test]
    fn constrained_min_relays() {
        assert_eq!(TransportProfile::Constrained.min_relays(), 1);
    }

    #[test]
    fn server_min_successful_sends() {
        assert_eq!(TransportProfile::Server.min_successful_sends(), 2);
    }

    #[test]
    fn desktop_min_successful_sends() {
        assert_eq!(TransportProfile::Desktop.min_successful_sends(), 2);
    }

    #[test]
    fn mobile_min_successful_sends() {
        assert_eq!(TransportProfile::Mobile.min_successful_sends(), 1);
    }

    #[test]
    fn constrained_min_successful_sends() {
        assert_eq!(TransportProfile::Constrained.min_successful_sends(), 1);
    }

    #[test]
    fn server_max_connections() {
        assert_eq!(TransportProfile::Server.max_connections(), usize::MAX);
    }

    #[test]
    fn desktop_max_connections() {
        assert_eq!(TransportProfile::Desktop.max_connections(), 50);
    }

    #[test]
    fn mobile_max_connections() {
        assert_eq!(TransportProfile::Mobile.max_connections(), 10);
    }

    #[test]
    fn constrained_max_connections() {
        assert_eq!(TransportProfile::Constrained.max_connections(), 2);
    }

    #[test]
    fn server_reconnect_backoff() {
        let range = TransportProfile::Server.reconnect_backoff_range();
        assert_eq!(
            range,
            Some((Duration::from_secs(1), Duration::from_secs(30)))
        );
    }

    #[test]
    fn desktop_reconnect_backoff() {
        let range = TransportProfile::Desktop.reconnect_backoff_range();
        assert_eq!(
            range,
            Some((Duration::from_secs(1), Duration::from_secs(30)))
        );
    }

    #[test]
    fn mobile_reconnect_backoff() {
        let range = TransportProfile::Mobile.reconnect_backoff_range();
        assert_eq!(
            range,
            Some((Duration::from_secs(5), Duration::from_secs(60)))
        );
    }

    #[test]
    fn constrained_reconnect_backoff() {
        assert_eq!(
            TransportProfile::Constrained.reconnect_backoff_range(),
            None
        );
    }

    #[test]
    fn server_cover_traffic_tier() {
        assert_eq!(
            TransportProfile::Server.cover_traffic_tier(),
            CoverTrafficTier::Full
        );
    }

    #[test]
    fn desktop_cover_traffic_tier() {
        assert_eq!(
            TransportProfile::Desktop.cover_traffic_tier(),
            CoverTrafficTier::Full
        );
    }

    #[test]
    fn mobile_cover_traffic_tier() {
        assert_eq!(
            TransportProfile::Mobile.cover_traffic_tier(),
            CoverTrafficTier::Reduced
        );
    }

    #[test]
    fn constrained_cover_traffic_tier() {
        assert_eq!(
            TransportProfile::Constrained.cover_traffic_tier(),
            CoverTrafficTier::Off
        );
    }

    // -- CoverTrafficTier::from_profile --

    #[test]
    fn from_profile_server_returns_full() {
        assert_eq!(
            CoverTrafficTier::from_profile(TransportProfile::Server),
            CoverTrafficTier::Full
        );
    }

    #[test]
    fn from_profile_desktop_returns_full() {
        assert_eq!(
            CoverTrafficTier::from_profile(TransportProfile::Desktop),
            CoverTrafficTier::Full
        );
    }

    #[test]
    fn from_profile_mobile_returns_reduced() {
        assert_eq!(
            CoverTrafficTier::from_profile(TransportProfile::Mobile),
            CoverTrafficTier::Reduced
        );
    }

    #[test]
    fn from_profile_constrained_returns_off() {
        assert_eq!(
            CoverTrafficTier::from_profile(TransportProfile::Constrained),
            CoverTrafficTier::Off
        );
    }

    // -- CoverTrafficTier accessors --

    #[test]
    fn full_tier_interval() {
        assert_eq!(
            CoverTrafficTier::Full.interval(),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn full_tier_padding() {
        assert_eq!(CoverTrafficTier::Full.padding_bytes(), Some(1024));
    }

    #[test]
    fn reduced_tier_interval() {
        assert_eq!(
            CoverTrafficTier::Reduced.interval(),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn reduced_tier_padding() {
        assert_eq!(CoverTrafficTier::Reduced.padding_bytes(), Some(256));
    }

    #[test]
    fn off_tier_interval() {
        assert_eq!(CoverTrafficTier::Off.interval(), None);
    }

    #[test]
    fn off_tier_padding() {
        assert_eq!(CoverTrafficTier::Off.padding_bytes(), None);
    }

    #[test]
    fn custom_tier_interval() {
        let tier = CoverTrafficTier::Custom {
            interval: Duration::from_secs(45),
            padding_bytes: 512,
        };
        assert_eq!(tier.interval(), Some(Duration::from_secs(45)));
    }

    #[test]
    fn custom_tier_padding() {
        let tier = CoverTrafficTier::Custom {
            interval: Duration::from_secs(45),
            padding_bytes: 512,
        };
        assert_eq!(tier.padding_bytes(), Some(512));
    }

    #[test]
    fn full_tier_is_enabled() {
        assert!(CoverTrafficTier::Full.is_enabled());
    }

    #[test]
    fn reduced_tier_is_enabled() {
        assert!(CoverTrafficTier::Reduced.is_enabled());
    }

    #[test]
    fn off_tier_is_not_enabled() {
        assert!(!CoverTrafficTier::Off.is_enabled());
    }

    #[test]
    fn custom_tier_is_enabled() {
        let tier = CoverTrafficTier::Custom {
            interval: Duration::from_secs(60),
            padding_bytes: 128,
        };
        assert!(tier.is_enabled());
    }

    // -- Platform default --

    #[test]
    fn platform_default_is_desktop_on_macos() {
        // This test validates the compile-time cfg path. On macOS, the
        // platform default must be Desktop per §10.13.1.
        #[cfg(target_os = "macos")]
        assert_eq!(
            TransportProfile::platform_default(),
            TransportProfile::Desktop
        );
    }

    #[test]
    fn platform_default_returns_a_valid_profile() {
        // On any platform, platform_default must return a valid variant.
        let profile = TransportProfile::platform_default();
        // Verify it's one of the four variants by checking min_relays is
        // in the expected range.
        assert!(profile.min_relays() >= 1);
        assert!(profile.min_relays() <= 3);
    }

    // -- Display --

    #[test]
    fn profile_display() {
        assert_eq!(TransportProfile::Server.to_string(), "server");
        assert_eq!(TransportProfile::Desktop.to_string(), "desktop");
        assert_eq!(TransportProfile::Mobile.to_string(), "mobile");
        assert_eq!(TransportProfile::Constrained.to_string(), "constrained");
    }

    #[test]
    fn cover_traffic_tier_display() {
        assert_eq!(CoverTrafficTier::Full.to_string(), "full");
        assert_eq!(CoverTrafficTier::Reduced.to_string(), "reduced");
        assert_eq!(CoverTrafficTier::Off.to_string(), "off");
        let custom = CoverTrafficTier::Custom {
            interval: Duration::from_secs(45),
            padding_bytes: 512,
        };
        assert_eq!(custom.to_string(), "custom(45s/512B)");
    }

    // -- Enum properties --

    #[test]
    fn profile_clone_and_eq() {
        let a = TransportProfile::Server;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn cover_traffic_tier_clone_and_eq() {
        let a = CoverTrafficTier::Full;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn profile_debug_impl() {
        // Verify Debug is implemented (compilation test + basic check).
        let debug = format!("{:?}", TransportProfile::Mobile);
        assert!(debug.contains("Mobile"));
    }

    // -- Environment variable override parsing --
    //
    // The actual env-var reading in `platform_default()` cannot be tested
    // directly because `set_var`/`remove_var` are unsafe under
    // `#![forbid(unsafe_code)]`. Instead, we test the extracted parsing
    // function `parse_profile_env_value()` which exercises the same logic.

    #[test]
    fn profile_env_parse_server() {
        assert_eq!(
            super::parse_profile_env_value("server"),
            Some(TransportProfile::Server)
        );
    }

    #[test]
    fn profile_env_parse_desktop_case_insensitive() {
        assert_eq!(
            super::parse_profile_env_value("Desktop"),
            Some(TransportProfile::Desktop)
        );
    }

    #[test]
    fn profile_env_parse_mobile_uppercase() {
        assert_eq!(
            super::parse_profile_env_value("MOBILE"),
            Some(TransportProfile::Mobile)
        );
    }

    #[test]
    fn profile_env_parse_constrained_mixed_case() {
        assert_eq!(
            super::parse_profile_env_value("Constrained"),
            Some(TransportProfile::Constrained)
        );
    }

    #[test]
    fn profile_env_parse_invalid_returns_none() {
        assert_eq!(super::parse_profile_env_value("invalid-value"), None);
    }

    #[test]
    fn profile_env_parse_empty_returns_none() {
        assert_eq!(super::parse_profile_env_value(""), None);
    }

    // -- TransportConfig integration is tested in config.rs --
}
