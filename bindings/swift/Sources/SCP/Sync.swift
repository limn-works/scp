import Foundation

// MARK: - SyncBridge

/// Namespace for UniFFI bridge function references used by sync/offline
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See ADR-029 in `.docs/adrs/phase-6.md`.
internal enum SyncBridge {
    /// Classify offline duration into a tier.
    internal typealias ClassifyOfflineFn = @Sendable (
        _ lastRelayContact: UInt64,
        _ now: UInt64
    ) -> String

    /// Classify offline duration with custom thresholds.
    internal typealias ClassifyOfflineCustomFn = @Sendable (
        _ lastRelayContact: UInt64,
        _ now: UInt64,
        _ tier1ThresholdSecs: UInt64,
        _ tier2ThresholdSecs: UInt64
    ) -> String

    /// Default classify offline function — delegates to UniFFI
    /// ``syncClassifyOffline``.
    internal static let defaultClassifyOffline: ClassifyOfflineFn = {
        lastRelayContact, now in
        syncClassifyOffline(lastRelayContact: lastRelayContact, now: now)
    }

    /// Default classify offline custom function — delegates to UniFFI
    /// ``syncClassifyOfflineCustom``.
    internal static let defaultClassifyOfflineCustom: ClassifyOfflineCustomFn = {
        lastRelayContact, now, tier1ThresholdSecs, tier2ThresholdSecs in
        syncClassifyOfflineCustom(
            lastRelayContact: lastRelayContact,
            now: now,
            tier1ThresholdSecs: tier1ThresholdSecs,
            tier2ThresholdSecs: tier2ThresholdSecs
        )
    }
}

// MARK: - Public API

/// Classifies an offline duration into the appropriate recovery tier.
///
/// The three tiers are:
/// - `"short"` — up to 4 hours. Normal catch-up.
/// - `"extended"` — 4 hours to 7 days. Epoch catch-up required.
/// - `"long"` — over 7 days. Full re-sync required.
///
/// - Parameters:
///   - lastRelayContact: Unix timestamp (seconds) of last relay contact.
///   - now: Current Unix timestamp (seconds).
///   - classifyOfflineFn: Bridge function override for testing.
/// - Returns: The offline tier: "short", "extended", or "long".
///
/// ## Provenance
///
/// - ADR-029 in `.docs/adrs/phase-6.md`
public func classifyOffline(
    lastRelayContact: UInt64,
    now: UInt64,
    classifyOfflineFn: SyncBridge.ClassifyOfflineFn = SyncBridge.defaultClassifyOffline
) -> String {
    classifyOfflineFn(lastRelayContact, now)
}

/// Classifies an offline duration using custom policy thresholds.
///
/// - Parameters:
///   - lastRelayContact: Unix timestamp (seconds) of last relay contact.
///   - now: Current Unix timestamp (seconds).
///   - tier1ThresholdSecs: Short offline upper bound in seconds.
///   - tier2ThresholdSecs: Extended offline upper bound in seconds.
///   - classifyOfflineCustomFn: Bridge function override for testing.
/// - Returns: The offline tier: "short", "extended", or "long".
///
/// ## Provenance
///
/// - ADR-029 in `.docs/adrs/phase-6.md`
public func classifyOfflineCustom(
    lastRelayContact: UInt64,
    now: UInt64,
    tier1ThresholdSecs: UInt64,
    tier2ThresholdSecs: UInt64,
    classifyOfflineCustomFn: SyncBridge.ClassifyOfflineCustomFn = SyncBridge.defaultClassifyOfflineCustom
) -> String {
    classifyOfflineCustomFn(lastRelayContact, now, tier1ThresholdSecs, tier2ThresholdSecs)
}
