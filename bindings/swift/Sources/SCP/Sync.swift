import Foundation

// MARK: - SyncBridge

/// Namespace for UniFFI bridge function references used by sync/offline
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See ADR-029 in `.docs/adrs/phase-6.md`.
public enum SyncBridge {
    /// Classify offline duration into a tier.
    public typealias ClassifyOfflineFn = @Sendable (
        _ lastRelayContact: UInt64,
        _ now: UInt64
    ) -> String

    /// Classify offline duration with custom thresholds.
    public typealias ClassifyOfflineCustomFn = @Sendable (
        _ lastRelayContact: UInt64,
        _ now: UInt64,
        _ tier1ThresholdSecs: UInt64,
        _ tier2ThresholdSecs: UInt64
    ) -> String

    /// Default classify offline function — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/syncClassifyOffline`` method.
    ///
    /// Non-throwing: falls back to `"long"` (the conservative tier) if the
    /// default instance is currently suspended or shut down.
    public static let defaultClassifyOffline: ClassifyOfflineFn = { lastRelayContact, now in
        guard let scp = try? Scp.defaultInstance() else { return "long" }
        return scp.syncClassifyOffline(lastRelayContact: lastRelayContact, now: now)
    }

    /// Default classify offline custom function — delegates to the
    /// process-wide default ``Scp`` instance's ``Scp/syncClassifyOfflineCustom``
    /// method.
    ///
    /// Non-throwing: falls back to `"long"` (the conservative tier) if the
    /// default instance is currently suspended or shut down.
    public static let defaultClassifyOfflineCustom: ClassifyOfflineCustomFn = { lastRelayContact, now, tier1ThresholdSecs, tier2ThresholdSecs in
        guard let scp = try? Scp.defaultInstance() else { return "long" }
        return scp.syncClassifyOfflineCustom(
            lastRelayContact: lastRelayContact,
            now: now,
            tier1ThresholdSecs: tier1ThresholdSecs,
            tier2ThresholdSecs: tier2ThresholdSecs
        )
    }

    /// Get the sync policy. Maps to UniFFI ``Scp/syncGetPolicy()``.
    public typealias GetPolicyFn = @Sendable () -> SyncPolicyResult

    /// Default get sync policy function — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/syncGetPolicy()`` method.
    ///
    /// Non-throwing: falls back to a `SyncPolicyResult` built from
    /// `scp_core::sync::SyncPolicy::default()` constants if the default
    /// instance is currently suspended or shut down. The Rust default is
    /// fixed at compile time, so the fallback matches the live policy
    /// exactly — callers see no behavioral difference.
    public static let defaultGetPolicy: GetPolicyFn = {
        if let scp = try? Scp.defaultInstance() {
            return scp.syncGetPolicy()
        }
        // Mirror `scp_core::sync::SyncPolicy::default()` — the Rust side
        // does not expose a `SyncPolicyResult::default()` via UniFFI, so
        // the constants are re-asserted here. If Rust defaults ever
        // change, this fallback must be updated in lockstep (the PR 4
        // enforcement check will catch drift).
        SyncPolicyResult(
            tier1ThresholdSecs: 14400,
            tier2ThresholdSecs: 604_800,
            gapTimeoutSecs: 30,
            reorderBufferCapacity: 100,
            maxSequentialCommits: 10,
            commitProcessTimeoutSecs: 5,
            senderKeyTimeoutSecs: 10,
            reconnectionDedupWindowSecs: 60
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func classifyOfflineCustom(
    lastRelayContact: UInt64,
    now: UInt64,
    tier1ThresholdSecs: UInt64,
    tier2ThresholdSecs: UInt64,
    classifyOfflineCustomFn: SyncBridge.ClassifyOfflineCustomFn = SyncBridge.defaultClassifyOfflineCustom
) -> String {
    classifyOfflineCustomFn(lastRelayContact, now, tier1ThresholdSecs, tier2ThresholdSecs)
}

/// Retrieves the default sync policy parameters.
///
/// The sync policy determines how offline recovery and state reconciliation
/// operate. Returns a ``SyncPolicyResult`` with all default thresholds and
/// timeouts.
///
/// - Parameter getPolicyFn: Bridge function override for testing.
/// - Returns: A ``SyncPolicyResult`` with the default sync policy values.
///
/// ## Provenance
///
/// - ADR-029 in `.docs/adrs/phase-6.md`
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func getSyncPolicy(
    getPolicyFn: SyncBridge.GetPolicyFn = SyncBridge.defaultGetPolicy
) -> SyncPolicyResult {
    getPolicyFn()
}
