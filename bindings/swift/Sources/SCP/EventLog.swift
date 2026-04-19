import Foundation

// Event, Proof, and Checkpoint are defined by UniFFI in ScpBindings.swift.
//
// UniFFI Event fields: eventType, actorDid, timestamp, payloadJson (String), sequence
// UniFFI Proof fields: verified (Bool), proofType (String), detailsJson (String)
// UniFFI Checkpoint fields: contextId, senderDid, eventCount, merkleRoot (hex),
//   epoch (optional), timestamp, signature (hex)
//
// EventLog is a pure Swift type. EventLogHandle is replaced by ContextHandle
// from UniFFI for bridge calls.

// Checkpoint is defined by UniFFI in ScpBindings.swift as a public struct with
// fields: contextId (String), senderDid (String), eventCount (UInt64),
// merkleRoot (String, hex-encoded), epoch (UInt64?), timestamp (UInt64),
// signature (String, hex-encoded).
//
// See ADR-011 acceptance criterion 8 in `.docs/adrs/phase-2.md`.

// MARK: - EventLogHandle

/// Internal opaque handle wrapping event log state.
///
/// Holds either a real ``ContextHandle`` for UniFFI bridge calls or a
/// standalone context ID for testing. When the XCFramework is available,
/// all event log operations delegate through the ``ContextHandle``.
final class EventLogHandle: Sendable {
    /// The context ID this event log belongs to.
    let contextId: String

    /// The UniFFI context handle, if available.
    let contextHandle: ContextHandle?

    /// Creates an ``EventLogHandle`` for the given context.
    init(contextId: String) {
        self.contextId = contextId
        contextHandle = nil
    }

    /// Creates an ``EventLogHandle`` backed by a UniFFI context handle.
    ///
    /// - Parameters:
    ///   - contextHandle: The UniFFI context handle.
    ///   - contextId: Optional override for the context ID. When `nil`,
    ///     the ID is read from the handle. Pass explicitly in tests where
    ///     the handle has no backing FFI pointer.
    init(contextHandle: ContextHandle, contextId: String? = nil) {
        self.contextId = contextId ?? contextHandle.contextId()
        self.contextHandle = contextHandle
    }
}

// MARK: - EventLogBridge

/// Namespace for UniFFI bridge function references used by event log operations.
/// Each typealias maps 1:1 to a UniFFI-generated async function. Closures are
/// injected for testability; defaults call through to ScpBindings.
///
/// See ADR-026 for the flat delegation pattern and ADR-011 for event log spec.
public enum EventLogBridge {
    /// Query events from a context's event log. Maps to ``eventLogQuery``.
    public typealias QueryFn = @Sendable (
        _ handle: ContextHandle,
        _ filterJson: String?
    ) async throws -> [Event]

    /// Verify an event log claim. Maps to ``eventLogVerify``.
    public typealias VerifyFn = @Sendable (
        _ handle: ContextHandle,
        _ claimJson: String
    ) async throws -> Proof

    /// Default query function — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/eventLogQuery(handle:filterJson:)`` method.
    public static let defaultQuery: QueryFn = { handle, filterJson in
        try await Scp.defaultInstance().eventLogQuery(handle: handle, filterJson: filterJson)
    }

    /// Default verify function — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/eventLogVerify(handle:claimJson:)`` method.
    public static let defaultVerify: VerifyFn = { handle, claimJson in
        try await Scp.defaultInstance().eventLogVerify(handle: handle, claimJson: claimJson)
    }

    /// Generate a signed consistency checkpoint. Maps to ``eventLogCheckpoint``.
    public typealias CheckpointFn = @Sendable (
        _ handle: ContextHandle,
        _ identity: Identity,
        _ epoch: UInt64
    ) async throws -> Checkpoint

    /// Default checkpoint function — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/eventLogCheckpoint(handle:identity:epoch:)``
    /// method.
    public static let defaultCheckpoint: CheckpointFn = { handle, identity, epoch in
        try await Scp.defaultInstance().eventLogCheckpoint(handle: handle, identity: identity, epoch: epoch)
    }
}

// MARK: - EventLog

/// A verifiable, append-only Merkle event log for an SCP context.
///
/// Delegates to UniFFI ``eventLogQuery`` and ``eventLogVerify`` bridge
/// functions when backed by a real ``ContextHandle``.
///
/// See ADR-011 (Event Log) in `.docs/adrs/phase-2.md`.
///
/// ## Provenance
///
/// - ADR-011 (Event Log) in `.docs/adrs/phase-2.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - Story SCP-221
public nonisolated struct EventLog: Sendable {
    /// The context ID this event log belongs to.
    public let contextId: String

    /// The internal handle wrapping the native UniFFI event log object.
    private let handle: EventLogHandle

    /// Bridge function for querying events (injectable for testing).
    private let queryFn: EventLogBridge.QueryFn

    /// Bridge function for verifying proofs (injectable for testing).
    private let verifyFn: EventLogBridge.VerifyFn

    /// Creates an ``EventLog`` from an internal ``EventLogHandle``.
    init(
        handle: EventLogHandle,
        queryFn: @escaping EventLogBridge.QueryFn = EventLogBridge.defaultQuery,
        verifyFn: @escaping EventLogBridge.VerifyFn = EventLogBridge.defaultVerify
    ) {
        contextId = handle.contextId
        self.handle = handle
        self.queryFn = queryFn
        self.verifyFn = verifyFn
    }

    /// Retrieves events from the log with optional filter criteria.
    ///
    /// - Parameters:
    ///   - fromSequence: Start sequence number for the query range.
    ///   - limit: Maximum number of events to return.
    /// - Returns: An array of ``Event`` records matching the criteria.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the query fails.
    public func query(fromSequence: UInt64, limit: UInt64) async throws -> [Event] {
        guard let contextHandle = handle.contextHandle else {
            throw ScpError.Context(
                msg: "EventLog not backed by a UniFFI ContextHandle",
                code: "SCP-CTX-2030"
            )
        }
        let filterJson = #"{"after_sequence": \#(fromSequence), "limit": \#(limit)}"#
        return try await queryFn(contextHandle, filterJson)
    }

    /// Generates a Merkle inclusion proof for the event at the given index.
    ///
    /// - Parameter leafIndex: The index of the event to prove inclusion for.
    /// - Returns: A ``Proof`` with the Merkle path and verification status.
    /// - Throws: ``ScpError/Context(msg:code:)`` if proof generation fails.
    public func proveInclusion(leafIndex: UInt64) async throws -> Proof {
        guard let contextHandle = handle.contextHandle else {
            throw ScpError.Context(
                msg: "EventLog not backed by a UniFFI ContextHandle",
                code: "SCP-CTX-2031"
            )
        }
        let claimJson = #"{"type": "inclusion", "leaf_index": \#(leafIndex)}"#
        return try await verifyFn(contextHandle, claimJson)
    }

    /// Verifies a Merkle inclusion proof.
    ///
    /// - Parameter proof: The proof to verify.
    /// - Returns: `true` if the proof is valid.
    public static func verifyInclusion(_ proof: Proof) -> Bool {
        proof.verified
    }
}

// MARK: - Event Log Checkpoint (free function)

/// Generates a signed consistency checkpoint for equivocation detection.
///
/// Members periodically exchange signed Merkle roots. If two members have
/// different roots for the same event count, the relay is equivocating
/// (showing different histories to different members).
///
/// Delegates to the UniFFI ``eventLogCheckpoint`` bridge function.
///
/// - Parameters:
///   - handle: The ``ContextHandle`` for the context whose event log to
///     checkpoint.
///   - identity: The ``Identity`` generating the checkpoint (used for signing).
///   - epoch: The current MLS epoch (pass 0 for broadcast contexts).
///   - checkpointFn: Bridge function override for testing.
/// - Returns: A ``Checkpoint`` containing the signed checkpoint data.
/// - Throws: ``ScpError/Context(msg:code:)`` if the context is not found.
///   ``ScpError/Permission(msg:code:)`` if key custody is not available.
///
/// ## Provenance
///
/// - ADR-011 (Event Log) acceptance criterion 8 in `.docs/adrs/phase-2.md`
/// - ADR-030 (Pruning/Checkpointing)
public func generateEventLogCheckpoint(
    handle: ContextHandle,
    identity: Identity,
    epoch: UInt64,
    checkpointFn: EventLogBridge.CheckpointFn = EventLogBridge.defaultCheckpoint
) async throws -> Checkpoint {
    try await checkpointFn(handle, identity, epoch)
}
