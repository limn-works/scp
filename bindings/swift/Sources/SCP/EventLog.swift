import Foundation

// Event, Proof, and Checkpoint are defined by UniFFI in ScpBindings.swift.
//
// UniFFI Event fields: eventType, actorDid, timestamp, payloadJson (String), sequence
// UniFFI Proof fields: proofType (String), detailsJson (String) — there is no
// `verified` flag; a returned Proof IS the positive answer, throwing IS the
// negative one (see `proveInclusion` below).
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
//
// Phase 4 PR 4 (ADR-048 demolition, #1549): the `EventLogBridge` namespace
// — closures whose defaults called `Scp.defaultInstance()` — has been
// deleted. Every event-log operation now dispatches through an explicit
// ``SCP`` instance stored on ``EventLog`` / passed into the free
// checkpoint helper.

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

// MARK: - EventLog

/// A verifiable, append-only Merkle event log for an SCP context.
///
/// Delegates to UniFFI ``eventLogQuery`` and ``eventLogVerify`` bridge
/// methods on the stored ``SCP`` instance when backed by a real
/// ``ContextHandle``.
///
/// See ADR-011 (Event Log) in `.docs/adrs/phase-2.md`.
///
/// ## Provenance
///
/// - ADR-011 (Event Log) in `.docs/adrs/phase-2.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - ADR-048 (Multi-instance SCP) — SCP instance is caller-owned
/// - Story SCP-221
public nonisolated struct EventLog: Sendable {
    /// The context ID this event log belongs to.
    public let contextId: String

    /// The SDK-level ``SCP`` instance that minted the underlying
    /// ``ContextHandle``. Every UniFFI call flows through this reference.
    public let scp: SCP

    /// The internal handle wrapping the native UniFFI event log object.
    private let handle: EventLogHandle

    /// Creates an ``EventLog`` from an internal ``EventLogHandle``.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that owns the handle.
    ///   - handle: The internal event-log handle (backed by a
    ///     ``ContextHandle`` in production).
    init(scp: SCP, handle: EventLogHandle) {
        self.scp = scp
        contextId = handle.contextId
        self.handle = handle
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
        return try await scp.eventLogQuery(handle: contextHandle, filterJson: filterJson)
    }

    /// Generates a Merkle inclusion proof for the event at the given index.
    ///
    /// Throwing IS the negative answer: a leaf index the authoritative log
    /// cannot prove raises rather than returning an unproven ``Proof``. The
    /// returned ``Proof/detailsJson`` carries the full Merkle material — leaf
    /// hash, sibling path with per-step direction, and the root the path
    /// reaches — for a recipient to re-verify independently.
    ///
    /// - Parameter leafIndex: The index of the event to prove inclusion for.
    /// - Returns: A ``Proof`` carrying the Merkle path.
    /// - Throws: ``ScpError/Context(msg:code:)`` — `SCP-CTX-2138` if the
    ///   authoritative event log is unreachable (FAILS CLOSED, never a proof
    ///   over a fallback tree), or `SCP-CTX-2139` if the log WAS read and the
    ///   inclusion claim is demonstrably FALSE (an empty log, or a leaf index
    ///   past the end of the tree) — a real negative answer about the log's
    ///   contents, distinct from "cannot answer".
    public func proveInclusion(leafIndex: UInt64) async throws -> Proof {
        guard let contextHandle = handle.contextHandle else {
            throw ScpError.Context(
                msg: "EventLog not backed by a UniFFI ContextHandle",
                code: "SCP-CTX-2031"
            )
        }
        let claimJson = #"{"type": "inclusion", "leaf_index": \#(leafIndex)}"#
        return try await scp.eventLogVerify(handle: contextHandle, claimJson: claimJson)
    }

    // `verifyInclusion(_ proof: Proof) -> Bool` used to live here, returning
    // `proof.verified`. It verified nothing: `verified` was a producer-set
    // constant `true` on every success path, so a "verifier" that read it back
    // was a false guarantee wearing a verification name. It is deleted along
    // with the field. Use `proveInclusion` throwing as the negative answer, and
    // re-derive the root from `Proof.detailsJson` when independent verification
    // is required.
}

// MARK: - Event Log Checkpoint (free function)

/// Generates a signed consistency checkpoint for equivocation detection.
///
/// Members periodically exchange signed Merkle roots. If two members have
/// different roots for the same event count, the relay is equivocating
/// (showing different histories to different members).
///
/// Forwards to ``SCP/eventLogCheckpoint(handle:identity:epoch:)``.
///
/// - Parameters:
///   - scp: The SDK-level ``SCP`` instance that owns ``handle``.
///   - handle: The ``ContextHandle`` for the context whose event log to
///     checkpoint.
///   - identity: The ``Identity`` generating the checkpoint (used for signing).
///   - epoch: The current MLS epoch (pass 0 for broadcast contexts).
/// - Returns: A ``Checkpoint`` containing the signed checkpoint data.
/// - Throws: ``ScpError/Context(msg:code:)`` if the context is not found.
///   ``ScpError/Identity(msg:code:)`` (`SCP-IDENT-1017`) if the identity
///   retains no signing custody (externally loaded).
///
/// ## Provenance
///
/// - ADR-011 (Event Log) acceptance criterion 8 in `.docs/adrs/phase-2.md`
/// - ADR-030 (Pruning/Checkpointing)
/// - ADR-048 (Multi-instance SCP)
public func generateEventLogCheckpoint(
    scp: SCP,
    handle: ContextHandle,
    identity: Identity,
    epoch: UInt64
) async throws -> Checkpoint {
    try await scp.eventLogCheckpoint(handle: handle, identity: identity, epoch: epoch)
}

/// Generates a signed consistency checkpoint scoped to a member DID.
///
/// Signs with the supplied ``identity``'s key material and records ``did`` as
/// the checkpoint's sender. The UniFFI bridge holds no DID-keyed identity
/// registry, so the ``Identity`` handle supplies the key material while
/// ``did`` names the member the checkpoint is attributed to (e.g. an agent
/// key). Forwards to ``SCP/eventLogCheckpointByDid(handle:identity:did:epoch:)``.
///
/// - Parameters:
///   - scp: The SDK-level ``SCP`` instance that owns ``handle``.
///   - handle: The ``ContextHandle`` for the context whose event log to
///     checkpoint.
///   - identity: The ``Identity`` whose key material signs the checkpoint.
///   - did: The DID of the member the checkpoint is attributed to.
///   - epoch: The current MLS epoch (pass 0 for broadcast contexts).
/// - Returns: A ``Checkpoint`` containing the signed checkpoint data.
/// - Throws: ``ScpError/Context(msg:code:)`` if the context is not found.
///   ``ScpError/Identity(msg:code:)`` (`SCP-IDENT-1017`) if the identity
///   retains no signing custody (externally loaded).
///
/// ## Provenance
///
/// - ADR-011 (Event Log) acceptance criterion 8 in `.docs/adrs/phase-2.md`
/// - ADR-030 (Pruning/Checkpointing)
/// - ADR-048 (Multi-instance SCP) §7 (per-SDK idiom)
public func generateEventLogCheckpointByDid(
    scp: SCP,
    handle: ContextHandle,
    identity: Identity,
    did: String,
    epoch: UInt64
) async throws -> Checkpoint {
    try await scp.eventLogCheckpointByDid(handle: handle, identity: identity, did: did, epoch: epoch)
}
