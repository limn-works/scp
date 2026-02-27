import Foundation

// MARK: - Event

/// A protocol event recorded in a context's append-only Merkle event log.
///
/// Each event records a single protocol action: who did it (``actorDid``),
/// what they did (``eventType`` + ``payload``), when (``timestamp``), the
/// position in the log (``sequence``), a hash-chain link to the previous
/// event (``prevHash``), and an Ed25519 signature over the event content.
///
/// See ADR-011 in `.docs/adrs/phase-2.md`.
public nonisolated struct Event: Sendable {
    /// The type of protocol action this event represents.
    public let eventType: String

    /// The DID of the actor who produced this event.
    public let actorDid: String

    /// Unix timestamp (seconds since epoch) when the event was created.
    public let timestamp: UInt64

    /// Monotonic event sequence number within this log (0-indexed).
    public let sequence: UInt64

    /// The event payload data. Interpretation depends on the event type.
    public let payload: Data

    /// SHA-256 hash of the previous event (32 bytes). For the first event,
    /// this is all zeros (the genesis sentinel).
    public let prevHash: Data

    /// Ed25519 signature over the serialized event content (64 bytes).
    public let signature: Data

    /// Memberwise initializer.
    public init(
        eventType: String,
        actorDid: String,
        timestamp: UInt64,
        sequence: UInt64,
        payload: Data,
        prevHash: Data,
        signature: Data
    ) {
        self.eventType = eventType
        self.actorDid = actorDid
        self.timestamp = timestamp
        self.sequence = sequence
        self.payload = payload
        self.prevHash = prevHash
        self.signature = signature
    }
}

// MARK: - Proof

/// A Merkle inclusion proof: the path from a leaf to the root.
///
/// The proof consists of sibling hashes at each tree level with direction
/// indicators. Proof size is O(log n) where n is the number of leaves.
/// Any third party can verify an inclusion proof without access to the log.
///
/// See ADR-011 acceptance criterion 3 in `.docs/adrs/phase-2.md`.
public nonisolated struct Proof: Sendable {
    /// The index of the leaf in the append-order log.
    public let leafIndex: UInt64

    /// The SHA-256 hash of the leaf (32 bytes).
    public let leafHash: Data

    /// The sibling hashes forming the Merkle path, from leaf to root.
    /// Each entry is a 32-byte SHA-256 hash paired with a direction
    /// indicator ("left" or "right").
    public let path: [(hash: Data, direction: String)]

    /// The Merkle root at the time the proof was generated (32 bytes).
    public let root: Data

    /// Creates a ``Proof`` with the given parameters.
    ///
    /// - Parameters:
    ///   - leafIndex: The leaf index in the log.
    ///   - leafHash: The SHA-256 hash of the leaf.
    ///   - path: The Merkle path (sibling hashes with direction indicators).
    ///   - root: The Merkle root hash.
    public init(
        leafIndex: UInt64,
        leafHash: Data,
        path: [(hash: Data, direction: String)],
        root: Data
    ) {
        self.leafIndex = leafIndex
        self.leafHash = leafHash
        self.path = path
        self.root = root
    }
}

// MARK: - Checkpoint

/// A signed consistency checkpoint for equivocation detection.
///
/// Members periodically exchange signed Merkle roots. If two members have
/// different roots for the same event count, the relay is equivocating
/// (showing different histories to different members).
///
/// See ADR-011 acceptance criterion 8 in `.docs/adrs/phase-2.md`.
public nonisolated struct Checkpoint: Sendable {
    /// The context this checkpoint belongs to.
    public let contextId: String

    /// The DID of the member who generated this checkpoint.
    public let senderDid: String

    /// The number of events in the log at checkpoint time.
    public let eventCount: UInt64

    /// The Merkle root hash at checkpoint time (32 bytes).
    public let merkleRoot: Data

    /// Current MLS epoch, if applicable. `nil` for broadcast contexts.
    public let epoch: UInt64?

    /// Unix timestamp (seconds since epoch) when the checkpoint was generated.
    public let timestamp: UInt64

    /// Ed25519 signature over the checkpoint content (64 bytes).
    public let signature: Data

    /// Memberwise initializer.
    public init(
        contextId: String,
        senderDid: String,
        eventCount: UInt64,
        merkleRoot: Data,
        epoch: UInt64?,
        timestamp: UInt64,
        signature: Data
    ) {
        self.contextId = contextId
        self.senderDid = senderDid
        self.eventCount = eventCount
        self.merkleRoot = merkleRoot
        self.epoch = epoch
        self.timestamp = timestamp
        self.signature = signature
    }
}

// MARK: - EventLogHandle (UniFFI bridge type)

/// Internal opaque handle wrapping the UniFFI-generated event log binding.
///
/// This placeholder mirrors the handle type that UniFFI will generate from
/// the Rust `EventLog` struct. When the XCFramework build pipeline ships
/// (SCP-103), this definition is replaced by the auto-generated type.
internal final class EventLogHandle: Sendable {
    /// The context ID this event log belongs to.
    let contextId: String

    /// Creates an ``EventLogHandle`` for the given context.
    init(contextId: String) {
        self.contextId = contextId
    }
}

// MARK: - UniFFI Bridge Stubs

/// Query events from an event log via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `event_log_query` function.
///
/// - Parameters:
///   - handle: The event log handle.
///   - fromSequence: The starting sequence number (inclusive).
///   - limit: Maximum number of events to return.
///   - completion: Callback delivering the events or an error.
internal func scpEventLogQuery(
    handle: EventLogHandle,
    fromSequence: UInt64,
    limit: UInt64,
    completion: @Sendable @escaping (Result<[Event], ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.validation(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-ELOG-001"
    )))
}

/// Prove inclusion of an event in the log via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `event_log_prove` function.
///
/// - Parameters:
///   - handle: The event log handle.
///   - leafIndex: The leaf index to prove inclusion for.
///   - completion: Callback delivering the proof or an error.
internal func scpEventLogProve(
    handle: EventLogHandle,
    leafIndex: UInt64,
    completion: @Sendable @escaping (Result<Proof, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.validation(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-ELOG-002"
    )))
}

/// Verify an inclusion proof via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `event_log_verify` function.
///
/// - Parameters:
///   - proof: The inclusion proof to verify.
///   - completion: Callback delivering the boolean result or an error.
internal func scpEventLogVerify(
    proof: Proof,
    completion: @Sendable @escaping (Result<Bool, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.validation(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-ELOG-003"
    )))
}

// MARK: - EventLog

/// A verifiable, append-only Merkle event log for an SCP context.
///
/// Every context maintains an event log that records all protocol events
/// (member joins/leaves, messages, tool invocations, governance actions, etc.)
/// in a Merkle tree following the Certificate Transparency (RFC 6962) structure.
///
/// ``EventLog`` is `nonisolated` because it has no mutable state after
/// construction -- all state lives in the Rust core accessed through the
/// UniFFI handle. Read operations are safe to call from any isolation context.
///
/// ## Operations
///
/// - ``query(fromSequence:limit:)`` -- Retrieve events from the log.
/// - ``proveInclusion(leafIndex:)`` -- Generate a Merkle inclusion proof.
/// - ``verifyInclusion(_:)`` -- Verify an inclusion proof (static, pure function).
///
/// ## Provenance
///
/// - ADR-011 (Event Log) in `.docs/adrs/phase-2.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - Story SCP-101
public nonisolated struct EventLog: Sendable {
    /// The context ID this event log belongs to.
    public let contextId: String

    /// The internal handle wrapping the native UniFFI event log object.
    private let handle: EventLogHandle

    // MARK: - Internal Initializer

    /// Creates an ``EventLog`` from an internal ``EventLogHandle``.
    ///
    /// This initializer is internal -- callers obtain an ``EventLog`` through
    /// the ``Context`` API.
    ///
    /// - Parameter handle: The opaque event log handle from the UniFFI bridge.
    internal init(handle: EventLogHandle) {
        self.contextId = handle.contextId
        self.handle = handle
    }

    // MARK: - Query

    /// Retrieves events from the log starting at a given sequence number.
    ///
    /// - Parameters:
    ///   - fromSequence: The starting sequence number (inclusive, 0-indexed).
    ///   - limit: Maximum number of events to return.
    /// - Returns: An array of ``Event`` values in append order.
    /// - Throws: ``ScpError/validation(message:code:)`` if the query fails.
    public func query(fromSequence: UInt64, limit: UInt64) async throws -> [Event] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[Event], Error>) in
            scpEventLogQuery(
                handle: handle,
                fromSequence: fromSequence,
                limit: limit
            ) { result in
                switch result {
                case .success(let events):
                    continuation.resume(returning: events)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Prove

    /// Generates a Merkle inclusion proof for the event at the given index.
    ///
    /// The proof consists of sibling hashes at each tree level from the leaf
    /// up to the root. Proof size is O(log n) where n is the number of events.
    ///
    /// - Parameter leafIndex: The 0-indexed position of the event in the log.
    /// - Returns: A ``Proof`` containing the Merkle path from leaf to root.
    /// - Throws: ``ScpError/validation(message:code:)`` if the leaf index is
    ///   out of bounds or the log is empty.
    public func proveInclusion(leafIndex: UInt64) async throws -> Proof {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Proof, Error>) in
            scpEventLogProve(handle: handle, leafIndex: leafIndex) { result in
                switch result {
                case .success(let proof):
                    continuation.resume(returning: proof)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Verify

    /// Verifies a Merkle inclusion proof.
    ///
    /// This is a **pure function** -- no access to the event log is needed.
    /// Any third party can verify an inclusion proof by recomputing the root
    /// hash from the leaf through the proof path.
    ///
    /// - Parameter proof: The ``Proof`` to verify.
    /// - Returns: `true` if the computed root matches the proof's stated root.
    /// - Throws: ``ScpError/validation(message:code:)`` if verification
    ///   encounters an internal error.
    public static func verifyInclusion(_ proof: Proof) async throws -> Bool {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Bool, Error>) in
            scpEventLogVerify(proof: proof) { result in
                switch result {
                case .success(let isValid):
                    continuation.resume(returning: isValid)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
