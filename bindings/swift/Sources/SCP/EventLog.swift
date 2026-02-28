import Foundation

// Event and Proof are now defined by UniFFI in ScpBindings.swift.
//
// UniFFI Event fields: eventType, actorDid, timestamp, payloadJson (String), sequence
// UniFFI Proof fields: verified (Bool), proofType (String), detailsJson (String)
//
// Checkpoint, EventLogHandle, and EventLog are pure Swift types (not in UniFFI).

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
internal func scpEventLogQuery(
    handle: EventLogHandle,
    fromSequence: UInt64,
    limit: UInt64,
    completion: @Sendable @escaping (Result<[Event], ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Validation(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-ELOG-001"
    )))
}

/// Prove inclusion of an event in the log via the UniFFI bridge.
internal func scpEventLogProve(
    handle: EventLogHandle,
    leafIndex: UInt64,
    completion: @Sendable @escaping (Result<Proof, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Validation(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-ELOG-002"
    )))
}

/// Verify an inclusion proof via the UniFFI bridge.
internal func scpEventLogVerify(
    proof: Proof,
    completion: @Sendable @escaping (Result<Bool, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Validation(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-ELOG-003"
    )))
}

// MARK: - EventLog

/// A verifiable, append-only Merkle event log for an SCP context.
///
/// See ADR-011 (Event Log) in `.docs/adrs/phase-2.md`.
public nonisolated struct EventLog: Sendable {
    /// The context ID this event log belongs to.
    public let contextId: String

    /// The internal handle wrapping the native UniFFI event log object.
    private let handle: EventLogHandle

    /// Creates an ``EventLog`` from an internal ``EventLogHandle``.
    internal init(handle: EventLogHandle) {
        self.contextId = handle.contextId
        self.handle = handle
    }

    /// Retrieves events from the log starting at a given sequence number.
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

    /// Generates a Merkle inclusion proof for the event at the given index.
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

    /// Verifies a Merkle inclusion proof.
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
