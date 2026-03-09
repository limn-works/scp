import Foundation

// MARK: - GovernanceActionResult

/// Result of executing a governance action (ADR-031).
///
/// Each case corresponds to one of the 28 governance action outcomes from
/// `scp_core::context::manager::GovernanceActionResult`.
///
/// See `.docs/specs/05-contexts.md` section 5.9 and ADR-031.
public enum GovernanceActionResult: String, Sendable {
    case memberAdded = "MemberAdded"
    case memberRemoved = "MemberRemoved"
    case roleChanged = "RoleChanged"
    case toolRegistered = "ToolRegistered"
    case toolRemoved = "ToolRemoved"
    case ceilingModified = "CeilingModified"
    case contextClosed = "ContextClosed"
    case ttlExtended = "TtlExtended"
    case pruningPolicyModified = "PruningPolicyModified"
    case adminTransferred = "AdminTransferred"
    case signerAdded = "SignerAdded"
    case signerRemoved = "SignerRemoved"
    case thresholdModified = "ThresholdModified"
    case childContextCreated = "ChildContextCreated"
    case toolInterfaceEstablished = "ToolInterfaceEstablished"
    case memberReset = "MemberReset"
    case conflictResolved = "ConflictResolved"
    case contextPromoted = "ContextPromoted"
    case readAccessRevoked = "ReadAccessRevoked"
    case readAccessRestored = "ReadAccessRestored"
    case writeAccessRevoked = "WriteAccessRevoked"
    case writeAccessRestored = "WriteAccessRestored"
    case contentKeysRotated = "ContentKeysRotated"
    case governanceReconfigured = "GovernanceReconfigured"
    case authorBlocked = "AuthorBlocked"
    case subscriberBanned = "SubscriberBanned"
    case subscriberUnbanned = "SubscriberUnbanned"
    case executed = "Executed"
}

// MARK: - MemberRole

/// Role assigned to a member within a context (spec section 5.5).
///
/// Mirrors `scp_core::context::roles::Role`.
public enum MemberRole: String, Sendable {
    /// Context administrator with full governance capabilities.
    case admin = "Admin"
    /// Regular participant with standard capabilities.
    case member = "Member"
    /// Read-only observer with no write capabilities.
    case observer = "Observer"
    /// Custom role defined by context governance.
    case custom = "Custom"

    /// Parse a bridge-layer role string into a ``MemberRole``.
    ///
    /// Falls back to ``custom`` for unrecognised strings.
    public static func fromBridge(_ raw: String) -> MemberRole {
        let normalised = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        return MemberRole(rawValue: normalised)
            ?? MemberRole(rawValue: normalised.capitalized)
            ?? .custom
    }
}

// MARK: - ContextLifecycleBridge

/// Namespace for UniFFI bridge function references used by context lifecycle
/// operations beyond basic create/join/leave/close (drain events, TTL, export/import).
enum ContextLifecycleBridge {
    /// Drain pending events from a context.
    typealias DrainEventsFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> [String]

    /// Handle TTL expiry for a context.
    typealias HandleTtlExpiryFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> Void

    /// Propose a TTL extension with member consent.
    typealias ProposeTtlExtensionFn = @Sendable (
        _ handle: ContextHandle,
        _ memberDid: String,
        _ proposedSeconds: UInt64
    ) async throws -> Bool

    /// Reset the TTL timer after unanimous extension.
    typealias ResetTtlTimerFn = @Sendable (
        _ handle: ContextHandle,
        _ newSeconds: UInt64
    ) async throws -> Void

    /// Export a context's full state as serialized bytes.
    typealias ExportFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> Data

    /// Import a context from serialized bytes.
    typealias ImportFn = @Sendable (
        _ data: Data
    ) async throws -> String

    /// Register a DID as locally controlled.
    typealias RegisterLocalDidFn = @Sendable (
        _ did: String
    ) async throws -> Void

    /// Check if a DID is registered as locally controlled.
    typealias IsLocalDidFn = @Sendable (
        _ did: String
    ) async throws -> Bool

    /// Verify participation requirements via the UniFFI bridge.
    typealias VerifyParticipationRequirementsFn = @Sendable (
        _ profileJson: String,
        _ requirementsJson: String
    ) throws -> Bool

    static let defaultDrainEvents: DrainEventsFn = { handle in
        await contextDrainEvents(handle: handle)
    }

    static let defaultHandleTtlExpiry: HandleTtlExpiryFn = { handle in
        try await contextHandleTtlExpiry(handle: handle)
    }

    static let defaultProposeTtlExtension: ProposeTtlExtensionFn = { handle, memberDid, proposedSeconds in
        try await contextProposeTtlExtension(
            handle: handle, memberDid: memberDid, proposedSeconds: proposedSeconds
        )
    }

    static let defaultResetTtlTimer: ResetTtlTimerFn = { handle, newSeconds in
        await contextResetTtlTimer(handle: handle, newSeconds: newSeconds)
    }

    /// Default export function.
    ///
    /// ``contextExport`` is not yet available in the UniFFI-generated bindings
    /// (ScpBindings.swift). The default throws a descriptive error. Inject a
    /// real closure in production once the UniFFI bridge is regenerated, or
    /// in tests via the injectable parameter.
    static let defaultExport: ExportFn = { _ in
        throw ScpError.Context(
            message: "contextExport is not yet available in the UniFFI-generated bindings. "
                + "Regenerate ScpBindings.swift or inject a bridge function.",
            code: "SCP-CTX-2030"
        )
    }

    /// Default import function.
    ///
    /// ``contextImport`` is not yet available in the UniFFI-generated bindings
    /// (ScpBindings.swift). The default throws a descriptive error.
    static let defaultImport: ImportFn = { _ in
        throw ScpError.Context(
            message: "contextImport is not yet available in the UniFFI-generated bindings. "
                + "Regenerate ScpBindings.swift or inject a bridge function.",
            code: "SCP-CTX-2032"
        )
    }

    static let defaultRegisterLocalDid: RegisterLocalDidFn = { did in
        await registerLocalDid(did: did)
    }

    static let defaultIsLocalDid: IsLocalDidFn = { did in
        await isLocalDid(did: did)
    }

    /// Default verify participation requirements function.
    ///
    /// ``verifyParticipationRequirements`` is not yet available in the
    /// UniFFI-generated bindings (ScpBindings.swift). The default throws
    /// a descriptive error. Use the pure-Swift
    /// ``verifyParticipationRequirements(requirement:profile:)`` in
    /// Trust.swift for local verification.
    static let defaultVerifyParticipationRequirements: VerifyParticipationRequirementsFn = { _, _ in
        throw ScpError.Validation(
            message: "verifyParticipationRequirements is not yet available in the UniFFI-generated "
                + "bindings. Use the pure-Swift verifyParticipationRequirements(requirement:profile:) "
                + "or regenerate ScpBindings.swift.",
            code: "SCP-VALID-7030"
        )
    }
}

// MARK: - GovernanceBridge

/// Namespace for UniFFI bridge function references used by governance operations.
enum GovernanceBridge {
    /// Execute a governance action. Maps to ``governanceExecute`` in ScpBindings.
    typealias ExecuteFn = @Sendable (
        _ handle: ContextHandle,
        _ proposalJson: String
    ) async throws -> String

    /// Default execute function that delegates to the UniFFI-generated binding.
    static let defaultExecute: ExecuteFn = { handle, proposalJson in
        try await governanceExecute(handle: handle, proposalJson: proposalJson)
    }
}

// MARK: - MembershipBridge

/// Namespace for UniFFI bridge function references used by membership queries.
enum MembershipBridge {
    /// Return the member count for a context.
    typealias MemberCountFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> UInt64?

    /// Check whether a DID is a member.
    typealias IsMemberFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> Bool

    /// Return all member DIDs.
    typealias MemberDidsFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> [String]

    /// Return a member's role.
    typealias MemberRoleFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> String?

    static let defaultMemberCount: MemberCountFn = { handle in
        try await contextMemberCount(handle: handle)
    }

    static let defaultIsMember: IsMemberFn = { handle, did in
        try await contextIsMember(handle: handle, did: did)
    }

    static let defaultMemberDids: MemberDidsFn = { handle in
        try await contextMemberDids(handle: handle)
    }

    static let defaultMemberRole: MemberRoleFn = { handle, did in
        try await contextMemberRole(handle: handle, did: did)
    }
}

// MARK: - BroadcastBridge

/// Namespace for UniFFI bridge function references used by broadcast operations.
enum BroadcastBridge {
    typealias SubscribeFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String
    ) async throws -> Void

    typealias UnsubscribeFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String,
        _ rotateKeys: Bool
    ) async throws -> Void

    typealias PublishFn = @Sendable (
        _ handle: ContextHandle,
        _ authorDid: String,
        _ payload: Data
    ) async throws -> Void

    typealias BlockSubscriberFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String,
        _ blockerDid: String
    ) async throws -> Void

    typealias HandleKeyRequestFn = @Sendable (
        _ handle: ContextHandle,
        _ authorDid: String,
        _ requesterDid: String
    ) async throws -> String

    typealias SubscriberCountFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> UInt64?

    typealias IsSubscriberFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> Bool

    typealias AdmissionFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> String?

    static let defaultSubscribe: SubscribeFn = { handle, subscriberDid in
        try await broadcastSubscribe(handle: handle, subscriberDid: subscriberDid)
    }

    static let defaultUnsubscribe: UnsubscribeFn = { handle, subscriberDid, rotateKeys in
        try await broadcastUnsubscribe(
            handle: handle, subscriberDid: subscriberDid, rotateKeys: rotateKeys
        )
    }

    static let defaultPublish: PublishFn = { handle, authorDid, payload in
        try await broadcastPublish(handle: handle, authorDid: authorDid, payload: payload)
    }

    static let defaultBlockSubscriber: BlockSubscriberFn = { handle, subscriberDid, blockerDid in
        try await broadcastBlockSubscriber(
            handle: handle, subscriberDid: subscriberDid, blockerDid: blockerDid
        )
    }

    static let defaultHandleKeyRequest: HandleKeyRequestFn = { handle, authorDid, requesterDid in
        try await broadcastHandleKeyRequest(
            handle: handle, authorDid: authorDid, requesterDid: requesterDid
        )
    }

    static let defaultSubscriberCount: SubscriberCountFn = { handle in
        try await broadcastSubscriberCount(handle: handle)
    }

    static let defaultIsSubscriber: IsSubscriberFn = { handle, did in
        try await broadcastIsSubscriber(handle: handle, did: did)
    }

    static let defaultAdmission: AdmissionFn = { handle in
        try await broadcastAdmission(handle: handle)
    }
}

// MARK: - Context Governance Extensions

public extension Context {
    /// Executes a governance action on this context.
    ///
    /// Delegates to the UniFFI ``governanceExecute`` bridge function.
    ///
    /// - Parameters:
    ///   - proposalJson: JSON-serialized ``GovernanceProposal``.
    ///   - executeFn: Bridge function override for testing.
    /// - Returns: A ``GovernanceActionResult`` describing the outcome.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or governance execution fails.
    func executeGovernanceAction(
        proposalJson: String,
        executeFn: GovernanceBridge.ExecuteFn = GovernanceBridge.defaultExecute
    ) async throws -> GovernanceActionResult {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        let raw = try await executeFn(contextHandle, proposalJson)
        return GovernanceActionResult(rawValue: raw) ?? .executed
    }
}

// MARK: - Context Membership Extensions

public extension Context {
    /// Returns the number of members in this context.
    ///
    /// - Parameter memberCountFn: Bridge function override for testing.
    /// - Returns: The member count, or `nil` if the context is not registered.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func memberCount(
        memberCountFn: MembershipBridge.MemberCountFn = MembershipBridge.defaultMemberCount
    ) async throws -> UInt64? {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await memberCountFn(contextHandle)
    }

    /// Checks whether a DID is a member of this context.
    ///
    /// - Parameters:
    ///   - did: The DID to check.
    ///   - isMemberFn: Bridge function override for testing.
    /// - Returns: `true` if the DID is a member.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func isMember(
        did: String,
        isMemberFn: MembershipBridge.IsMemberFn = MembershipBridge.defaultIsMember
    ) async throws -> Bool {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await isMemberFn(contextHandle, did)
    }

    /// Returns all member DIDs in this context.
    ///
    /// - Parameter memberDidsFn: Bridge function override for testing.
    /// - Returns: An array of DID strings.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func memberDids(
        memberDidsFn: MembershipBridge.MemberDidsFn = MembershipBridge.defaultMemberDids
    ) async throws -> [String] {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await memberDidsFn(contextHandle)
    }

    /// Returns the role of a member in this context.
    ///
    /// - Parameters:
    ///   - did: The DID of the member.
    ///   - memberRoleFn: Bridge function override for testing.
    /// - Returns: A ``MemberRole``, or `nil` if the member is not found.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func memberRole(
        did: String,
        memberRoleFn: MembershipBridge.MemberRoleFn = MembershipBridge.defaultMemberRole
    ) async throws -> MemberRole? {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        guard let raw = try await memberRoleFn(contextHandle, did) else {
            return nil
        }
        return MemberRole.fromBridge(raw)
    }
}

// MARK: - Context Broadcast Extensions

public extension Context {
    /// Subscribes a DID to this broadcast context.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID subscribing to broadcasts.
    ///   - subscribeFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or not a broadcast context.
    func broadcastSubscribe(
        subscriberDid: String,
        subscribeFn: BroadcastBridge.SubscribeFn = BroadcastBridge.defaultSubscribe
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        try await subscribeFn(contextHandle, subscriberDid)
    }

    /// Unsubscribes a DID from this broadcast context.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID to unsubscribe.
    ///   - rotateKeys: When `true`, all authors rotate their broadcast keys.
    ///   - unsubscribeFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or not a broadcast context.
    func broadcastUnsubscribe(
        subscriberDid: String,
        rotateKeys: Bool = false,
        unsubscribeFn: BroadcastBridge.UnsubscribeFn = BroadcastBridge.defaultUnsubscribe
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        try await unsubscribeFn(contextHandle, subscriberDid, rotateKeys)
    }

    /// Publishes a message to this broadcast context.
    ///
    /// - Parameters:
    ///   - authorDid: The DID of the author publishing the message.
    ///   - payload: The raw message payload.
    ///   - publishFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or not a broadcast context.
    func broadcastPublish(
        authorDid: String,
        payload: Data,
        publishFn: BroadcastBridge.PublishFn = BroadcastBridge.defaultPublish
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        try await publishFn(contextHandle, authorDid, payload)
    }

    /// Blocks a subscriber's read access in this broadcast context.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID of the subscriber to block.
    ///   - blockerDid: The DID of the blocker.
    ///   - blockSubscriberFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the operation fails.
    func broadcastBlockSubscriber(
        subscriberDid: String,
        blockerDid: String,
        blockSubscriberFn: BroadcastBridge.BlockSubscriberFn =
            BroadcastBridge.defaultBlockSubscriber
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        try await blockSubscriberFn(contextHandle, subscriberDid, blockerDid)
    }

    /// Handles a broadcast key request from a subscriber.
    ///
    /// - Parameters:
    ///   - authorDid: The DID of the author handling the request.
    ///   - requesterDid: The DID of the requester.
    ///   - handleKeyRequestFn: Bridge function override for testing.
    /// - Returns: A string describing the key request decision.
    /// - Throws: ``ScpError/Context(message:code:)`` if the operation fails.
    func broadcastHandleKeyRequest(
        authorDid: String,
        requesterDid: String,
        handleKeyRequestFn: BroadcastBridge.HandleKeyRequestFn =
            BroadcastBridge.defaultHandleKeyRequest
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await handleKeyRequestFn(contextHandle, authorDid, requesterDid)
    }

    /// Returns the number of broadcast subscribers for this context.
    ///
    /// - Parameter subscriberCountFn: Bridge function override for testing.
    /// - Returns: The subscriber count, or `nil` if not a broadcast context.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func broadcastSubscriberCount(
        subscriberCountFn: BroadcastBridge.SubscriberCountFn =
            BroadcastBridge.defaultSubscriberCount
    ) async throws -> UInt64? {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await subscriberCountFn(contextHandle)
    }

    /// Checks whether a DID is a broadcast subscriber.
    ///
    /// - Parameters:
    ///   - did: The DID to check.
    ///   - isSubscriberFn: Bridge function override for testing.
    /// - Returns: `true` if the DID is a subscriber.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func broadcastIsSubscriber(
        did: String,
        isSubscriberFn: BroadcastBridge.IsSubscriberFn = BroadcastBridge.defaultIsSubscriber
    ) async throws -> Bool {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await isSubscriberFn(contextHandle, did)
    }

    /// Returns the broadcast admission policy for this context.
    ///
    /// - Parameter admissionFn: Bridge function override for testing.
    /// - Returns: The policy (`"Open"` or `"Gated"`), or `nil` if not broadcast.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func broadcastAdmission(
        admissionFn: BroadcastBridge.AdmissionFn = BroadcastBridge.defaultAdmission
    ) async throws -> String? {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await admissionFn(contextHandle)
    }
}

// MARK: - Context Lifecycle Extensions

public extension Context {
    /// Drains all pending events from this context.
    ///
    /// Returns event descriptions as strings. The events are consumed (removed
    /// from the internal queue) by this call.
    ///
    /// - Parameter drainEventsFn: Bridge function override for testing.
    /// - Returns: An array of event description strings.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func drainEvents(
        drainEventsFn: ContextLifecycleBridge.DrainEventsFn =
            ContextLifecycleBridge.defaultDrainEvents
    ) async throws -> [String] {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await drainEventsFn(contextHandle)
    }

    /// Handles TTL expiry for this context.
    ///
    /// Transitions the context from active to expired, destroying keys per
    /// the context's memory scope policy.
    ///
    /// - Parameter handleTtlExpiryFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func handleTtlExpiry(
        handleTtlExpiryFn: ContextLifecycleBridge.HandleTtlExpiryFn =
            ContextLifecycleBridge.defaultHandleTtlExpiry
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        try await handleTtlExpiryFn(contextHandle)
        state = .expired
    }

    /// Proposes a TTL extension for this context.
    ///
    /// Records consent from the given member for the proposed extension
    /// duration. Returns `true` when all members have consented (unanimous
    /// approval).
    ///
    /// - Parameters:
    ///   - memberDid: The DID of the member consenting to the extension.
    ///   - proposedSeconds: The proposed TTL extension duration in seconds.
    ///   - proposeTtlExtensionFn: Bridge function override for testing.
    /// - Returns: `true` if all members have consented, `false` otherwise.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or the member is not found.
    func proposeTtlExtension(
        memberDid: String,
        proposedSeconds: UInt64,
        proposeTtlExtensionFn: ContextLifecycleBridge.ProposeTtlExtensionFn =
            ContextLifecycleBridge.defaultProposeTtlExtension
    ) async throws -> Bool {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await proposeTtlExtensionFn(contextHandle, memberDid, proposedSeconds)
    }

    /// Resets the TTL timer after a successful unanimous extension.
    ///
    /// Cancels the old timer and spawns a new one with the given duration.
    /// Call this after ``proposeTtlExtension(memberDid:proposedSeconds:proposeTtlExtensionFn:)``
    /// returns `true`.
    ///
    /// - Parameters:
    ///   - newSeconds: The new TTL duration in seconds.
    ///   - resetTtlTimerFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    func resetTtlTimer(
        newSeconds: UInt64,
        resetTtlTimerFn: ContextLifecycleBridge.ResetTtlTimerFn =
            ContextLifecycleBridge.defaultResetTtlTimer
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        try await resetTtlTimerFn(contextHandle, newSeconds)
    }

    /// Exports this context's full state as serialized bytes.
    ///
    /// Returns the serialized bytes of a `StoredValue<ContextExport>` envelope
    /// (spec section 17.5), suitable for backup, migration, or transfer to
    /// another node.
    ///
    /// - Parameter exportFn: Bridge function override for testing.
    /// - Returns: The serialized context state as `Data`.
    /// - Throws: ``ScpError/Context(message:code:)`` if export fails.
    func exportContext(
        exportFn: ContextLifecycleBridge.ExportFn = ContextLifecycleBridge.defaultExport
    ) async throws -> Data {
        guard state == .active else {
            throw ScpError.Context(message: "Context is not active", code: "SCP-CTX-2001")
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await exportFn(contextHandle)
    }
}

// MARK: - Context Import (free function)

/// Imports a context from serialized bytes.
///
/// The bytes must be a `StoredValue<ContextExport>` envelope (spec section
/// 17.5), as produced by ``Context/exportContext(exportFn:)``.
///
/// - Parameters:
///   - data: The serialized context state.
///   - importFn: Bridge function override for testing.
/// - Returns: The context ID of the imported context.
/// - Throws: ``ScpError/Context(message:code:)`` if deserialization,
///   validation, or import fails.
///
/// ## Provenance
///
/// - Spec section 17.5
public func importContext(
    data: Data,
    importFn: ContextLifecycleBridge.ImportFn = ContextLifecycleBridge.defaultImport
) async throws -> String {
    try await importFn(data)
}

// MARK: - Local DID Management

/// Registers a DID as locally controlled by this node/SDK.
///
/// Used for defense-in-depth validation in broadcast key request handling.
///
/// - Parameters:
///   - did: The DID string to register as local.
///   - registerLocalDidFn: Bridge function override for testing.
///
/// ## Provenance
///
/// - Spec section 5.14 (Broadcast)
public func registerLocalDid(
    did: String,
    registerLocalDidFn: ContextLifecycleBridge.RegisterLocalDidFn =
        ContextLifecycleBridge.defaultRegisterLocalDid
) async throws {
    try await registerLocalDidFn(did)
}

/// Checks whether a DID is registered as locally controlled.
///
/// - Parameters:
///   - did: The DID string to check.
///   - isLocalDidFn: Bridge function override for testing.
/// - Returns: `true` if the DID is locally registered, `false` otherwise.
///
/// ## Provenance
///
/// - Spec section 5.14 (Broadcast)
public func isLocalDid(
    did: String,
    isLocalDidFn: ContextLifecycleBridge.IsLocalDidFn =
        ContextLifecycleBridge.defaultIsLocalDid
) async throws -> Bool {
    try await isLocalDidFn(did)
}

// MARK: - Participation Requirements (Bridge)

/// Verifies participation profiles against admission requirements via the
/// UniFFI bridge.
///
/// Both inputs are JSON strings:
/// - `profileJson`: JSON array of participation profile objects.
/// - `requirementsJson`: JSON array of participation requirement objects.
///
/// Uses the current system time for freshness checks. Returns `true` if all
/// requirements are satisfied.
///
/// For a pure-Swift version that uses typed ``RequireParticipation`` and
/// ``ParticipationProfile`` inputs, see
/// ``verifyParticipationRequirements(requirement:profile:)`` in Trust.swift.
///
/// - Parameters:
///   - profileJson: JSON string of participation profiles.
///   - requirementsJson: JSON string of participation requirements.
///   - verifyFn: Bridge function override for testing.
/// - Returns: `true` if all requirements are satisfied.
/// - Throws: ``ScpError/Validation(message:code:)`` if JSON parsing fails
///   or a requirement is not met.
///
/// ## Provenance
///
/// - Spec section 23.7 (Participation Requirements)
/// - ADR-017 Layer 2
public func verifyParticipationRequirementsBridge(
    profileJson: String,
    requirementsJson: String,
    verifyFn: ContextLifecycleBridge.VerifyParticipationRequirementsFn =
        ContextLifecycleBridge.defaultVerifyParticipationRequirements
) throws -> Bool {
    try verifyFn(profileJson, requirementsJson)
}
