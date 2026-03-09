import Foundation

// MARK: - GovernanceActionResult

/// Result of executing a governance action (ADR-031).
///
/// Each case corresponds to one of the 24+ governance action outcomes from
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

// MARK: - GovernanceBridge

/// Namespace for UniFFI bridge function references used by governance operations.
internal enum GovernanceBridge {
    /// Execute a governance action. Maps to ``governanceExecute`` in ScpBindings.
    internal typealias ExecuteFn = @Sendable (
        _ handle: ContextHandle,
        _ proposalJson: String
    ) async throws -> String

    /// Default execute function that delegates to the UniFFI-generated binding.
    internal static let defaultExecute: ExecuteFn = { handle, proposalJson in
        try await governanceExecute(handle: handle, proposalJson: proposalJson)
    }
}

// MARK: - MembershipBridge

/// Namespace for UniFFI bridge function references used by membership queries.
internal enum MembershipBridge {
    /// Return the member count for a context.
    internal typealias MemberCountFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> UInt64?

    /// Check whether a DID is a member.
    internal typealias IsMemberFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> Bool

    /// Return all member DIDs.
    internal typealias MemberDidsFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> [String]

    /// Return a member's role.
    internal typealias MemberRoleFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> String?

    internal static let defaultMemberCount: MemberCountFn = { handle in
        try await contextMemberCount(handle: handle)
    }

    internal static let defaultIsMember: IsMemberFn = { handle, did in
        try await contextIsMember(handle: handle, did: did)
    }

    internal static let defaultMemberDids: MemberDidsFn = { handle in
        try await contextMemberDids(handle: handle)
    }

    internal static let defaultMemberRole: MemberRoleFn = { handle, did in
        try await contextMemberRole(handle: handle, did: did)
    }
}

// MARK: - BroadcastBridge

/// Namespace for UniFFI bridge function references used by broadcast operations.
internal enum BroadcastBridge {
    internal typealias SubscribeFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String
    ) async throws -> Void

    internal typealias UnsubscribeFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String,
        _ rotateKeys: Bool
    ) async throws -> Void

    internal typealias PublishFn = @Sendable (
        _ handle: ContextHandle,
        _ payload: Data
    ) async throws -> Void

    internal typealias BlockSubscriberFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String,
        _ blockerDid: String
    ) async throws -> Void

    internal typealias HandleKeyRequestFn = @Sendable (
        _ handle: ContextHandle,
        _ authorDid: String,
        _ requesterDid: String
    ) async throws -> String

    internal typealias SubscriberCountFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> UInt64?

    internal typealias IsSubscriberFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> Bool

    internal typealias AdmissionFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> String?

    internal static let defaultSubscribe: SubscribeFn = { handle, subscriberDid in
        try await broadcastSubscribe(handle: handle, subscriberDid: subscriberDid)
    }

    internal static let defaultUnsubscribe: UnsubscribeFn = {
        handle, subscriberDid, rotateKeys in
        try await broadcastUnsubscribe(
            handle: handle, subscriberDid: subscriberDid, rotateKeys: rotateKeys
        )
    }

    internal static let defaultPublish: PublishFn = { handle, payload in
        try await broadcastPublish(handle: handle, payload: payload)
    }

    internal static let defaultBlockSubscriber: BlockSubscriberFn = {
        handle, subscriberDid, blockerDid in
        try await broadcastBlockSubscriber(
            handle: handle, subscriberDid: subscriberDid, blockerDid: blockerDid
        )
    }

    internal static let defaultHandleKeyRequest: HandleKeyRequestFn = {
        handle, authorDid, requesterDid in
        try await broadcastHandleKeyRequest(
            handle: handle, authorDid: authorDid, requesterDid: requesterDid
        )
    }

    internal static let defaultSubscriberCount: SubscriberCountFn = { handle in
        try await broadcastSubscriberCount(handle: handle)
    }

    internal static let defaultIsSubscriber: IsSubscriberFn = { handle, did in
        try await broadcastIsSubscriber(handle: handle, did: did)
    }

    internal static let defaultAdmission: AdmissionFn = { handle in
        try await broadcastAdmission(handle: handle)
    }
}

// MARK: - Context Governance Extensions

extension Context {

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
    public func executeGovernanceAction(
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

extension Context {

    /// Returns the number of members in this context.
    ///
    /// - Parameter memberCountFn: Bridge function override for testing.
    /// - Returns: The member count, or `nil` if the context is not registered.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not active.
    public func memberCount(
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
    public func isMember(
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
    public func memberDids(
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
    public func memberRole(
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

extension Context {

    /// Subscribes a DID to this broadcast context.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID subscribing to broadcasts.
    ///   - subscribeFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or not a broadcast context.
    public func broadcastSubscribe(
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
    public func broadcastUnsubscribe(
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
    ///   - payload: The raw message payload.
    ///   - publishFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or not a broadcast context.
    public func broadcastPublish(
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
        try await publishFn(contextHandle, payload)
    }

    /// Blocks a subscriber's read access in this broadcast context.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID of the subscriber to block.
    ///   - blockerDid: The DID of the blocker.
    ///   - blockSubscriberFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the operation fails.
    public func broadcastBlockSubscriber(
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
    public func broadcastHandleKeyRequest(
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
    public func broadcastSubscriberCount(
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
    public func broadcastIsSubscriber(
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
    public func broadcastAdmission(
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
