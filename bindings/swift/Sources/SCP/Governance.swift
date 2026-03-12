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
    /// Moderator with messaging, moderation, and governance proposal capabilities.
    case moderator = "Moderator"
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
public enum ContextLifecycleBridge {
    /// Drain pending events from a context.
    public typealias DrainEventsFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> [String]

    /// Handle TTL expiry for a context.
    public typealias HandleTtlExpiryFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> Void

    /// Propose a TTL extension with member consent.
    public typealias ProposeTtlExtensionFn = @Sendable (
        _ handle: ContextHandle,
        _ memberDid: String,
        _ proposedSeconds: UInt64
    ) async throws -> Bool

    /// Reset the TTL timer after unanimous extension.
    public typealias ResetTtlTimerFn = @Sendable (
        _ handle: ContextHandle,
        _ newSeconds: UInt64
    ) async throws -> Void

    /// Export a context's full state as serialized bytes.
    public typealias ExportFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> Data

    /// Import a context from serialized bytes.
    public typealias ImportFn = @Sendable (
        _ data: Data
    ) async throws -> String

    /// Register a DID as locally controlled.
    public typealias RegisterLocalDidFn = @Sendable (
        _ did: String
    ) async throws -> Void

    /// Check if a DID is registered as locally controlled.
    public typealias IsLocalDidFn = @Sendable (
        _ did: String
    ) async throws -> Bool

    /// Verify participation requirements via the UniFFI bridge.
    public typealias VerifyParticipationRequirementsFn = @Sendable (
        _ profileJson: String,
        _ requirementsJson: String
    ) throws -> Bool

    public static let defaultDrainEvents: DrainEventsFn = { handle in
        await contextDrainEvents(handle: handle)
    }

    public static let defaultHandleTtlExpiry: HandleTtlExpiryFn = { handle in
        try await contextHandleTtlExpiry(handle: handle)
    }

    public static let defaultProposeTtlExtension: ProposeTtlExtensionFn = { handle, memberDid, proposedSeconds in
        try await contextProposeTtlExtension(
            handle: handle, memberDid: memberDid, proposedSeconds: proposedSeconds
        )
    }

    public static let defaultResetTtlTimer: ResetTtlTimerFn = { handle, newSeconds in
        await contextResetTtlTimer(handle: handle, newSeconds: newSeconds)
    }

    /// Default export function — delegates to UniFFI
    /// ``contextExport(handle:)``.
    public static let defaultExport: ExportFn = { handle in
        try await contextExport(handle: handle)
    }

    /// Default import function — delegates to UniFFI
    /// ``contextImport(data:)``.
    public static let defaultImport: ImportFn = { data in
        try await contextImport(data: data)
    }

    public static let defaultRegisterLocalDid: RegisterLocalDidFn = { did in
        await registerLocalDid(did: did)
    }

    public static let defaultIsLocalDid: IsLocalDidFn = { did in
        await isLocalDid(did: did)
    }

    /// Default verify participation requirements function — delegates to
    /// UniFFI ``verifyParticipationRequirements(profileJson:requirementsJson:)``.
    ///
    /// For a pure-Swift alternative using typed inputs, see
    /// ``verifyParticipationRequirements(requirement:profile:)`` in Trust.swift.
    public static let defaultVerifyParticipationRequirements: VerifyParticipationRequirementsFn = { profileJson, requirementsJson in
        try verifyParticipationRequirements(profileJson: profileJson, requirementsJson: requirementsJson)
    }
}

// MARK: - GovernanceBridge

/// Namespace for UniFFI bridge function references used by governance operations.
public enum GovernanceBridge {
    /// Execute a governance action. Maps to ``governanceExecute`` in ScpBindings.
    public typealias ExecuteFn = @Sendable (
        _ handle: ContextHandle,
        _ proposalJson: String
    ) async throws -> String

    /// Propose a governance action for voting (#621).
    public typealias ProposeFn = @Sendable (
        _ handle: ContextHandle,
        _ proposerDid: String,
        _ actionJson: String
    ) async throws -> String

    /// Approve a pending governance proposal (#621).
    public typealias ApproveFn = @Sendable (
        _ handle: ContextHandle,
        _ voterDid: String,
        _ proposalIdHex: String
    ) async throws -> String

    /// Reject a pending governance proposal (#621).
    public typealias RejectFn = @Sendable (
        _ handle: ContextHandle,
        _ voterDid: String,
        _ proposalIdHex: String
    ) async throws -> String

    /// Withdraw a vote on a pending governance proposal (#621).
    public typealias WithdrawFn = @Sendable (
        _ handle: ContextHandle,
        _ voterDid: String,
        _ proposalIdHex: String
    ) async throws -> String

    /// Default execute function that delegates to the UniFFI-generated binding.
    public static let defaultExecute: ExecuteFn = { handle, proposalJson in
        try await governanceExecute(handle: handle, proposalJson: proposalJson)
    }

    /// Default propose function that delegates to the UniFFI-generated binding.
    public static let defaultPropose: ProposeFn = { handle, proposerDid, actionJson in
        try await governancePropose(
            handle: handle, proposerDid: proposerDid, actionJson: actionJson
        )
    }

    /// Default approve function that delegates to the UniFFI-generated binding.
    public static let defaultApprove: ApproveFn = { handle, voterDid, proposalIdHex in
        try await governanceApprove(
            handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex
        )
    }

    /// Default reject function that delegates to the UniFFI-generated binding.
    public static let defaultReject: RejectFn = { handle, voterDid, proposalIdHex in
        try await governanceReject(
            handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex
        )
    }

    /// Default withdraw function that delegates to the UniFFI-generated binding.
    public static let defaultWithdraw: WithdrawFn = { handle, voterDid, proposalIdHex in
        try await governanceWithdraw(
            handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex
        )
    }

    /// Retrieve a single governance proposal by hex-encoded ID (#621).
    public typealias GetProposalFn = @Sendable (
        _ handle: ContextHandle,
        _ proposalIdHex: String
    ) async throws -> String

    /// List all governance proposals for a context (#621).
    public typealias ListProposalsFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> String

    /// Default get proposal function that delegates to the UniFFI-generated binding.
    public static let defaultGetProposal: GetProposalFn = { handle, proposalIdHex in
        try await governanceGetProposal(
            handle: handle, proposalIdHex: proposalIdHex
        )
    }

    /// Default list proposals function that delegates to the UniFFI-generated binding.
    public static let defaultListProposals: ListProposalsFn = { handle in
        try await governanceListProposals(handle: handle)
    }
}

// MARK: - MembershipBridge

/// Namespace for UniFFI bridge function references used by membership queries.
public enum MembershipBridge {
    /// Return the member count for a context.
    public typealias MemberCountFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> UInt64?

    /// Check whether a DID is a member.
    public typealias IsMemberFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> Bool

    /// Return all member DIDs.
    public typealias MemberDidsFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> [String]

    /// Return a member's role.
    public typealias MemberRoleFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> String?

    public static let defaultMemberCount: MemberCountFn = { handle in
        try await contextMemberCount(handle: handle)
    }

    public static let defaultIsMember: IsMemberFn = { handle, did in
        try await contextIsMember(handle: handle, did: did)
    }

    public static let defaultMemberDids: MemberDidsFn = { handle in
        try await contextMemberDids(handle: handle)
    }

    public static let defaultMemberRole: MemberRoleFn = { handle, did in
        try await contextMemberRole(handle: handle, did: did)
    }
}

// MARK: - BroadcastBridge

/// Namespace for UniFFI bridge function references used by broadcast operations.
public enum BroadcastBridge {
    public typealias SubscribeFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String
    ) async throws -> Void

    public typealias UnsubscribeFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String,
        _ rotateKeys: Bool
    ) async throws -> Void

    public typealias PublishFn = @Sendable (
        _ handle: ContextHandle,
        _ identity: Identity,
        _ payload: Data
    ) async throws -> Void

    public typealias BlockSubscriberFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String,
        _ blockerDid: String
    ) async throws -> Void

    public typealias UnblockSubscriberFn = @Sendable (
        _ handle: ContextHandle,
        _ subscriberDid: String,
        _ unblockerDid: String
    ) async throws -> Void

    public typealias HandleKeyRequestFn = @Sendable (
        _ handle: ContextHandle,
        _ authorDid: String,
        _ requesterDid: String
    ) async throws -> String

    public typealias SubscriberCountFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> UInt64?

    public typealias IsSubscriberFn = @Sendable (
        _ handle: ContextHandle,
        _ did: String
    ) async throws -> Bool

    public typealias AdmissionFn = @Sendable (
        _ handle: ContextHandle
    ) async throws -> String?

    public static let defaultSubscribe: SubscribeFn = { handle, subscriberDid in
        try await broadcastSubscribe(handle: handle, subscriberDid: subscriberDid)
    }

    public static let defaultUnsubscribe: UnsubscribeFn = { handle, subscriberDid, rotateKeys in
        try await broadcastUnsubscribe(
            handle: handle, subscriberDid: subscriberDid, rotateKeys: rotateKeys
        )
    }

    public static let defaultPublish: PublishFn = { handle, identity, payload in
        try await broadcastPublish(handle: handle, identity: identity, payload: payload)
    }

    public static let defaultBlockSubscriber: BlockSubscriberFn = { handle, subscriberDid, blockerDid in
        try await broadcastBlockSubscriber(
            handle: handle, subscriberDid: subscriberDid, blockerDid: blockerDid
        )
    }

    public static let defaultUnblockSubscriber: UnblockSubscriberFn = { handle, subscriberDid, unblockerDid in
        try await broadcastUnblockSubscriber(
            handle: handle, subscriberDid: subscriberDid, unblockerDid: unblockerDid
        )
    }

    public static let defaultHandleKeyRequest: HandleKeyRequestFn = { handle, authorDid, requesterDid in
        try await broadcastHandleKeyRequest(
            handle: handle, authorDid: authorDid, requesterDid: requesterDid
        )
    }

    public static let defaultSubscriberCount: SubscriberCountFn = { handle in
        try await broadcastSubscriberCount(handle: handle)
    }

    public static let defaultIsSubscriber: IsSubscriberFn = { handle, did in
        try await broadcastIsSubscriber(handle: handle, did: did)
    }

    public static let defaultAdmission: AdmissionFn = { handle in
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

// MARK: - Context Governance Proposal Lifecycle Extensions (#621)

public extension Context {
    /// Proposes a governance action for voting.
    ///
    /// For `SingleAdmin` contexts, the proposal is auto-approved and executed
    /// immediately. For multi-admin models (Threshold, Majority, Unanimity),
    /// the proposal enters `Pending` status and must accumulate votes.
    ///
    /// - Parameters:
    ///   - actionJson: JSON-serialized ``GovernanceAction``.
    ///   - proposerDid: DID of the proposer.
    ///   - proposeFn: Bridge function override for testing.
    /// - Returns: JSON string with `proposal_id`, `status`, and `execution_result`.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or the proposal fails.
    func proposeGovernanceAction(
        actionJson: String,
        proposerDid: String,
        proposeFn: GovernanceBridge.ProposeFn = GovernanceBridge.defaultPropose
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2041"
            )
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await proposeFn(contextHandle, proposerDid, actionJson)
    }

    /// Casts an approval vote on a pending governance proposal.
    ///
    /// If the vote pushes the proposal past quorum, the action is auto-executed.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded 32-byte proposal ID.
    ///   - voterDid: DID of the voter.
    ///   - approveFn: Bridge function override for testing.
    /// - Returns: JSON string with `status`.
    /// - Throws: ``ScpError/Context(message:code:)`` if the vote fails.
    func approveGovernanceProposal(
        proposalIdHex: String,
        voterDid: String,
        approveFn: GovernanceBridge.ApproveFn = GovernanceBridge.defaultApprove
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2042"
            )
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await approveFn(contextHandle, voterDid, proposalIdHex)
    }

    /// Casts a rejection vote on a pending governance proposal.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded 32-byte proposal ID.
    ///   - voterDid: DID of the voter.
    ///   - rejectFn: Bridge function override for testing.
    /// - Returns: JSON string with `status`.
    /// - Throws: ``ScpError/Context(message:code:)`` if the vote fails.
    func rejectGovernanceProposal(
        proposalIdHex: String,
        voterDid: String,
        rejectFn: GovernanceBridge.RejectFn = GovernanceBridge.defaultReject
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2043"
            )
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await rejectFn(contextHandle, voterDid, proposalIdHex)
    }

    /// Withdraws a previously cast vote on a pending governance proposal.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded 32-byte proposal ID.
    ///   - voterDid: DID of the voter.
    ///   - withdrawFn: Bridge function override for testing.
    /// - Returns: JSON string with `status`.
    /// - Throws: ``ScpError/Context(message:code:)`` if the withdrawal fails.
    func withdrawGovernanceVote(
        proposalIdHex: String,
        voterDid: String,
        withdrawFn: GovernanceBridge.WithdrawFn = GovernanceBridge.defaultWithdraw
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2044"
            )
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await withdrawFn(contextHandle, voterDid, proposalIdHex)
    }

    /// Retrieves a governance proposal by hex-encoded ID.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded 32-byte proposal ID.
    ///   - getProposalFn: Bridge function override for testing.
    /// - Returns: JSON string with proposal details.
    /// - Throws: ``ScpError/Context(message:code:)`` if the proposal is not found.
    func getGovernanceProposal(
        proposalIdHex: String,
        getProposalFn: GovernanceBridge.GetProposalFn = GovernanceBridge.defaultGetProposal
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2045"
            )
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await getProposalFn(contextHandle, proposalIdHex)
    }

    /// Lists all governance proposals for this context.
    ///
    /// - Parameter listProposalsFn: Bridge function override for testing.
    /// - Returns: JSON array of proposals.
    /// - Throws: ``ScpError/Context(message:code:)`` if listing fails.
    func listGovernanceProposals(
        listProposalsFn: GovernanceBridge.ListProposalsFn = GovernanceBridge.defaultListProposals
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                message: "Context is not active",
                code: "SCP-CTX-2046"
            )
        }
        guard let contextHandle = handle as? ContextHandle else {
            throw ScpError.Context(
                message: "Context handle is not a UniFFI ContextHandle",
                code: "SCP-CTX-2002"
            )
        }
        return try await listProposalsFn(contextHandle)
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
    ///   - identity: The identity of the author publishing the message.
    ///   - payload: The raw message payload.
    ///   - publishFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the context is not
    ///   active or not a broadcast context.
    func broadcastPublish(
        identity: Identity,
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
        try await publishFn(contextHandle, identity, payload)
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

    /// Unblocks a previously blocked subscriber in this broadcast context (§9.16.8).
    ///
    /// Forward-only restoration: the unblocked subscriber can request the
    /// current key on next pull but cannot decrypt content from the block period.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID of the subscriber to unblock.
    ///   - unblockerDid: The DID of the author performing the unblock.
    ///   - unblockSubscriberFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(message:code:)`` if the operation fails.
    func broadcastUnblockSubscriber(
        subscriberDid: String,
        unblockerDid: String,
        unblockSubscriberFn: BroadcastBridge.UnblockSubscriberFn =
            BroadcastBridge.defaultUnblockSubscriber
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
        try await unblockSubscriberFn(contextHandle, subscriberDid, unblockerDid)
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
