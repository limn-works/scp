import Foundation
@testable import SCP
import Testing

// MARK: - Governance Tests

// Tests for governance actions, membership queries, broadcast operations,
// and their associated enums and bridge delegation.
//
// All functions in Governance.swift use the injectable bridge pattern: tests
// inject mock closures that capture arguments and return canned responses,
// isolating the Swift ergonomics layer from the UniFFI/Rust runtime.
//
// See ADR-026 (Swift SDK), ADR-031 (governance actions), spec §5.9.
// swiftlint:disable:next type_body_length
struct GovernanceTests {
    // MARK: - Helpers

    /// Creates a ``Context`` with a real ``ContextHandle`` for active-state testing.
    ///
    /// Uses `ContextHandle(noPointer: .init())` so that `handle as? ContextHandle`
    /// succeeds inside governance/membership/broadcast methods.
    private func makeActiveContext() -> Context {
        let handle = ContextHandle(noPointer: .init())
        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        return Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )
    }

    /// Creates a ``Context`` backed by a mock handle that can start in a closed state.
    private func makeClosedContext() async throws -> Context {
        let context = makeActiveContext()
        try await context.close()
        return context
    }

    // MARK: - GovernanceActionResult enum tests

    @Test("GovernanceActionResult has exactly 28 cases")
    func governanceActionResultCount() {
        let allCases: [GovernanceActionResult] = [
            .memberAdded, .memberRemoved, .roleChanged,
            .toolRegistered, .toolRemoved, .ceilingModified,
            .contextClosed, .ttlExtended, .pruningPolicyModified,
            .adminTransferred, .signerAdded, .signerRemoved,
            .thresholdModified, .childContextCreated, .toolInterfaceEstablished,
            .memberReset, .conflictResolved, .contextPromoted,
            .readAccessRevoked, .readAccessRestored,
            .writeAccessRevoked, .writeAccessRestored,
            .contentKeysRotated, .governanceReconfigured,
            .authorBlocked, .subscriberBanned, .subscriberUnbanned,
            .executed
        ]
        #expect(allCases.count == 28)
    }

    @Test("GovernanceActionResult raw values match Rust GovernanceActionResult variants")
    func governanceActionResultRawValues() {
        #expect(GovernanceActionResult.memberAdded.rawValue == "MemberAdded")
        #expect(GovernanceActionResult.memberRemoved.rawValue == "MemberRemoved")
        #expect(GovernanceActionResult.roleChanged.rawValue == "RoleChanged")
        #expect(GovernanceActionResult.toolRegistered.rawValue == "ToolRegistered")
        #expect(GovernanceActionResult.toolRemoved.rawValue == "ToolRemoved")
        #expect(GovernanceActionResult.ceilingModified.rawValue == "CeilingModified")
        #expect(GovernanceActionResult.contextClosed.rawValue == "ContextClosed")
        #expect(GovernanceActionResult.ttlExtended.rawValue == "TtlExtended")
        #expect(GovernanceActionResult.pruningPolicyModified.rawValue == "PruningPolicyModified")
        #expect(GovernanceActionResult.adminTransferred.rawValue == "AdminTransferred")
        #expect(GovernanceActionResult.signerAdded.rawValue == "SignerAdded")
        #expect(GovernanceActionResult.signerRemoved.rawValue == "SignerRemoved")
        #expect(GovernanceActionResult.thresholdModified.rawValue == "ThresholdModified")
        #expect(GovernanceActionResult.childContextCreated.rawValue == "ChildContextCreated")
        #expect(GovernanceActionResult.toolInterfaceEstablished.rawValue == "ToolInterfaceEstablished")
        #expect(GovernanceActionResult.memberReset.rawValue == "MemberReset")
        #expect(GovernanceActionResult.conflictResolved.rawValue == "ConflictResolved")
        #expect(GovernanceActionResult.contextPromoted.rawValue == "ContextPromoted")
        #expect(GovernanceActionResult.readAccessRevoked.rawValue == "ReadAccessRevoked")
        #expect(GovernanceActionResult.readAccessRestored.rawValue == "ReadAccessRestored")
        #expect(GovernanceActionResult.writeAccessRevoked.rawValue == "WriteAccessRevoked")
        #expect(GovernanceActionResult.writeAccessRestored.rawValue == "WriteAccessRestored")
        #expect(GovernanceActionResult.contentKeysRotated.rawValue == "ContentKeysRotated")
        #expect(GovernanceActionResult.governanceReconfigured.rawValue == "GovernanceReconfigured")
        #expect(GovernanceActionResult.authorBlocked.rawValue == "AuthorBlocked")
        #expect(GovernanceActionResult.subscriberBanned.rawValue == "SubscriberBanned")
        #expect(GovernanceActionResult.subscriberUnbanned.rawValue == "SubscriberUnbanned")
        #expect(GovernanceActionResult.executed.rawValue == "Executed")
    }

    @Test("GovernanceActionResult can be constructed from raw value")
    func governanceActionResultFromRawValue() {
        #expect(GovernanceActionResult(rawValue: "MemberAdded") == .memberAdded)
        #expect(GovernanceActionResult(rawValue: "ContentKeysRotated") == .contentKeysRotated)
        #expect(GovernanceActionResult(rawValue: "Executed") == .executed)
        #expect(GovernanceActionResult(rawValue: "InvalidAction") == nil)
    }

    @Test("GovernanceActionResult is Sendable")
    func governanceActionResultIsSendable() async {
        let result: GovernanceActionResult = .memberAdded
        let task = Task { result }
        let value = await task.value
        #expect(value == .memberAdded)
    }

    // MARK: - MemberRole enum tests

    @Test("MemberRole has correct raw values")
    func memberRoleRawValues() {
        #expect(MemberRole.admin.rawValue == "Admin")
        #expect(MemberRole.member.rawValue == "Member")
        #expect(MemberRole.observer.rawValue == "Observer")
        #expect(MemberRole.custom.rawValue == "Custom")
    }

    @Test("MemberRole.fromBridge parses known roles")
    func memberRoleFromBridgeKnown() {
        #expect(MemberRole.fromBridge("Admin") == .admin)
        #expect(MemberRole.fromBridge("Member") == .member)
        #expect(MemberRole.fromBridge("Observer") == .observer)
        #expect(MemberRole.fromBridge("Custom") == .custom)
    }

    @Test("MemberRole.fromBridge handles capitalization")
    func memberRoleFromBridgeCapitalization() {
        #expect(MemberRole.fromBridge("admin") == .admin)
        #expect(MemberRole.fromBridge("member") == .member)
        #expect(MemberRole.fromBridge("observer") == .observer)
    }

    @Test("MemberRole.fromBridge trims whitespace and quotes")
    func memberRoleFromBridgeTrimming() {
        #expect(MemberRole.fromBridge("  Admin  ") == .admin)
        #expect(MemberRole.fromBridge("\"Member\"") == .member)
        #expect(MemberRole.fromBridge("  \"Observer\"  ") == .observer)
    }

    @Test("MemberRole.fromBridge falls back to .custom for unknown strings")
    func memberRoleFromBridgeFallback() {
        #expect(MemberRole.fromBridge("Moderator") == .custom)
        #expect(MemberRole.fromBridge("") == .custom)
        #expect(MemberRole.fromBridge("ADMIN") == .custom) // not "Admin" or "admin"
    }

    @Test("MemberRole is Sendable")
    func memberRoleIsSendable() async {
        let role: MemberRole = .admin
        let task = Task { role }
        let value = await task.value
        #expect(value == .admin)
    }

    // MARK: - executeGovernanceAction tests

    @Test("executeGovernanceAction calls bridge and returns parsed result")
    func executeGovernanceActionRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedJson: String?
        let mockExecute: GovernanceBridge.ExecuteFn = { _, proposalJson in
            receivedJson = proposalJson
            return "MemberAdded"
        }

        let result = try await context.executeGovernanceAction(
            proposalJson: #"{"action":"add_member","did":"did:dht:z6MkAlice"}"#,
            executeFn: mockExecute
        )

        #expect(result == .memberAdded)
        #expect(receivedJson == #"{"action":"add_member","did":"did:dht:z6MkAlice"}"#)
    }

    @Test("executeGovernanceAction returns .executed for unknown result strings")
    func executeGovernanceActionFallback() async throws {
        let context = makeActiveContext()

        let mockExecute: GovernanceBridge.ExecuteFn = { _, _ in
            "SomeUnknownResult"
        }

        let result = try await context.executeGovernanceAction(
            proposalJson: "{}",
            executeFn: mockExecute
        )

        #expect(result == .executed)
    }

    @Test("executeGovernanceAction returns each of the 28 result types")
    func executeGovernanceActionAllResults() async throws {
        let context = makeActiveContext()

        let expectedPairs: [(String, GovernanceActionResult)] = [
            ("MemberAdded", .memberAdded),
            ("MemberRemoved", .memberRemoved),
            ("RoleChanged", .roleChanged),
            ("ToolRegistered", .toolRegistered),
            ("ToolRemoved", .toolRemoved),
            ("CeilingModified", .ceilingModified),
            ("ContextClosed", .contextClosed),
            ("TtlExtended", .ttlExtended),
            ("PruningPolicyModified", .pruningPolicyModified),
            ("AdminTransferred", .adminTransferred),
            ("SignerAdded", .signerAdded),
            ("SignerRemoved", .signerRemoved),
            ("ThresholdModified", .thresholdModified),
            ("ChildContextCreated", .childContextCreated),
            ("ToolInterfaceEstablished", .toolInterfaceEstablished),
            ("MemberReset", .memberReset),
            ("ConflictResolved", .conflictResolved),
            ("ContextPromoted", .contextPromoted),
            ("ReadAccessRevoked", .readAccessRevoked),
            ("ReadAccessRestored", .readAccessRestored),
            ("WriteAccessRevoked", .writeAccessRevoked),
            ("WriteAccessRestored", .writeAccessRestored),
            ("ContentKeysRotated", .contentKeysRotated),
            ("GovernanceReconfigured", .governanceReconfigured),
            ("AuthorBlocked", .authorBlocked),
            ("SubscriberBanned", .subscriberBanned),
            ("SubscriberUnbanned", .subscriberUnbanned),
            ("Executed", .executed)
        ]

        for (rawValue, expected) in expectedPairs {
            let mockExecute: GovernanceBridge.ExecuteFn = { _, _ in rawValue }
            let result = try await context.executeGovernanceAction(
                proposalJson: "{}",
                executeFn: mockExecute
            )
            #expect(result == expected, "Expected \(expected) for raw value \"\(rawValue)\"")
        }
    }

    @Test("executeGovernanceAction throws SCP-CTX-2001 when context is closed")
    func executeGovernanceActionThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.executeGovernanceAction(proposalJson: "{}")
            Issue.record("Expected executeGovernanceAction to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("executeGovernanceAction propagates bridge errors")
    func executeGovernanceActionPropagatesBridgeErrors() async throws {
        let context = makeActiveContext()

        let mockExecute: GovernanceBridge.ExecuteFn = { _, _ in
            throw ScpError.Permission(
                message: "Not authorized to execute governance action",
                code: "SCP-PERM-3001"
            )
        }

        do {
            _ = try await context.executeGovernanceAction(
                proposalJson: "{}",
                executeFn: mockExecute
            )
            Issue.record("Expected bridge error to propagate")
        } catch let error as ScpError {
            if case let .Permission(message, code) = error {
                #expect(code == "SCP-PERM-3001")
                #expect(message.contains("Not authorized"))
            } else {
                Issue.record("Expected ScpError.Permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Membership query tests

    @Test("memberCount calls bridge and returns count")
    func memberCountRoundtrip() async throws {
        let context = makeActiveContext()

        let mockMemberCount: MembershipBridge.MemberCountFn = { _ in 42 }

        let count = try await context.memberCount(memberCountFn: mockMemberCount)
        #expect(count == 42)
    }

    @Test("memberCount returns nil when bridge returns nil")
    func memberCountReturnsNil() async throws {
        let context = makeActiveContext()

        let mockMemberCount: MembershipBridge.MemberCountFn = { _ in nil }

        let count = try await context.memberCount(memberCountFn: mockMemberCount)
        #expect(count == nil)
    }

    @Test("memberCount throws SCP-CTX-2001 when context is closed")
    func memberCountThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.memberCount()
            Issue.record("Expected memberCount to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("isMember calls bridge and returns result")
    func isMemberRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedDid: String?
        let mockIsMember: MembershipBridge.IsMemberFn = { _, did in
            receivedDid = did
            return true
        }

        let result = try await context.isMember(did: "did:dht:z6MkAlice", isMemberFn: mockIsMember)
        #expect(result == true)
        #expect(receivedDid == "did:dht:z6MkAlice")
    }

    @Test("isMember returns false for non-members")
    func isMemberReturnsFalse() async throws {
        let context = makeActiveContext()

        let mockIsMember: MembershipBridge.IsMemberFn = { _, _ in false }

        let result = try await context.isMember(did: "did:dht:z6MkUnknown", isMemberFn: mockIsMember)
        #expect(result == false)
    }

    @Test("isMember throws SCP-CTX-2001 when context is closed")
    func isMemberThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.isMember(did: "did:dht:z6MkAlice")
            Issue.record("Expected isMember to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("memberDids calls bridge and returns DID list")
    func memberDidsRoundtrip() async throws {
        let context = makeActiveContext()

        let mockMemberDids: MembershipBridge.MemberDidsFn = { _ in
            ["did:dht:z6MkAlice", "did:dht:z6MkBob", "did:dht:z6MkCarol"]
        }

        let dids = try await context.memberDids(memberDidsFn: mockMemberDids)
        #expect(dids.count == 3)
        #expect(dids[0] == "did:dht:z6MkAlice")
        #expect(dids[1] == "did:dht:z6MkBob")
        #expect(dids[2] == "did:dht:z6MkCarol")
    }

    @Test("memberDids returns empty array when no members")
    func memberDidsEmpty() async throws {
        let context = makeActiveContext()

        let mockMemberDids: MembershipBridge.MemberDidsFn = { _ in [] }

        let dids = try await context.memberDids(memberDidsFn: mockMemberDids)
        #expect(dids.isEmpty)
    }

    @Test("memberDids throws SCP-CTX-2001 when context is closed")
    func memberDidsThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.memberDids()
            Issue.record("Expected memberDids to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("memberRole calls bridge and returns parsed role")
    func memberRoleRoundtrip() async throws {
        let context = makeActiveContext()

        let mockMemberRole: MembershipBridge.MemberRoleFn = { _, did in
            switch did {
            case "did:dht:z6MkAlice": return "Admin"
            case "did:dht:z6MkBob": return "Member"
            case "did:dht:z6MkCarol": return "Observer"
            default: return nil
            }
        }

        let aliceRole = try await context.memberRole(
            did: "did:dht:z6MkAlice", memberRoleFn: mockMemberRole
        )
        #expect(aliceRole == .admin)

        let bobRole = try await context.memberRole(
            did: "did:dht:z6MkBob", memberRoleFn: mockMemberRole
        )
        #expect(bobRole == .member)

        let carolRole = try await context.memberRole(
            did: "did:dht:z6MkCarol", memberRoleFn: mockMemberRole
        )
        #expect(carolRole == .observer)
    }

    @Test("memberRole returns nil for unknown members")
    func memberRoleReturnsNil() async throws {
        let context = makeActiveContext()

        let mockMemberRole: MembershipBridge.MemberRoleFn = { _, _ in nil }

        let role = try await context.memberRole(
            did: "did:dht:z6MkUnknown", memberRoleFn: mockMemberRole
        )
        #expect(role == nil)
    }

    @Test("memberRole throws SCP-CTX-2001 when context is closed")
    func memberRoleThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.memberRole(did: "did:dht:z6MkAlice")
            Issue.record("Expected memberRole to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Broadcast operation tests

    @Test("broadcastSubscribe calls bridge with subscriber DID")
    func broadcastSubscribeRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedDid: String?
        let mockSubscribe: BroadcastBridge.SubscribeFn = { _, did in
            receivedDid = did
        }

        try await context.broadcastSubscribe(
            subscriberDid: "did:dht:z6MkSub",
            subscribeFn: mockSubscribe
        )
        #expect(receivedDid == "did:dht:z6MkSub")
    }

    @Test("broadcastSubscribe throws SCP-CTX-2001 when context is closed")
    func broadcastSubscribeThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            try await context.broadcastSubscribe(subscriberDid: "did:dht:z6MkSub")
            Issue.record("Expected broadcastSubscribe to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("broadcastUnsubscribe calls bridge with DID and rotateKeys flag")
    func broadcastUnsubscribeRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedDid: String?
        var receivedRotate: Bool?
        let mockUnsubscribe: BroadcastBridge.UnsubscribeFn = { _, did, rotate in
            receivedDid = did
            receivedRotate = rotate
        }

        try await context.broadcastUnsubscribe(
            subscriberDid: "did:dht:z6MkSub",
            rotateKeys: true,
            unsubscribeFn: mockUnsubscribe
        )
        #expect(receivedDid == "did:dht:z6MkSub")
        #expect(receivedRotate == true)
    }

    @Test("broadcastUnsubscribe defaults rotateKeys to false")
    func broadcastUnsubscribeDefaultRotate() async throws {
        let context = makeActiveContext()

        var receivedRotate: Bool?
        let mockUnsubscribe: BroadcastBridge.UnsubscribeFn = { _, _, rotate in
            receivedRotate = rotate
        }

        try await context.broadcastUnsubscribe(
            subscriberDid: "did:dht:z6MkSub",
            unsubscribeFn: mockUnsubscribe
        )
        #expect(receivedRotate == false)
    }

    @Test("broadcastUnsubscribe throws SCP-CTX-2001 when context is closed")
    func broadcastUnsubscribeThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            try await context.broadcastUnsubscribe(subscriberDid: "did:dht:z6MkSub")
            Issue.record("Expected broadcastUnsubscribe to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("broadcastPublish calls bridge with author DID and payload")
    func broadcastPublishRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedAuthor: String?
        var receivedPayload: Data?
        let mockPublish: BroadcastBridge.PublishFn = { _, author, payload in
            receivedAuthor = author
            receivedPayload = payload
        }

        let payload = Data("broadcast message".utf8)
        try await context.broadcastPublish(
            authorDid: "did:dht:z6MkAuthor",
            payload: payload,
            publishFn: mockPublish
        )
        #expect(receivedAuthor == "did:dht:z6MkAuthor")
        #expect(receivedPayload == payload)
    }

    @Test("broadcastPublish throws SCP-CTX-2001 when context is closed")
    func broadcastPublishThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            try await context.broadcastPublish(
                authorDid: "did:dht:z6MkAuthor",
                payload: Data("msg".utf8)
            )
            Issue.record("Expected broadcastPublish to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("broadcastBlockSubscriber calls bridge with subscriber and blocker DIDs")
    func broadcastBlockSubscriberRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedSubscriber: String?
        var receivedBlocker: String?
        let mockBlock: BroadcastBridge.BlockSubscriberFn = { _, subscriber, blocker in
            receivedSubscriber = subscriber
            receivedBlocker = blocker
        }

        try await context.broadcastBlockSubscriber(
            subscriberDid: "did:dht:z6MkBadActor",
            blockerDid: "did:dht:z6MkAdmin",
            blockSubscriberFn: mockBlock
        )
        #expect(receivedSubscriber == "did:dht:z6MkBadActor")
        #expect(receivedBlocker == "did:dht:z6MkAdmin")
    }

    @Test("broadcastBlockSubscriber throws SCP-CTX-2001 when context is closed")
    func broadcastBlockSubscriberThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            try await context.broadcastBlockSubscriber(
                subscriberDid: "did:dht:z6MkBad",
                blockerDid: "did:dht:z6MkAdmin"
            )
            Issue.record("Expected broadcastBlockSubscriber to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("broadcastHandleKeyRequest calls bridge and returns decision")
    func broadcastHandleKeyRequestRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedAuthor: String?
        var receivedRequester: String?
        let mockKeyRequest: BroadcastBridge.HandleKeyRequestFn = { _, author, requester in
            receivedAuthor = author
            receivedRequester = requester
            return "Approved"
        }

        let decision = try await context.broadcastHandleKeyRequest(
            authorDid: "did:dht:z6MkAuthor",
            requesterDid: "did:dht:z6MkRequester",
            handleKeyRequestFn: mockKeyRequest
        )
        #expect(decision == "Approved")
        #expect(receivedAuthor == "did:dht:z6MkAuthor")
        #expect(receivedRequester == "did:dht:z6MkRequester")
    }

    @Test("broadcastHandleKeyRequest throws SCP-CTX-2001 when context is closed")
    func broadcastHandleKeyRequestThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.broadcastHandleKeyRequest(
                authorDid: "did:dht:z6MkAuthor",
                requesterDid: "did:dht:z6MkRequester"
            )
            Issue.record("Expected broadcastHandleKeyRequest to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("broadcastSubscriberCount calls bridge and returns count")
    func broadcastSubscriberCountRoundtrip() async throws {
        let context = makeActiveContext()

        let mockCount: BroadcastBridge.SubscriberCountFn = { _ in 17 }

        let count = try await context.broadcastSubscriberCount(subscriberCountFn: mockCount)
        #expect(count == 17)
    }

    @Test("broadcastSubscriberCount returns nil for non-broadcast context")
    func broadcastSubscriberCountReturnsNil() async throws {
        let context = makeActiveContext()

        let mockCount: BroadcastBridge.SubscriberCountFn = { _ in nil }

        let count = try await context.broadcastSubscriberCount(subscriberCountFn: mockCount)
        #expect(count == nil)
    }

    @Test("broadcastSubscriberCount throws SCP-CTX-2001 when context is closed")
    func broadcastSubscriberCountThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.broadcastSubscriberCount()
            Issue.record("Expected broadcastSubscriberCount to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("broadcastIsSubscriber calls bridge and returns result")
    func broadcastIsSubscriberRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedDid: String?
        let mockIsSubscriber: BroadcastBridge.IsSubscriberFn = { _, did in
            receivedDid = did
            return true
        }

        let result = try await context.broadcastIsSubscriber(
            did: "did:dht:z6MkSub",
            isSubscriberFn: mockIsSubscriber
        )
        #expect(result == true)
        #expect(receivedDid == "did:dht:z6MkSub")
    }

    @Test("broadcastIsSubscriber returns false for non-subscribers")
    func broadcastIsSubscriberReturnsFalse() async throws {
        let context = makeActiveContext()

        let mockIsSubscriber: BroadcastBridge.IsSubscriberFn = { _, _ in false }

        let result = try await context.broadcastIsSubscriber(
            did: "did:dht:z6MkUnknown",
            isSubscriberFn: mockIsSubscriber
        )
        #expect(result == false)
    }

    @Test("broadcastIsSubscriber throws SCP-CTX-2001 when context is closed")
    func broadcastIsSubscriberThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.broadcastIsSubscriber(did: "did:dht:z6MkSub")
            Issue.record("Expected broadcastIsSubscriber to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("broadcastAdmission calls bridge and returns policy string")
    func broadcastAdmissionRoundtrip() async throws {
        let context = makeActiveContext()

        let mockAdmission: BroadcastBridge.AdmissionFn = { _ in "Open" }

        let policy = try await context.broadcastAdmission(admissionFn: mockAdmission)
        #expect(policy == "Open")
    }

    @Test("broadcastAdmission returns Gated policy")
    func broadcastAdmissionGated() async throws {
        let context = makeActiveContext()

        let mockAdmission: BroadcastBridge.AdmissionFn = { _ in "Gated" }

        let policy = try await context.broadcastAdmission(admissionFn: mockAdmission)
        #expect(policy == "Gated")
    }

    @Test("broadcastAdmission returns nil for non-broadcast context")
    func broadcastAdmissionReturnsNil() async throws {
        let context = makeActiveContext()

        let mockAdmission: BroadcastBridge.AdmissionFn = { _ in nil }

        let policy = try await context.broadcastAdmission(admissionFn: mockAdmission)
        #expect(policy == nil)
    }

    @Test("broadcastAdmission throws SCP-CTX-2001 when context is closed")
    func broadcastAdmissionThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.broadcastAdmission()
            Issue.record("Expected broadcastAdmission to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Bridge error propagation tests

    @Test("memberCount propagates bridge errors")
    func memberCountPropagatesBridgeErrors() async throws {
        let context = makeActiveContext()

        let mockMemberCount: MembershipBridge.MemberCountFn = { _ in
            throw ScpError.Context(message: "Internal error", code: "SCP-CTX-2099")
        }

        do {
            _ = try await context.memberCount(memberCountFn: mockMemberCount)
            Issue.record("Expected bridge error to propagate")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2099")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("broadcastPublish propagates bridge errors")
    func broadcastPublishPropagatesBridgeErrors() async throws {
        let context = makeActiveContext()

        let mockPublish: BroadcastBridge.PublishFn = { _, _, _ in
            throw ScpError.Permission(
                message: "Not authorized to publish",
                code: "SCP-PERM-3002"
            )
        }

        do {
            try await context.broadcastPublish(
                authorDid: "did:dht:z6MkUnauthorized",
                payload: Data("msg".utf8),
                publishFn: mockPublish
            )
            Issue.record("Expected bridge error to propagate")
        } catch let error as ScpError {
            if case let .Permission(_, code) = error {
                #expect(code == "SCP-PERM-3002")
            } else {
                Issue.record("Expected ScpError.Permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Context Lifecycle Extension tests

    @Test("drainEvents calls bridge and returns event list")
    func drainEventsRoundtrip() async throws {
        let context = makeActiveContext()

        let mockDrain: ContextLifecycleBridge.DrainEventsFn = { _ in
            ["MemberJoined(did:dht:z6MkAlice)", "MessageSent(payload_len=42)"]
        }

        let events = try await context.drainEvents(drainEventsFn: mockDrain)
        #expect(events.count == 2)
        #expect(events[0].contains("MemberJoined"))
        #expect(events[1].contains("MessageSent"))
    }

    @Test("drainEvents returns empty array when no events")
    func drainEventsEmpty() async throws {
        let context = makeActiveContext()

        let mockDrain: ContextLifecycleBridge.DrainEventsFn = { _ in [] }

        let events = try await context.drainEvents(drainEventsFn: mockDrain)
        #expect(events.isEmpty)
    }

    @Test("drainEvents throws SCP-CTX-2001 when context is closed")
    func drainEventsThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.drainEvents()
            Issue.record("Expected drainEvents to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("handleTtlExpiry calls bridge and transitions state to expired")
    func handleTtlExpiryRoundtrip() async throws {
        let context = makeActiveContext()

        var called = false
        let mockExpiry: ContextLifecycleBridge.HandleTtlExpiryFn = { _ in
            called = true
        }

        try await context.handleTtlExpiry(handleTtlExpiryFn: mockExpiry)
        #expect(called)
        #expect(context.state == .expired)
    }

    @Test("handleTtlExpiry throws SCP-CTX-2001 when context is closed")
    func handleTtlExpiryThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            try await context.handleTtlExpiry()
            Issue.record("Expected handleTtlExpiry to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("proposeTtlExtension calls bridge with member DID and duration")
    func proposeTtlExtensionRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedDid: String?
        var receivedSeconds: UInt64?
        let mockPropose: ContextLifecycleBridge.ProposeTtlExtensionFn = { _, did, seconds in
            receivedDid = did
            receivedSeconds = seconds
            return true
        }

        let unanimous = try await context.proposeTtlExtension(
            memberDid: "did:dht:z6MkAlice",
            proposedSeconds: 3600,
            proposeTtlExtensionFn: mockPropose
        )
        #expect(unanimous == true)
        #expect(receivedDid == "did:dht:z6MkAlice")
        #expect(receivedSeconds == 3600)
    }

    @Test("proposeTtlExtension returns false when not unanimous")
    func proposeTtlExtensionNotUnanimous() async throws {
        let context = makeActiveContext()

        let mockPropose: ContextLifecycleBridge.ProposeTtlExtensionFn = { _, _, _ in false }

        let result = try await context.proposeTtlExtension(
            memberDid: "did:dht:z6MkBob",
            proposedSeconds: 7200,
            proposeTtlExtensionFn: mockPropose
        )
        #expect(result == false)
    }

    @Test("proposeTtlExtension throws SCP-CTX-2001 when context is closed")
    func proposeTtlExtensionThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.proposeTtlExtension(
                memberDid: "did:dht:z6MkAlice",
                proposedSeconds: 3600
            )
            Issue.record("Expected proposeTtlExtension to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("resetTtlTimer calls bridge with new duration")
    func resetTtlTimerRoundtrip() async throws {
        let context = makeActiveContext()

        var receivedSeconds: UInt64?
        let mockReset: ContextLifecycleBridge.ResetTtlTimerFn = { _, seconds in
            receivedSeconds = seconds
        }

        try await context.resetTtlTimer(newSeconds: 7200, resetTtlTimerFn: mockReset)
        #expect(receivedSeconds == 7200)
    }

    @Test("resetTtlTimer throws SCP-CTX-2001 when context is closed")
    func resetTtlTimerThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            try await context.resetTtlTimer(newSeconds: 3600)
            Issue.record("Expected resetTtlTimer to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("exportContext calls bridge and returns data")
    func exportContextRoundtrip() async throws {
        let context = makeActiveContext()

        let mockExport: ContextLifecycleBridge.ExportFn = { _ in
            Data("exported-context-data".utf8)
        }

        let data = try await context.exportContext(exportFn: mockExport)
        #expect(String(data: data, encoding: .utf8) == "exported-context-data")
    }

    @Test("exportContext throws SCP-CTX-2001 when context is closed")
    func exportContextThrowsWhenClosed() async throws {
        let context = try await makeClosedContext()

        do {
            _ = try await context.exportContext()
            Issue.record("Expected exportContext to throw on closed context")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                // SCP-CTX-2001 (context not active)
                #expect(code == "SCP-CTX-2001")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("importContext calls bridge and returns context ID")
    func importContextRoundtrip() async throws {
        let mockImport: ContextLifecycleBridge.ImportFn = { _ in
            "ctx-imported-123"
        }

        let contextId = try await importContext(
            data: Data("serialized".utf8),
            importFn: mockImport
        )
        #expect(contextId == "ctx-imported-123")
    }

    // MARK: - Local DID Management tests

    @Test("registerLocalDid calls bridge with DID")
    func registerLocalDidRoundtrip() async throws {
        var receivedDid: String?
        let mockRegister: ContextLifecycleBridge.RegisterLocalDidFn = { did in
            receivedDid = did
        }

        try await registerLocalDid(did: "did:dht:z6MkLocal", registerLocalDidFn: mockRegister)
        #expect(receivedDid == "did:dht:z6MkLocal")
    }

    @Test("isLocalDid calls bridge and returns result")
    func isLocalDidRoundtrip() async throws {
        var receivedDid: String?
        let mockIsLocal: ContextLifecycleBridge.IsLocalDidFn = { did in
            receivedDid = did
            return true
        }

        let result = try await isLocalDid(did: "did:dht:z6MkLocal", isLocalDidFn: mockIsLocal)
        #expect(result == true)
        #expect(receivedDid == "did:dht:z6MkLocal")
    }

    @Test("isLocalDid returns false for unregistered DID")
    func isLocalDidReturnsFalse() async throws {
        let mockIsLocal: ContextLifecycleBridge.IsLocalDidFn = { _ in false }

        let result = try await isLocalDid(did: "did:dht:z6MkUnknown", isLocalDidFn: mockIsLocal)
        #expect(result == false)
    }

    // MARK: - Participation Requirements Bridge tests

    @Test("verifyParticipationRequirementsBridge calls bridge with JSON")
    func verifyParticipationRequirementsBridgeRoundtrip() throws {
        var receivedProfile: String?
        var receivedRequirements: String?
        let mockVerify: ContextLifecycleBridge.VerifyParticipationRequirementsFn = { profile, requirements in
            receivedProfile = profile
            receivedRequirements = requirements
            return true
        }

        let result = try verifyParticipationRequirementsBridge(
            profileJson: "[{}]",
            requirementsJson: "[{}]",
            verifyFn: mockVerify
        )
        #expect(result == true)
        #expect(receivedProfile == "[{}]")
        #expect(receivedRequirements == "[{}]")
    }
} // end GovernanceTests
