@testable import SCP
import XCTest

/// Tests for pure-Swift convenience types in `Types.swift`.
///
/// These tests do NOT require the native UniFFI binary — the capability string
/// helpers are pure Swift string construction.
final class TypesTests: XCTestCase {
    func testCanonicalCapabilityNames() {
        XCTAssertEqual(Capability.Name.messagesRead, "messages:read")
        XCTAssertEqual(Capability.Name.messagesWrite, "messages:write")
        XCTAssertEqual(Capability.Name.outletQueryAll, "outlet:query:*")
        XCTAssertEqual(Capability.Name.outletCallAll, "outlet:call:*")
        XCTAssertEqual(Capability.Name.outletRegister, "outlet:register")
        XCTAssertEqual(Capability.Name.outletInterface, "outlet:interface")
    }

    func testOutletCallCapabilityString() {
        XCTAssertEqual(Capability.outletCall("calculator"), "outlet:call:calculator")
    }

    func testOutletQueryCapabilityString() {
        XCTAssertEqual(Capability.outletQuery("calculator"), "outlet:query:calculator")
    }
}

/// Names every bridge emits, copied from the name functions in
/// crates/scp-ffi/common/src/governance_result.rs. Listed here as literals so a
/// test reads each name a bridge sends, not the enum under test.
private let rustActionResultNames = [
    "MemberAdded", "MemberRemoved", "RoleChanged", "OutletRegistered", "OutletRemoved",
    "CeilingModified", "ContextClosed", "TtlExtended", "PruningPolicyModified",
    "AdminTransferred", "SignerAdded", "SignerRemoved", "ThresholdModified",
    "ChildContextCreated", "OutletInterfaceEstablished", "MemberReset", "ConflictResolved",
    "ContextPromoted", "MemberSuspended", "AccessRevoked", "AccessRestored",
    "ContentKeysRotated", "GovernanceReconfigured", "SubscriberBanned", "SubscriberUnbanned",
    "Executed", "MigrationProposed", "MigrationCancelled", "ContextTombstoned"
]
private let rustProposalStatusNames = [
    "Pending", "Approved", "Rejected", "Expired", "Cancelled", "Invalidated"
]
private let rustRejectionReasonNames = [
    "AdminRejected", "MajorityRejected", "UnanimityBroken", "ApprovalImpossible",
    "InsufficientParticipation"
]

private func assertGov11040(
    _ run: () throws -> Any,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    XCTAssertThrowsError(try run(), file: file, line: line) { error in
        guard case let ScpError.Context(_, code) = error else {
            return XCTFail("expected ScpError.Context, got \(error)", file: file, line: line)
        }
        XCTAssertEqual(code, "SCP-GOV-11040", file: file, line: line)
    }
}

final class GovernanceTypesTests: XCTestCase {
    func testEveryActionResultNameParses() throws {
        for name in rustActionResultNames {
            XCTAssertEqual(try GovernanceActionResult.fromBridge(name).rawValue, name)
        }
    }

    func testEveryProposalStatusNameParses() throws {
        for name in rustProposalStatusNames {
            XCTAssertEqual(try ProposalStatus.fromBridge(name).rawValue, name)
        }
    }

    func testEveryRejectionReasonNameParses() throws {
        for name in rustRejectionReasonNames {
            XCTAssertEqual(try RejectionReason.fromBridge(name).rawValue, name)
        }
    }

    func testUnknownNameThrowsGov11040() {
        for raw in ["SomethingThisSdkDoesNotKnow", "", " Executed", "executed"] {
            assertGov11040 { try GovernanceActionResult.fromBridge(raw) }
            assertGov11040 { try ProposalStatus.fromBridge(raw) }
            assertGov11040 { try RejectionReason.fromBridge(raw) }
        }
    }

    func testCheckProposalResponseReturnsKnownResponses() throws {
        for raw in [
            #"{"proposal_id":"ab","status":"Approved","execution_result":"RoleChanged"}"#,
            #"{"proposal_id":"ab","status":"Pending","execution_result":null}"#,
            #"{"status":"Rejected","reason":"UnanimityBroken","rejector":"did:dht:zA"}"#,
            #"{"status":"Invalidated","reason":"proposer removed"}"#,
            #"{"status":"Cancelled"}"#
        ] {
            XCTAssertEqual(try checkProposalResponse(raw), raw)
        }
    }

    func testCheckProposalResponseThrowsGov11040OnUnreadableNames() {
        for raw in [
            #"{"status":"Approved","execution_result":"SomethingNew"}"#,
            #"{"status":"SomethingNew"}"#,
            #"{"status":"Rejected","reason":"SomethingNew"}"#,
            #"{"status":"Rejected"}"#,
            #"{"status":"Invalidated"}"#,
            #"{"execution_result":"Executed"}"#,
            #"{"status":"Approved","execution_result":7}"#,
            "not json",
            "[]"
        ] {
            assertGov11040 { try checkProposalResponse(raw) }
        }
    }
}

/// `MemberRole.fromBridge` reads `RoleAssignment.role_name`.
final class MemberRoleTypesTests: XCTestCase {
    func testAuthorAndSubscriberAreBuiltInRoles() throws {
        XCTAssertEqual(try MemberRole.fromBridge("author"), .author)
        XCTAssertEqual(try MemberRole.fromBridge("subscriber"), .subscriber)
    }

    func testEveryReservedNameParsesToItsBuiltInRole() throws {
        // The six names `RESERVED_ROLE_NAMES` in
        // `crates/scp-protocol/src/context/roles.rs` reserves.
        let expected: [String: MemberRole] = [
            "admin": .admin, "moderator": .moderator, "member": .member,
            "observer": .observer, "author": .author, "subscriber": .subscriber
        ]
        for (raw, role) in expected {
            XCTAssertEqual(try MemberRole.fromBridge(raw), role, raw)
        }
    }

    func testGovernanceDefinedRoleCarriesItsName() throws {
        XCTAssertEqual(
            try MemberRole.fromBridge("night-shift-reviewer"),
            .custom(name: "night-shift-reviewer")
        )
    }

    func testMalformedNameThrowsGov11040() {
        for raw in ["Author", "My-role", "", "-lead", "a b", String(repeating: "x", count: 65)] {
            assertGov11040 { try MemberRole.fromBridge(raw) }
        }
    }
}
