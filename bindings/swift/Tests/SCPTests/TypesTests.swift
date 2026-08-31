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

    /// Every governance outcome that
    /// `scp_core::context::state::GovernanceActionResult` defines has a case
    /// here, and each case's raw value is that variant's name — which is what
    /// one shared bridge mapping (`scp_ffi_common::governance_result`) reports.
    /// Dropping a case sends `executeGovernanceAction` down its fail-closed
    /// path for an outcome this SDK should name, so this counts them.
    func testGovernanceActionResultNamesEveryRustVariant() {
        let names = [
            "MemberAdded", "MemberRemoved", "RoleChanged", "OutletRegistered",
            "OutletRemoved", "CeilingModified", "ContextClosed", "TtlExtended",
            "PruningPolicyModified", "AdminTransferred", "SignerAdded", "SignerRemoved",
            "ThresholdModified", "ChildContextCreated", "OutletInterfaceEstablished",
            "MemberReset", "ConflictResolved", "ContextPromoted", "MemberSuspended",
            "AccessRevoked", "AccessRestored", "ContentKeysRotated",
            "GovernanceReconfigured", "SubscriberBanned", "SubscriberUnbanned",
            "Executed", "MigrationProposed", "MigrationCancelled", "ContextTombstoned"
        ]
        XCTAssertEqual(names.count, 29)
        for name in names {
            XCTAssertNotNil(
                GovernanceActionResult(rawValue: name),
                "GovernanceActionResult must name \(name)"
            )
        }
    }

    /// A name no case carries produces `nil`, which is what
    /// `executeGovernanceAction` turns into a thrown `SCP-GOV-11040` rather
    /// than into `.executed`.
    func testUnknownGovernanceOutcomeHasNoCase() {
        XCTAssertNil(GovernanceActionResult(rawValue: "SomethingThisSdkDoesNotKnow"))
    }

    /// Each of the six names `RESERVED_ROLE_NAMES` reserves
    /// (`crates/scp-protocol/src/context/roles.rs`) parses to the case of that
    /// name. A bridge reports `RoleAssignment.role_name` in the lowercase form
    /// the protocol stores, and no custom role may take any of these six names,
    /// so reading one of them as `.custom` would report a protocol-defined role
    /// as a role a context's governance defined. `author` carries
    /// `messages:write` and the outlet capabilities, and `subscriber` is what a
    /// broadcast subscribe assigns, so an app that cannot tell them apart
    /// cannot tell a writer from a reader.
    func testEveryBuiltInRoleNameParsesToItsOwnCase() {
        XCTAssertEqual(MemberRole.fromBridge("admin"), .admin)
        XCTAssertEqual(MemberRole.fromBridge("moderator"), .moderator)
        XCTAssertEqual(MemberRole.fromBridge("member"), .member)
        XCTAssertEqual(MemberRole.fromBridge("observer"), .observer)
        XCTAssertEqual(MemberRole.fromBridge("author"), .author)
        XCTAssertEqual(MemberRole.fromBridge("subscriber"), .subscriber)
    }

    /// A name outside those six is a role a context's governance defined, and
    /// `custom` is what this protocol calls that.
    func testGovernanceDefinedRoleNameParsesToCustom() {
        XCTAssertEqual(MemberRole.fromBridge("night-shift-reviewer"), .custom)
    }
}
