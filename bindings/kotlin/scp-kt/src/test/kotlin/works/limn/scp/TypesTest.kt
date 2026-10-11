// TypesTest.kt — Unit tests for pure-Kotlin convenience types in Types.kt.
//
// The Capability helpers are pure Kotlin string construction and do not
// require the native UniFFI binary.
//
// Provenance: §5.4.2 (outlet capabilities), ADR-049 §1 (outlet→outlet rename)

package works.limn.scp

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import uniffi.scp.ScpException
import works.limn.scp.bridge.CoroutineBridge
import works.limn.scp.bridge.GovernanceBridgeOps
import works.limn.scp.bridge.NativeBindings
import works.limn.scp.bridge.StubNativeBindings

class TypesTest {
    @Test
    fun `canonical outlet capability constants use colon form`() {
        assertEquals("outlet:query:*", Capability.OUTLET_QUERY_ALL)
        assertEquals("outlet:call:*", Capability.OUTLET_CALL_ALL)
        assertEquals("outlet:register", Capability.OUTLET_REGISTER)
        assertEquals("outlet:interface", Capability.OUTLET_INTERFACE)
        assertEquals("messages:read", Capability.MESSAGES_READ)
        assertEquals("messages:write", Capability.MESSAGES_WRITE)
    }

    @Test
    fun `outletCall builds parameterised capability string`() {
        assertEquals("outlet:call:calculator", Capability.outletCall("calculator"))
    }

    @Test
    fun `outletQuery builds parameterised capability string`() {
        assertEquals("outlet:query:calculator", Capability.outletQuery("calculator"))
    }

    @Test
    fun `outlet call wildcard covers specific outlet call`() {
        val handle =
            ScopedHandle(
                contextId = "ctx-1",
                grantedCapabilities = listOf(Capability.OUTLET_CALL_ALL),
                appDid = "did:key:app",
            )
        assertEquals(true, handle.hasCapability("outlet:call:calculator"))
        assertEquals(false, handle.hasCapability("outlet:query:calculator"))
    }

    @Test
    fun `outlet query wildcard covers specific outlet query`() {
        val handle =
            ScopedHandle(
                contextId = "ctx-1",
                grantedCapabilities = listOf(Capability.OUTLET_QUERY_ALL),
                appDid = "did:key:app",
            )
        assertEquals(true, handle.hasCapability("outlet:query:calculator"))
        assertEquals(false, handle.hasCapability("outlet:call:calculator"))
    }
}

// Names every bridge emits, copied from the name functions in
// crates/scp-ffi/common/src/governance_result.rs. Listed here as literals so a
// test reads each name a bridge sends, not the enum under test.
private val rustActionResultNames =
    listOf(
        "MemberAdded",
        "MemberRemoved",
        "RoleChanged",
        "OutletRegistered",
        "OutletRemoved",
        "CeilingModified",
        "ContextClosed",
        "TtlExtended",
        "PruningPolicyModified",
        "AdminTransferred",
        "SignerAdded",
        "SignerRemoved",
        "ThresholdModified",
        "ChildContextCreated",
        "OutletInterfaceEstablished",
        "MemberReset",
        "ConflictResolved",
        "ContextPromoted",
        "MemberSuspended",
        "AccessRevoked",
        "AccessRestored",
        "ContentKeysRotated",
        "GovernanceReconfigured",
        "SubscriberBanned",
        "SubscriberUnbanned",
        "Executed",
        "MigrationProposed",
        "MigrationCancelled",
        "ContextTombstoned",
    )
private val rustProposalStatusNames =
    listOf("Pending", "Approved", "Rejected", "Expired", "Cancelled", "Invalidated")
private val rustRejectionReasonNames =
    listOf(
        "AdminRejected",
        "MajorityRejected",
        "UnanimityBroken",
        "ApprovalImpossible",
        "InsufficientParticipation",
    )

private fun assertGov11040(run: () -> Any) {
    val err = assertThrows(ScpException.Context::class.java) { run() }
    assertEquals("SCP-GOV-11040", err.code)
}

private suspend fun assertGov11040Suspend(run: suspend () -> Any) {
    val err =
        try {
            run()
            null
        } catch (e: ScpException.Context) {
            e
        }
    assertEquals("SCP-GOV-11040", err?.code)
}

class GovernanceTypesTest {
    @Test
    fun everyActionResultNameParses() {
        for (name in rustActionResultNames) {
            assertEquals(name, GovernanceActionResult.fromBridge(name).rawValue)
        }
    }

    @Test
    fun everyProposalStatusNameParses() {
        for (name in rustProposalStatusNames) {
            assertEquals(name, ProposalStatus.fromBridge(name).rawValue)
        }
    }

    @Test
    fun everyRejectionReasonNameParses() {
        for (name in rustRejectionReasonNames) {
            assertEquals(name, RejectionReason.fromBridge(name).rawValue)
        }
    }

    @Test
    fun unknownNameThrowsGov11040() {
        for (raw in listOf("SomethingThisSdkDoesNotKnow", "", " Executed", "executed")) {
            assertGov11040 { GovernanceActionResult.fromBridge(raw) }
            assertGov11040 { ProposalStatus.fromBridge(raw) }
            assertGov11040 { RejectionReason.fromBridge(raw) }
        }
    }

    @Test
    fun checkProposalResponseReturnsKnownResponses() {
        for (raw in listOf(
            """{"proposal_id":"ab","status":"Approved","execution_result":"RoleChanged"}""",
            """{"proposal_id":"ab","status":"Pending","execution_result":null}""",
            """{"status":"Rejected","reason":"UnanimityBroken","rejector":"did:dht:zA"}""",
            """{"status":"Invalidated","reason":"proposer removed"}""",
            """{"status":"Cancelled"}""",
        )) {
            assertEquals(raw, checkProposalResponse(raw))
        }
    }

    @Test
    fun checkProposalResponseThrowsGov11040OnUnreadableNames() {
        for (raw in listOf(
            """{"status":"Approved","execution_result":"SomethingNew"}""",
            """{"status":"SomethingNew"}""",
            """{"status":"Rejected","reason":"SomethingNew"}""",
            """{"status":"Rejected"}""",
            """{"status":"Invalidated"}""",
            """{"execution_result":"Executed"}""",
            """{"status":"Approved","execution_result":7}""",
            "not json",
            "[]",
        )) {
            assertGov11040 { checkProposalResponse(raw) }
        }
    }

    @Test
    fun governanceBridgeOpsReturnTypedOutcomesAndCheckResponses() =
        runTest {
            val ok = """{"status":"Pending"}"""
            val bad = """{"status":"SomethingNew","execution_result":"SomethingNew"}"""

            fun ops(
                execute: String,
                json: String,
            ): GovernanceBridgeOps =
                CoroutineBridge(
                    nativeBindings =
                        object : NativeBindings by StubNativeBindings() {
                            override fun governanceExecute(
                                contextHandle: Long,
                                proposalIdHex: String,
                            ): String = execute

                            override fun governancePropose(
                                contextHandle: Long,
                                proposerDid: String,
                                actionJson: String,
                            ): String = json

                            override fun governanceApprove(
                                contextHandle: Long,
                                voterDid: String,
                                proposalIdHex: String,
                            ): String = json

                            override fun governanceReject(
                                contextHandle: Long,
                                voterDid: String,
                                proposalIdHex: String,
                            ): String = json

                            override fun governanceWithdraw(
                                contextHandle: Long,
                                voterDid: String,
                                proposalIdHex: String,
                            ): String = json
                        },
                ).governance

            val good = ops("MemberSuspended", ok)
            assertEquals(GovernanceActionResult.MEMBER_SUSPENDED, good.execute(1L, "ab"))
            assertEquals(ok, good.propose(1L, "did:dht:zA", "{}"))
            assertEquals(ok, good.approve(1L, "did:dht:zA", "ab"))
            assertEquals(ok, good.reject(1L, "did:dht:zA", "ab"))
            assertEquals(ok, good.withdraw(1L, "did:dht:zA", "ab"))

            val unknown = ops("SomethingNew", bad)
            assertGov11040Suspend { unknown.execute(1L, "ab") }
            assertGov11040Suspend { unknown.propose(1L, "did:dht:zA", "{}") }
            assertGov11040Suspend { unknown.approve(1L, "did:dht:zA", "ab") }
            assertGov11040Suspend { unknown.reject(1L, "did:dht:zA", "ab") }
            assertGov11040Suspend { unknown.withdraw(1L, "did:dht:zA", "ab") }
        }
}
