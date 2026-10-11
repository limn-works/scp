/**
 * Context creation and the invite-and-join handshake.
 *
 * Demonstrates creating an SCP context with governance parameters,
 * inviting a second identity, joining from the sealed invitation, and
 * reading the membership.
 *
 * The creator and the joiner each run their own [SCP] instance with its own
 * database, as two devices would, and each passes its own
 * [KeyCustodyProvider]. `CustodyType.IN_MEMORY` works only in a build
 * compiled with the `testing` feature.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   contextExample(aliceProvider, bobProvider, context.filesDir, passphrase)
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.InviteMemberOutcome
import uniffi.scp.KeyCustodyProvider
import uniffi.scp.MemoryScope
import works.limn.scp.SCP
import java.io.File

fun contextExample(
    aliceProvider: KeyCustodyProvider,
    bobProvider: KeyCustodyProvider,
    storageRoot: File,
    storagePassphrase: String,
) = runBlocking {
    val aliceNode = SCP.withSqlite(File(storageRoot, "scp-context-alice"), storagePassphrase)
    val bobNode = SCP.withSqlite(File(storageRoot, "scp-context-bob"), storagePassphrase)

    // 1. Each side creates its identity in its own node.
    val alice = aliceNode.identityCreateWithCustody(aliceProvider)
    val bob = bobNode.identityCreateWithCustody(bobProvider)
    println("Alice DID: ${alice.did()}")
    println("Bob DID:   ${bob.did()}")

    // 2. Define context parameters. The ceiling caps what any member can
    //    hold. Inviting runs through the governance gate, so the ceiling
    //    must carry governance:propose.
    val params =
        ContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling =
                listOf(
                    "messages:read",
                    "messages:write",
                    "member:invite",
                    "member:remove",
                    "governance:propose",
                ),
            ceilingPolicy = CeilingPolicy.IMMUTABLE,
            governance = GovernanceModel.SINGLE_ADMIN,
            memoryScope = MemoryScope.EPHEMERAL,
            ttlSeconds = 0uL,
            promotable = false,
            minProtocolVersion = 0.toUShort(),
            maxChainDepth = null,
            maxNestingDepth = null,
            sessionCap = null,
            economicPolicy = null,
            consequenceRulesJson = null,
            consequenceConfigJson = null,
        )

    // 3. Alice creates the context. The returned ContextHandle is the
    //    reference every later context call takes.
    val handle = aliceNode.contextCreate(alice, params)
    println()
    println("Context created: ${handle.contextId()}")
    println("  Creator: ${handle.creatorDid()}")
    println("  State: ${handle.state()}")

    // 4. Bob reserves a single-use KeyPackage and hands Alice its public
    //    bytes out of band.
    val reservation = bobNode.reserveKeyPackage(bob)

    // 5. Alice seals an invitation to that KeyPackage. An empty relay list
    //    means Alice delivers the sealed bundle to Bob herself.
    val outcome =
        aliceNode.inviteMember(
            identity = alice,
            contextId = handle.contextId(),
            inviteeDid = bob.did(),
            inviteeKeyPackage = reservation.keyPackagePublic,
            relayUrls = emptyList(),
        )
    val bundle =
        when (outcome) {
            is InviteMemberOutcome.Sealed -> outcome.bundle
        }

    // 6. Bob opens the sealed bundle and joins.
    val bobHandle = bobNode.contextJoinFromWelcome(bob, bundle, reservation.reservationId)
    println()
    println("Bob joined context: ${bobHandle.contextId()}")

    // 7. Read the membership from Alice's node.
    val members = aliceNode.contextMemberDids(handle)
    println("Members: $members")

    // 8. Close the context for every member.
    aliceNode.contextClose(handle, alice)
    println("Context closed.")

    // SCP.shutdown takes a CoroutineBridge, and the SDK ships no NativeBindings
    // implementation to build one with, so this example cannot shut either
    // instance down. The finalizer logs a warning when the JVM collects it.
    println()
    println("Context lifecycle complete.")
}
