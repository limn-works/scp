/**
 * Identity creation and DID document inspection.
 *
 * Demonstrates creating a new SCP identity using did:dht,
 * inspecting the resulting DID document, and resolving it.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="identity"
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import works.limn.scp.CustodyType
import works.limn.scp.bridge.CoroutineBridge

fun identityExample(bridge: CoroutineBridge) = runBlocking {
    // 1. Create a new identity with in-memory key custody.
    //    In production on Android, use CustodyType.PLATFORM for Keystore.
    //    All FFI calls are dispatched on Dispatchers.IO via the bridge.
    val identityHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    println("Identity handle: $identityHandle")
    println("Custody type: ${CustodyType.IN_MEMORY.rawValue}")
    println()

    // 2. Resolve the DID to its document.
    //    Returns a JSON string representing the DID document.
    //    The bridge dispatches the blocking JNA call on Dispatchers.IO.
    val didString = "did:dht:z6MkExample"
    val docJson = bridge.identity.resolve(didString)

    println("DID Document (JSON):")
    println("  $docJson")
    println()

    // 3. Load an existing identity by DID string.
    //    Returns an opaque handle (Long) for the loaded identity.
    val loadedHandle = bridge.identity.load(didString)
    println("Loaded identity handle: $loadedHandle")
    println()

    // 4. Agent key management (ADR-039).
    //    Requires CoroutineBridge constructed with ExtendedBindings
    //    that include IdentityAdvancedBindings.
    //    bridge.identityAdvanced is nullable; here we assert non-null
    //    because we know extended bindings were provided.
    val advanced = bridge.identityAdvanced
        ?: error("identityAdvanced requires ExtendedBindings")

    //    Create an identity with an agent signing key for
    //    human+agent shared DID patterns.
    val agentHandle = advanced.createWithAgentKey(CustodyType.IN_MEMORY)
    println("Agent identity handle: $agentHandle")

    // 5. Add an agent key to an existing identity.
    val withAgent = advanced.addAgentKey(identityHandle)
    println("Added agent key, new handle: $withAgent")

    // 6. Rotate the agent key.
    val rotated = advanced.rotateAgentKey(withAgent)
    println("Rotated agent key, new handle: $rotated")

    // 7. Remove the agent key.
    val cleaned = advanced.removeAgentKey(rotated)
    println("Removed agent key, new handle: $cleaned")

    // 8. Migrate identity to a new DID (Layer 2 rotation).
    val migrated = advanced.migrate(identityHandle)
    println("Migrated identity, new handle: $migrated")

    // 9. Device attestation (section 9.3).
    val token = advanced.attestDevice(identityHandle)
    println("\nDevice attestation token: ${token.take(40)}...")

    val valid = advanced.verifyDeviceAttestation(didString, token)
    println("Attestation valid: $valid")

    println()
    println("Identity operations complete.")
}
