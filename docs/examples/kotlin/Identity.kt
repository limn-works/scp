/**
 * Identity creation and DID document inspection.
 *
 * Demonstrates creating a new SCP identity using did:dht,
 * inspecting the resulting DID document, and resolving it.
 *
 * The Kotlin SDK ships no production key store that `identityCreate(custody)`
 * reaches: its one [works.limn.scp.CustodyType], `IN_MEMORY`, works only in a
 * build compiled with the `testing` feature, and a shipped build rejects it
 * with `SCP-IDENT-1008`. A production caller implements
 * [uniffi.scp.KeyCustodyProvider] over its own key store and passes it to
 * `identityCreateWithCustody`.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   identityExample(myProvider, File(context.filesDir, "scp-identity"), passphrase)
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import uniffi.scp.KeyCustodyProvider
import works.limn.scp.SCP
import java.io.File

fun identityExample(
    provider: KeyCustodyProvider,
    storageDir: File,
    storagePassphrase: String,
) = runBlocking {
    val scp = SCP.withSqlite(storageDir, storagePassphrase)

    // 1. Create a new identity whose keys the caller's provider holds.
    val identity = scp.identityCreateWithCustody(provider)
    println("DID: ${identity.did()}")
    println("Custody type: ${identity.custodyType()}")
    println()

    val doc = scp.identityResolve(identity.did())
    println(doc.id)
    println()

    // 2. Load an existing identity by DID string.
    val loaded = scp.identityLoad(identity.did())
    println("Loaded identity: ${loaded.did()}")
    println()

    // 3. Add an agent key to the identity.
    val withAgent = scp.identityAddAgentKey(identity)
    println("Added agent key to: ${withAgent.did()}")

    // 4. Rotate the agent key.
    val rotated = scp.identityRotateAgentKey(withAgent)
    println("Rotated agent key for: ${rotated.did()}")

    // 5. Remove the agent key.
    val cleaned = scp.identityRemoveAgentKey(rotated)
    println("Removed agent key from: ${cleaned.did()}")

    // SCP.shutdown takes a CoroutineBridge, and the SDK ships no NativeBindings
    // implementation to build one with, so this example cannot shut the
    // instance down. The finalizer logs a warning when the JVM collects it.
    println()
    println("Identity operations complete.")
}
