/**
 * Minimal SCP Android app entry point.
 *
 * Creates a DID identity, opens an encrypted context, and sends a message.
 * Uses the in-memory key store: no custody string reaches Android Keystore, so
 * Keystore-held keys need a KeyCustodyProvider injected through
 * identityCreateWithCustody on a works.limn.scp.SCP instance.
 */
package com.example.scpapp

import kotlinx.coroutines.runBlocking
import works.limn.scp.CustodyType
import works.limn.scp.bridge.CoroutineBridge

fun main() = runBlocking {
    // In a real Android app, initialize CoroutineBridge with NativeBindings
    // loaded from the UniFFI-generated shared library.
    //
    // val bindings = loadNativeBindings()
    // val bridge = CoroutineBridge(bindings)

    println("SCP Android Scaffold")
    println("====================")
    println()
    println("To run this scaffold in a real Android app:")
    println("1. Add the scp-kt dependency to build.gradle.kts")
    println("2. Load the native library: System.loadLibrary(\"scp_ffi_uniffi\")")
    println("3. Initialize CoroutineBridge with NativeBindings")
    println("4. Use bridge.identity.create() to create a DID")
    println("5. Use bridge.context.create() to open a context")
    println("6. Use bridge.context.send() to send messages")
    println()

    // Demonstration of the API surface (requires native library):
    //
    // val bridge = CoroutineBridge(nativeBindings)
    //
    // // 1. Create identity. This in-memory key store loses every key on
    // //    process exit, and a released build rejects it with SCP-IDENT-1008.
    // val identityHandle = bridge.identity.create(CustodyType.ENCRYPTED_FILE)
    //
    // // 2. Create an encrypted context
    // val paramsJson = """
    //     {
    //         "ceiling": ["messages:read", "messages:write"],
    //         "memory_scope": "ephemeral",
    //         "governance": "single_admin"
    //     }
    // """.trimIndent()
    // val contextHandle = bridge.context.create(identityHandle, paramsJson)
    //
    // // 3. Send a message
    // bridge.context.send(contextHandle, "Hello from Android!".toByteArray())
    //
    // // 4. Clean up
    // bridge.context.leave(contextHandle)

    println("Scaffold complete.")
}
