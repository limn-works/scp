/**
 * Minimal SCP Android app entry point.
 *
 * Creates a DID identity through a caller-supplied key custody provider and
 * opens an encrypted context.
 *
 * The Kotlin SDK ships no key store that `identityCreate(custody)` reaches in
 * a shipped build: its one `CustodyType`, `IN_MEMORY`, works only in a build
 * compiled with the `testing` feature, and a shipped build rejects it with
 * `SCP-IDENT-1008`. Implement [makeKeyCustodyProvider] over your app's key
 * store before running.
 */
package com.example.scpapp

import kotlinx.coroutines.runBlocking
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.KeyCustodyProvider
import uniffi.scp.MemoryScope
import works.limn.scp.SCP
import java.io.File

/**
 * Returns the [KeyCustodyProvider] over your app's key store. In an Android
 * app, return `UniffiKeyCustody(AndroidKeyCustody(applicationContext))` from
 * `works.limn:scp-kt-android`; this JVM scaffold has no Android `Context`.
 */
fun makeKeyCustodyProvider(): KeyCustodyProvider =
    throw UnsupportedOperationException("implement makeKeyCustodyProvider over your app's key store")

fun main() =
    runBlocking {
        val passphrase =
            System.getenv("SCP_STORAGE_PASSPHRASE")
                ?: error("SCP_STORAGE_PASSPHRASE is not set")
        val scp = SCP.withSqlite(File("scp-data"), passphrase)

        // 1. Create a DID identity whose keys the provider holds.
        val identity = scp.identityCreateWithCustody(makeKeyCustodyProvider())
        println("Created identity: ${identity.did()}")

        // 2. Create an encrypted single-admin context.
        val params =
            ContextParams(
                mode = ContextMode.ENCRYPTED,
                ceiling = listOf("messages:read", "messages:write"),
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
        val handle = scp.contextCreate(identity, params)
        println("Created context: ${handle.contextId()}")

        // 3. Close the context. SCP.shutdown takes a CoroutineBridge, and the
        //    SDK ships no NativeBindings implementation to build one with, so
        //    the scaffold cannot shut the instance down.
        scp.contextClose(handle, identity)
        println("Scaffold complete.")
    }
