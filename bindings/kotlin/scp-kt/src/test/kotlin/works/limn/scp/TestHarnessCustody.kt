// TestHarnessCustody.kt — the one route by which an scp-kt test reaches the
// in-memory key store, which the SDK's CustodyType cannot name.
//
// Spec 03 section 3.2.2 states that an SDK's custody type carries
// `encrypted_file` and `os_keystore` and no other member, and that `in_memory`
// is a testing-build affordance, "never a peer of the two request values".
// [CustodyType] therefore has no in-memory entry, and these helpers pass the raw
// string to the UniFFI `Scp` object through [SCP.inner] instead of going through
// [SCP.identityCreate].
//
// Only a native library built with the `testing` cargo feature
// (`./gradlew test -Pscp.uniffi.cargoFeatures=testing`) accepts the string. A
// library built without it answers `SCP-IDENT-1008` and builds nothing, so a
// test that calls these helpers fails on a shipped build instead of reaching a
// weaker backend.
//
// The file sits in the `src/test` source set, which no published artifact
// packages, and every declaration is `internal`.

package works.limn.scp

import uniffi.scp.Identity

/**
 * The raw custody string a `testing` build accepts for the in-memory key store
 * (spec 03 section 3.2.2).
 */
internal const val IN_MEMORY_CUSTODY = "in_memory"

/**
 * Creates an identity whose keys live in the test-only in-memory key store.
 *
 * @param testingSeed The ADR-046 cross-bridge parity seed, or `null` to let the
 *   in-memory backend draw its keys from the OS RNG.
 */
internal suspend fun SCP.identityCreateInMemory(testingSeed: ByteArray? = null): Identity =
    inner.identityCreate(custody = IN_MEMORY_CUSTODY, testingSeed = testingSeed)

/**
 * Creates an identity carrying an `#agent` signing key (ADR-039) in the
 * test-only in-memory key store.
 */
internal suspend fun SCP.identityCreateWithAgentKeyInMemory(): Identity {
    return inner.identityCreateWithAgentKey(custody = IN_MEMORY_CUSTODY)
}
