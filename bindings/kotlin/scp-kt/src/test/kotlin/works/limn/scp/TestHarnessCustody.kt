package works.limn.scp

import uniffi.scp.Identity

/**
 * Test-harness custody: reaching the in-memory key store the SDK cannot name.
 *
 * §3.2.2 of the identity spec, "The Custody Vocabulary", states that a caller
 * names one of two backends, `"encrypted_file"` and `"os_keystore"`, and that
 * the vocabulary "holds no third value". It states separately that a build
 * carrying the bridge's `testing` cargo feature "additionally accepts the
 * string `in_memory` at the bridge, which reaches that test-only backend", that
 * the string "is a test-harness affordance and not a value of this vocabulary",
 * and that "no SDK enum spells it, a test that needs it passes the raw string
 * to the bridge".
 *
 * [SCP.identityCreate] therefore takes a [CustodyType], which spells only the
 * two vocabulary values, and the helpers below reach the UniFFI `Scp` object
 * directly with the raw string.
 */
internal object TestHarnessCustody {
    /**
     * The raw custody string a `testing` build accepts for the in-memory key
     * store. A build without that cargo feature answers it with
     * `SCP-IDENT-1008` and builds nothing.
     */
    const val RAW = "in_memory"
}

/**
 * Creates an identity whose keys live in the test-only in-memory key store.
 *
 * @param testingSeed The ADR-046 cross-bridge parity seed, or `null` to let the
 *   in-memory backend draw from the OS RNG.
 */
internal suspend fun SCP.identityCreateInTestHarnessCustody(testingSeed: ByteArray? = null): Identity =
    inner.identityCreate(custody = TestHarnessCustody.RAW, testingSeed = testingSeed)

/**
 * Creates an identity carrying an `#agent` signing key (ADR-039, the shared-DID
 * agent binding) in the test-only in-memory key store.
 */
internal suspend fun SCP.identityCreateWithAgentKeyInTestHarnessCustody(): Identity =
    inner.identityCreateWithAgentKey(custody = TestHarnessCustody.RAW)
