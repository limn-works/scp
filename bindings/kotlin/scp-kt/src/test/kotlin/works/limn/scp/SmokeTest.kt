package works.limn.scp

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SmokeTest {
    @Test
    fun `CustodyType carries the two values the vocabulary states`() {
        // Exercises real SDK code with no native dependency: the typed
        // CustodyType enum's wire-format mapping and its fromRawValue parser.
        //
        // §3.2.2 of the identity spec, "The Custody Vocabulary", states that a
        // caller "names exactly one of two custody values" and that "The
        // vocabulary holds no third value". Pin the whole set rather than one
        // entry, so an entry added without a matching arm in
        // `build_key_custody` fails here.
        assertEquals(
            listOf("encrypted_file", "os_keystore"),
            CustodyType.entries.map { it.rawValue },
        )
        assertEquals("encrypted_file", CustodyType.ENCRYPTED_FILE.rawValue)
        assertEquals("os_keystore", CustodyType.OS_KEYSTORE.rawValue)
        assertEquals(CustodyType.ENCRYPTED_FILE, CustodyType.fromRawValue("encrypted_file"))
        assertEquals(CustodyType.OS_KEYSTORE, CustodyType.fromRawValue("os_keystore"))
        assertNull(CustodyType.fromRawValue("not-a-custody-type"))
    }

    @Test
    fun `CustodyType spells no retired custody string and no test-harness string`() {
        // §3.2.2 names five spellings and states that they "name no custody
        // backend": the bridge answers each one with SCP-VALID-7005. It states
        // separately that "in_memory" "is a test-harness affordance and not a
        // value of this vocabulary" and that "no SDK enum spells it".
        // `CustodyCallErrorCodeTest` calls the bridge and asserts those codes;
        // this test pins the SDK half, that the enum spells none of them, so a
        // caller cannot name one through a typed API.
        val absent = listOf("platform", "software", "file", "platform_managed", "hardware", "in_memory")
        for (spelling in absent) {
            assertNull(
                CustodyType.fromRawValue(spelling),
                "CustodyType must not spell $spelling",
            )
        }
    }
}
