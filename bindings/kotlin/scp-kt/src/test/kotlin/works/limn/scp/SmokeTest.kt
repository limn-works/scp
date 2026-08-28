package works.limn.scp

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SmokeTest {
    @Test
    fun `CustodyType carries every custody string the bridge names`() {
        // Exercises real SDK code with no native dependency: the typed
        // CustodyType enum's wire-format mapping and its fromRawValue parser.
        //
        // `parse_custody_method` in `crates/scp-ffi/uniffi/src/bridge.rs` names
        // "in_memory", "platform", and "software" in its match arms and
        // answers every other string with SCP-VALID-7005. Pin the whole set
        // rather than one entry, so an entry added without a matching arm
        // there fails here.
        assertEquals(
            listOf("in_memory", "platform", "software"),
            CustodyType.entries.map { it.rawValue },
        )
        assertEquals("in_memory", CustodyType.IN_MEMORY.rawValue)
        assertEquals("platform", CustodyType.PLATFORM.rawValue)
        assertEquals("software", CustodyType.SOFTWARE.rawValue)
        assertEquals(CustodyType.IN_MEMORY, CustodyType.fromRawValue("in_memory"))
        assertEquals(CustodyType.PLATFORM, CustodyType.fromRawValue("platform"))
        assertEquals(CustodyType.SOFTWARE, CustodyType.fromRawValue("software"))
        assertNull(CustodyType.fromRawValue("not-a-custody-type"))
    }

    @Test
    fun `CustodyType offers one entry that reaches a key store`() {
        // The bridge builds a key store for "in_memory" alone, and answers
        // "platform" and "software" with SCP-IDENT-1003, because neither
        // string reaches Android Keystore — a caller reaches it by injecting a
        // KeyCustodyProvider through identityCreateWithCustody.
        // `CustodyCallErrorCodeTest` calls the bridge and asserts those codes;
        // this test pins the SDK half, that the enum spells each rejected
        // string the way the bridge's match arm spells it, so a caller reads
        // one vocabulary.
        assertEquals(
            listOf("platform", "software"),
            CustodyType.entries
                .filter { it != CustodyType.IN_MEMORY }
                .map { it.rawValue },
        )
    }
}
