package works.limn.scp

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SmokeTest {
    @Test
    fun `CustodyType enum exposes wire-format raw values and round-trips`() {
        // Exercises real SDK code with no native dependency: the typed
        // CustodyType enum's wire-format mapping and its fromRawValue parser.
        // (Replaces a prior assertTrue(true) placeholder that asserted nothing.)
        assertEquals("platform", CustodyType.PLATFORM.rawValue)
        assertEquals("in_memory", CustodyType.IN_MEMORY.rawValue)
        assertEquals("software", CustodyType.SOFTWARE.rawValue)
        assertEquals(CustodyType.IN_MEMORY, CustodyType.fromRawValue("in_memory"))
        assertNull(CustodyType.fromRawValue("not-a-custody-type"))
    }
}
