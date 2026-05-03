// SCP-OUT-037 (UniFFI portion) — Kotlin streaming surface tests.
//
// These tests exercise the Kotlin-side ergonomics layer added in
// `OutletsStreaming.kt`. Full FFI round-trip tests require the
// UniFFI-generated bindings linked from the JNI cdylib. The tests in
// this file cover:
//
// - `OutletStreamChunkData` — record-shape equality and content-equals
//   semantics for `ByteArray` fields.
// - `OutletStreamChunkData.fromFfi` — constructs the record from the
//   FFI shape unchanged.
//
// Tests that drive the actual FFI streaming round-trip live in the
// integration suite under `RealFFITest.kt` and run only when the
// native binary is on the JVM library path.

@file:Suppress("MaximumLineLength")

package works.limn.scp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

class OutletStreamChunkDataTest {
    @Test
    fun `equals uses content-equals on byte arrays`() {
        val a = OutletStreamChunkData(
            requestId = byteArrayOf(0x11, 0x22, 0x33, 0x44),
            sequence = 7uL,
            sig = byteArrayOf(0x55),
            payloadType = "data",
            valueJson = """{"x":1}""",
            pct = null,
            note = null,
            aggregateJson = null,
            provenanceJson = null,
            executionTimeMs = null,
            code = null,
            message = null,
            terminal = null,
        )
        val b = OutletStreamChunkData(
            requestId = byteArrayOf(0x11, 0x22, 0x33, 0x44),
            sequence = 7uL,
            sig = byteArrayOf(0x55),
            payloadType = "data",
            valueJson = """{"x":1}""",
            pct = null,
            note = null,
            aggregateJson = null,
            provenanceJson = null,
            executionTimeMs = null,
            code = null,
            message = null,
            terminal = null,
        )
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `equals flips when request_id differs`() {
        val a = OutletStreamChunkData(
            requestId = byteArrayOf(0x11),
            sequence = 0uL,
            sig = byteArrayOf(0x00),
            payloadType = "progress",
            valueJson = null,
            pct = 5000u.toUShort(),
            note = "halfway",
            aggregateJson = null,
            provenanceJson = null,
            executionTimeMs = null,
            code = null,
            message = null,
            terminal = null,
        )
        val b = OutletStreamChunkData(
            requestId = byteArrayOf(0x22),
            sequence = 0uL,
            sig = byteArrayOf(0x00),
            payloadType = "progress",
            valueJson = null,
            pct = 5000u.toUShort(),
            note = "halfway",
            aggregateJson = null,
            provenanceJson = null,
            executionTimeMs = null,
            code = null,
            message = null,
            terminal = null,
        )
        assertNotEquals(a, b)
    }

    @Test
    fun `fromFfi populates every field`() {
        val record = OutletStreamChunkData.fromFfi(
            requestId = byteArrayOf(0xAA.toByte()),
            sequence = 13uL,
            sig = byteArrayOf(0xBB.toByte()),
            payloadType = "end",
            valueJson = null,
            pct = null,
            note = null,
            aggregateJson = """{"final":true}""",
            provenanceJson = """{"contextId":"ctx"}""",
            executionTimeMs = 9999uL,
            code = null,
            message = null,
            terminal = null,
        )
        assertEquals("end", record.payloadType)
        assertEquals(13uL, record.sequence)
        assertEquals("""{"final":true}""", record.aggregateJson)
        assertEquals("""{"contextId":"ctx"}""", record.provenanceJson)
        assertEquals(9999uL, record.executionTimeMs)
    }
}
