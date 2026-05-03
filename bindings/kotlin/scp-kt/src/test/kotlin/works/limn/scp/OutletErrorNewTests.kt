// SCP-OUT-041d — Kotlin SDK tests for OutletError.new options-object
// form, the FFI bridge delegate path, and the catalog-rotation
// dwell-time validator.

package works.limn.scp

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

/** Shorthand factory for [CatalogKey] used by the tests below. */
private fun catalogKey(raw: String): CatalogKey = CatalogKey.of(raw)

/** Shorthand factory for [OutletId] used by the tests below. */
private fun outletId(raw: String): OutletId = OutletId.of(raw)

class OutletErrorNewTests {

    @AfterEach
    fun resetBridge() {
        // Restore the default not-configured delegate to avoid leaking
        // a per-test stub into other suites.
        OutletErrorBridge.setDelegate(object : OutletErrorBridge.Delegate {
            override suspend fun outletErrorNew(
                opts: OutletErrorNewBridgeOptions,
            ): OutletError = throw OutletError.Bridge(
                message = "test default — override per test",
                code = "SCP-CTX-2000",
            )

            override suspend fun outletCatalogRotationValidator(
                priorCatalog: List<MessageTemplateRecord>,
                newCatalog: List<MessageTemplateRecord>,
                priorAppendTimeSecs: Long,
                newAppendTimeSecs: Long,
            ) {
                // no-op: tests opt in to real validation by injecting a stub.
            }
        })
    }

    @Test
    fun `new options-object returns AuthorizationError for class authorization`() {
        val key = catalogKey("authorization.denied")
        val opts = OutletErrorNewOptions(
            outletId = outletId("outlet-test"),
            catalogKey = key,
            errorClass = OutletErrorClass.AUTHORIZATION,
        )
        val err = OutletError.new(opts)
        // The original assertion compared `"authorization"` against the
        // stringified result of a `.contains(...)` call (always
        // `"true"`/`"false"`) — a pre-existing test bug. Restore the
        // intended invariant: the constructed instance must be an
        // `AuthorizationError` and its class-wire discriminator must
        // be `AUTHORIZATION`.
        assertEquals(true, err is AuthorizationError)
        assertEquals(OutletErrorClass.AUTHORIZATION, (err as AuthorizationError).classWire)
    }

    @Test
    fun `OutletErrorNewBridgeOptions enforces 32-byte registrationEventId`() {
        assertThrows(IllegalArgumentException::class.java) {
            OutletErrorNewBridgeOptions(
                contextId = "ctx-1",
                outletId = outletId("outlet-1"),
                registrationEventId = ByteArray(8),
                catalogKey = catalogKey("authorization.denied"),
                errorClass = OutletErrorClass.AUTHORIZATION,
            )
        }
    }

    @Test
    fun `OutletErrorNewBridgeOptions enforces 16-byte padNonce when set`() {
        assertThrows(IllegalArgumentException::class.java) {
            OutletErrorNewBridgeOptions(
                contextId = "ctx-1",
                outletId = outletId("outlet-1"),
                registrationEventId = ByteArray(32),
                catalogKey = catalogKey("authorization.denied"),
                errorClass = OutletErrorClass.AUTHORIZATION,
                padNonce = ByteArray(8),
            )
        }
    }

    @Test
    fun `newViaBridge delegates to OutletErrorBridge`() = runTest {
        val expected = OutletError.new(
            OutletErrorNewOptions(
                outletId = outletId("outlet-test"),
                catalogKey = catalogKey("authorization.denied"),
                errorClass = OutletErrorClass.AUTHORIZATION,
            ),
        )
        OutletErrorBridge.setDelegate(object : OutletErrorBridge.Delegate {
            override suspend fun outletErrorNew(
                opts: OutletErrorNewBridgeOptions,
            ): OutletError = expected

            override suspend fun outletCatalogRotationValidator(
                priorCatalog: List<MessageTemplateRecord>,
                newCatalog: List<MessageTemplateRecord>,
                priorAppendTimeSecs: Long,
                newAppendTimeSecs: Long,
            ) {
                // No-op: this stub bridge is exercised only by the outletErrorNew
                // path in this test file, so the catalog-rotation hook is
                // intentionally inert.
            }
        })

        val opts = OutletErrorNewBridgeOptions(
            contextId = "ctx-1",
            outletId = outletId("outlet-test"),
            registrationEventId = ByteArray(32),
            catalogKey = catalogKey("authorization.denied"),
            errorClass = OutletErrorClass.AUTHORIZATION,
        )
        val err = OutletError.newViaBridge(opts)
        assertNotNull(err)
    }
}
