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
            outletId = "outlet-test",
            catalogKey = key,
            errorClass = OutletErrorClass.AUTHORIZATION,
        )
        val err = OutletError.new(opts)
        assertEquals("authorization", err::class.simpleName?.let { _ ->
            (err as OutletError).javaClass.simpleName.lowercase().contains("authorization")
        }.toString())
    }

    @Test
    fun `OutletErrorNewBridgeOptions enforces 32-byte registrationEventId`() {
        assertThrows(IllegalArgumentException::class.java) {
            OutletErrorNewBridgeOptions(
                contextId = "ctx-1",
                outletId = "outlet-1",
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
                outletId = "outlet-1",
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
                outletId = "outlet-test",
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
            ) {}
        })

        val opts = OutletErrorNewBridgeOptions(
            contextId = "ctx-1",
            outletId = "outlet-test",
            registrationEventId = ByteArray(32),
            catalogKey = catalogKey("authorization.denied"),
            errorClass = OutletErrorClass.AUTHORIZATION,
        )
        val err = OutletError.newViaBridge(opts)
        assertNotNull(err)
    }
}
