// McpClientConnectSseTest.kt — the Kotlin wrapper hands the caller's
// bearer token to the UniFFI `mcpClientConnectSse`, so a Kotlin client
// passes the bearer check an SCP SSE server always runs (ADR-015). The
// native object records the call and holds no Rust pointer, so no native
// code runs.

package works.limn.scp

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import uniffi.scp.NoPointer
import kotlin.test.assertEquals
import uniffi.scp.Scp as NativeScp

class McpClientConnectSseTest {
    private class RecordingNativeScp : NativeScp(NoPointer) {
        val connects = mutableListOf<Pair<String, String?>>()

        override suspend fun mcpClientConnectSse(
            url: String,
            authToken: String?,
        ): String {
            connects += url to authToken
            return "mcp-client-1"
        }
    }

    @Test
    fun connectSseForwardsTheBearerToken(): Unit =
        runBlocking {
            val native = RecordingNativeScp()

            SCP(native).mcpClientConnectSse(url = "http://127.0.0.1:9/sse", authToken = "tok-1")

            val expected: List<Pair<String, String?>> = listOf("http://127.0.0.1:9/sse" to "tok-1")
            assertEquals(expected, native.connects.toList())
        }
}
