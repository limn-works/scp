// Tests for client-side ContentPath, MimeType, and deploy_id validation (SCP-297).
//
// Validates that the SDK-layer validation functions produce clear, descriptive
// error messages for invalid inputs BEFORE the FFI boundary is crossed.
//
// Mirrors the Rust validation in `crates/scp-core/src/context/broadcast_content.rs`.
//
// Provenance: SCP-297, spec §18.11.9

package works.limn.scp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import works.limn.scp.bridge.BridgeException
import kotlin.test.assertContains
import kotlin.test.assertEquals

class ValidationTest {
    // -- ContentPath ----------------------------------------------------------

    @Test
    fun `content path - valid root path accepted`() {
        assertDoesNotThrow { validateContentPath("/") }
    }

    @Test
    fun `content path - valid simple path accepted`() {
        assertDoesNotThrow { validateContentPath("/index.html") }
    }

    @Test
    fun `content path - valid nested path accepted`() {
        assertDoesNotThrow { validateContentPath("/assets/css/main.css") }
    }

    @Test
    fun `content path - valid hidden file accepted`() {
        assertDoesNotThrow { validateContentPath("/.well-known/acme-challenge/token") }
    }

    @Test
    fun `content path - rejects no leading slash`() {
        val ex = assertThrows<BridgeException> { validateContentPath("index.html") }
        assertContains(ex.message.orEmpty(), "must start with '/'")
        assertEquals("SCP-VALID-7010", ex.code)
    }

    @Test
    fun `content path - rejects empty string`() {
        assertThrows<BridgeException> { validateContentPath("") }
    }

    @Test
    fun `content path - rejects too long`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/" + "a".repeat(1024)) }
        assertContains(ex.message.orEmpty(), "exceeds 1024 bytes")
    }

    @Test
    fun `content path - rejects backslash`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path\\file") }
        assertContains(ex.message.orEmpty(), "backslashes")
    }

    @Test
    fun `content path - rejects percent-encoded bytes`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path%20file") }
        assertContains(ex.message.orEmpty(), "percent-encoded")
    }

    @Test
    fun `content path - rejects query string`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path?key=value") }
        assertContains(ex.message.orEmpty(), "query strings")
    }

    @Test
    fun `content path - rejects fragment`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path#section") }
        assertContains(ex.message.orEmpty(), "fragments")
    }

    @Test
    fun `content path - rejects null byte`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path\u0000file") }
        assertContains(ex.message.orEmpty(), "null bytes")
    }

    @Test
    fun `content path - rejects control character`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path\u0001file") }
        assertContains(ex.message.orEmpty(), "control character")
    }

    @Test
    fun `content path - rejects DEL character`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path\u007Ffile") }
        assertContains(ex.message.orEmpty(), "control character")
    }

    @Test
    fun `content path - rejects double slash`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path//file") }
        assertContains(ex.message.orEmpty(), "'//'")
    }

    @Test
    fun `content path - rejects trailing slash`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path/") }
        assertContains(ex.message.orEmpty(), "trailing slash")
    }

    @Test
    fun `content path - rejects dot segment`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path/./file") }
        assertContains(ex.message.orEmpty(), "'.' segments")
    }

    @Test
    fun `content path - rejects dotdot segment`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path/../etc/passwd") }
        assertContains(ex.message.orEmpty(), "directory traversal")
    }

    @Test
    fun `content path - rejects C1 control character`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path\u0085file") }
        assertContains(ex.message.orEmpty(), "control character U+0085")
    }

    @Test
    fun `content path - rejects zero-width space`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path\u200Bfile") }
        assertContains(ex.message.orEmpty(), "whitespace/formatting U+200B")
    }

    @Test
    fun `content path - rejects bidi override`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path\u202Efile") }
        assertContains(ex.message.orEmpty(), "whitespace/formatting U+202E")
    }

    @Test
    fun `content path - rejects NBSP`() {
        val ex = assertThrows<BridgeException> { validateContentPath("/path\u00A0file") }
        assertContains(ex.message.orEmpty(), "whitespace/formatting U+00A0")
    }

    @Test
    fun `content path - NFC normalizes before validation`() {
        // U+0065 U+0301 (e + combining acute) normalizes to U+00E9 (e-acute)
        assertDoesNotThrow { validateContentPath("/caf\u0065\u0301") }
    }

    // -- MimeType -------------------------------------------------------------

    @Test
    fun `mime type - valid text-html accepted`() {
        assertDoesNotThrow { validateMimeType("text/html") }
    }

    @Test
    fun `mime type - valid application-json accepted`() {
        assertDoesNotThrow { validateMimeType("application/json") }
    }

    @Test
    fun `mime type - valid image-png accepted`() {
        assertDoesNotThrow { validateMimeType("image/png") }
    }

    @Test
    fun `mime type - rejects empty string`() {
        val ex = assertThrows<BridgeException> { validateMimeType("") }
        assertContains(ex.message.orEmpty(), "must not be empty")
        assertEquals("SCP-VALID-7011", ex.code)
    }

    @Test
    fun `mime type - rejects no slash`() {
        val ex = assertThrows<BridgeException> { validateMimeType("texthtml") }
        assertContains(ex.message.orEmpty(), "exactly one '/'")
    }

    @Test
    fun `mime type - rejects double slash`() {
        val ex = assertThrows<BridgeException> { validateMimeType("text/html/extra") }
        assertContains(ex.message.orEmpty(), "exactly one '/'")
    }

    @Test
    fun `mime type - rejects empty type part`() {
        val ex = assertThrows<BridgeException> { validateMimeType("/html") }
        assertContains(ex.message.orEmpty(), "both be non-empty")
    }

    @Test
    fun `mime type - rejects empty subtype part`() {
        val ex = assertThrows<BridgeException> { validateMimeType("text/") }
        assertContains(ex.message.orEmpty(), "both be non-empty")
    }

    @Test
    fun `mime type - rejects semicolon`() {
        val ex = assertThrows<BridgeException> { validateMimeType("text/html; charset=utf-8") }
        assertContains(ex.message.orEmpty(), "parameters")
    }

    @Test
    fun `mime type - rejects carriage return`() {
        val ex = assertThrows<BridgeException> { validateMimeType("text/html\r") }
        assertContains(ex.message.orEmpty(), "control character")
    }

    @Test
    fun `mime type - rejects line feed`() {
        val ex = assertThrows<BridgeException> { validateMimeType("text/html\n") }
        assertContains(ex.message.orEmpty(), "control character")
    }

    @Test
    fun `mime type - rejects null byte`() {
        val ex = assertThrows<BridgeException> { validateMimeType("text/\u0000html") }
        assertContains(ex.message.orEmpty(), "control character")
    }

    @Test
    fun `mime type - rejects C1 control character`() {
        val ex = assertThrows<BridgeException> { validateMimeType("text/\u0085html") }
        assertContains(ex.message.orEmpty(), "control character U+0085")
    }

    @Test
    fun `mime type - rejects non-tchar in type part`() {
        val ex = assertThrows<BridgeException> { validateMimeType("te xt/html") }
        assertContains(ex.message.orEmpty(), "type part contains invalid")
    }

    @Test
    fun `mime type - rejects non-tchar in subtype part`() {
        val ex = assertThrows<BridgeException> { validateMimeType("text/ht ml") }
        assertContains(ex.message.orEmpty(), "subtype part contains invalid")
    }

    @Test
    fun `mime type - accepts tchar special characters`() {
        assertDoesNotThrow { validateMimeType("application/vnd.foo+bar") }
    }

    // -- deploy_id ------------------------------------------------------------

    @Test
    fun `deploy id - valid simple accepted`() {
        assertDoesNotThrow { validateDeployId("deploy-1") }
    }

    @Test
    fun `deploy id - valid hex accepted`() {
        assertDoesNotThrow { validateDeployId("abc123def456") }
    }

    @Test
    fun `deploy id - valid underscore accepted`() {
        assertDoesNotThrow { validateDeployId("my_deploy_id") }
    }

    @Test
    fun `deploy id - valid mixed accepted`() {
        assertDoesNotThrow { validateDeployId("Deploy-2024_v1") }
    }

    @Test
    fun `deploy id - rejects empty string`() {
        val ex = assertThrows<BridgeException> { validateDeployId("") }
        assertContains(ex.message.orEmpty(), "must not be empty")
        assertEquals("SCP-VALID-7012", ex.code)
    }

    @Test
    fun `deploy id - rejects too long`() {
        val ex = assertThrows<BridgeException> { validateDeployId("a".repeat(129)) }
        assertContains(ex.message.orEmpty(), "exceeds 128 bytes")
    }

    @Test
    fun `deploy id - rejects spaces`() {
        val ex = assertThrows<BridgeException> { validateDeployId("deploy 1") }
        assertContains(ex.message.orEmpty(), "ASCII alphanumeric")
    }

    @Test
    fun `deploy id - rejects special characters`() {
        val ex = assertThrows<BridgeException> { validateDeployId("deploy@1") }
        assertContains(ex.message.orEmpty(), "ASCII alphanumeric")
    }

    @Test
    fun `deploy id - rejects slash`() {
        val ex = assertThrows<BridgeException> { validateDeployId("deploy/1") }
        assertContains(ex.message.orEmpty(), "ASCII alphanumeric")
    }
}
