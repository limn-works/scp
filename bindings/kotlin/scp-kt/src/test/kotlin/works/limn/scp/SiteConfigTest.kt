// SiteConfigTest.kt — Unit tests for SiteConfig (SCP-293, spec §18.11.12)
//
// Verifies construction, defaults, hostname validation (RFC 1123),
// deploy retention count bounds, CSP validation, and JSON serialization.
//
// Provenance: spec §18.11.12, SCP-293

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SiteConfigTest {
    // MARK: - Construction

    @Test
    fun `construction with defaults`() {
        val config = SiteConfig(hostname = "example.com")
        assertEquals("example.com", config.hostname)
        assertEquals("/index.html", config.indexPath)
        assertEquals(10_000, config.maxAssetsPerDeploy)
        assertEquals(536_870_912L, config.maxDeploySizeBytes)
        assertEquals(2, config.deployRetentionCount)
        assertNull(config.cspOverride)
    }

    @Test
    fun `construction with all fields`() {
        val config = SiteConfig(
            hostname = "cdn.example.com",
            indexPath = "/home.html",
            maxAssetsPerDeploy = 5_000,
            maxDeploySizeBytes = 268_435_456L,
            deployRetentionCount = 4,
            cspOverride = "default-src 'self'",
        )
        assertEquals("cdn.example.com", config.hostname)
        assertEquals("/home.html", config.indexPath)
        assertEquals(5_000, config.maxAssetsPerDeploy)
        assertEquals(268_435_456L, config.maxDeploySizeBytes)
        assertEquals(4, config.deployRetentionCount)
        assertEquals("default-src 'self'", config.cspOverride)
    }

    @Test
    fun `data class equality`() {
        val a = SiteConfig(hostname = "example.com")
        val b = SiteConfig(hostname = "example.com")
        assertEquals(a, b)
    }

    // MARK: - Hostname Validation

    @Test
    fun `valid hostnames accepted`() {
        SiteConfig(hostname = "example.com")
        SiteConfig(hostname = "my-site.example.com")
        SiteConfig(hostname = "localhost")
        SiteConfig(hostname = "a.b.c.d")
    }

    @Test
    fun `empty hostname rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "")
        }.also { assertTrue(it.message!!.contains("hostname must not be empty")) }
    }

    @Test
    fun `hostname exceeding 253 chars rejected`() {
        val long = "a".repeat(63) + "." + "b".repeat(63) + "." +
            "c".repeat(63) + "." + "d".repeat(63) + ".e"
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = long)
        }.also { assertTrue(it.message!!.contains("hostname exceeds 253 characters")) }
    }

    @Test
    fun `hostname with invalid chars rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "bad_host.com")
        }.also { assertTrue(it.message!!.contains("hostname label contains invalid characters")) }
    }

    @Test
    fun `hostname label leading hyphen rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "-bad.com")
        }.also { assertTrue(it.message!!.contains("hostname label contains invalid characters")) }
    }

    @Test
    fun `hostname label trailing hyphen rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "bad-.com")
        }.also { assertTrue(it.message!!.contains("hostname label contains invalid characters")) }
    }

    // MARK: - Retention Count Validation

    @Test
    fun `retention count 1 accepted`() {
        val config = SiteConfig(hostname = "example.com", deployRetentionCount = 1)
        assertEquals(1, config.deployRetentionCount)
    }

    @Test
    fun `retention count 8 accepted`() {
        val config = SiteConfig(hostname = "example.com", deployRetentionCount = 8)
        assertEquals(8, config.deployRetentionCount)
    }

    @Test
    fun `retention count 0 rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", deployRetentionCount = 0)
        }.also { assertTrue(it.message!!.contains("deployRetentionCount must be between 1 and 8")) }
    }

    @Test
    fun `retention count 9 rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", deployRetentionCount = 9)
        }.also { assertTrue(it.message!!.contains("deployRetentionCount must be between 1 and 8")) }
    }

    // MARK: - CSP Validation

    @Test
    fun `valid CSP accepted`() {
        SiteConfig(hostname = "example.com", cspOverride = "default-src 'self'")
    }

    @Test
    fun `CSP unsafe-eval rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", cspOverride = "script-src 'unsafe-eval'")
        }.also { assertTrue(it.message!!.contains("CSP must not contain 'unsafe-eval'")) }
    }

    @Test
    fun `CSP unsafe-inline rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", cspOverride = "style-src 'unsafe-inline'")
        }.also { assertTrue(it.message!!.contains("CSP must not contain 'unsafe-inline'")) }
    }

    @Test
    fun `CSP unsafe-hashes rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", cspOverride = "script-src 'unsafe-hashes'")
        }.also { assertTrue(it.message!!.contains("CSP must not contain 'unsafe-hashes'")) }
    }

    @Test
    fun `CSP bare wildcard rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", cspOverride = "default-src *")
        }.also { assertTrue(it.message!!.contains("CSP must not contain bare wildcard '*'")) }
    }

    @Test
    fun `CSP subdomain wildcard accepted`() {
        SiteConfig(hostname = "example.com", cspOverride = "default-src *.example.com")
    }

    @Test
    fun `CSP data source rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", cspOverride = "img-src data:")
        }.also { assertTrue(it.message!!.contains("CSP must not contain 'data:' source")) }
    }

    @Test
    fun `CSP blob source rejected`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", cspOverride = "worker-src blob:")
        }.also { assertTrue(it.message!!.contains("CSP must not contain 'blob:' source")) }
    }

    @Test
    fun `CSP case insensitive`() {
        assertFailsWith<IllegalArgumentException> {
            SiteConfig(hostname = "example.com", cspOverride = "script-src 'Unsafe-Eval'")
        }.also { assertTrue(it.message!!.contains("CSP must not contain 'unsafe-eval'")) }
    }

    // MARK: - JSON Serialization

    @Test
    fun `toJson with defaults`() {
        val config = SiteConfig(hostname = "example.com")
        val json = config.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject

        assertEquals("example.com", obj["hostname"]?.jsonPrimitive?.content)
        assertEquals("/index.html", obj["index_path"]?.jsonPrimitive?.content)
        assertEquals(10_000, obj["max_assets_per_deploy"]?.jsonPrimitive?.content?.toInt())
        assertEquals(536_870_912L, obj["max_deploy_size_bytes"]?.jsonPrimitive?.long)
        assertEquals(2, obj["deploy_retention_count"]?.jsonPrimitive?.content?.toInt())
        assertFalse(obj.containsKey("csp_override"))
    }

    @Test
    fun `toJson with csp override`() {
        val config = SiteConfig(
            hostname = "cdn.example.com",
            cspOverride = "default-src 'self'",
        )
        val json = config.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject

        assertEquals("default-src 'self'", obj["csp_override"]?.jsonPrimitive?.content)
    }
}
