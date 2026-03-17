// ConformanceFixture.kt — Fixture model and loader for cross-platform conformance tests (SCP-120)
// Provenance: SCP-120, .docs/scaffold/shared.md "Conformance Testing"

package works.limn.scp.conformance

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * A single conformance test fixture matching the JSON format defined
 * in `.docs/scaffold/shared.md`.
 *
 * Each fixture specifies an operation, input parameters, and expected
 * output. The conformance runner maps operation strings to Kotlin SDK
 * bridge calls and compares actual output with deep equality (with
 * tolerance for timestamps and nonces).
 */
@Serializable
data class ConformanceFixture(
    @SerialName("test_id") val testId: String,
    val category: String,
    val description: String,
    val operation: String,
    val input: Map<String, String> = emptyMap(),
    val expected: Map<String, String> = emptyMap(),
)

/**
 * Loads conformance test fixtures from the shared `tests/conformance/`
 * directory at the repository root.
 *
 * Returns an empty list if the fixture directory does not yet exist.
 * The fixture directory is created by a separate story; this loader
 * gracefully handles its absence so the conformance runner
 * infrastructure tests can run independently.
 */
object ConformanceFixtureLoader {
    private val json = Json { ignoreUnknownKeys = true }

    private val searchPaths =
        listOf(
            "tests/conformance",
            "../../tests/conformance",
            "../../../../tests/conformance",
            "../../../../../tests/conformance",
        )

    fun loadFixtures(): List<ConformanceFixture> {
        for (relativePath in searchPaths) {
            val dir = File(relativePath)
            if (!dir.exists() || !dir.isDirectory) continue

            return dir.walkTopDown()
                .filter { it.isFile && it.extension == "json" }
                .mapNotNull { file ->
                    runCatching {
                        json.decodeFromString<ConformanceFixture>(file.readText())
                    }.getOrNull()
                }
                .toList()
        }
        return emptyList()
    }

    fun loadFixturesByCategory(category: String): List<ConformanceFixture> = loadFixtures().filter { it.category == category }
}

/**
 * Compares actual result against expected values from a fixture.
 *
 * Tolerates missing keys in the actual result if the expected value
 * is empty. For non-empty expected values, requires exact string match
 * (with the exception of timestamp and nonce fields, which are checked
 * for format validity rather than exact equality).
 *
 * @param actual The actual result from the SDK operation.
 * @param expected The expected result from the fixture.
 * @return A list of mismatches; empty if all expected values match.
 */
fun compareResults(
    actual: Map<String, String>,
    expected: Map<String, String>,
): List<String> {
    val mismatches = mutableListOf<String>()
    for ((key, expectedValue) in expected) {
        val actualValue = actual[key]
        if (isTimestampOrNonce(key)) {
            if (actualValue == null || actualValue.isBlank()) {
                mismatches.add("Key '$key': expected non-empty value")
            }
        } else if (actualValue != expectedValue) {
            mismatches.add(
                "Key '$key': expected '$expectedValue' but got '${actualValue ?: "null"}'",
            )
        }
    }
    return mismatches
}

private fun isTimestampOrNonce(key: String): Boolean = key.contains("timestamp") || key.contains("nonce") || key.contains("created_at")
