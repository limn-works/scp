// ToolDefinitionTest.kt — Unit tests for ToolDefinition.toJson() and ToolCost (#1203)
//
// Verifies that ToolDefinition.toJson() produces structurally valid JSON that is
// immune to injection via untrusted string fields, and that the monetary
// ToolCost.amount is a ULong serialized as its canonical decimal string
// (ADR-060 native-integer money surface).
//
// Provenance: spec §5.4.1, ADR-010, ADR-060, issue #1203

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ToolDefinitionTest {
    @Test
    fun `basic round-trip`() {
        val def =
            ToolDefinition(
                name = "calculator",
                description = "Adds two numbers",
                inputSchemaJson = """{"type":"object","properties":{"a":{"type":"number"}}}""",
                outputSchemaJson = """{"type":"object","properties":{"sum":{"type":"number"}}}""",
                operatorDid = "did:dht:operator123",
                testVectorsJson = """[{"input":{"a":1},"output":{"sum":1}}]""",
                implementationHashHex = "abcdef0123456789",
                cost = ToolCost(amount = 100uL, currency = "USD", payee = "did:dht:payee456", costFormula = "flat"),
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject

        assertEquals("calculator", obj["name"]?.jsonPrimitive?.content)
        assertEquals("Adds two numbers", obj["description"]?.jsonPrimitive?.content)
        assertEquals("did:dht:operator123", obj["operator_did"]?.jsonPrimitive?.content)
        assertEquals("abcdef0123456789", obj["implementation_hash"]?.jsonPrimitive?.content)

        val costObj = obj["cost"]?.jsonObject
        // ADR-060: amount is the canonical decimal STRING, not a bare number.
        assertEquals("100", costObj?.get("amount")?.jsonPrimitive?.content)
        assertEquals(true, costObj?.get("amount")?.jsonPrimitive?.isString)
        assertEquals("USD", costObj?.get("currency")?.jsonPrimitive?.content)
        assertEquals("did:dht:payee456", costObj?.get("payee")?.jsonPrimitive?.content)
        assertEquals("flat", costObj?.get("cost_formula")?.jsonPrimitive?.content)

        // Schema fields are parsed JSON objects, not escaped strings
        assertTrue(obj["input_schema_json"]?.jsonObject?.containsKey("type") == true)
        assertTrue(obj["output_schema_json"]?.jsonObject?.containsKey("type") == true)

        // Test vectors are a parsed JSON array, not an escaped string
        val vectors = obj["test_vectors_json"]
        assertTrue(vectors.toString().startsWith("["))
    }

    @Test
    fun `minimal definition`() {
        val def =
            ToolDefinition(
                name = "ping",
                description = "health check",
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op1",
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject

        assertEquals("ping", obj["name"]?.jsonPrimitive?.content)
        assertEquals("health check", obj["description"]?.jsonPrimitive?.content)
        assertEquals("did:dht:op1", obj["operator_did"]?.jsonPrimitive?.content)
        assertFalse(obj.containsKey("test_vectors_json"))
        assertFalse(obj.containsKey("implementation_hash"))
        assertFalse(obj.containsKey("cost"))
    }

    @Test
    fun `special characters in name`() {
        val def =
            ToolDefinition(
                name = "tool\"with\\special\nchars",
                description = "desc\twith\ttabs",
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op",
            )
        val json = def.toJson()
        // Must parse without exception — proves structural validity
        val obj = Json.parseToJsonElement(json).jsonObject
        assertEquals("tool\"with\\special\nchars", obj["name"]?.jsonPrimitive?.content)
        assertEquals("desc\twith\ttabs", obj["description"]?.jsonPrimitive?.content)
    }

    @Test
    fun `special characters in cost fields`() {
        val def =
            ToolDefinition(
                name = "tool",
                description = "d",
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op",
                cost =
                    ToolCost(
                        amount = 50uL,
                        currency = "US\"D",
                        payee = "did:dht:payee\u00e9\u00fc",
                    ),
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject
        val costObj = obj["cost"]?.jsonObject
        assertEquals("US\"D", costObj?.get("currency")?.jsonPrimitive?.content)
        assertEquals("did:dht:payee\u00e9\u00fc", costObj?.get("payee")?.jsonPrimitive?.content)
    }

    @Test
    fun `zero amount accepted`() {
        val cost = ToolCost(amount = 0uL, currency = "USD", payee = "did:dht:p")
        assertEquals(0uL, cost.amount)
    }

    @Test
    fun `full-width ULong amount survives exactly through toJson`() {
        // ULong.MAX_VALUE (2^64 - 1) exceeds Long.MAX_VALUE — a signed Long would
        // have overflowed. As the canonical decimal string it round-trips exactly.
        val cost = ToolCost(amount = ULong.MAX_VALUE, currency = "BTC", payee = "did:dht:p")
        assertEquals(ULong.MAX_VALUE, cost.amount)

        val def =
            ToolDefinition(
                name = "expensive",
                description = "d",
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op",
                cost = cost,
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject
        val amount = obj["cost"]?.jsonObject?.get("amount")?.jsonPrimitive
        assertEquals(true, amount?.isString)
        assertEquals("18446744073709551615", amount?.content)
        // And the string parses back to the exact ULong.
        assertEquals(ULong.MAX_VALUE, amount?.content?.toULong())
    }

    @Test
    fun `cost formula omission`() {
        val def =
            ToolDefinition(
                name = "tool",
                description = "d",
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op",
                cost = ToolCost(amount = 10uL, currency = "USD", payee = "did:dht:p"),
            )
        val json = def.toJson()
        val costObj = Json.parseToJsonElement(json).jsonObject["cost"]?.jsonObject
        assertFalse(costObj?.containsKey("cost_formula") == true)
    }

    @Test
    fun `schema fields embedded as objects`() {
        val inputSchema = """{"type":"object","properties":{"x":{"type":"integer"}}}"""
        val outputSchema = """{"type":"array","items":{"type":"string"}}"""
        val def =
            ToolDefinition(
                name = "tool",
                description = "d",
                inputSchemaJson = inputSchema,
                outputSchemaJson = outputSchema,
                operatorDid = "did:dht:op",
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject

        // These must be JSON objects/arrays, not double-encoded strings
        val parsedInput = obj["input_schema_json"]?.jsonObject
        assertEquals("object", parsedInput?.get("type")?.jsonPrimitive?.content)

        val parsedOutput = obj["output_schema_json"]
        // output_schema_json is an array type schema — verify it parsed as a JSON object
        assertTrue(parsedOutput?.jsonObject?.containsKey("type") == true)
        assertEquals("array", parsedOutput?.jsonObject?.get("type")?.jsonPrimitive?.content)
    }
}
