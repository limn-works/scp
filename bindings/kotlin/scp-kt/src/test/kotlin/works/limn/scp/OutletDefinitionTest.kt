// OutletDefinitionTest.kt — Unit tests for OutletDefinition.toJson() and OutletCost (#1203)
//
// Verifies that OutletDefinition.toJson() produces structurally valid JSON that is
// immune to injection via untrusted string fields, and that the monetary
// OutletCost.amount is a ULong serialized as its canonical decimal string
// (ADR-060 native-integer money surface).
//
// Provenance: spec §5.4.1, §5.4.2, ADR-010, ADR-060, issue #1203

package works.limn.scp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import uniffi.scp.OutletKind
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class OutletDefinitionTest {
    @Test
    fun `basic round-trip`() {
        val def =
            OutletDefinition(
                name = "calculator",
                description = "Adds two numbers",
                kind = OutletKind.ACTION,
                inputSchemaJson = """{"type":"object","properties":{"a":{"type":"number"}}}""",
                outputSchemaJson = """{"type":"object","properties":{"sum":{"type":"number"}}}""",
                operatorDid = "did:dht:operator123",
                testVectorsJson = """[{"input":{"a":1},"output":{"sum":1}}]""",
                implementationHashHex = "abcdef0123456789",
                cost = OutletCost(amount = 100uL, currency = "USD", payee = "did:dht:payee456", costFormula = "flat"),
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject

        assertEquals("calculator", obj["name"]?.jsonPrimitive?.content)
        assertEquals("Adds two numbers", obj["description"]?.jsonPrimitive?.content)
        // §5.4.2 wire vocabulary: Action serializes as the lowercase "action".
        assertEquals("action", obj["kind"]?.jsonPrimitive?.content)
        assertEquals(true, obj["kind"]?.jsonPrimitive?.isString)
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
    fun `query kind serializes with the query wire string`() {
        // §5.4.2: a Query outlet must serialize its kind as the lowercase
        // "query" wire token — the spelling the Rust bridge deserializes to
        // OutletKind::Query, which selects the outlet_query:{id} UCAN stem.
        val def =
            OutletDefinition(
                name = "weather-lookup",
                description = "Read-only weather query",
                kind = OutletKind.QUERY,
                inputSchemaJson = """{"type":"object","properties":{"city":{"type":"string"}}}""",
                outputSchemaJson = """{"type":"object","properties":{"tempC":{"type":"number"}}}""",
                operatorDid = "did:dht:weatherop",
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject

        assertEquals("query", obj["kind"]?.jsonPrimitive?.content)
        assertEquals(true, obj["kind"]?.jsonPrimitive?.isString)
        assertEquals("weather-lookup", obj["name"]?.jsonPrimitive?.content)
    }

    @Test
    fun `minimal definition`() {
        val def =
            OutletDefinition(
                name = "ping",
                description = "health check",
                kind = OutletKind.ACTION,
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op1",
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject

        assertEquals("ping", obj["name"]?.jsonPrimitive?.content)
        assertEquals("health check", obj["description"]?.jsonPrimitive?.content)
        assertEquals("action", obj["kind"]?.jsonPrimitive?.content)
        assertEquals("did:dht:op1", obj["operator_did"]?.jsonPrimitive?.content)
        assertFalse(obj.containsKey("test_vectors_json"))
        assertFalse(obj.containsKey("implementation_hash"))
        assertFalse(obj.containsKey("cost"))
    }

    @Test
    fun `special characters in name`() {
        val def =
            OutletDefinition(
                name = "outlet\"with\\special\nchars",
                description = "desc\twith\ttabs",
                kind = OutletKind.ACTION,
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op",
            )
        val json = def.toJson()
        // Must parse without exception — proves structural validity
        val obj = Json.parseToJsonElement(json).jsonObject
        assertEquals("outlet\"with\\special\nchars", obj["name"]?.jsonPrimitive?.content)
        assertEquals("desc\twith\ttabs", obj["description"]?.jsonPrimitive?.content)
    }

    @Test
    fun `special characters in cost fields`() {
        val def =
            OutletDefinition(
                name = "outlet",
                description = "d",
                kind = OutletKind.ACTION,
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op",
                cost =
                    OutletCost(
                        amount = 50uL,
                        currency = "US\"D",
                        payee = "did:dht:payeeéü",
                    ),
            )
        val json = def.toJson()
        val obj = Json.parseToJsonElement(json).jsonObject
        val costObj = obj["cost"]?.jsonObject
        assertEquals("US\"D", costObj?.get("currency")?.jsonPrimitive?.content)
        assertEquals("did:dht:payeeéü", costObj?.get("payee")?.jsonPrimitive?.content)
    }

    @Test
    fun `zero amount accepted`() {
        val cost = OutletCost(amount = 0uL, currency = "USD", payee = "did:dht:p")
        assertEquals(0uL, cost.amount)
    }

    @Test
    fun `full-width ULong amount survives exactly through toJson`() {
        // ULong.MAX_VALUE (2^64 - 1) exceeds Long.MAX_VALUE — a signed Long would
        // have overflowed. As the canonical decimal string it round-trips exactly.
        val cost = OutletCost(amount = ULong.MAX_VALUE, currency = "BTC", payee = "did:dht:p")
        assertEquals(ULong.MAX_VALUE, cost.amount)

        val def =
            OutletDefinition(
                name = "expensive",
                description = "d",
                kind = OutletKind.ACTION,
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
            OutletDefinition(
                name = "outlet",
                description = "d",
                kind = OutletKind.ACTION,
                inputSchemaJson = """{}""",
                outputSchemaJson = """{}""",
                operatorDid = "did:dht:op",
                cost = OutletCost(amount = 10uL, currency = "USD", payee = "did:dht:p"),
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
            OutletDefinition(
                name = "outlet",
                description = "d",
                kind = OutletKind.ACTION,
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
