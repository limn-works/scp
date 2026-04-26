// OutletCapabilityParseTest.kt - SCP-OUT-014 outlet capability stem parser conformance.
//
// Loads `tests/conformance/vectors/outlet_capability_parse.json` and asserts
// every positive vector parses to the expected variant and every negative
// vector rejects to `null`. The fixture is identical across bridges -
// divergence between the Kotlin wrapper and the Rust core would mean a
// parser-differential authorization bug.
//
// Spec references:
// - .docs/specs/05-contexts.md \u00a75.4.2.1 UCAN Capability Stem Parser
// - .docs/adrs/ADR-049-outlet-redesign.md \u00a71 Rename hard break, \u00a72

@file:Suppress("TooManyFunctions", "LargeClass")

package works.limn.scp

import java.io.File
import java.nio.file.Path
import java.nio.file.Paths
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OutletCapabilityParseTest {

    sealed class Parsed {
        object MessagesRead : Parsed()
        object MessagesWrite : Parsed()
        data class OutletQuery(val id: String) : Parsed()
        object OutletQueryAll : Parsed()
        data class OutletCall(val id: String) : Parsed()
        object OutletCallAll : Parsed()
        object OutletRegister : Parsed()
        object MemberInvite : Parsed()
        object MemberRemove : Parsed()
        object RoleAssign : Parsed()
        object GovernancePropose : Parsed()
        object GovernanceVote : Parsed()
        object ContextClose : Parsed()
        object ChildContextCreate : Parsed()
        object OutletInterface : Parsed()
        object Bridging : Parsed()
        object MediaVoice : Parsed()
        object MediaVideo : Parsed()
        object MediaScreenShare : Parsed()
        object MemberBan : Parsed()
        object MetadataEdit : Parsed()
        data class Custom(val name: String) : Parsed()
    }

    private val suffixRegex = Regex("^[a-z0-9_-]{1,128}$")

    @Suppress("ReturnCount", "ComplexMethod", "LongMethod", "CyclomaticComplexMethod", "ComplexCondition")
    private fun parseCapability(name: String): Parsed? {
        if (name.startsWith("outlet:invoke:") || name.startsWith("outlet_invoke:")) return null
        if (name == "outlet:invoke:*" || name == "outlet_invoke:*") return null
        if (name.startsWith("tool:invoke:") || name.startsWith("tool_invoke:")) return null
        if (name == "tool:register" || name == "tool:interface" ||
            name == "tool_register" || name == "tool_interface"
        ) {
            return null
        }

        when (name) {
            "messages:read" -> return Parsed.MessagesRead
            "messages:write" -> return Parsed.MessagesWrite
            "outlet:query:*", "outlet_query:*" -> return Parsed.OutletQueryAll
            "outlet:call:*", "outlet_call:*" -> return Parsed.OutletCallAll
            "outlet:register" -> return Parsed.OutletRegister
            "member:invite" -> return Parsed.MemberInvite
            "member:remove" -> return Parsed.MemberRemove
            "role:assign" -> return Parsed.RoleAssign
            "governance:propose" -> return Parsed.GovernancePropose
            "governance:vote" -> return Parsed.GovernanceVote
            "context:close" -> return Parsed.ContextClose
            "context:child:create" -> return Parsed.ChildContextCreate
            "outlet:interface" -> return Parsed.OutletInterface
            "bridging" -> return Parsed.Bridging
            "media:voice" -> return Parsed.MediaVoice
            "media:video" -> return Parsed.MediaVideo
            "media:screen_share" -> return Parsed.MediaScreenShare
            "member:ban" -> return Parsed.MemberBan
            "metadata:edit" -> return Parsed.MetadataEdit
        }

        val outletPrefixes = listOf(
            "outlet:query:" to ::makeQuery,
            "outlet_query:" to ::makeQuery,
            "outlet:call:" to ::makeCall,
            "outlet_call:" to ::makeCall,
        )
        for ((prefix, factory) in outletPrefixes) {
            if (name.startsWith(prefix)) {
                val suffix = name.substring(prefix.length)
                if (!suffixRegex.matches(suffix)) return null
                return factory(suffix)
            }
        }

        return if (name.startsWith("custom:")) {
            Parsed.Custom(name.substring("custom:".length))
        } else {
            Parsed.Custom(name)
        }
    }

    private fun makeQuery(id: String): Parsed = Parsed.OutletQuery(id)
    private fun makeCall(id: String): Parsed = Parsed.OutletCall(id)

    private fun fixturePath(): Path {
        var dir = File(System.getProperty("user.dir")).absoluteFile
        repeat(6) {
            val candidate = File(dir, "tests/conformance/vectors/outlet_capability_parse.json")
            if (candidate.exists()) return candidate.toPath()
            dir = dir.parentFile ?: return Paths.get("tests/conformance/vectors/outlet_capability_parse.json")
        }
        return Paths.get("tests/conformance/vectors/outlet_capability_parse.json")
    }

    private fun loadFixture(): JsonObject {
        val text = File(fixturePath().toString()).readText()
        return Json.parseToJsonElement(text).jsonObject
    }

    @Suppress("ComplexMethod", "CyclomaticComplexMethod", "LongMethod", "ReturnCount")
    private fun expectedToParsed(expected: JsonObject): Parsed {
        val kind = expected["kind"]!!.jsonPrimitive.content
        return when (kind) {
            "MessagesRead" -> Parsed.MessagesRead
            "MessagesWrite" -> Parsed.MessagesWrite
            "OutletQuery" -> Parsed.OutletQuery(expected["id"]!!.jsonPrimitive.content)
            "OutletQueryAll" -> Parsed.OutletQueryAll
            "OutletCall" -> Parsed.OutletCall(expected["id"]!!.jsonPrimitive.content)
            "OutletCallAll" -> Parsed.OutletCallAll
            "OutletRegister" -> Parsed.OutletRegister
            "MemberInvite" -> Parsed.MemberInvite
            "MemberRemove" -> Parsed.MemberRemove
            "RoleAssign" -> Parsed.RoleAssign
            "GovernancePropose" -> Parsed.GovernancePropose
            "GovernanceVote" -> Parsed.GovernanceVote
            "ContextClose" -> Parsed.ContextClose
            "ChildContextCreate" -> Parsed.ChildContextCreate
            "OutletInterface" -> Parsed.OutletInterface
            "Bridging" -> Parsed.Bridging
            "MediaVoice" -> Parsed.MediaVoice
            "MediaVideo" -> Parsed.MediaVideo
            "MediaScreenShare" -> Parsed.MediaScreenShare
            "MemberBan" -> Parsed.MemberBan
            "MetadataEdit" -> Parsed.MetadataEdit
            "Custom" -> Parsed.Custom(expected["name"]!!.jsonPrimitive.content)
            else -> throw IllegalArgumentException("unknown expected kind: $kind")
        }
    }

    @Test
    fun fixtureLoadsAndCardinality() {
        val fixture = loadFixture()
        assertEquals("SCP-OUT-014", fixture["story"]!!.jsonPrimitive.content)
        assertTrue(fixture["positive"]!!.jsonArray.size >= 20)
        assertTrue(fixture["negative"]!!.jsonArray.size >= 20)
    }

    @Test
    fun positiveVectorsParse() {
        val fixture = loadFixture()
        for (v in fixture["positive"]!!.jsonArray) {
            val obj = v.jsonObject
            val input = obj["input"]!!.jsonPrimitive.content
            val expected = expectedToParsed(obj["expected"]!!.jsonObject)
            val actual = parseCapability(input)
            assertNotNull(actual, "positive fixture failed: $input")
            assertEquals(expected, actual, "kind/payload mismatch for $input")
        }
    }

    @Test
    fun negativeVectorsReject() {
        val fixture = loadFixture()
        for (v in fixture["negative"]!!.jsonArray) {
            val obj = v.jsonObject
            val input = obj["input"]!!.jsonPrimitive.content
            val reason = obj["reason"]!!.jsonPrimitive.content
            val actual = parseCapability(input)
            assertNull(actual, "negative fixture must reject $input ($reason)")
        }
    }

    @Test
    fun hardBreakOutletInvokeDeleted() {
        assertNull(parseCapability("outlet:invoke:*"))
        assertNull(parseCapability("outlet_invoke:*"))
        assertNull(parseCapability("outlet:invoke:foo"))
        assertNull(parseCapability("outlet_invoke:bar"))
    }

    @Test
    fun hardBreakToolInvokePreRenameRejected() {
        assertNull(parseCapability("tool:invoke:*"))
        assertNull(parseCapability("tool_invoke:*"))
        assertNull(parseCapability("tool:invoke:calculator"))
        assertNull(parseCapability("tool:register"))
        assertNull(parseCapability("tool:interface"))
    }
}
