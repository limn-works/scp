/**
 * Tool registration and invocation within a context.
 *
 * Demonstrates defining a tool with a JSON schema, registering it
 * in a context, invoking it, and verifying test vectors.
 *
 * Prerequisites:
 *   implementation("works.limn:scp-kt:0.1.0")
 *
 * Usage:
 *   ./gradlew run --args="tools"
 */

package works.limn.scp.examples

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import works.limn.scp.CustodyType
import works.limn.scp.bridge.CoroutineBridge

fun toolsExample(bridge: CoroutineBridge) = runBlocking {
    // 1. Create an identity for the tool operator.
    val operatorHandle = bridge.identity.create(CustodyType.IN_MEMORY)
    println("Operator handle: $operatorHandle")

    // 2. Create a context with tool capabilities.
    val paramsJson = buildJsonObject {
        putJsonArray("ceiling") {
            add("messages:read")
            add("messages:write")
            add("tool:register")
            add("tool:invoke_all")
        }
    }.toString()

    val contextHandle = bridge.context.create(operatorHandle, paramsJson)
    println("Context handle: $contextHandle")

    // 3. Define a calculator tool as JSON.
    //    The Kotlin SDK passes tool definitions as JSON strings through
    //    the FFI bridge. The Rust side validates the schema.
    val definitionJson = buildJsonObject {
        put("name", "calculator")
        put("description", "A simple arithmetic calculator")
        putJsonObject("input_schema") {
            put("type", "object")
            putJsonObject("properties") {
                putJsonObject("a") { put("type", "number") }
                putJsonObject("b") { put("type", "number") }
                putJsonObject("op") {
                    put("type", "string")
                    putJsonArray("enum") {
                        add("add")
                        add("sub")
                        add("mul")
                    }
                }
            }
            putJsonArray("required") {
                add("a")
                add("b")
                add("op")
            }
        }
        putJsonObject("output_schema") {
            put("type", "object")
            putJsonObject("properties") {
                putJsonObject("result") { put("type", "number") }
            }
            putJsonArray("required") { add("result") }
        }
    }.toString()

    println("\nTool defined: calculator")

    // 4. Register the tool in the context.
    val toolId = bridge.tools.register(contextHandle, definitionJson)
    println("  Registered with ID: $toolId")

    // 5. Verify the tool against test vectors.
    //    The verify function checks that the tool's implementation
    //    matches its declared input/output schemas.
    val verifyInput = """{"a": 2, "b": 3, "op": "add"}"""
    val verifyOutput = """{"result": 5}"""
    val passed = bridge.tools.verify(toolId, verifyInput, verifyOutput)
    println("  Verification passed: $passed")

    // 6. Invoke the tool.
    //    Input is passed as a JSON string. The result is returned
    //    as a JSON string.
    val inputJson = """{"a": 7, "b": 3, "op": "mul"}"""
    println("\nInvoking calculator with: $inputJson")

    val resultJson = bridge.tools.invoke(contextHandle, toolId, inputJson)
    println("  Result: $resultJson")

    // 7. UCAN authorization for tool invocation.
    //    In production, tool invocation requires a valid UCAN token
    //    with tool_invoke:* or tool_invoke:{tool_id} capability.
    //
    //    val ucanToken = bridge.ucan.mint(
    //        operatorHandle,
    //        memberDid,
    //        """["tool_invoke:*"]"""
    //    )
    //
    //    See spec section 7.2 for UCAN enforcement rules.

    // 8. Clean up.
    bridge.context.close(contextHandle)
    println("\nTool operations complete.")
}
