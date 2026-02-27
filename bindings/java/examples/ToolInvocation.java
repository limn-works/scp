/** Tool invocation: register a tool with test vectors and invoke it. */

package com.limn.scp.examples;

import com.limn.scp.Context;
import com.limn.scp.Identity;
import java.util.List;
import java.util.Map;

public class ToolInvocation {
    public static void main(String[] args) throws Exception {
        var identity = Identity.create("platform").join();

        var ctx = Context.create(identity, Map.of(
            "ceiling", List.of("msg:send", "msg:receive", "tool:invoke"),
            "tools", List.of(Map.of(
                "name", "weather",
                "description", "Get current weather for a city",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of("city", Map.of("type", "string")),
                    "required", List.of("city")
                ),
                "outputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "tempC", Map.of("type", "number"),
                        "condition", Map.of("type", "string")
                    )
                ),
                "operator", identity.did(),
                "testVectors", List.of(Map.of(
                    "input", Map.of("city", "Berlin"),
                    "expectedOutput", Map.of("tempC", 18, "condition", "cloudy"),
                    "description", "Berlin weather lookup"
                ))
            ))
        )).join();

        // Invoke the tool
        var result = ctx.invokeTool("weather", Map.of("city", "Berlin")).join();
        System.out.println("Weather result: " + result);

        ctx.close();
        identity.close();
    }
}
