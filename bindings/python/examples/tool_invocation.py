"""Tool invocation: register a tool with test vectors and invoke it."""

import asyncio

from scp_sdk import Context, Identity


async def main() -> None:
    identity = await Identity.create(custody="platform")

    ctx = await Context.create(
        identity=identity,
        params={
            "ceiling": ["msg:send", "msg:receive", "tool:invoke"],
            "tools": [
                {
                    "name": "weather",
                    "description": "Get current weather for a city",
                    "input_schema": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"],
                    },
                    "output_schema": {
                        "type": "object",
                        "properties": {
                            "temp_c": {"type": "number"},
                            "condition": {"type": "string"},
                        },
                    },
                    "operator": identity.did,
                    "test_vectors": [
                        {
                            "input": {"city": "Berlin"},
                            "expected_output": {"temp_c": 18, "condition": "cloudy"},
                            "description": "Berlin weather lookup",
                        }
                    ],
                }
            ],
        },
    )

    # Invoke the tool
    result = await ctx.invoke_tool("weather", {"city": "Berlin"})
    print(f"Weather result: {result}")

    await ctx.close()


if __name__ == "__main__":
    asyncio.run(main())
