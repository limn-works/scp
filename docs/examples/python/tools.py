"""Tool registration and invocation within a context.

Demonstrates defining a tool with a JSON schema, registering it
in a context, and invoking it with UCAN authorization. Also shows
cross-context tool invocation and stateful tool sessions.

Prerequisites:
    pip install scp-sdk
    # or: maturin develop --release (from bindings/python/)

Usage:
    python tools.py
"""

import asyncio

from scp_sdk import (
    Capability,
    Context,
    CustodyType,
    Identity,
    ToolDefinition,
    TestVector,
)
from scp_sdk.tools import session_create, session_invoke, session_close
from scp_sdk.ucan import mint


async def main() -> None:
    # 1. Create an identity for the tool operator.
    operator = await Identity.create(custody=CustodyType.IN_MEMORY)
    print(f"Operator DID: {operator.did}")

    # 2. Create a context with tool capabilities.
    async with await Context.create(
        creator=operator,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.TOOL_REGISTER,
            Capability.TOOL_INVOKE_ALL,
        ],
    ) as ctx:
        print(f"Context: {ctx.context_id}")

        # 3. Define a calculator tool with JSON schemas.
        calculator = ToolDefinition(
            name="calculator",
            description="A simple arithmetic calculator",
            input_schema={
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                    "op": {"type": "string", "enum": ["add", "sub", "mul"]},
                },
                "required": ["a", "b", "op"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "result": {"type": "number"},
                },
                "required": ["result"],
            },
            operator=operator.did,
            test_vectors=[
                TestVector(
                    input={"a": 2, "b": 3, "op": "add"},
                    expected_output={"result": 5},
                    description="2 + 3 = 5",
                ),
                TestVector(
                    input={"a": 7, "b": 3, "op": "mul"},
                    expected_output={"result": 21},
                    description="7 * 3 = 21",
                ),
            ],
        )
        print(f"\nTool defined: {calculator.name}")
        print(f"  Description: {calculator.description}")
        print(f"  Test vectors: {len(calculator.test_vectors)}")

        # 4. Mint a UCAN token authorizing tool invocation.
        #    The token grants tool_invoke:* capability for this context.
        ucan_token = await mint(
            operator._handle,
            operator.did,
            '["tool_invoke:*"]',
        )
        print(f"\nUCAN minted (length: {len(ucan_token)})")

        # 5. Invoke the tool.
        #    In a real application, the context would have the tool
        #    registered server-side. Here we show the invocation pattern.
        result = await ctx.invoke(
            tool="calculator",
            input={"a": 7, "b": 3, "op": "mul"},
            ucan_token=ucan_token,
            identity=operator,
        )
        print(f"\nInvoked calculator: 7 * 3")
        print(f"  Result: {result}")

        # 6. Stateful tool sessions (spec section 6.2.1).
        #    Sessions enable multi-turn workflows with state preservation.
        session_id = await session_create(
            context_id=ctx.context_id,
            tool_id="calculator",
            source_context_id=ctx.context_id,
            ttl_seconds=300,  # 5-minute session
        )
        print(f"\nSession created: {session_id}")

        # Invoke within the session (state is carried forward).
        session_result = await session_invoke(
            context_id=ctx.context_id,
            session_id=session_id,
            input={"a": 10, "b": 5, "op": "sub"},
            invoker_did=operator.did,
            ucan_token=ucan_token,
        )
        print(f"  Session invoke: 10 - 5 = {session_result}")

        # Close the session.
        await session_close(
            context_id=ctx.context_id,
            session_id=session_id,
        )
        print("  Session closed.")

    print("\nTool operations complete.")


if __name__ == "__main__":
    asyncio.run(main())
