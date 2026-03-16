"""Tool invocation: register a tool and invoke it with UCAN authorization."""

import asyncio

from scp_sdk import Context, Identity
from scp_sdk.types import Capability, CustodyType, MemoryScope
from scp_sdk.ucan import mint


async def main() -> None:
    identity = await Identity.create(custody=CustodyType.IN_MEMORY)

    ctx = await Context.create(
        creator=identity,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.TOOL_INVOKE_ALL,
            Capability.TOOL_REGISTER,
        ],
        memory_scope=MemoryScope.EPHEMERAL,
        governance="single_admin",
    )

    # Mint a UCAN token authorizing tool invocation
    ucan_token = await mint(
        audience=identity.did,
        capabilities=["tool:invoke:*"],
        context=ctx.context_id,
    )

    # Invoke the tool (requires a UCAN token)
    try:
        result = await ctx.invoke(
            tool="weather",
            input={"city": "Berlin"},
            ucan_token=ucan_token.token_id,
        )
        print(f"Weather result: {result}")
    except Exception as exc:
        # Tool invocation may fail without a registered tool handler
        print(f"Tool invocation result: {exc}")

    await ctx.close(identity)


if __name__ == "__main__":
    asyncio.run(main())
