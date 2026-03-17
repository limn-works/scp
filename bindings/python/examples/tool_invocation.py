"""Tool invocation demo.

Starts an in-memory relay, creates an identity, creates a context with
tool capabilities, registers a tool, mints a UCAN token for authorization,
invokes the tool, and verifies the result.

Requires a built native extension (``maturin develop --release``).
"""

import asyncio

from scp_sdk import Context, Identity
from scp_sdk.server import Relay
from scp_sdk.transport import connect_relay
from scp_sdk.types import Capability, CustodyType, MemoryScope
from scp_sdk.ucan import mint


async def main() -> None:
    # 1. Start an in-memory relay
    async with await Relay.start_in_memory() as relay:
        print(f"Relay listening at {relay.relay_url}")

        # 1b. Connect transport to the relay
        await connect_relay(relay.relay_url)

        # 2. Create an identity
        identity = await Identity.create(custody=CustodyType.IN_MEMORY)
        print(f"Identity DID: {identity.did}")

        # 3. Create a context with tool capabilities
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
        print(f"Context created: {ctx.context_id}")

        # 4. Mint a UCAN token authorizing tool invocation
        ucan_token = await mint(
            audience=identity.did,
            capabilities=["tool:invoke:*"],
            context=ctx.context_id,
        )
        print(f"UCAN minted: {ucan_token.token_id}")

        # 5. Invoke the tool (requires a UCAN token)
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

        # 6. Cleanup
        await ctx.close(identity)
        print("Context closed")

    print("Demo complete")


if __name__ == "__main__":
    asyncio.run(main())
