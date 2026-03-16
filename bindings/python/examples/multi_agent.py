"""Multi-agent coordination: multiple agents collaborating in a shared context."""

import asyncio

from scp_sdk import Context, Identity
from scp_sdk.types import Capability, CustodyType, MemoryScope
from scp_sdk.ucan import mint


async def run_agent(name: str, identity: Identity, ctx: Context) -> None:
    """Agent loop: join context, listen for messages, respond."""
    membership = await ctx.join(identity)
    print(f"[{name}] Joined context {ctx.context_id} as {membership.role}")

    await ctx.send(f"[{name}] reporting in".encode(), identity=identity)

    count = 0
    receiver = await ctx.receive()
    async for msg in receiver:
        sender = msg.sender_did[:16]
        print(f"[{name}] Received from {sender}...: {msg.content!r}")
        count += 1
        if count >= 2:
            break

    await ctx.leave(identity)
    print(f"[{name}] Left context")


async def main() -> None:
    # Create identities for coordinator and two agents
    coordinator = await Identity.create(custody=CustodyType.IN_MEMORY)
    agent_a = await Identity.create(custody=CustodyType.IN_MEMORY)
    agent_b = await Identity.create(custody=CustodyType.IN_MEMORY)

    # Coordinator creates the context with broad capabilities so agents can
    # be invited and participate.  single_admin governance means the
    # coordinator (creator) must add members via ctx.join().
    ctx = await Context.create(
        creator=coordinator,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.TOOL_INVOKE_ALL,
            Capability.MEMBER_INVITE,
            Capability.MEMBER_REMOVE,
            Capability.ROLE_ASSIGN,
        ],
        roles={"agent": ["messages:write", "messages:read", "tool:invoke:*"]},
        memory_scope=MemoryScope.EPHEMERAL,
        governance="single_admin",
    )
    print(f"Context created: {ctx.context_id}")

    # Mint UCANs for each agent (capability delegation)
    await mint(
        audience=agent_a.did,
        capabilities=["messages:write", "messages:read"],
        context=ctx.context_id,
    )
    await mint(
        audience=agent_b.did,
        capabilities=["messages:write", "messages:read"],
        context=ctx.context_id,
    )

    # Run agents concurrently
    await asyncio.gather(
        run_agent("Agent-A", agent_a, ctx),
        run_agent("Agent-B", agent_b, ctx),
    )

    await ctx.close(coordinator)


if __name__ == "__main__":
    asyncio.run(main())
