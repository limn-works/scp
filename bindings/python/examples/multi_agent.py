"""Multi-agent coordination: multiple agents collaborating in a shared context."""

import asyncio

from scp_sdk import Context, Identity
from scp_sdk.ucan import mint


async def run_agent(name: str, identity: Identity, context_id: str) -> None:
    """Agent loop: join context, listen for messages, respond."""
    ctx = await Context.join(identity=identity, context_id=context_id)
    print(f"[{name}] Joined context {context_id}")

    await ctx.send(f"[{name}] reporting in".encode())

    count = 0
    async for msg in ctx.receive():
        sender = msg.sender_did[:16]
        print(f"[{name}] Received from {sender}...: {msg.content.decode()}")
        count += 1
        if count >= 2:
            break

    await ctx.leave()
    print(f"[{name}] Left context")


async def main() -> None:
    # Create identities for coordinator and two agents
    coordinator = await Identity.create(custody="platform")
    agent_a = await Identity.create(custody="platform")
    agent_b = await Identity.create(custody="platform")

    # Coordinator creates the context with agent capabilities
    ctx = await Context.create(
        identity=coordinator,
        params={
            "ceiling": ["msg:send", "msg:receive", "tool:invoke"],
            "roles": {
                "agent": ["msg:send", "msg:receive", "tool:invoke"],
            },
            "governance": "single_admin",
        },
    )
    print(f"Context created: {ctx.context_id}")

    # Mint UCANs for each agent (capability delegation)
    await mint(
        issuer=coordinator,
        audience=agent_a.did,
        capabilities=["msg:send", "msg:receive"],
        context_id=ctx.context_id,
    )
    await mint(
        issuer=coordinator,
        audience=agent_b.did,
        capabilities=["msg:send", "msg:receive"],
        context_id=ctx.context_id,
    )

    # Run agents concurrently
    await asyncio.gather(
        run_agent("Agent-A", agent_a, ctx.context_id),
        run_agent("Agent-B", agent_b, ctx.context_id),
    )

    await ctx.close()


if __name__ == "__main__":
    asyncio.run(main())
