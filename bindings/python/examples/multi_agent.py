"""Multi-agent coordination: multiple agents collaborating in a shared context.

Phase 4 PR 5 (#1549) moved every lifecycle operation onto :class:`SCP`.
Agent entry points receive the shared :class:`SCP` instance and the
context handle explicitly.
"""

import asyncio

from scp_sdk import SCP
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def run_agent(scp: SCP, name: str, identity, ctx) -> None:  # type: ignore[no-untyped-def]
    """Agent loop: join context, listen for messages, respond."""
    await scp.context_join(ctx._raw_handle, identity.did)
    print(f"[{name}] Joined context {ctx.context_id}")

    await scp.context_send(ctx._raw_handle, identity.did, f"[{name}] reporting in".encode())

    count = 0
    receiver = await scp.context_receive(ctx._raw_handle)
    async for msg in receiver:
        sender = msg.sender_did[:16]
        print(f"[{name}] Received from {sender}...: {msg.payload!r}")
        count += 1
        if count >= 2:
            break

    await scp.context_leave(ctx._raw_handle, identity.did)
    print(f"[{name}] Left context")


async def main() -> None:
    with SCP(storage={"type": "in_memory"}) as scp:
        # Create identities for coordinator and two agents.
        coordinator = await scp.identity_create(CustodyType.IN_MEMORY)
        agent_a = await scp.identity_create(CustodyType.IN_MEMORY)
        agent_b = await scp.identity_create(CustodyType.IN_MEMORY)

        # Coordinator creates the context with broad capabilities.
        ctx = await scp.context_create(
            coordinator.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.TOOL_INVOKE_ALL.value,
                    Capability.MEMBER_INVITE.value,
                    Capability.MEMBER_REMOVE.value,
                    Capability.ROLE_ASSIGN.value,
                ],
                "roles": {"agent": ["messages:write", "messages:read", "tool:invoke:*"]},
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
            },
        )
        print(f"Context created: {ctx.context_id}")

        # Mint UCANs for each agent (capability delegation).
        await scp.ucan_mint(
            ctx.context_id,
            agent_a.did,
            ["messages:write", "messages:read"],
        )
        await scp.ucan_mint(
            ctx.context_id,
            agent_b.did,
            ["messages:write", "messages:read"],
        )

        # Run agents concurrently.
        await asyncio.gather(
            run_agent(scp, "Agent-A", agent_a, ctx),
            run_agent(scp, "Agent-B", agent_b, ctx),
        )

        await scp.context_close(ctx._raw_handle, coordinator.did)


if __name__ == "__main__":
    asyncio.run(main())
