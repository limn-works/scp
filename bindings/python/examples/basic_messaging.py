"""Basic messaging: create identity, create context, send and receive messages.

Post-Phase-4 (ADR-048): every SDK call routes through an explicit
:class:`~scp_sdk.SCP` instance. Construct one at process start, pass it to
:meth:`Identity.create`, and let the ``with`` block drain in-flight work
via ``scp.shutdown()`` on exit.
"""

import asyncio

from scp_sdk import SCP, Context, Identity
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    with SCP() as scp:
        # Create two identities (in_memory custody for examples)
        alice = await Identity.create(scp, custody=CustodyType.IN_MEMORY)
        bob = await Identity.create(scp, custody=CustodyType.IN_MEMORY)
        print(f"Alice DID: {alice.did}")
        print(f"Bob DID: {bob.did}")

        # Alice creates a context
        async with await Context.create(
            scp,
            creator=alice,
            ceiling=[Capability.MESSAGES_READ, Capability.MESSAGES_WRITE, Capability.MEMBER_INVITE],
            memory_scope=MemoryScope.EPHEMERAL,
            governance="single_admin",
            ttl=3600.0,
        ) as ctx:
            print(f"Context ID: {ctx.context_id}")

            # Bob joins the context (admin adds bob via the context instance)
            membership = await ctx.join(bob)
            print(f"Bob joined as: {membership.role}")

            # Alice sends a message
            await ctx.send(b"Hello Bob, this is Alice")

            # Bob receives it
            receiver = await ctx.receive()
            async for msg in receiver:
                print(f"Bob received from {msg.sender_did}: {msg.content!r}")
                break

            # Bob leaves
            await ctx.leave(bob)

            # Alice closes the context
            await ctx.close(alice)


if __name__ == "__main__":
    asyncio.run(main())
