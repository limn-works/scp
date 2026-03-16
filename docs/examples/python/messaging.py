"""Two-participant message exchange.

Demonstrates creating a context, adding a second participant,
and exchanging messages between them. Shows how the receive
iterator delivers messages asynchronously.

Prerequisites:
    pip install scp-sdk
    # or: maturin develop --release (from bindings/python/)

Usage:
    python messaging.py
"""

import asyncio

from scp_sdk import Capability, Context, ContextMode, CustodyType, Identity


async def main() -> None:
    # 1. Create two identities.
    alice = await Identity.create(custody=CustodyType.IN_MEMORY)
    bob = await Identity.create(custody=CustodyType.IN_MEMORY)
    print(f"Alice: {alice.did}")
    print(f"Bob:   {bob.did}")

    # 2. Alice creates a context with messaging capabilities.
    async with await Context.create(
        creator=alice,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.MEMBER_INVITE,
            Capability.MEMBER_REMOVE,
        ],
        mode=ContextMode.ENCRYPTED,
    ) as ctx:
        print(f"\nContext: {ctx.context_id}")

        # 3. Bob joins the context.
        await ctx.join(bob)
        print("Bob joined the context.")

        members = await ctx.member_dids()
        print(f"Members: {members}")
        assert len(members) == 2

        # 4. Alice sends a message.
        await ctx.send("Hello Bob!", identity=alice)
        print("\nAlice: Hello Bob!")

        # 5. Bob sends a reply.
        await ctx.send("Hi Alice!", identity=bob)
        print("Bob: Hi Alice!")

        # 6. Receive messages via async iterator.
        #    In a real application, you would consume this in a long-running
        #    loop. Here we demonstrate the pattern:
        #
        #    receiver = await ctx.receive()
        #    async for msg in receiver:
        #        print(f"  [{msg.sender_did}] {msg.content}")
        #        if some_condition:
        #            break
        #
        #    The iterator is backed by a bounded buffer (default 1,000 events).
        #    When the consumer falls behind, the oldest unconsumed event is
        #    dropped and a BufferOverflow warning is emitted.
        print("\n(Message receive iterator ready for consumption)")

        # 7. Bob leaves the context.
        await ctx.leave(bob)
        print("\nBob left the context.")

        remaining = await ctx.member_dids()
        print(f"Remaining members: {remaining}")

    print("\nMessage exchange complete.")


if __name__ == "__main__":
    asyncio.run(main())
