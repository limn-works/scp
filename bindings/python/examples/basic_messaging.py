"""Basic messaging: create identity, create context, send and receive messages."""

import asyncio

from scp_sdk import Context, Identity


async def main() -> None:
    # Create two identities
    alice = await Identity.create(custody="platform")
    bob = await Identity.create(custody="platform")
    print(f"Alice DID: {alice.did}")
    print(f"Bob DID: {bob.did}")

    # Alice creates a context
    ctx_alice = await Context.create(
        identity=alice,
        params={
            "ceiling": ["msg:send", "msg:receive"],
            "ttl": 3600,
            "governance": "single_admin",
        },
    )
    print(f"Context ID: {ctx_alice.context_id}")

    # Bob joins the context
    ctx_bob = await Context.join(identity=bob, context_id=ctx_alice.context_id)

    # Alice sends a message
    await ctx_alice.send(b"Hello Bob, this is Alice")

    # Bob receives it
    async for msg in ctx_bob.receive():
        print(f"Bob received from {msg.sender_did}: {msg.content.decode()}")
        break

    # Cleanup
    await ctx_bob.leave()
    await ctx_alice.close()


if __name__ == "__main__":
    asyncio.run(main())
