"""E2E encrypted messaging demo.

Starts an in-memory relay, creates two identities, creates an encrypted
context, joins both participants, sends a message from Alice, receives
it as Bob, and shuts everything down cleanly.

Requires a built native extension (``maturin develop --release``).
"""

import asyncio

from scp_sdk import Context, Identity
from scp_sdk.server import Relay
from scp_sdk.transport import connect_relay
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    # 1. Start an in-memory relay (zero external dependencies)
    async with await Relay.start_in_memory() as relay:
        print(f"Relay listening at {relay.relay_url}")

        # 1b. Connect transport to the relay
        await connect_relay(relay.relay_url)

        # 2. Create two identities
        alice = await Identity.create(custody=CustodyType.IN_MEMORY)
        bob = await Identity.create(custody=CustodyType.IN_MEMORY)
        print(f"Alice DID: {alice.did}")
        print(f"Bob DID:   {bob.did}")

        # 3. Alice creates an encrypted context on this relay
        async with await Context.create(
            creator=alice,
            ceiling=[
                Capability.MESSAGES_READ,
                Capability.MESSAGES_WRITE,
                Capability.MEMBER_INVITE,
            ],
            memory_scope=MemoryScope.EPHEMERAL,
            governance="single_admin",
            ttl=300.0,
        ) as ctx:
            print(f"Context created: {ctx.context_id}")

            # 4. Bob joins the context
            membership = await ctx.join(bob)
            print(f"Bob joined with role: {membership.role}")

            # 5. Alice sends a message
            plaintext = b"Hello Bob, this message is E2E encrypted via MLS"
            await ctx.send(plaintext)
            print("Alice sent message")

            # 6. Bob receives the message
            receiver = await ctx.receive()
            async for msg in receiver:
                print(f"Bob received from {msg.sender_did}: {msg.content!r}")
                break

            # 7. Cleanup
            await ctx.leave(bob)
            print("Bob left the context")

            await ctx.close(alice)
            print("Context closed")

    print("Relay shut down -- demo complete")


if __name__ == "__main__":
    asyncio.run(main())
