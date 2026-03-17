"""Broadcast demo.

Starts an in-memory relay, creates a broadcast context, subscribes
a listener, publishes a message, and verifies receipt.

Requires a built native extension (``maturin develop --release``).
"""

import asyncio

from scp_sdk import Context, Identity
from scp_sdk.server import Relay
from scp_sdk.transport import connect_relay
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    # 1. Start an in-memory relay
    async with await Relay.start_in_memory() as relay:
        print(f"Relay listening at {relay.relay_url}")

        # 1b. Connect transport to the relay
        await connect_relay(relay.relay_url)

        # 2. Create publisher and subscriber identities
        publisher = await Identity.create(custody=CustodyType.IN_MEMORY)
        subscriber = await Identity.create(custody=CustodyType.IN_MEMORY)
        print(f"Publisher DID:  {publisher.did}")
        print(f"Subscriber DID: {subscriber.did}")

        # 3. Create a broadcast context
        async with await Context.create(
            creator=publisher,
            ceiling=[
                Capability.MESSAGES_READ,
                Capability.MESSAGES_WRITE,
                Capability.MEMBER_INVITE,
            ],
            memory_scope=MemoryScope.EPHEMERAL,
            governance="single_admin",
            mode="broadcast",
            ttl=300.0,
        ) as ctx:
            print(f"Broadcast context created: {ctx.context_id}")

            # 4. Subscriber joins and subscribes
            await ctx.join(subscriber)
            print("Subscriber joined")

            # 5. Publisher sends a broadcast message
            payload = b"Breaking news: SCP protocol is live!"
            await ctx.send(payload)
            print("Publisher sent broadcast")

            # 6. Subscriber receives the broadcast
            receiver = await ctx.receive()
            async for msg in receiver:
                print(f"Subscriber received: {msg.content!r}")
                break

            # 7. Cleanup
            await ctx.leave(subscriber)
            await ctx.close(publisher)

    print("Demo complete")


if __name__ == "__main__":
    asyncio.run(main())
