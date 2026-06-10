"""Broadcast demo.

Starts an in-memory relay, creates a broadcast context, subscribes
a listener, publishes a message, and verifies receipt.

Requires a built native extension (``maturin develop --release``).
"""

import asyncio

from scp_sdk import SCP
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    with SCP(storage={"type": "in_memory"}) as scp:
        # 1. Start an in-memory relay.
        relay = await scp.relay_start_in_memory()
        print(f"Relay listening at {relay.relay_url}")

        # 1b. Connect transport to the relay.
        await scp.transport_connect(relay.relay_url)

        # 2. Create publisher and subscriber identities.
        publisher = await scp.identity_create(CustodyType.IN_MEMORY)
        subscriber = await scp.identity_create(CustodyType.IN_MEMORY)
        print(f"Publisher DID:  {publisher.did}")
        print(f"Subscriber DID: {subscriber.did}")

        # 3. Create a broadcast context.
        ctx = await scp.context_create(
            publisher.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.MEMBER_INVITE.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
                "mode": "broadcast",
                "ttl": 300.0,
            },
        )
        print(f"Broadcast context created: {ctx.context_id}")

        try:
            # 4. Subscriber joins.
            await scp.context_join(ctx._raw_handle, subscriber.did)
            print("Subscriber joined")

            # 5. Publisher sends a broadcast message.
            payload = b"Breaking news: SCP protocol is live!"
            await scp.context_send(ctx._raw_handle, publisher.did, payload)
            print("Publisher sent broadcast")

            # 6. Subscriber receives the broadcast.
            receiver = await scp.context_receive(ctx._raw_handle)
            async for msg in receiver:
                print(f"Subscriber received: {msg.payload!r}")
                break

            # 7. Cleanup.
            await scp.context_leave(ctx._raw_handle, subscriber.did)
            await scp.context_close(ctx._raw_handle, publisher.did)
        finally:
            await relay.shutdown()

    print("Demo complete")


if __name__ == "__main__":
    asyncio.run(main())
