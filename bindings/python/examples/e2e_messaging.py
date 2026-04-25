"""E2E encrypted messaging demo.

Starts an in-memory relay, creates two identities, creates an encrypted
context, joins both participants, sends a message from Alice, receives
it as Bob, and shuts everything down cleanly.

Requires a built native extension (``maturin develop --release``).
"""

import asyncio

from scp_sdk import SCP
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    with SCP() as scp:
        # 1. Start an in-memory relay (zero external dependencies)
        relay = await scp.relay_start_in_memory()
        print(f"Relay listening at {relay.relay_url}")

        # 1b. Connect transport to the relay.
        await scp.transport_connect(relay.relay_url)

        # 2. Create two identities
        alice = await scp.identity_create(CustodyType.IN_MEMORY)
        bob = await scp.identity_create(CustodyType.IN_MEMORY)
        print(f"Alice DID: {alice.did}")
        print(f"Bob DID:   {bob.did}")

        # 3. Alice creates an encrypted context on this relay.
        ctx = await scp.context_create(
            alice.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.MEMBER_INVITE.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
                "ttl": 300.0,
            },
        )
        print(f"Context created: {ctx.context_id}")

        try:
            # 4. Bob joins the context.
            await scp.context_join(ctx._raw_handle, bob.did)
            print(f"Bob joined: {bob.did}")

            # 5. Alice sends a message.
            plaintext = b"Hello Bob, this message is E2E encrypted via MLS"
            await scp.context_send(ctx._raw_handle, alice.did, plaintext)
            print("Alice sent message")

            # 6. Bob receives the message.
            receiver = await scp.context_receive(ctx._raw_handle)
            async for msg in receiver:
                print(f"Bob received from {msg.sender_did}: {msg.payload!r}")
                break

            # 7. Cleanup.
            await scp.context_leave(ctx._raw_handle, bob.did)
            print("Bob left the context")

            await scp.context_close(ctx._raw_handle, alice.did)
            print("Context closed")
        finally:
            await relay.shutdown()

    print("Relay shut down -- demo complete")


if __name__ == "__main__":
    asyncio.run(main())
