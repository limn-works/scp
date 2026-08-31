"""Basic messaging: create identity, create context, send and receive messages.

Post-Phase-4 (#1549, ADR-048): every SDK call routes through an explicit
:class:`scp_sdk.SCP` instance. Construct one at process start, call
:meth:`SCP.identity_create` / :meth:`SCP.context_create` / etc., and let
the ``with`` block drain in-flight work via ``scp.shutdown()`` on exit.
"""

import asyncio

from scp_sdk import SCP
from scp_sdk.types import Capability, CustodyType, MemoryScope


async def main() -> None:
    with SCP(storage={"type": "in_memory"}) as scp:
        # Create two identities in the encrypted key file SCP implements.
        alice = await scp.identity_create(CustodyType.ENCRYPTED_FILE)
        bob = await scp.identity_create(CustodyType.ENCRYPTED_FILE)
        print(f"Alice DID: {alice.did}")
        print(f"Bob DID: {bob.did}")

        # Alice creates a context.
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
                "ttl": 3600.0,
            },
        )
        print(f"Context ID: {ctx.context_id}")

        # Bob joins the context.
        await scp.context_join(ctx._raw_handle, bob.did)
        print(f"Bob joined: {bob.did}")

        # Alice sends a message.
        await scp.context_send(ctx._raw_handle, alice.did, b"Hello Bob, this is Alice")

        # Bob receives it.
        receiver = await scp.context_receive(ctx._raw_handle)
        async for msg in receiver:
            print(f"Bob received from {msg.sender_did}: {msg.payload!r}")
            break

        # Bob leaves.
        await scp.context_leave(ctx._raw_handle, bob.did)

        # Alice closes the context.
        await scp.context_close(ctx._raw_handle, alice.did)


if __name__ == "__main__":
    asyncio.run(main())
