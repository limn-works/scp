"""Two-participant message exchange over a relay.

Demonstrates two nodes that each attach a relay transport, a context
that Alice creates and Bob joins, a message that Alice sends, and the
receive iterator on Bob's side.

The creator and the joiner each run their own ``SCP`` instance with its
own database, as two devices would. Both instances read the same key file,
because this script runs both in one process.

Prerequisites:
    pip install scp-sdk
    # or: maturin develop --release (from bindings/python/)
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts each SQLCipher database
    export SCP_RELAY_URL=wss://...     # a relay both nodes reach

Usage:
    python messaging.py
"""

import asyncio
import os
from pathlib import Path

from scp_sdk import (
    SCP,
    Capability,
    Context,
    ContextError,
    CustodyType,
    MemoryScope,
    StorageConfig,
)

# A send fails with this code until a peer's routing announcement has
# arrived over the relay (spec §9.10.4). The send is rolled back, so a
# retry is safe.
NO_PEER_ROUTE = "SCP-CTX-2095"
SEND_ATTEMPTS = 10
RETRY_DELAY_SECONDS = 0.5
RECEIVE_TIMEOUT_SECONDS = 10.0


def node_storage(name: str) -> StorageConfig:
    """Return SQLCipher storage at ``$HOME/.scp/<name>``.

    ``SCP_STORAGE_PASSPHRASE`` derives the database key. An unset variable
    raises ``KeyError`` here, before any database opens.
    """
    path = Path.home() / ".scp" / name
    path.mkdir(parents=True, exist_ok=True)
    return {
        "type": "sqlite",
        "path": str(path),
        "passphrase": os.environ["SCP_STORAGE_PASSPHRASE"],
    }


async def send_when_routable(
    node: SCP, ctx: Context, sender_did: str, payload: bytes
) -> None:
    """Send ``payload``, retrying only while no peer route is known."""
    for attempt in range(1, SEND_ATTEMPTS + 1):
        try:
            await node.context_send(ctx, sender_did, payload)
            return
        except ContextError as exc:
            if exc.code != NO_PEER_ROUTE or attempt == SEND_ATTEMPTS:
                raise
            await asyncio.sleep(RETRY_DELAY_SECONDS)


async def main() -> None:
    relay_url = os.environ["SCP_RELAY_URL"]

    async with (
        SCP(storage=node_storage("messaging-example-alice")) as alice_node,
        SCP(storage=node_storage("messaging-example-bob")) as bob_node,
    ):
        # 1. Each side creates its identity in its own node.
        alice = await alice_node.identity_create(CustodyType.FILE)
        bob = await bob_node.identity_create(CustodyType.FILE)
        print(f"Alice: {alice.did}")
        print(f"Bob:   {bob.did}")

        # 2. Each node attaches its relay transport before it creates or
        #    joins a context: the context supervisor starts on the first
        #    context and binds the transport it finds then.
        for node, did in ((alice_node, alice.did), (bob_node, bob.did)):
            await node.configure_relay_transport(relay_url, did)
            await node.transport_connect(relay_url)

        # 3. Alice creates a single-admin context. Inviting runs through the
        #    governance gate, so the ceiling carries governance:propose.
        ctx = await alice_node.context_create(
            alice.did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.MEMBER_INVITE.value,
                    Capability.MEMBER_REMOVE.value,
                    Capability.GOVERNANCE_PROPOSE.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
            },
        )
        print(f"\nContext: {ctx.context_id}")

        # 4. Bob reserves a KeyPackage, Alice seals an invitation to it,
        #    and Bob joins from the sealed bundle.
        reservation_id, key_package = await bob_node.reserve_key_package(bob.did)
        outcome = await alice_node.invite_member(
            ctx.context_id, alice.did, bob.did, key_package, [relay_url]
        )
        bob_ctx = await bob_node.context_join_from_welcome(
            bob.did, outcome.bundle, reservation_id
        )
        print("Bob joined the context.")

        # 5. Bob opens his receive iterator before Alice sends. The iterator
        #    is backed by a bounded buffer; when the consumer falls behind,
        #    the oldest unconsumed event is dropped.
        receiver = await bob_node.context_receive(bob_ctx)

        # 6. Alice sends once Bob's routing announcement has reached her.
        await send_when_routable(alice_node, ctx, alice.did, b"Hello Bob!")
        print("\nAlice: Hello Bob!")

        # 7. Bob reads one message, waiting a bounded time for it.
        msg = await asyncio.wait_for(anext(receiver), RECEIVE_TIMEOUT_SECONDS)
        print(f"Bob received from {msg.sender_did}: {msg.payload.decode()}")

        # 8. Bob leaves the context.
        await bob_node.context_leave(bob_ctx, bob.did)
        print("\nBob left the context.")

    print("\nMessage exchange complete.")


if __name__ == "__main__":
    asyncio.run(main())
