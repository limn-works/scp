"""Context creation and the invite-and-join handshake.

Demonstrates creating an SCP context with governance parameters,
inviting a second identity, and joining from the sealed invitation.

The creator and the joiner each run their own ``SCP`` instance with its
own database, as two devices would. Both instances read the same key file,
because this script runs both in one process.

Prerequisites:
    pip install scp-sdk
    # or: maturin develop --release (from bindings/python/)
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts each SQLCipher database

Usage:
    python context.py
"""

import asyncio
import os
from pathlib import Path

from scp_sdk import SCP, Capability, CustodyType, MemoryScope, StorageConfig


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


async def main() -> None:
    async with (
        SCP(storage=node_storage("context-example-alice")) as alice_node,
        SCP(storage=node_storage("context-example-bob")) as bob_node,
    ):
        # 1. Each side creates its identity in its own node.
        alice = await alice_node.identity_create(CustodyType.FILE)
        bob = await bob_node.identity_create(CustodyType.FILE)
        print(f"Alice DID: {alice.did}")
        print(f"Bob DID:   {bob.did}")

        # 2. Alice creates a single-admin context. The ceiling caps what any
        #    member can hold. Inviting runs through the governance gate, so
        #    the ceiling must carry governance:propose.
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
        print()
        print(f"Context created: {ctx.context_id}")
        print(f"  State: {ctx.state}")

        # 3. Bob reserves a single-use KeyPackage and hands Alice its public
        #    bytes out of band.
        reservation_id, key_package = await bob_node.reserve_key_package(bob.did)

        # 4. Alice seals an invitation to that KeyPackage. An empty relay list
        #    means Alice delivers the sealed bundle to Bob herself.
        outcome = await alice_node.invite_member(
            ctx.context_id,
            alice.did,
            bob.did,
            key_package,
            [],
        )
        print(f"  Invitation sealed for {bob.did}")

        # 5. Bob opens the sealed bundle and joins.
        joined = await bob_node.context_join_from_welcome(
            bob.did, outcome.bundle, reservation_id
        )
        print()
        print(f"Bob joined context: {joined.context_id}")

    print()
    print("Context lifecycle complete.")


if __name__ == "__main__":
    asyncio.run(main())
