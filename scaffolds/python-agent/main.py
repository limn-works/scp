"""Minimal SCP agent in Python.

Creates a DID identity, opens an encrypted context, and sends a message.

Usage:
    pip install -e ../../bindings/python
    python main.py

Replace in_memory custody with platform custody for production use.
"""

import asyncio

from scp_sdk import Capability, Context, Identity


async def main() -> None:
    # 1. Create a DID identity with in-memory key custody.
    identity = await Identity.create(custody="in_memory")
    print(f"Created identity: {identity.did}")

    # 2. Create an encrypted context with messaging capabilities.
    async with await Context.create(
        creator=identity,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.ROLE_ASSIGN,
            Capability.MEMBER_INVITE,
            Capability.MEMBER_REMOVE,
        ],
        memory_scope="ephemeral",
    ) as ctx:
        print(f"Created context: {ctx.context_id}")
        print(f"  State: {ctx.state}")

        # 3. Send a message.
        await ctx.send("Hello, SCP!", identity=identity)
        print("  Message sent.")

        # 4. Check membership.
        members = await ctx.member_dids()
        print(f"  Members: {members}")

    print("\nAgent complete.")


if __name__ == "__main__":
    asyncio.run(main())
