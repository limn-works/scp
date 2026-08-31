"""Minimal SCP agent in Python.

Creates a DID identity, opens an encrypted context, and sends a message.

Usage:
    pip install -e ../../bindings/python
    python main.py

For production, pass "encrypted_file" for the on-disk key store SCP implements,
or "os_keystore" together with a KeyCustodyProvider to hold the keys in the
operating system's own key store. Section 3.2.2 of the identity spec, the
custody vocabulary, states those two values and states that a shipped build
answers every other string with a typed error. Neither call creates an identity
on a released wheel: both return SCP-IDENT-1059, because no pre-rotation custody
backend is wired yet.
"""

import asyncio

from scp_sdk import Capability, Context, Identity


async def main() -> None:
    # 1. Create a DID identity with encrypted-key-file custody.
    identity = await Identity.create(custody="encrypted_file")
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
