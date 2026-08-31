"""Context creation and lifecycle management.

Demonstrates creating an SCP context with governance parameters,
inspecting its state, joining/leaving, and managing membership.

Prerequisites:
    pip install scp-sdk
    # or: maturin develop --release (from bindings/python/)

Usage:
    python context.py
"""

import asyncio

from scp_sdk import (
    Capability,
    Context,
    ContextMode,
    CustodyType,
    Identity,
    MemoryScope,
)


async def main() -> None:
    # 1. Create the identity that will own the context.
    alice = await Identity.create(custody=CustodyType.ENCRYPTED_FILE)
    print(f"Alice DID: {alice.did}")

    # 2. Create a context with messaging capabilities.
    #    The context uses async-with for automatic cleanup on exit.
    async with await Context.create(
        creator=alice,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.MEMBER_INVITE,
            Capability.MEMBER_REMOVE,
            Capability.TOOL_REGISTER,
            Capability.TOOL_INVOKE_ALL,
        ],
        mode=ContextMode.ENCRYPTED,
        memory_scope=MemoryScope.FULL,
        governance="single_admin",
    ) as ctx:
        print()
        print(f"Context created: {ctx.context_id}")
        print(f"  State: {ctx.state}")

        # 3. Check membership -- the creator is automatically a member.
        members = await ctx.member_dids()
        print(f"  Members: {members}")

        count = await ctx.member_count()
        print(f"  Member count: {count}")

        is_alice = await ctx.is_member(alice.did)
        print(f"  Alice is member: {is_alice}")

        role = await ctx.member_role(alice.did)
        print(f"  Alice role: {role}")

        # 4. Send a message to the context.
        await ctx.send("Hello, context!", identity=alice)
        print("  Message sent successfully.")

        # 5. Bob joins the context.
        bob = await Identity.create(custody=CustodyType.ENCRYPTED_FILE)
        membership = await ctx.join(bob)
        print()
        print(f"Bob joined: {membership.did} as {membership.role}")

        members = await ctx.member_dids()
        print(f"  Members after join: {members}")

        # 6. Bob leaves the context.
        await ctx.leave(bob)
        print("Bob left the context.")

        members = await ctx.member_dids()
        print(f"  Remaining members: {members}")

    # Context is automatically cleaned up after exiting async-with.
    print()
    print("Context lifecycle complete.")


if __name__ == "__main__":
    asyncio.run(main())
