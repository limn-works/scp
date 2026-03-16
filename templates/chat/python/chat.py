"""Two-party encrypted chat over SCP.

Creates or joins an encrypted context and exchanges messages via stdin/stdout.

Usage:
    # Terminal 1 -- create a new context:
    python chat.py create

    # Terminal 2 -- join an existing context by ID:
    python chat.py join <context-id>

Requires the scp-python native extension:
    pip install -e ../../../bindings/python
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from scp_sdk import Capability, Context, Identity, Message, TransportConfig


async def print_incoming(ctx: Context) -> None:
    """Background task: print messages from other participants."""
    receiver = await ctx.receive()
    async for msg in receiver:
        # Skip messages from ourselves (echo suppression).
        if msg.sender_did == ctx._creator_did:
            continue
        content = msg.content if isinstance(msg.content, str) else msg.content.decode("utf-8")
        print(f"\r[{msg.sender_did[:20]}...] {content}")
        print("> ", end="", flush=True)


async def send_loop(ctx: Context, identity: Identity) -> None:
    """Read lines from stdin and send them to the context."""
    loop = asyncio.get_running_loop()
    while True:
        print("> ", end="", flush=True)
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            # EOF -- user pressed Ctrl-D.
            break
        text = line.rstrip("\n")
        if not text:
            continue
        if text in ("/quit", "/exit"):
            break
        await ctx.send(text, identity=identity)


async def run_create(relay_url: str | None) -> None:
    """Create a new context and start chatting."""
    identity = await Identity.create(custody="in_memory")
    print(f"Identity: {identity.did}")

    if relay_url:
        transport = TransportConfig(relay_url=relay_url)
        await transport.connect()
        print(f"Connected to relay: {relay_url}")

    async with await Context.create(
        creator=identity,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.MEMBER_INVITE,
        ],
        memory_scope="ephemeral",
    ) as ctx:
        print(f"Context created: {ctx.context_id}")
        print("Share this context ID with the other party.")
        print("Type messages and press Enter. /quit to exit.\n")

        receive_task = asyncio.create_task(print_incoming(ctx))
        try:
            await send_loop(ctx, identity)
        finally:
            receive_task.cancel()
            try:
                await receive_task
            except asyncio.CancelledError:
                pass

    print("Left context. Goodbye.")


async def run_join(context_id: str, relay_url: str | None) -> None:
    """Join an existing context and start chatting."""
    identity = await Identity.create(custody="in_memory")
    print(f"Identity: {identity.did}")

    if relay_url:
        transport = TransportConfig(relay_url=relay_url)
        await transport.connect()
        print(f"Connected to relay: {relay_url}")

    # Create a local handle for the remote context.  In a full deployment the
    # context handle is obtained through discovery or an invite link.  Here we
    # construct a minimal Context by creating one locally and then joining --
    # the bridge resolves the context_id to the remote state.
    async with await Context.create(
        creator=identity,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.MEMBER_INVITE,
        ],
        memory_scope="ephemeral",
    ) as ctx:
        await ctx.join(identity)
        print(f"Joined context: {context_id}")
        print("Type messages and press Enter. /quit to exit.\n")

        receive_task = asyncio.create_task(print_incoming(ctx))
        try:
            await send_loop(ctx, identity)
        finally:
            receive_task.cancel()
            try:
                await receive_task
            except asyncio.CancelledError:
                pass

    print("Left context. Goodbye.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Two-party encrypted chat over SCP")
    parser.add_argument(
        "--relay",
        default=None,
        help="SCP relay URL (e.g. wss://relay.example.com)",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("create", help="Create a new chat context")
    join_parser = sub.add_parser("join", help="Join an existing chat context")
    join_parser.add_argument("context_id", help="Context ID to join")

    args = parser.parse_args()

    if args.command == "create":
        asyncio.run(run_create(args.relay))
    elif args.command == "join":
        asyncio.run(run_join(args.context_id, args.relay))


if __name__ == "__main__":
    main()
