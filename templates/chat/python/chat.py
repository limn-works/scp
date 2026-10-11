"""Two-party encrypted chat over SCP.

One side creates an encrypted context and invites the other; both then
exchange messages via stdin/stdout over a shared relay.

The invitation crosses between the two terminals by copy and paste: the
joiner prints its DID and a single-use KeyPackage, the creator pastes that
line and prints a sealed invitation, and the joiner pastes the invitation.

Usage:
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database

    # Terminal 1 -- create a new context:
    python chat.py --relay wss://relay.example.com create

    # Terminal 2 -- join it:
    python chat.py --relay wss://relay.example.com join

Requires the scp-python native extension:
    pip install -e ../../../bindings/python
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from scp_sdk import (
    SCP,
    Capability,
    Context,
    ContextError,
    CustodyType,
    MemoryScope,
    SealedInvitation,
    StorageConfig,
)

# A send fails with this code until the peer's routing announcement has
# arrived over the relay (spec §9.10.4). The send is rolled back, so a retry
# is safe.
NO_PEER_ROUTE = "SCP-CTX-2095"
SEND_ATTEMPTS = 20
RETRY_DELAY_SECONDS = 0.5


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


async def read_line(prompt: str) -> str:
    """Print ``prompt`` and read one stripped line from stdin; EOF raises."""
    print(prompt, end="", flush=True)
    line: str = await asyncio.get_running_loop().run_in_executor(
        None, sys.stdin.readline
    )
    if not line:
        raise SystemExit("stdin closed")
    return line.strip()


async def start_node(node: SCP, relay_url: str) -> str:
    """Create this side's identity and attach the relay; return the DID.

    The relay transport is attached before any context exists: the context
    supervisor starts on the first context and binds the transport it finds
    then.
    """
    identity = await node.identity_create(CustodyType.FILE)
    print(f"Identity: {identity.did}")
    await node.configure_relay_transport(relay_url, identity.did)
    await node.transport_connect(relay_url)
    print(f"Connected to relay: {relay_url}")
    return identity.did


async def print_incoming(node: SCP, ctx: Context, own_did: str) -> None:
    """Background task: print messages from the other participant."""
    receiver = await node.context_receive(ctx)
    async for msg in receiver:
        # Skip messages from ourselves (echo suppression).
        if msg.sender_did == own_did:
            continue
        print(f"\r[{msg.sender_did[:20]}...] {msg.payload.decode('utf-8', 'replace')}")
        print("> ", end="", flush=True)


async def send(node: SCP, ctx: Context, own_did: str, text: str) -> None:
    """Send ``text``, retrying only while the peer's route is unknown."""
    for attempt in range(1, SEND_ATTEMPTS + 1):
        try:
            await node.context_send(ctx, own_did, text)
            return
        except ContextError as exc:
            if exc.code != NO_PEER_ROUTE or attempt == SEND_ATTEMPTS:
                raise
            await asyncio.sleep(RETRY_DELAY_SECONDS)


async def chat(node: SCP, ctx: Context, own_did: str) -> None:
    """Run the receive task and read lines from stdin until /quit or EOF."""
    print("Type messages and press Enter. /quit to exit.\n")
    receive_task = asyncio.create_task(print_incoming(node, ctx, own_did))
    loop = asyncio.get_running_loop()
    try:
        while True:
            print("> ", end="", flush=True)
            line: str = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                # EOF -- user pressed Ctrl-D.
                break
            text = line.rstrip("\n")
            if not text:
                continue
            if text in ("/quit", "/exit"):
                break
            await send(node, ctx, own_did, text)
    finally:
        receive_task.cancel()
        try:
            await receive_task
        except asyncio.CancelledError:
            pass
        await node.context_leave(ctx, own_did)


async def run_create(relay_url: str) -> None:
    """Create a new context, invite the joiner, and start chatting."""
    async with SCP(storage=node_storage("chat-create")) as node:
        did = await start_node(node, relay_url)

        # Inviting runs through the governance gate, so the ceiling carries
        # governance:propose.
        ctx = await node.context_create(
            did,
            {
                "ceiling": [
                    Capability.MESSAGES_READ.value,
                    Capability.MESSAGES_WRITE.value,
                    Capability.MEMBER_INVITE.value,
                    Capability.GOVERNANCE_PROPOSE.value,
                ],
                "memory_scope": MemoryScope.EPHEMERAL.value,
                "governance": "single_admin",
            },
        )
        print(f"Context created: {ctx.context_id}")

        request = json.loads(await read_line("Paste the joiner's request line: "))
        outcome = await node.invite_member(
            ctx.context_id,
            did,
            request["did"],
            bytes.fromhex(request["key_package"]),
            [relay_url],
        )
        bundle = outcome.bundle
        invitation = {
            "context_id": bundle.context_id,
            "creator_did": bundle.creator_did,
            "enc": bundle.enc.hex(),
            "ciphertext": bundle.ciphertext.hex(),
        }
        print("\nPaste this invitation line into the joiner:")
        print(json.dumps(invitation))
        print()

        await chat(node, ctx, did)

    print("Left context. Goodbye.")


async def run_join(relay_url: str) -> None:
    """Request an invitation, join from it, and start chatting."""
    async with SCP(storage=node_storage("chat-join")) as node:
        did = await start_node(node, relay_url)

        # Reserve a single-use KeyPackage; only its public bytes leave here.
        reservation_id, key_package = await node.reserve_key_package(did)
        print("\nPaste this request line into the creator:")
        print(json.dumps({"did": did, "key_package": key_package.hex()}))
        print()

        invitation = json.loads(
            await read_line("Paste the creator's invitation line: ")
        )
        sealed = SealedInvitation(
            context_id=invitation["context_id"],
            creator_did=invitation["creator_did"],
            enc=bytes.fromhex(invitation["enc"]),
            ciphertext=bytes.fromhex(invitation["ciphertext"]),
        )
        ctx = await node.context_join_from_welcome(did, sealed, reservation_id)
        print(f"Joined context: {ctx.context_id}")

        await chat(node, ctx, did)

    print("Left context. Goodbye.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Two-party encrypted chat over SCP")
    parser.add_argument(
        "--relay",
        required=True,
        help="SCP relay URL both parties reach (e.g. wss://relay.example.com)",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("create", help="Create a chat context and invite the other party")
    sub.add_parser("join", help="Join a chat context from an invitation")

    args = parser.parse_args()

    if args.command == "create":
        asyncio.run(run_create(args.relay))
    elif args.command == "join":
        asyncio.run(run_join(args.relay))


if __name__ == "__main__":
    main()
