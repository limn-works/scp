"""SCP broadcast feed publisher.

Creates a broadcast context (spec section 5.14) with single-admin governance
and demonstrates the publisher side of the broadcast pattern: creating the
feed, publishing content, registering a subscriber, sealing the author's
broadcast key to that subscriber, and managing the subscriber (block,
unblock).

Broadcast contexts use per-author AES-256-GCM broadcast keys instead of MLS
group encryption, enabling unlimited subscriber scale. Authors publish
encrypted content; subscribers obtain author keys and decrypt locally.

Key requests have no network path yet, so the subscriber hands its DID and
wrapping key to the publisher out of band, and the publisher prints the
sealed key for the subscriber to paste back.

Usage:
    pip install -e ../../bindings/python
    export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
    export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database
    export SCP_RELAY_URL=wss://...     # the relay the feed publishes to

    # Start the subscriber first; it prints its DID and wrapping key:
    python subscriber.py

    # Then pass both to the publisher:
    python feed.py --subscriber <did> --wrapping-key <hex>
"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from scp_sdk import (
    SCP,
    Capability,
    Context,
    CustodyType,
    Identity,
    MemoryScope,
    StorageConfig,
)


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


async def create_broadcast_feed(node: SCP, publisher: Identity) -> Context:
    """Create an open broadcast context with single-admin governance.

    The publisher is the context creator and sole author. The ceiling
    includes messages:read (subscribers), messages:write (authors),
    role:assign (for promoting subscribers to authors), and member:invite
    (for gated admission workflows).

    Uses the public-broadcast template semantics: subscribers register
    by DID, with no admin-issued UCAN.
    """
    ctx = await node.context_create(
        publisher.did,
        {
            "ceiling": [
                Capability.MESSAGES_READ.value,
                Capability.MESSAGES_WRITE.value,
                Capability.ROLE_ASSIGN.value,
                Capability.MEMBER_INVITE.value,
                Capability.MEMBER_REMOVE.value,
                Capability.CONTEXT_CLOSE.value,
            ],
            "governance": "single_admin",
            "mode": "broadcast",
            "memory_scope": MemoryScope.FULL.value,
            "template_id": "PublicBroadcast",
        },
    )
    print(f"Broadcast feed created: {ctx.context_id}")
    print("  Mode: broadcast (per-author AES-256-GCM keys)")
    print("  Governance: single_admin")
    print(f"  State: {ctx.state}")
    return ctx


async def publish_content(
    node: SCP, ctx: Context, publisher: Identity, content: str
) -> None:
    """Publish a broadcast message to the feed.

    The payload is encrypted with the publisher's broadcast key. Subscribers
    who hold the key can decrypt it locally.
    """
    await node.broadcast_publish(ctx, publisher.did, content.encode("utf-8"))
    print(f"  Published: {content!r}")


async def seal_key_for(
    node: SCP,
    ctx: Context,
    publisher: Identity,
    subscriber_did: str,
    wrapping_key: bytes,
) -> str | None:
    """Seal the publisher's current broadcast key to a subscriber.

    Returns the sealed key JSON on grant, or ``None`` when the publisher
    denies the request: a denied requester receives no key material
    (spec section 5.14.8).
    """
    return await node.broadcast_handle_key_request(
        ctx, publisher.did, subscriber_did, wrapping_key
    )


async def register_subscriber(node: SCP, ctx: Context, subscriber_did: str) -> None:
    """Register a subscriber on the feed.

    In open broadcast contexts, subscriber registration is DID-authenticated
    (no admin-issued UCAN needed).
    """
    await node.broadcast_subscribe(ctx, subscriber_did)
    is_sub = await node.broadcast_is_subscriber(ctx, subscriber_did)
    print(f"  Subscriber registered: {subscriber_did} (active: {is_sub})")


async def block_subscriber(
    node: SCP,
    ctx: Context,
    publisher: Identity,
    subscriber_did: str,
) -> None:
    """Block a subscriber's read access.

    Blocking revokes the subscriber's ability to request new broadcast keys.
    Existing keys are invalidated via epoch rotation. The subscriber cannot
    decrypt content published after the block.

    Spec section 5.14.8: blocking in broadcast contexts uses the content
    access key layer (ADR-038). Authors rotate their broadcast key on block
    events, and the blocked subscriber is excluded from future key requests.
    """
    await node.broadcast_block_subscriber(ctx, subscriber_did, publisher.did)
    print(f"  Blocked subscriber: {subscriber_did}")


async def unblock_subscriber(
    node: SCP,
    ctx: Context,
    publisher: Identity,
    subscriber_did: str,
) -> None:
    """Unblock a previously blocked subscriber.

    Forward-only restoration (spec section 9.16.8): the unblocked subscriber
    can request the current key on next pull but cannot decrypt content from
    the block period.
    """
    await node.broadcast_unblock_subscriber(ctx, subscriber_did, publisher.did)
    print(f"  Unblocked subscriber: {subscriber_did}")


async def run_publisher(subscriber_did: str | None, wrapping_key: bytes | None) -> None:
    """Run the full publisher lifecycle."""
    relay_url = os.environ["SCP_RELAY_URL"]

    async with SCP(storage=node_storage("broadcast-feed-publisher")) as node:
        # 1. Create the publisher identity.
        publisher = await node.identity_create(CustodyType.ENCRYPTED_FILE)
        print(f"Publisher DID: {publisher.did}")

        # 2. Attach the relay transport before creating the feed: the context
        #    supervisor starts on the first context and binds the transport it
        #    finds then.
        await node.configure_relay_transport(relay_url, publisher.did)
        print(f"Relay transport: {relay_url}")

        # 3. Create the broadcast feed.
        feed = await create_broadcast_feed(node, publisher)

        # 4. Publish initial content.
        print("\nPublishing content:")
        await publish_content(node, feed, publisher, "Welcome to the broadcast feed!")
        await publish_content(node, feed, publisher, "This is post #2.")

        # 5. Report the feed's admission policy and subscriber count.
        print(f"\n  Admission policy: {await node.broadcast_admission(feed)}")
        print(f"  Subscriber count: {await node.broadcast_subscriber_count(feed)}")

        if subscriber_did is not None and wrapping_key is not None:
            # 6. Register the subscriber, then show that a blocked subscriber
            #    is denied a key and an unblocked one is granted the current
            #    key again.
            print(f"\nSubscriber lifecycle ({subscriber_did}):")
            await register_subscriber(node, feed, subscriber_did)
            await block_subscriber(node, feed, publisher, subscriber_did)
            denied = await seal_key_for(
                node, feed, publisher, subscriber_did, wrapping_key
            )
            print(f"  Key request while blocked granted: {denied is not None}")
            await unblock_subscriber(node, feed, publisher, subscriber_did)

            # 7. Seal the current key for the subscriber to paste back.
            sealed = await seal_key_for(
                node, feed, publisher, subscriber_did, wrapping_key
            )
            if sealed is None:
                raise RuntimeError(
                    f"publisher denied the key request from {subscriber_did}"
                )
            print("\n--- Paste this sealed key into the subscriber ---")
            print(sealed)
            print("--- ---")

        # 8. Keep publishing (in production, this runs indefinitely).
        print()
        await publish_content(
            node, feed, publisher, "Breaking: SCP broadcast contexts are live."
        )

    print("\nPublisher stopped.")


def main() -> None:
    """Entry point for the broadcast feed publisher."""
    parser = argparse.ArgumentParser(description="SCP broadcast feed publisher")
    parser.add_argument("--subscriber", help="DID the subscriber printed")
    parser.add_argument(
        "--wrapping-key",
        help="hex wrapping key the subscriber printed (65-byte uncompressed P-256 point)",
    )
    args = parser.parse_args()
    if (args.subscriber is None) != (args.wrapping_key is None):
        parser.error("--subscriber and --wrapping-key go together")
    wrapping_key = (
        None if args.wrapping_key is None else bytes.fromhex(args.wrapping_key)
    )
    asyncio.run(run_publisher(args.subscriber, wrapping_key))


if __name__ == "__main__":
    main()
