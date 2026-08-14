"""SCP broadcast feed publisher.

Creates a broadcast context (spec section 5.14) with single-admin governance
and demonstrates the publisher side of the broadcast pattern: creating the
feed, publishing content, handling subscriber registrations, and managing
subscribers (approve, block, unblock, remove).

Broadcast contexts use per-author AES-256-GCM broadcast keys instead of MLS
group encryption, enabling unlimited subscriber scale. Authors publish
encrypted content; subscribers pull author keys and decrypt locally.

Usage:
    pip install -e ../../bindings/python
    python feed.py

    # In another terminal, pass the printed context ID to the subscriber:
    python subscriber.py <context_id>
"""

from __future__ import annotations

import asyncio
import json
import sys

from scp_sdk import (
    Capability,
    Context,
    Identity,
    connect_relay,
    execute_governance_action,
    propose_governance_action,
)
from scp_sdk.types import ContextMode, MemberRole


RELAY_URL = "wss://relay.example.com"


async def create_publisher() -> Identity:
    """Create a publisher identity with in-memory custody."""
    identity = await Identity.create(custody="in_memory")
    print(f"Publisher DID: {identity.did}")
    return identity


async def create_broadcast_feed(publisher: Identity) -> Context:
    """Create an open broadcast context with single-admin governance.

    The publisher is the context creator and sole author. The ceiling
    includes messagesRead (subscribers), messagesWrite (authors),
    roleAssign (for promoting subscribers to authors), and memberInvite
    (for gated admission workflows).

    Uses the public-broadcast template semantics: subscribers auto-register
    via DID-authenticated requests.
    """
    ctx = await Context.create(
        creator=publisher,
        ceiling=[
            Capability.MESSAGES_READ,
            Capability.MESSAGES_WRITE,
            Capability.ROLE_ASSIGN,
            Capability.MEMBER_INVITE,
            Capability.MEMBER_REMOVE,
            Capability.CONTEXT_CLOSE,
        ],
        governance="single_admin",
        mode=ContextMode.BROADCAST,
        memory_scope="full",
        template_id="scp:template/public-broadcast",
    )
    print(f"Broadcast feed created: {ctx.context_id}")
    print(f"  Mode: broadcast (per-author AES-256-GCM keys)")
    print(f"  Governance: single_admin")
    print(f"  State: {ctx.state}")
    return ctx


async def publish_content(ctx: Context, publisher: Identity, content: str) -> None:
    """Publish a broadcast message to the feed.

    The payload is encrypted with the publisher's broadcast key. Subscribers
    who hold the key can decrypt it locally.
    """
    payload = content.encode("utf-8")
    await ctx.broadcast_publish(payload, identity=publisher)
    print(f"  Published: {content!r}")


async def handle_subscriber_registration(
    ctx: Context,
    publisher: Identity,
    subscriber_did: str,
) -> None:
    """Register a subscriber and handle their broadcast key request.

    In open broadcast contexts, subscriber registration is DID-authenticated
    (no admin-issued UCAN needed). The publisher processes the registration
    and responds with the current broadcast key via the pull-based key
    distribution protocol (spec section 5.14.3).
    """
    await ctx.broadcast_subscribe(subscriber_did)
    print(f"  Subscriber registered: {subscriber_did}")

    # Handle the key request -- the subscriber needs the author's current
    # broadcast key to decrypt published content.
    result = await ctx.broadcast_handle_key_request(
        author_did=publisher.did,
        requester_did=subscriber_did,
    )
    print(f"  Key request handled: {result}")


async def manage_subscribers(ctx: Context, publisher: Identity) -> None:
    """Demonstrate subscriber management operations.

    Shows how to check subscriber status, block/unblock subscribers,
    and remove subscribers from the feed.
    """
    # Query subscriber count.
    count = await ctx.broadcast_subscriber_count()
    print(f"\n  Subscriber count: {count}")

    # Query admission policy.
    admission = await ctx.broadcast_admission()
    print(f"  Admission policy: {admission}")

    # Check if a specific DID is subscribed.
    test_did = "did:dht:z6MkTestSubscriber"
    is_sub = await ctx.broadcast_is_subscriber(test_did)
    print(f"  Is {test_did} subscribed? {is_sub}")


async def block_subscriber(
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
    await ctx.broadcast_block_subscriber(
        subscriber_did=subscriber_did,
        blocker_did=publisher.did,
    )
    print(f"  Blocked subscriber: {subscriber_did}")


async def unblock_subscriber(
    ctx: Context,
    publisher: Identity,
    subscriber_did: str,
) -> None:
    """Unblock a previously blocked subscriber.

    Forward-only restoration (spec section 9.16.8): the unblocked subscriber
    can request the current key on next pull but cannot decrypt content from
    the block period.
    """
    await ctx.broadcast_unblock_subscriber(
        subscriber_did=subscriber_did,
        unblocker_did=publisher.did,
    )
    print(f"  Unblocked subscriber: {subscriber_did}")


async def remove_subscriber(ctx: Context, subscriber_did: str) -> None:
    """Remove a subscriber from the feed entirely.

    Unsubscribes the DID and rotates all author broadcast keys to prevent
    the removed subscriber from decrypting future content.
    """
    await ctx.broadcast_unsubscribe(subscriber_did, rotate_keys=True)
    print(f"  Removed subscriber (keys rotated): {subscriber_did}")


async def add_author(
    ctx: Context,
    publisher: Identity,
    new_author_did: str,
) -> None:
    """Promote a subscriber to author role via governance.

    Authors hold messagesWrite and can publish their own broadcast-key-
    encrypted content. Each author maintains an independent broadcast key
    with its own epoch counter (spec section 5.14.2).
    """
    action = json.dumps(
        {
            "action": {
                "RoleChange": {
                    "target_did": new_author_did,
                    "new_role": "author",
                }
            }
        }
    )
    result = await propose_governance_action(ctx, action, identity_did=publisher.did)
    print(f"  Promoted to author: {new_author_did} -> {result}")


async def run_publisher() -> None:
    """Run the full publisher lifecycle."""
    # 1. Create publisher identity.
    publisher = await create_publisher()

    # 2. Connect to relay.
    transport = await connect_relay(RELAY_URL)
    print(f"Connected to relay: {RELAY_URL}")

    # 3. Create broadcast feed.
    feed = await create_broadcast_feed(publisher)
    context_id = feed.context_id

    # Print context ID for subscribers to use.
    print(f"\n--- Share this context ID with subscribers ---")
    print(f"  {context_id}")
    print(f"--- ---\n")

    async with feed:
        # 4. Publish initial content.
        print("Publishing content:")
        await publish_content(feed, publisher, "Welcome to the broadcast feed!")
        await publish_content(feed, publisher, "This is post #2.")
        await publish_content(
            feed, publisher, "Breaking: SCP broadcast contexts are live."
        )

        # 5. Demonstrate subscriber management.
        print("\nSubscriber management:")
        await manage_subscribers(feed, publisher)

        # 6. Simulate subscriber lifecycle (block/unblock/remove).
        # In production, subscriber_did comes from actual registration events.
        demo_subscriber = "did:dht:z6MkDemoSubscriber"
        print(f"\nSubscriber lifecycle demo ({demo_subscriber}):")
        await handle_subscriber_registration(feed, publisher, demo_subscriber)
        await block_subscriber(feed, publisher, demo_subscriber)
        await unblock_subscriber(feed, publisher, demo_subscriber)
        await remove_subscriber(feed, demo_subscriber)

        # 7. Keep publishing (in production, this runs indefinitely).
        await publish_content(feed, publisher, "Final broadcast before shutdown.")

    print("\nFeed closed.")


def main() -> None:
    """Entry point for the broadcast feed publisher."""
    asyncio.run(run_publisher())


if __name__ == "__main__":
    main()
