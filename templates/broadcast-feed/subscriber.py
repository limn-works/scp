"""SCP broadcast feed subscriber.

Joins an existing broadcast context and receives published content.
Demonstrates the subscriber side of the broadcast pattern: creating an
identity, subscribing to the feed, requesting the author's broadcast key,
and consuming messages from the async receive stream.

Usage:
    pip install -e ../../bindings/python

    # Get the context ID from the publisher's output, then:
    python subscriber.py <context_id>
"""

from __future__ import annotations

import asyncio
import sys

from scp_sdk import Context, Identity, Message, connect_relay
from scp_sdk.types import ContextMode


RELAY_URL = "wss://relay.example.com"


async def create_subscriber() -> Identity:
    """Create a subscriber identity with in-memory custody."""
    identity = await Identity.create(custody="in_memory")
    print(f"Subscriber DID: {identity.did}")
    return identity


async def join_feed(subscriber: Identity, context_id: str) -> Context:
    """Join an existing broadcast feed context.

    The subscriber joins the context and registers for broadcast key
    distribution. In open broadcast contexts (public-broadcast template),
    registration is DID-authenticated -- no admin-issued UCAN is required
    (spec section 5.14.4).
    """
    # Create a Context handle for the existing broadcast context.
    # In production, the context_id and relay info come from discovery
    # (spec section 5.14.11) -- shared via URI, .well-known/scp, or
    # discovery context registration.
    ctx = await Context.create(
        creator=subscriber,
        ceiling=[],
        mode=ContextMode.BROADCAST,
        governance="single_admin",
        memory_scope="full",
    )

    # Join the broadcast context as a subscriber.
    membership = await ctx.join(subscriber)
    print(f"Joined feed: {context_id}")
    print(f"  Role: {membership.role}")
    print(f"  Context: {membership.context_id}")

    # Register as a broadcast subscriber. This triggers the pull-based
    # key distribution protocol -- the author's SDK will respond with
    # the current broadcast key (spec section 5.14.3).
    await ctx.broadcast_subscribe(subscriber.did)
    print(f"  Subscribed to broadcasts")

    return ctx


async def receive_messages(ctx: Context, subscriber: Identity) -> None:
    """Consume messages from the broadcast feed.

    Messages arrive via the async receive stream. Each message is a
    BroadcastEnvelope (spec section 5.14.5) that has been decrypted
    using the cached author broadcast key.

    The receive iterator is backed by a bounded buffer (default 1,000
    events) with oldest-drop overflow semantics.
    """
    print("\nListening for broadcasts (Ctrl+C to stop)...")
    stream = await ctx.receive()

    async for message in stream:
        content = (
            message.content.decode("utf-8")
            if isinstance(message.content, bytes)
            else message.content
        )
        print(f"  [{message.sender_did[:20]}...] {content}")


async def check_subscription(ctx: Context, subscriber: Identity) -> None:
    """Verify subscription status."""
    is_sub = await ctx.broadcast_is_subscriber(subscriber.did)
    print(f"  Subscription active: {is_sub}")

    count = await ctx.broadcast_subscriber_count()
    print(f"  Total subscribers: {count}")


async def run_subscriber(context_id: str) -> None:
    """Run the subscriber lifecycle."""
    # 1. Create subscriber identity.
    subscriber = await create_subscriber()

    # 2. Connect to relay.
    transport = await connect_relay(RELAY_URL)
    print(f"Connected to relay: {RELAY_URL}")

    # 3. Join the broadcast feed.
    feed = await join_feed(subscriber, context_id)

    async with feed:
        # 4. Verify subscription.
        await check_subscription(feed, subscriber)

        # 5. Receive messages until interrupted or feed closes.
        try:
            await receive_messages(feed, subscriber)
        except KeyboardInterrupt:
            print("\nStopping...")

    print("Left feed.")


def main() -> None:
    """Entry point for the broadcast subscriber."""
    if len(sys.argv) < 2:
        print("Usage: python subscriber.py <context_id>", file=sys.stderr)
        print(
            "\nGet the context ID from the publisher's output (python feed.py).",
            file=sys.stderr,
        )
        sys.exit(1)

    context_id = sys.argv[1]
    asyncio.run(run_subscriber(context_id))


if __name__ == "__main__":
    main()
