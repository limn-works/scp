# Broadcast Feed

A broadcast context (SCP spec section 5.14) with publisher and subscriber management.

## What are broadcast contexts?

Broadcast contexts provide a one-to-many communication pattern at unlimited subscriber scale. Unlike encrypted contexts (which use MLS group encryption and are bounded by group size), broadcast contexts use per-author AES-256-GCM broadcast keys distributed via a pull-based protocol.

Key properties:

- **Authors** hold `messagesWrite` and publish broadcast-key-encrypted content. Each author maintains an independent broadcast key with a monotonic epoch counter.
- **Subscribers** hold `messagesRead` and receive author broadcast keys on request. Subscribers are unbounded.
- **No MLS group** -- broadcast contexts substitute per-author broadcast keys for MLS group encryption, enabling unlimited scale.
- **Open vs. gated admission** -- open contexts (`public-broadcast` template) auto-grant `messagesRead` on DID-authenticated registration. Gated contexts (`gated-broadcast` template) require admin-issued UCANs.
- **Blocking** uses the content access key layer (ADR-038). When a subscriber is blocked, authors rotate their broadcast key, and the blocked subscriber is excluded from future key requests. Unblocking is forward-only -- the subscriber gets the current key but cannot decrypt content from the block period.

## Files

| File | Description |
|------|-------------|
| `feed.py` | Publisher: creates a broadcast feed, publishes content, manages subscribers |
| `subscriber.py` | Subscriber: joins a feed, receives broadcasts |
| `pyproject.toml` | Python project metadata and dependencies |

## Running

### Prerequisites

Install the SCP Python SDK from the repository root:

```bash
pip install -e ../../bindings/python
```

### Start the publisher

```bash
python feed.py
```

The publisher will:
1. Create an identity and connect to a relay
2. Create a broadcast context with `single_admin` governance
3. Print the context ID for subscribers to use
4. Publish sample content
5. Demonstrate subscriber management (register, block, unblock, remove)

### Start a subscriber

In a separate terminal, pass the context ID printed by the publisher:

```bash
python subscriber.py <context_id>
```

The subscriber will:
1. Create its own identity and connect to the relay
2. Join the broadcast context and register as a subscriber
3. Request the author's broadcast key
4. Listen for incoming broadcasts on the async receive stream

Press `Ctrl+C` to stop the subscriber.

## Customizing

### Relay URL

Both scripts default to `wss://relay.example.com`. Change the `RELAY_URL` constant in each file to point to your relay, or run a local relay with the `personal-relay` template.

### Gated broadcast

To require admin approval for subscribers, remove the `template_id` and configure the context for gated admission:

```python
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
    template_id="scp:template/gated-broadcast",
)
```

In gated mode, subscribers need an admin-issued `messagesRead` UCAN before they can access content.

### Multiple authors

Promote a subscriber to author role via governance:

```python
action = json.dumps({
    "action": {
        "RoleChange": {
            "target_did": subscriber_did,
            "new_role": "author",
        }
    }
})
await propose_governance_action(ctx, action, identity_did=publisher.did)
```

Each author gets their own broadcast key and can publish independently.

### Economic policy

For paid subscriptions, use the `paid-broadcast` template with an economic policy:

```python
ctx = await Context.create(
    creator=publisher,
    ceiling=[Capability.MESSAGES_READ, Capability.MESSAGES_WRITE],
    governance="single_admin",
    mode=ContextMode.BROADCAST,
    template_id="scp:template/paid-broadcast",
    economic_policy='{"per_period": {"amount": "1.00", "currency": "USD", "period_seconds": 2592000}}',
)
```

## Key custody

Every snippet here passes `in_memory`, which §3.2.2 of the identity spec, the custody
vocabulary, classifies as a test-harness string rather than a value a shipped caller
names. A shipped build rejects it with `SCP-IDENT-1008`. That section states the two
values a shipped caller does name: `encrypted_file` selects the on-disk key store SCP
implements, and `os_keystore` selects the operating system's own key store, which SCP
reaches through the platform key-custody callback the SDK consumer supplies. The words
`platform`, `software`, `file`, and `hardware` name no custody value.
