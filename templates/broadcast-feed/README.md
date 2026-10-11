# Broadcast Feed

A broadcast context (SCP spec section 5.14) with publisher and subscriber management.

## What are broadcast contexts?

Broadcast contexts provide a one-to-many communication pattern at unlimited subscriber scale. Unlike encrypted contexts (which use MLS group encryption and are bounded by group size), broadcast contexts use per-author AES-256-GCM broadcast keys distributed via a pull-based protocol.

Key properties:

- **Authors** hold `messages:write` and publish broadcast-key-encrypted content. Each author maintains an independent broadcast key with a monotonic epoch counter.
- **Subscribers** hold `messages:read` and receive author broadcast keys on request. Subscribers are unbounded.
- **No MLS group** -- broadcast contexts substitute per-author broadcast keys for MLS group encryption, enabling unlimited scale.
- **Open vs. gated admission** -- open contexts (`PublicBroadcast` template) admit a subscriber on DID-authenticated registration. Gated contexts (`GatedBroadcast` template) require an admin-issued `messages:read` UCAN.
- **Blocking** uses the content access key layer (ADR-038). When a subscriber is blocked, authors rotate their broadcast key, and the blocked subscriber is excluded from future key requests. Unblocking is forward-only -- the subscriber gets the current key but cannot decrypt content from the block period.

## Files

| File | Description |
|------|-------------|
| `feed.py` | Publisher: creates a broadcast feed, publishes content, registers a subscriber, seals its broadcast key to the subscriber, blocks and unblocks |
| `subscriber.py` | Subscriber: creates an identity and a wrapping key, opens the sealed broadcast key |
| `pyproject.toml` | Python project metadata and dependencies |

## What runs today

A broadcast key request has no network path yet: no runtime or relay code carries a subscriber's request to the author or carries the sealed key back (#2727). The two scripts therefore exchange the request and the sealed key through you, by copy and paste. The publisher's `broadcast_handle_key_request` and the subscriber's `broadcast_open_key` are the same calls the network path will make.

The subscriber does not yet receive published posts: the Python SDK has no call that pulls broadcast content from a relay (#2856).

## Running

### Prerequisites

Install the SCP Python SDK from source. The build needs a Rust toolchain, a C compiler, and, on Linux and Windows, a full perl (plus make on Linux) for the OpenSSL the build compiles; `bindings/python/README.md` §Requirements has the details. From the repository root:

```bash
cd templates/broadcast-feed
pip install -e ../../bindings/python
pip install cryptography
```

Both scripts keep keys in `$HOME/.scp/keys.bin` (`CustodyType.ENCRYPTED_FILE`) and each opens its own SQLCipher database under `$HOME/.scp/`. Set these in each terminal:

```bash
export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database
```

The publisher also needs a relay:

```bash
export SCP_RELAY_URL=wss://relay.example.com
```

Run the commands below from `templates/broadcast-feed`.

### Start the subscriber

```bash
python subscriber.py
```

The subscriber will:
1. Create its identity
2. Generate a DHKEM(P-256) wrapping key pair, keeping the secret half in memory
3. Print its DID and the public half of its wrapping key
4. Wait for you to paste the sealed key from the publisher

### Start the publisher

In a separate terminal, pass the two values the subscriber printed:

```bash
python feed.py --subscriber <did> --wrapping-key <hex>
```

The publisher will:
1. Create an identity and attach the relay transport
2. Create a broadcast context with `single_admin` governance
3. Publish sample content
4. Print the admission policy and subscriber count
5. Register the subscriber, block it, show that its key request is denied, and unblock it
6. Print the sealed broadcast key for the subscriber

Paste the sealed key into the subscriber's terminal. The subscriber opens it and reports the 32-byte broadcast key. Run `python feed.py` with no arguments to create the feed and publish without a subscriber.

## Customizing

### Relay URL

Set `SCP_RELAY_URL` to your relay, or run a local relay with the `personal-relay` template.

### Gated broadcast

To require admin approval for subscribers, create the context from the gated template:

```python
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
        "template_id": "GatedBroadcast",
    },
)
```

In gated mode, `broadcast_subscribe` takes the subscriber's admin-issued `messages:read` UCAN as `messages_read_ucan_jwt`.

### Removing a subscriber

Unsubscribe the DID and rotate every author's broadcast key, so the removed subscriber cannot decrypt future content:

```python
await node.broadcast_unsubscribe(ctx, subscriber_did, rotate_keys=True)
```

### Multiple authors

Promote a subscriber to author role via governance:

```python
action = json.dumps({"ChangeRole": {"did": subscriber_did, "new_role": "author"}})
result = await node.governance_propose(ctx, publisher.did, action)
```

Each author gets their own broadcast key and can publish independently.

### Economic policy

For paid subscriptions, create the context from the `scp:template/paid-broadcast` template and pass `economic_policy`, the JSON of an economic policy: its cost schedule, accepted payment adapters, and payee (spec section 19.3).
