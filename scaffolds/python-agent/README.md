# SCP Python Agent Scaffold

Minimal Python agent using the SCP SDK. Creates a DID identity, opens an encrypted context, and sends a message.

## Prerequisites

- Python 3.12+
- SCP Python SDK (`pip install scp-python`, or install from source: `pip install -e ../../bindings/python`)

## Build and Run

```bash
cd scaffolds/python-agent
pip install -e ../../bindings/python  # install SDK from source
python main.py
```

## What This Does

1. Creates a `did:dht` identity with in-memory key custody
2. Opens an encrypted context with messaging capabilities
3. Sends a message and checks membership
4. Automatically cleans up via `async with` context manager

## Next Steps

- Replace `"in_memory"` custody with `"encrypted_file"` and export `SCP_KEY_PASSPHRASE` — that value selects the on-disk key store SCP implements, which derives an AES-256 key from the passphrase with Argon2id. For the operating system's own key store, pass `"os_keystore"` together with a `KeyCustodyProvider`. §3.2.2 of the identity spec, the custody vocabulary, states those two values and states that a shipped build answers every other string with a typed error. Neither call creates an identity on a released wheel: both return `SCP-IDENT-1059`, because no pre-rotation custody backend is wired yet
- Add a second participant with `ctx.join(other_identity)`
- Register tools with `ToolDefinition` and invoke them with `ctx.invoke()`
- Connect to a relay with `connect_relay()` for real transport
- See `docs/examples/python/` for more detailed examples
