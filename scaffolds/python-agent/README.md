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

- Replace `"in_memory"` custody with `"file"` for production key storage, and export `SCP_KEY_PASSPHRASE` — the PyO3 bridge encrypts `$HOME/.scp/keys.bin` under that passphrase. For an OS keystore, pass a `KeyCustodyProvider` to `scp.identity_create_with_custody()` instead; the bridge rejects the custody string `"platform"` with `SCP-IDENT-1003`
- Add a second participant with `ctx.join(other_identity)`
- Register tools with `ToolDefinition` and invoke them with `ctx.invoke()`
- Connect to a relay with `connect_relay()` for real transport
- See `docs/examples/python/` for more detailed examples
