# SCP Python Agent Scaffold

Minimal Python agent using the SCP SDK. Creates a DID identity and opens an encrypted context.

## Prerequisites

- Python 3.12+
- For the source install: a Rust toolchain, a C compiler, and, on Linux and Windows, a full perl (plus make on Linux) for the OpenSSL the build compiles; `bindings/python/README.md` §Requirements has the details
- SCP Python SDK (`pip install scp-python`, or install from source: `pip install -e ../../bindings/python`)

## Build and Run

```bash
cd scaffolds/python-agent
pip install -e ../../bindings/python  # install SDK from source
export SCP_KEY_PASSPHRASE=...      # seals $HOME/.scp/keys.bin
export SCP_STORAGE_PASSPHRASE=...  # encrypts the SQLCipher database
python main.py
```

## What This Does

1. Opens one `SCP` instance over a SQLCipher database in `$HOME/.scp/python-agent`
2. Creates a `did:dht` identity with `CustodyType.ENCRYPTED_FILE`, which keeps the keys in
   `$HOME/.scp/keys.bin`, sealed under `SCP_KEY_PASSPHRASE`
3. Opens an encrypted single-admin context
4. Shuts the instance down when the `async with` block exits

A build without the bridge's `testing` feature has no pre-rotation custody
backend and raises `SCP-IDENT-1059` for `CustodyType.ENCRYPTED_FILE`.

## Next Steps

- Invite a second identity with `reserve_key_package`, `invite_member` and
  `context_join_from_welcome` (see `docs/examples/python/context.py`)
- Register an outlet with `outlet_register` and mint a UCAN for it with
  `ucan_mint` (see `docs/examples/python/tools.py`)
- Serve the context's outlets to an MCP client with `mcp_serve`
- See `docs/examples/python/` for more detailed examples
