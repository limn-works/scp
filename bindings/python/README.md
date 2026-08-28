# SCP Python SDK

> `scp-python` -- Shared Context Protocol for Python

Cryptographic identity, encrypted contexts, capability-based auth, and outlet invocation for AI agents. Built on Rust via PyO3.

## Install

```bash
pip install scp-python
```

## Quick Start

```python
import asyncio
from scp_sdk import SCP
from scp_sdk.types import CustodyType


async def main():
    with SCP(storage={"type": "in_memory"}) as scp:
        # Create a cryptographic identity (DID). CustodyType.FILE writes an
        # encrypted key file to $HOME/.scp/keys.bin; export SCP_KEY_PASSPHRASE
        # before this call or the bridge raises ValidationError. On a shipped
        # build this call raises SCP-IDENT-1059 -- read "No shipped build
        # creates an identity yet" below before you run it.
        identity = await scp.identity_create(CustodyType.FILE)
        print(f"DID: {identity.did}")

        # Create an encrypted context
        ctx = await scp.context_create(
            identity.did,
            {"ceiling": ["msg:send", "msg:receive"], "ttl": 3600},
        )

        # Send a message (MLS-encrypted, signed, provenance-tagged)
        await scp.context_send(ctx._raw_handle, identity.did, b"Hello from SCP")

        # Receive a message
        msg = await scp.context_receive(ctx._raw_handle)
        print(f"{msg.sender_did}: {msg.content}")

        await scp.context_close(ctx._raw_handle, identity.did)


asyncio.run(main())
```

## Key custody

`identity_create` takes a `CustodyType` or the string it spells, and carries no
default, so a caller names the key store and this SDK names none for them. A
shipped PyO3 build accepts one
of them: `CustodyType.FILE` (`"file"`) builds a `FileKeyCustody` that derives
the file key with Argon2id and encrypts `$HOME/.scp/keys.bin` with AES-256-GCM.
`CustodyType.IN_MEMORY` (`"in_memory"`) compiles only under the bridge's
`testing` feature, so a shipped build raises `IdentityError` with code
`SCP-IDENT-1008`. Every other string, `"platform"` and `"software"` included,
raises an error: `"platform"` raises `IdentityError` with code `SCP-IDENT-1003`,
and an unrecognised string raises `ValidationError` with code `SCP-VALID-7005`.

No custody string reaches Apple Keychain or Android Keystore. To store keys in
a platform-native key store, implement `scp_sdk.scp.KeyCustodyProvider` over that
key store and pass it to `scp.identity_create_with_custody(provider)`. That
method is where a real platform backend lands, and it is the only entry point
that takes an injected provider.

## No shipped build creates an identity yet

`identity_create_with_custody` raises `IdentityError` with code
`SCP-IDENT-1059` on every shipped build, and `identity_create(CustodyType.FILE)`
raises it too once `SCP_KEY_PASSPHRASE` is set. Section 9.7.4.1 of the security
model, pre-rotation key custody, makes every identity commit a pre-rotation
commitment when it is created. That commitment needs a `PreRotationCustody`
backend, and the only implementation is the test-harness
`InMemoryPreRotationCustody`, which the bridge's `testing` feature severs from
production, so `crates/scp-ffi/src/identity.rs` returns the typed error rather
than minting the test double. ADR-062, capability injection and prove-absent
dev backends, records that state as accepted in its §Decision 6 and holds the
real backend out of its own scope. Every code example above therefore runs
against a wheel built with the `testing` feature.

Two separate gaps produce those codes, and closing one does not close the
other. `SCP-IDENT-1003` and `SCP-IDENT-1008` say that the custody string you
passed names no key store this bridge builds. `SCP-IDENT-1059` says that no
pre-rotation custody backend exists for any create path to use. A wired
platform provider clears the first gap; a real pre-rotation backend clears the
second.

## Requirements

- Python >= 3.12
- Rust toolchain (build only -- wheels are pre-built for Linux, macOS, Windows)

## API Reference

Generated from source via `pydoc`. Build locally:

```bash
cd bindings/python
python -m pydoc scp_sdk
```

Published API docs are generated on every release by CI.

## Type Checking

PEP 561 compliant. The package ships `py.typed` marker and `_scp_core.pyi` stubs for full IDE autocompletion and mypy/pyright support.

```bash
mypy your_code.py  # type stubs resolve automatically
```

## Examples

See [`examples/`](./examples/) for runnable scripts:

| File | Description |
|------|-------------|
| `basic_messaging.py` | Create identity, context, send/receive messages |
| `outlet_invocation.py` | Register and invoke a outlet with test vectors |
| `mcp_integration.py` | Expose SCP outlets via MCP JSON-RPC server |
| `multi_agent.py` | Coordinate multiple agents in a shared context |

## Error Handling

All errors inherit from `ScpError` with a machine-readable `code` field:

```python
from scp_sdk import ScpError, ContextError

try:
    await ctx.send(b"data")
except ContextError as e:
    print(f"[{e.code}] {e}")
```

## Source

- Scaffold: `.docs/scaffold/python.md`
- Standards: `.docs/standards/python.md`
- API sketch: `.docs/sketch.md`
