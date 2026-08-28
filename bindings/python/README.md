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
        # Create a cryptographic identity (DID). CustodyType.ENCRYPTED_FILE writes an
        # encrypted key file to $HOME/.scp/keys.bin; export SCP_KEY_PASSPHRASE
        # before this call or the bridge raises ValidationError. On a shipped
        # build this call raises SCP-IDENT-1059 -- read "No shipped build
        # creates an identity yet" below before you run it.
        identity = await scp.identity_create(CustodyType.ENCRYPTED_FILE)
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
default, so a caller names the key store and this SDK names none for them.
Section 3.2.2 of the identity spec, "The Custody Vocabulary", states the two
values `CustodyType` carries. `CustodyType.ENCRYPTED_FILE` (`"encrypted_file"`)
selects the on-disk key store SCP implements, which derives the file key with
Argon2id and encrypts `$HOME/.scp/keys.bin` with AES-256-GCM.
`CustodyType.OS_KEYSTORE` (`"os_keystore"`) selects the operating system's own
key store, which SCP reaches through the platform key-custody callback you
supply. Every other string raises `ValidationError` with code
`SCP-VALID-7005`, and that includes `"platform"`, `"software"`, `"file"`,
`"platform_managed"`, and `"hardware"`.

`identity_create(CustodyType.OS_KEYSTORE)` raises `IdentityError` with code
`SCP-IDENT-1003`, because that call supplies no provider and the bridge falls
back to neither the encrypted key file nor an in-memory store. To store keys in
a platform-native key store, implement `scp_sdk.scp.KeyCustodyProvider` over
that key store and pass it to `scp.identity_create_with_custody(provider)`.
That method is where a real platform backend lands, and it is the only entry
point that takes an injected provider.

A build carrying the bridge's `testing` cargo feature additionally accepts the
raw string `"in_memory"`, which reaches the test-only in-memory key store. No
`CustodyType` member spells it, a test that needs it passes the raw string, and
a shipped build raises `IdentityError` with code `SCP-IDENT-1008`.

## What a DID document publishes about custody

`scp.identity_published_custody(did)` returns what a stranger reading that
DID document learns about custody, which section 3.2.2 states is whether the
key can leave its store and which factor unlocks it:
`"non-extractable-biometric"`, `"non-extractable-pin"`, or
`"extractable-passphrase"`. It returns `None` when the backend holding the
`#active` key reports a pair the published vocabulary states no value for.
The bridge derives the value from the running backend, so a participant cannot
publish a custody they do not run: `KeyCustodyProvider.key_is_extractable` and
`KeyCustodyProvider.unlock_factor` answer the two questions for an injected
provider, and the encrypted key file answers them for itself.

## No shipped build creates an identity yet

`identity_create_with_custody` raises `IdentityError` with code
`SCP-IDENT-1059` on every shipped build, and `identity_create(CustodyType.ENCRYPTED_FILE)`
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
other. `SCP-IDENT-1003`, `SCP-IDENT-1008`, and `SCP-VALID-7005` say that the
custody value you passed names no key store this bridge builds. `SCP-IDENT-1059` says that no
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
