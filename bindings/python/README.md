# SCP Python SDK

> `scp-python` -- Shared Context Protocol for Python

Cryptographic identity, encrypted contexts, capability-based auth, and outlet invocation for AI agents. Built on Rust via PyO3.

## Install

```bash
pip install scp-python
```

## Quick Start

Set `SCP_KEY_PASSPHRASE` before you run this. `CustodyType.FILE` protects
`$HOME/.scp/keys.bin` with that passphrase and reads it from the environment;
without it `identity_create` raises `ValidationError`.

```sh
export SCP_KEY_PASSPHRASE='a passphrase you keep'
```

```python
import asyncio

from scp_sdk import SCP, Capability, CustodyType, MemoryScope


async def main():
    # Every call routes through an SCP instance (ADR-048). Name a storage
    # backend: this constructor has no default.
    scp = SCP(storage={"type": "in_memory"})

    # Create a cryptographic identity (DID). Name a custody backend too —
    # `identity_create` has no default either (spec §17.17.1,
    # SCP-CAPSEL-8000). `CustodyType.FILE` encrypts $HOME/.scp/keys.bin under
    # SCP_KEY_PASSPHRASE (Argon2id + AES-256-GCM, spec §17.8).
    identity = await scp.identity_create(CustodyType.FILE)
    print(f"DID: {identity.did}")

    # Create an encrypted context. The ceiling bounds every capability any
    # member of this context can ever hold, so it must carry `context:close`
    # for the `context_close` call below to pass its capability check.
    ctx = await scp.context_create(
        identity.did,
        {
            "ceiling": [
                Capability.MESSAGES_READ.value,
                Capability.MESSAGES_WRITE.value,
                Capability.CONTEXT_CLOSE.value,
            ],
            "memory_scope": MemoryScope.EPHEMERAL.value,
            "ttl": 3600,
        },
    )

    # Send a message (MLS-encrypted, signed, provenance-tagged).
    await scp.context_send(ctx._raw_handle, identity.did, b"Hello from SCP")

    await scp.context_close(ctx._raw_handle, identity.did)
    await scp.shutdown(5.0)


asyncio.run(main())
```

### One call this SDK answers closed today

`identity_create` commits a pre-rotation commitment at creation, which spec
§9.7.4.1 §3 makes mandatory. No production `PreRotationCustody` backend exists
yet, so a wheel published from PyPI answers every `identity_create` call —
whichever custody you name — with:

```
[SCP-IDENT-1059] no production pre-rotation custody backend available
```

That is the protocol failing closed rather than minting a test-only stand-in
(`.docs/adrs/ADR-062-capability-injection.md` §Decision 6). Issue #1729 and RFC
#2130 track the real backend. To run the quick start above before that backend
lands, build this SDK from source with the `testing` feature:

```sh
cd bindings/python
maturin develop --features scp-core/testing,testing
```

`tests/test_readme_quickstart.py` runs the block above verbatim, so this README
stops drifting from what runs.

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
