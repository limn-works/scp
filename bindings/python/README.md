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

from scp_sdk import SCP, Capability, CustodyType, MemoryScope


async def main():
    # Every call routes through an SCP instance (ADR-048). Name a storage
    # backend: this constructor has no default.
    scp = SCP(storage={"type": "in_memory"})

    # Create a cryptographic identity (DID). Name a custody backend too —
    # `identity_create` has no default either (spec §17.17.1,
    # SCP-CAPSEL-8000). `CustodyType.FILE` stores keys encrypted at rest.
    identity = await scp.identity_create(CustodyType.FILE)
    print(f"DID: {identity.did}")

    # Create an encrypted context.
    ctx = await scp.context_create(
        identity.did,
        {
            "ceiling": [
                Capability.MESSAGES_READ.value,
                Capability.MESSAGES_WRITE.value,
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
