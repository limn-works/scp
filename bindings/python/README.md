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
from scp_sdk import Identity, Context


async def main():
    # Create a cryptographic identity (DID)
    identity = await Identity.create(custody="platform")
    print(f"DID: {identity.did}")

    # Create an encrypted context
    ctx = await Context.create(
        identity=identity,
        params={"ceiling": ["msg:send", "msg:receive"], "ttl": 3600},
    )

    # Send a message (MLS-encrypted, signed, provenance-tagged)
    await ctx.send(b"Hello from SCP")

    # Receive messages
    async for msg in ctx.receive():
        print(f"{msg.sender_did}: {msg.content}")
        break

    await ctx.close()


asyncio.run(main())
```

## Requirements

- A Python version inside the `requires-python` range that `pyproject.toml` declares
- Nothing else when a wheel exists for your platform: wheels are pre-built for CPython 3.10-3.13 on Linux x86_64 and aarch64 with glibc 2.28 or newer, macOS 11 or newer, and Windows x86_64
- A build from source needs a Rust toolchain and a C compiler (gcc or clang on Linux, the Xcode Command Line Tools on macOS, MSVC on Windows), because SQLCipher compiles from C source on every platform. This holds both when pip falls back to the source distribution because no wheel matches and when you run `maturin develop` in `bindings/python`. On Linux and Windows the build also compiles OpenSSL, which needs a full perl, plus make on Linux. On Windows, NASM is optional: with it on PATH OpenSSL builds its assembly routines, and without it the build configures OpenSSL with `no-asm`. Setting `OPENSSL_NO_VENDOR` to anything but `0` skips that OpenSSL build and links the host's OpenSSL instead. On macOS the build compiles no OpenSSL, because SQLCipher uses CommonCrypto from the OS, unless `OPENSSL_DIR` (or both `OPENSSL_LIB_DIR` and `OPENSSL_INCLUDE_DIR`) is set, in which case SQLCipher links that OpenSSL's libcrypto dynamically. The build scripts read each of these variables first under the target triple as a prefix, so `AARCH64_APPLE_DARWIN_OPENSSL_DIR` or `X86_64_UNKNOWN_LINUX_GNU_OPENSSL_NO_VENDOR` has the same effect as the bare name for that target.

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
