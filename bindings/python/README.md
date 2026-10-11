# SCP Python SDK

> `scp-python` -- Shared Context Protocol for Python

Cryptographic identity, encrypted contexts, capability-based auth, and outlet invocation for AI agents. Built on Rust via PyO3.

## Install

```bash
pip install scp-python
```

## Quick Start

This quick start runs only in a build compiled with the `testing` feature (`maturin develop --features testing` in `bindings/python`), because a published wheel rejects `CustodyType.IN_MEMORY`.

```python
import asyncio

from scp_sdk import SCP, CustodyType


async def main():
    # Every call goes through an SCP instance, which takes a required storage backend.
    scp = SCP({"type": "in_memory"})

    # Create a cryptographic identity (DID) whose keys live in process memory.
    identity = await scp.identity_create(CustodyType.IN_MEMORY)
    print(f"DID: {identity.did}")

    # Create an encrypted context that this identity administers.
    ctx = await scp.context_create(
        identity.did,
        {
            "ceiling": ["messages:read", "messages:write", "context:close"],
            "memory_scope": "ephemeral",
            "governance": "single_admin",
        },
    )
    print(f"Context: {ctx.context_id} ({ctx.state})")

    await scp.shutdown(5.0)


asyncio.run(main())
```

`tests/test_readme_quickstart.py` reads the block above from this file and runs it.

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

When an `SCP` method rejects its arguments before calling the native module, it raises a subclass of `scp_sdk.ScpError` that carries a machine-readable `code`. Here `identity_create` rejects a missing custody choice with `IdentityError` code `SCP-IDENT-1116`. Like the quick start, this example needs a build with the `testing` feature.

```python
import asyncio

from scp_sdk import SCP, IdentityError


async def main():
    scp = SCP({"type": "in_memory"})
    custody = None  # for example, a setting nobody filled in
    try:
        await scp.identity_create(custody)
    except IdentityError as e:
        print(f"[{e.code}] {e.message}")
    finally:
        await scp.shutdown(5.0)


asyncio.run(main())
```

`tests/test_readme_quickstart.py` runs this block too.

## Source

- Scaffold: `.docs/scaffold/python.md`
- Standards: `.docs/standards/python.md`
- API sketch: `.docs/sketch.md`
