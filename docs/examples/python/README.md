# SCP Python SDK Examples

Demonstrates the core operations of the SCP Python SDK: identity management,
context lifecycle, messaging, and tool invocation.

## Prerequisites

1. **Rust toolchain** (for building the native extension):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Python 3.12+** (via mise):
   ```bash
   mise install python@3.12
   ```

3. **Build the native extension**:
   ```bash
   cd bindings/python
   pip install maturin
   maturin develop --release
   ```

## Running the Examples

Each example is a standalone async script:

```bash
# Identity creation and DID document inspection
python identity.py

# Context creation and lifecycle management
python context.py

# Two-party message exchange
python messaging.py

# Tool registration and invocation
python tools.py
```

## Examples

| File | Description |
|------|-------------|
| `identity.py` | Create identity, resolve DID, inspect document, agent key management |
| `context.py` | Create context, configure capabilities, join/leave, membership queries |
| `messaging.py` | Two-party message exchange with async receive iterator |
| `tools.py` | Define tools with JSON schemas, UCAN-authorized invocation, stateful sessions |

## Key Patterns

- **Async-first**: All SDK operations are `async def`. Use `asyncio.run()` in scripts.
- **Context manager**: `Context` supports `async with` for automatic cleanup.
- **Enum types**: Use `CustodyType`, `Capability`, `ContextMode`, `MemoryScope` for type safety.
- **UCAN authorization**: Tool invocation requires a valid UCAN token (spec section 7.2).
- **Receive iterator**: `ctx.receive()` returns an `AsyncIterator[Message]` with bounded buffering.

## SDK Reference

- Python SDK source: `bindings/python/scp_sdk/`
- PyO3 bridge: `crates/scp-ffi/src/`
- Protocol spec: `.docs/specs/`

## Key custody

Every snippet here passes `in_memory`, which §3.2.2 of the identity spec, the custody
vocabulary, classifies as a test-harness string rather than a value a shipped caller
names. A shipped build rejects it with `SCP-IDENT-1008`. That section states the two
values a shipped caller does name: `encrypted_file` selects the on-disk key store SCP
implements, and `os_keystore` selects the operating system's own key store, which SCP
reaches through the platform key-custody callback the SDK consumer supplies. The words
`platform`, `software`, `file`, and `hardware` name no custody value.
