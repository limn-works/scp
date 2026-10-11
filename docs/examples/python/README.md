# SCP Python SDK Examples

Demonstrates identity creation, the context invite-and-join handshake, and
outlet registration in the SCP Python SDK.

## Prerequisites

1. **Rust toolchain, a C compiler, and, on Linux and Windows, a full perl (plus
   make on Linux)**: step 3 compiles the native extension and, on Linux and
   Windows, the OpenSSL its SQLCipher uses (see `bindings/python/README.md`
   §Requirements):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **CPython 3.10 or later**, the `requires-python` floor in
   `bindings/python/pyproject.toml`; the repository's mise config installs 3.12:
   ```bash
   mise install python@3.12
   ```

3. **Build the native extension**, from the repository root:
   ```bash
   (cd bindings/python && pip install maturin && maturin develop --release)
   ```

4. **Set two passphrases.** Each example keeps its keys in the encrypted key file
   `$HOME/.scp/keys.bin` (`CustodyType.FILE`) and its state in a SQLCipher
   database under `$HOME/.scp/`:
   ```bash
   export SCP_KEY_PASSPHRASE=...      # seals the key file; unset raises SCP-VALID-7001
   export SCP_STORAGE_PASSPHRASE=...  # derives each database key
   ```

## Running the Examples

Each example is a standalone async script. From the repository root:

```bash
cd docs/examples/python

# Identity creation and DID document inspection
python identity.py

# Context creation, invitation, and join
python context.py

# Outlet registration, verification, and UCAN minting
python tools.py
```

## Examples

| File | Description |
|------|-------------|
| `identity.py` | Create identity, resolve DID, inspect document, agent key management |
| `context.py` | Create a context, reserve a KeyPackage, invite a member, join from the sealed invitation |
| `tools.py` | Define an outlet with JSON schemas and test vectors, register it, verify it, mint a UCAN |

No example sends or receives messages. Every `SCP` method that does, such as
`context_send` and `context_receive`, takes the context's bridge handle, and the
`Context` object `context_create` returns exposes that handle only through a
private attribute.

## Key Patterns

- **One `SCP` instance per node**: every operation is a method on `SCP`. Use
  `async with SCP(storage=...)` so the instance shuts down on exit.
- **Custody is required**: `identity_create` takes a `CustodyType` and has no
  default. `CustodyType.FILE` is the custody a shipped build offers.
  `CustodyType.IN_MEMORY` works only in a build compiled with the `testing`
  feature; a shipped build rejects it with `SCP-IDENT-1008`. To hold keys in
  your own store, pass a `KeyCustodyProvider` to `identity_create_with_custody`.
- **Enum types**: use `CustodyType`, `Capability`, `MemoryScope` and `OutletKind`
  in place of raw strings.
- **UCAN authorization**: calling an outlet requires a UCAN token that grants
  `outlet:call:<outlet id>`.

## SDK Reference

- Python SDK source: `bindings/python/scp_sdk/`
- PyO3 bridge: `crates/scp-ffi/src/`
- Protocol spec: `.docs/specs/`
