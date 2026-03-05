# scp-ffi

PyO3 bridge between the Rust core (`scp-core`, `scp-identity`, `scp-transport`, `scp-mcp`, `scp-event-log`) and the Python SDK (`bindings/python/scp_sdk`). This crate compiles to a `cdylib` named `_scp_core`, which maturin packages as `scp_sdk._scp_core`. The pure-Python layer in `bindings/python/scp_sdk/` imports this module and wraps its functions and classes with async context managers, method chaining, and Pythonic ergonomics.

## Architecture

### Module structure

| Module | Purpose | Delegates to |
|---|---|---|
| `lib.rs` | Module entry point, tokio runtime init, `atexit` shutdown | -- |
| `identity.rs` | DID lifecycle: create, load, resolve, rotate, migrate, agent keys | `scp-identity` |
| `context.rs` | Context lifecycle: create, join, leave, close, send, receive | `scp-core` context + runtime registry |
| `tools.rs` | Tool registration, invocation, verification | `scp-core` tools |
| `ucan.rs` | UCAN minting, validation, delegation, revocation | `scp-core` UCAN |
| `event_log.rs` | Event log querying and Merkle proof verification | `scp-event-log` |
| `mcp.rs` | MCP server/client: stdio + SSE transports | `scp-mcp` |
| `transport.rs` | Relay connection management | `scp-transport` |
| `runtime.rs` | Global registries: contexts, identities, known contexts, relay, storage | -- |
| `error.rs` | `ScpPyError` enum and Python exception hierarchy | -- |
| `types.rs` | `serde_json::Value` <-> Python dict conversion | -- |
| `validate.rs` | Input validation at FFI boundary (DIDs, context IDs, URLs, etc.) | -- |
| `bridge_adapters.rs` | Trait adapter implementations for MCP bridge | `scp-mcp` traits |

### Type mapping

Rust types are exposed to Python as opaque `#[pyclass]` structs with `#[getter]` properties. Internal state (key material, crypto handles) never crosses the FFI boundary. Bridge functions use `#[pyfunction]` with the `py_` prefix convention (e.g., `py_identity_create`); the Python SDK strips the prefix.

Async operations use synchronous `#[pyfunction]` with `py.allow_threads(|| rt.block_on(...))` to run tokio futures while releasing the GIL. The one exception is `PyMessageReceiver::__anext__`, which returns an `asyncio.Future` resolved via `call_soon_threadsafe` to avoid blocking the asyncio event loop.

### Error mapping

`ScpPyError` has one variant per Python exception class. `From` impls map every `scp-core` error type to the appropriate variant. The Python exception hierarchy:

```
Exception
  ScpError
    IdentityError
    ContextError
    CryptoError
    TransportError
    UcanError
    ValidationError
```

### Runtime registries

`runtime.rs` maintains process-global `DashMap` registries for contexts, identities, known contexts, relay connections, and storage. Bridge functions look up state by string ID via `with_context()` / `with_identity()` closures. These registries are single-tenant only (see RED-017 / SCP-228).

## Build

Local development:

```sh
maturin develop --release
```

This builds the `cdylib` and installs it into the active Python environment. The `extension-module` feature is passed automatically by maturin via `pyproject.toml`.

To check compilation without Python linkage:

```sh
cargo check -p scp-ffi
```

The crate has `crate-type = ["cdylib", "rlib"]`. The `cdylib` is for the Python extension module; the `rlib` enables `cargo test` to link against this crate without the `extension-module` feature (which suppresses Python symbol linking).

## Testing

### Rust unit tests

Rust tests require the Python shared library on the linker path. Without it, tests will fail with unresolved symbol errors.

```sh
# macOS
DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
  cargo test -p scp-ffi

# Linux
LD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
  cargo test -p scp-ffi
```

The dev-dependency on `pyo3` includes `auto-initialize`, which embeds a Python interpreter in the test binary for tests that need it.

### Python integration tests

After `maturin develop --release`:

```sh
cd bindings/python
python3.12 -m pytest tests/ -v
```

### Full workspace test (including this crate)

```sh
DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
  cargo test --workspace
```

## Adding new bindings

To expose a new Rust type or function to Python:

1. **Choose the module.** If the type belongs to an existing domain (identity, context, tools, UCAN, etc.), add it to that module's `.rs` file. Otherwise create a new module and declare it in `lib.rs`.

2. **Define the bridge type or function.** Use `#[pyclass]` for types and `#[pyfunction]` for standalone functions. Follow the `py_` prefix convention for functions. Expose fields via `#[getter]` properties -- never expose internal Rust types directly.

   ```rust
   #[pyclass(name = "PyWidget", frozen)]
   pub struct PyWidget {
       inner_value: String,
   }

   #[pymethods]
   impl PyWidget {
       #[getter]
       fn value(&self) -> &str {
           &self.inner_value
       }
   }

   #[pyfunction]
   fn py_widget_create(py: Python<'_>, name: &str) -> PyResult<PyWidget> {
       validate::validate_context_id(name)?; // validate at the boundary
       let rt = crate::runtime()?;
       py.allow_threads(|| {
           rt.block_on(async {
               // call scp-core ...
               Ok(PyWidget { inner_value: name.to_owned() })
           })
       })
   }
   ```

3. **Validate inputs.** Add a validator to `validate.rs` if the input type is new (string format, length, character restrictions). All string inputs are validated at the FFI boundary before reaching `scp-core`.

4. **Map errors.** If your `scp-core` function returns a new error type, add a `From<YourError> for ScpPyError` impl in `error.rs` mapping it to the appropriate exception variant.

5. **Register on the module.** Add a `register_*` function that calls `m.add_class::<PyWidget>()` and/or `m.add_function(wrap_pyfunction!(py_widget_create, m)?)`, then call it from `_scp_core` in `lib.rs`.

6. **Add a Python wrapper.** In `bindings/python/scp_sdk/`, create or extend the corresponding `.py` file with a Pythonic async wrapper that imports from `scp_sdk._scp_core`. Update `_scp_core.pyi` type stubs.
