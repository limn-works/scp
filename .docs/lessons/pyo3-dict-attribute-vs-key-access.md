# PyO3 Dict Returns Require Key Access, Not Attribute Access

**Date:** 2026-02-28
**Source:** SCP-213 security review of `bindings/python/scp_sdk/mcp.py:687`

## The Bug

`py_mcp_load_contexts` returns `Vec<PyObject>` where each element is a `PyDict` built in Rust:

```rust
let dict = PyDict::new(py);
dict.set_item("context_id", ctx_id)?;
// ...
results.push(dict.into());
```

The Python caller at `mcp.py:687` iterates with attribute access:

```python
context_ids = [h.context_id for h in context_handles]
```

This raises `AttributeError: 'dict' object has no attribute 'context_id'` at runtime. Python
`dict` objects do not support attribute access for their keys. The correct form is:

```python
context_ids = [h["context_id"] for h in context_handles]
```

## Why This Is Easy to Miss

The Rust return type `Vec<PyObject>` gives no hint that the objects are dicts — `PyObject` is
fully opaque. The Python caller must know (from documentation or convention) whether the returned
objects are dicts, dataclasses, or typed `#[pyclass]` instances with actual attributes.

Typed `#[pyclass]` instances (e.g., `PyContextHandle`, `PyTransportStatus`) support attribute
access via `#[pyo3(get)]` fields. Raw `PyDict` instances do not. These look identical at the
call site in Python.

## The Invariant

When a `#[pyfunction]` returns `PyObject` or `Vec<PyObject>`:

1. **Document the concrete type** in the Rust doc comment: "Returns a list of dicts with keys
   `context_id`, `source`, `relay_active`."
2. **Use key access** in Python callers: `h["key"]`, not `h.key`.
3. **Prefer typed `#[pyclass]` returns** over raw dicts when the schema is stable. A typed
   class makes attribute access safe, gives Python type-checkers something to work with, and
   prevents this class of error entirely.

## How to Catch This

- Any `PyObject` or `Vec<PyObject>` return type that is constructed from `PyDict::new()` in
  Rust must be consumed with dict-style access in Python.
- Search for `PyDict::new` in Rust FFI code; audit every Python caller for `.key` vs `["key"]`.
- Add a Python integration test that calls the function and accesses every documented key.

## Resolution

Change `mcp.py:687` from:

```python
context_ids = [h.context_id for h in context_handles]
```

to:

```python
context_ids = [h["context_id"] for h in context_handles]
```

Alternatively, define a `#[pyclass] struct PyContextInfo` with `#[pyo3(get)] context_id: String`
and return `Vec<PyContextInfo>` from `py_mcp_load_contexts`. This makes the return type
self-describing and eliminates the dict/attribute ambiguity.

## Related

- `PyContextHandle` and `PyTransportStatus` are `#[pyclass]` instances with `#[pyo3(get)]`
  fields — these correctly support attribute access. Use this pattern for new structured returns.
- See `crates/scp-ffi/src/mcp.rs:1418` for the return type and `crates/scp-ffi/src/context.rs`
  for examples of the preferred typed `#[pyclass]` pattern.
