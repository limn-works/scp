# FFI Registries Must Be Populated From Production Code Paths

**Source:** SCP-213 security review of `crates/scp-ffi/src/mcp.rs`, `runtime.rs`

## The Bug

`KNOWN_CONTEXTS` is a global `DashMap` that `probe_relay_for_known_contexts` reads to determine
which routing IDs to probe on the relay. The registry has a correct `register_known_context`
function. But `py_context_create` — the only production entry point for context creation — calls
`register_context` for `CONTEXT_REGISTRY` but never calls `register_known_context` for
`KNOWN_CONTEXTS`.

In tests, `register_known_context` is called directly inside `#[cfg(test)]` setup helpers. All
unit tests pass. In production, the registry is always empty, so `probe_relay_for_known_contexts`
iterates over an empty slice and returns an empty set unconditionally. The relay probe path is
structurally dead code in production.

## Why Tests Missed It

Unit tests directly call `register_known_context` in test setup fixtures. They never exercise
the production path from `py_context_create` → registry population. The test confirms the probe
*logic* works, but not that the probe *reaches* the relay under realistic conditions.

## The Invariant

For any registry pattern in the FFI bridge:

1. **Every write path** (all functions that call `register_X`) must be reachable from production
   entry points, not only from test helpers.
2. **Acceptance tests must trace the full call graph** from the public-facing function down to
   the registry read. If a registry read returns data only when a test bypasses the production
   write path, the feature is not actually wired.

## How to Catch This

When reviewing a new registry (DashMap, HashMap, etc.) in the FFI bridge:
- Grep for all callers of the insert/register function.
- Verify at least one caller is a `#[pyfunction]` or is transitively reachable from one.
- Verify a test exercises the full chain: `#[pyfunction]` → insert → read.

## Resolution

`py_context_create` must call `register_known_context` immediately after `register_context`
succeeds. It needs a routing ID (derived from the context ID or provided by the MLS layer) and
the active relay URL (from `runtime::get_relay_connection` URL tracking). The `KnownContext`
struct is already defined; the wiring just needs to happen at the right call site.

## Related

- `context_ids_for_member` reads `CONTEXT_REGISTRY`, which IS populated from `py_context_create`.
  That path works correctly. The bug is isolated to `KNOWN_CONTEXTS`.
- See `crates/scp-ffi/src/context.rs:459` for the fix site.
