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

## Second occurrence, outside the FFI layer (2026-08-17)

`crates/scp-node/src/bridge_auth.rs` repeated this shape at a different layer. A
`StorageBridgeLookup` held every registered bridge, every operator DID document, and every
platform webhook key that §12.10.2 authentication reads. Its three writers —
`register_bridge`, `register_did_document`, `register_webhook_key` — had call sites only past
`#[cfg(test)]`. Both node build paths constructed that store and hydrated it from storage, which
held nothing, so a shipped node answered `BRIDGE_NOT_AUTHORIZED` (401) to every bridge request
forever. Twenty-seven tests covering per-bridge and per-context scope rules all passed, because
each one seeded that store directly and none of them ran a registration through a node.

Two things generalize from this second occurrence:

1. **A store is not FFI-specific.** Apply the invariant to any read-side cache or registry
   an authorization decision consults, whatever layer holds it.
2. **A 401-on-everything failure looks like correct fail-closed behaviour.** Nothing logs an
   error, nothing panics, and every negative test still passes. Ask instead which production
   call makes an authorized request succeed, and require a test that performs it.

The fix made `admit_registration` the one entry point that writes a connector and gave it two
production callers: `ApplicationNode::register_bridge`, which an embedder calls, and
`ApplicationNode::admit_bridge_registrations`, which the shipped `scp-node` binary calls at
startup when `SCP_NODE_BRIDGE_REGISTRATIONS` names a file of operator-supplied approvals.
`crates/scp-node/tests/bridge_registration_wiring.rs` requires 401 before that call and 200
after it.

A third lesson came out of a review of that first fix. Moving a writer from `#[cfg(test)]` to a
`pub` method is not the same as wiring it: a public method whose only callers are tests leaves a
shipped binary in the same state the original defect described. Ask which shipped entry point —
a binary's `main`, a request handler, a startup sequence — reaches that writer, and name it.
"Callable from outside the crate" is not an answer.

## Related

- `context_ids_for_member` reads `CONTEXT_REGISTRY`, which IS populated from `py_context_create`.
  That path works correctly. The bug is isolated to `KNOWN_CONTEXTS`.
- See `crates/scp-ffi/src/context.rs:459` for the fix site.
