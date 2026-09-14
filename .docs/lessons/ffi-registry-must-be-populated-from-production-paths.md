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

The first fix made `admit_registration` the one entry point that writes a connector and gave it
two callers reachable from a shipped build: `ApplicationNode::register_bridge`, which an embedder
calls, and `ApplicationNode::admit_bridge_registrations`, which the `scp-node` binary called at
startup when `SCP_NODE_BRIDGE_REGISTRATIONS` named a file of operator-supplied approvals.
`crates/scp-node/tests/bridge_registration_wiring.rs` required 401 before that call and 200
after it.

A third lesson came out of a review of that first fix. Moving a writer from `#[cfg(test)]` to a
`pub` method is not the same as wiring it: a public method whose only callers are tests leaves a
shipped binary in the same state the original defect described. Ask which shipped entry point —
a binary's `main`, a request handler, a startup sequence — reaches that writer, and name it.
"Callable from outside the crate" is not an answer.

## The operator file was the wrong entry point, and the fourth lesson says why

A fourth review round of pull request #2373, the bridge-handler authorization-scope branch,
withdrew that operator file. Spec §12.10.6 step 1 states the criterion a bridge node
applies before it admits a bridge: among the bridge lifecycle leaves in the event log the node
holds as a member of the context, the highest-sequence leaf naming that bridge is a
`BridgeRegistered` or `BridgeReactivated` leaf. The node reads admission out of that log and out
of no other input, and §12.10.6 step 1 names "a file the node's operator writes" among the paths
it MUST refuse. §12.2 gives admission to the context's governance model and gives it to no node
operator.

A file states that governance approved something. It proves nothing, because the node that reads
it verifies nothing. Running `register_bridge` and `approve_registration` over a fresh registry
built out of the file's own fields re-applies every §12.2.1 shape rule to the file's contents and
establishes nothing about governance, so the node ended up storing an approval its operator
asserted. That is the false guarantee the CLAUDE.md builder tenet forbids: a capability that is
honestly absent is detectable, and a stand-in for it lies.

**The fourth lesson: a shipped entry point that asserts is not a fix for a writer that nothing
calls.** The third lesson asks which shipped entry point reaches the writer. Ask a second
question after it: does that entry point *verify* what the writer stores, or does it *assert* it?
When the verifier is unbuilt, the capability fails closed — here `scp-node` admits no bridge,
`admit_registration` and the two lifecycle writers compile only under `feature = "testing"`, and
every `/v1/scp/bridge/*` endpoint answers `BRIDGE_NOT_AUTHORIZED` (401), which §12.10.6 step 1
itself gives as the answer for a bridge that fails the criterion. The 401-on-everything state the
original defect produced by accident is the correct state until the node derives a context event
log, and the second lesson above still holds: it looks identical to the defect, so
`crates/scp-node/src/main.rs` logs the absence and its reason at startup.

## Related

- `context_ids_for_member` reads `CONTEXT_REGISTRY`, which IS populated from `py_context_create`.
  That path works correctly. The bug is isolated to `KNOWN_CONTEXTS`.
- See `crates/scp-ffi/src/context.rs:459` for the fix site.
