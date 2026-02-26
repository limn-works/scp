# Loom Status

## Failing Tests
None. All 1,978 workspace tests pass (1,496 scp-core + 158 scp-mcp + 64 scp-node [was 10 lib + doc] + 10 scp-media + 44 scp-platform + 195 scp-transport + others).

## Uncommitted Changes
None. All changes committed.

## Fixed This Iteration
No previously-failing tests.

## Tests Added / Updated
- `crates/scp-transport/src/native/server.rs`: 3 new shutdown lifecycle tests (shutdown_does_not_panic, shutdown_stops_accepting_connections, in_flight_connection_survives_shutdown).
- `crates/scp-node/src/lib.rs`: Replaced 2 runtime validation tests (build_requires_domain, build_requires_identity_source) with 2 type-state compile-pass tests (type_state_builder_compiles_with_all_required_fields, type_state_optional_fields_at_any_point).

## Tool-Gated Stories
None.

## Subagent Outcomes
Subagents were launched with worktree isolation but their branches did not contain commits (worktree cleanup issue). Both stories were implemented directly in the main working tree.

1. **SCP-208** (Add relay graceful shutdown handle) — **DONE**. ShutdownHandle wrapping CancellationToken. start() returns (ShutdownHandle, SocketAddr). Accept loop and TTL expiry task use biased select! on cancellation token. In-flight connections drain naturally. RelayHandle in scp-node stores ShutdownHandle. ApplicationNode exposes shutdown() convenience method. All callers updated (server.rs, client.rs, phase1.rs, lib.rs). 3 lifecycle tests added.
2. **SCP-209** (Type-state builder for ApplicationNode) — **DONE**. Added NoDomain/HasDomain and NoIdentity/HasIdentity marker types with PhantomData. domain() transitions NoDomain→HasDomain. identity()/generate_identity_with() transition NoIdentity→HasIdentity. build() restricted to HasDomain+HasIdentity. Optional setters generic over Dom and Id. 2 compile-pass tests replace 2 runtime tests.

## Remaining Stories
No actionable stories remain in the PRD. All stories are done or cancelled.
