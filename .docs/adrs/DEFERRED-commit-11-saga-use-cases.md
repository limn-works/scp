# DEFERRED — ADR-049 commit 11.5: saga use-case wiring

**Status:** DEFERRED. Input to a future spec-update pass.

**Context.** ADR-049 commit 11 migrates the non-saga standing-pair, tool,
and broadcast handlers to the actor shape. The 4 cross-context saga
use cases (standing-pair create, migration, cross-context tool
invocation, broadcast hosting handshake) are deferred to commit 11.5
because the current spec does not fully define the wire-level protocols
needed to execute the 2-phase Prepare+Commit FSM end to end.

**What commit 11 DOES land.**
- Full `ContextCommand` sub-enum extension for standing / tools /
  broadcast — one variant per public `ContextManager` method
  (excluding generic-executor methods that cannot cross the actor
  mailbox).
- Shim-callable handler implementations in
  `crates/scp-runtime/src/context/actor/handlers/{standing,tools,broadcast}.rs`
  wired through `MutationStateView`, delegating byte-identically to
  `ContextManager`.
- `Supervisor::dispatch_{standing,tools,broadcast}_command` plus
  `dispatch_broadcast_command_with_custody` for the publish path.
- Saga coordinator FSM in `Supervisor::start_saga` — the full
  `Initiated → PreparingA → PreparingB → Committing → Committed |
  Aborting → Aborted | NeedsRepair` state machine with:
  - `SagaId` UUIDv4 generation.
  - Per-phase 30s timeout.
  - 3× commit retry with 500ms/1s/2s back-off.
  - Journal append before every state transition.
  - `mark_resolved` with secret-bearing evidence overwrite per spec
    §9.4.3.
- `Supervisor::replay_unresolved_sagas` — crash recovery dispatcher,
  per-state classification for unresolved journal entries.
- Supervisor-wide `saga_pending_guard` atomic bool — a concurrent
  `start_saga` while one is in flight returns
  `ContextError::ActorBusy("SagaBusy ...")`.
- Shim-parity integration tests for all 3 new dispatch methods
  (`actor_{standing,tools,broadcast}_shim.rs`).
- Generic coordinator FSM tests exercising journal write ordering,
  abort on Prepare failure, concurrent-saga guard, and crash recovery
  (`actor_saga_{coordinator,concurrent,crash_recovery}.rs`).

**What commit 11 does NOT land (the spec gaps).**

## Gap 1 — Standing-pair 2-phase decomposition

**What's missing.** The spec (§5.15.7) defines the `standing_context`
get-or-create flow but does not specify:
- Which fields of the `CreationReceipt` are covered by the Prepare-side
  commitment (public fields vs. committed-to-bytes).
- How Prepare-B rolls back if the remote side's key package fetch fails
  after a local MLS group was created in Prepare-A.
- Whether the TOCTOU re-check in the legacy implementation should be
  driven by Commit-side idempotence or by a Prepare-side lock.

**What needs specification.**
- Canonical commitment bytes for the `CreationReceipt` (preimage
  definition + SHA-256 of canonical serialization).
- Prepare-A ↔ Prepare-B message exchange (who sends what, which side
  allocates the group ID, which side signs the receipt).
- Rollback protocol: does Prepare-A clean up the MLS group on abort,
  or does the commit-12 actor state reconciler do it on next boot.
- Interaction with `register_standing_context` under replay.

**Current placeholder.** `StandingCommand::InitiateStandingPairCreate`
returns `ContextError::NotImplemented` referencing this gap. Non-saga
`StandingContext` (get-or-create, idempotent) still routes through
the legacy direct path.

## Gap 2 — Cross-context tool invocation transport

**What's missing.** The spec (§5.16) defines tool invocation within a
context but not the cross-context forwarding path:
- Wire format for forwarding a tool invocation from the calling
  context to the target context (envelope type, sender identity,
  event log recording on both sides).
- Which party presents the UCAN proof at the target (caller forwards
  vs. target fetches from a UCAN store).
- How the tool's `ToolInvokedEvent` is relayed back to the caller,
  and whether the caller's event log records it separately from the
  target's event log.

**What needs specification.**
- A new envelope type (e.g. `CrossContextToolInvoke`) with fields:
  caller context ID, caller DID, target tool registration ID, input
  JSON, optional UCAN proof reference.
- The transport leg: does the caller serialize and send via
  `send_message` to the target context, or does a dedicated
  cross-context relay route exist.
- Receipt / response path: how the target's output reaches the
  caller (same envelope type on a return channel vs. separate
  `CrossContextToolReceipt`).

**Current placeholder.**
`ToolsCommand::InitiateCrossContextToolInvocation` returns
`ContextError::NotImplemented`. Note:
`ContextManager::invoke_tool_with_economy` is not migrated to a
command variant because its generic `F: FnOnce(Value) -> Fut`
executor closure cannot cross the actor mailbox — it continues to
run on the direct manager surface (FFI bridges invoke it inline).

## Gap 3 — Broadcast hosting handshake protocol

**What's missing.** Spec §5.14.2 describes broadcast contexts but does
not fully specify the "hosting handshake" — the flow where a
subscriber requests that a host context relay broadcasts from a
broadcast context:
- Subscriber → host key-exchange frames (is it ECIES on host's
  X25519 key, or an MLS handshake).
- Host config negotiation (rate limits, max subscribers, forwarding
  policy).
- The §5.14.2 step-4 transport: how the host signals its willingness
  to relay (dedicated envelope, or piggy-back on a control message).

**What needs specification.**
- Handshake message type(s) and canonical bytes.
- Negotiated-config object (`BroadcastHostConfig`) schema.
- Abort-on-rate-limit-exceeded semantics.
- Snapshot format for the host's accepted-subscriber list.

**Current placeholder.**
`BroadcastCommand::InitiateBroadcastHostingHandshake` returns
`ContextError::NotImplemented`.

## Gap 4 — Migration CustodyHandover envelope

**What's missing.** Spec §9.4.3 describes the migration flow at a high
level and defines the saga evidence bytes discipline (SHA-256
commitment, synchronous overwrite on resolution). The envelope type
itself is underspecified:
- Canonical wire format for `CustodyHandover` (bearer bytes).
- Which fields are committed-to by the supervisor's journal and which
  are held only in actor-local `saga_pending`.
- Replay semantics after Commit: does the target actor re-verify the
  commitment against the journal's SHA-256, or is the Prepare-side
  commitment authoritative.
- Interaction with the source-side tombstone grace period.

**What needs specification.**
- `CustodyHandover` struct definition + canonical serialization.
- Commitment computation (`SHA-256(domain_separator ‖ envelope ‖
  nonce)` is specified in §9.4.3 — the domain separator and envelope
  bytes both need fixing).
- Secret-bearing journal entry contract: what the evidence payload
  looks like in pre-resolution vs. post-resolution (evidence zeroed).
- Target-side Commit verification: must recompute the commitment and
  fail fast on mismatch.

**Current placeholder.** The supervisor's
`SagaInput::ContextMigration` variant routes through the FSM and
journals as secret-bearing (`mark_resolved` is called with
`secret_bearing = true` on Committed / Aborted). Prepare-A / Prepare-B
dispatch returns `NotImplemented`.

## Gap 5 — FFI SagaId wire format (block-until-terminal vs async)

**What's missing.** FFI bridges currently have no `SagaId` exports.
The saga surface requires a decision on the caller's wait model:
- **Block-until-terminal:** `start_saga(input) -> SagaId` returns
  only after the saga reaches Committed / Aborted / NeedsRepair.
  Simpler for callers, but ties up the FFI worker thread.
- **Async:** `start_saga(input) -> SagaId` returns immediately with
  a durable ID; callers poll `saga_state(id)` or subscribe to a
  saga event stream. Higher complexity, better throughput.

**What needs specification.**
- Choice of wait model (and the rationale — likely async for
  migration, block for standing-pair create).
- `SagaId` wire format at each FFI boundary (string vs. opaque
  bytes, base32 vs. hex encoding).
- Error taxonomy at the FFI layer (which saga terminal states map
  to which language-native error types).
- Timeout / cancellation semantics: what happens if the caller's
  FFI handle is dropped while a saga is in flight.

**Current placeholder.** No FFI bridges currently expose `SagaId`
at all. The supervisor's `start_saga` returns `SagaOutput { saga_id }`
synchronously; commit 11.5 defines the FFI surface.

## Commit 11.5 exit criteria

Commit 11.5 MUST land — not commit 12 — if any saga use case needs to
go to production:

1. A spec update (.docs/specs/ or a new ADR) filling in each of the 5
   gaps above with canonical wire formats and state-machine tables.
2. Replacement of the 4 `reply_saga_deferred` placeholders in
   `handlers/{standing,tools,broadcast}.rs` with real Prepare+Commit
   dispatches.
3. Per-use-case integration tests (covering all 4 variants) under
   `crates/scp-runtime/tests/actor_saga_*.rs`.
4. FFI bridge exports for `start_saga` / `saga_state` (wire-format
   decision from gap 5).
5. SDK wrappers for each supported language target.

## References

- ADR-049 — actor-per-context architecture
- Spec §5.12.4 (standing contexts / contact graph)
- Spec §5.14.2 (broadcast contexts, hosting handshake)
- Spec §5.15.7 (standing-pair creation)
- Spec §5.16 (tool invocation)
- Spec §9.4.3 (saga journal secret handling)
- Spec §17.16 (saga journal API)
- `crates/scp-runtime/src/context/supervisor/supervisor.rs` — FSM + dispatch methods
- `crates/scp-runtime/src/context/supervisor/saga_prepared_state.rs` — prepared-state shapes
- `crates/scp-runtime/src/context/actor/handlers/{standing,tools,broadcast}.rs` — handler modules
