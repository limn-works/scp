# DEFERRED — ADR-049 commit 11.5: saga use-case wiring

**Status:** RESOLVED (commit 11.5). Three of the four saga use cases were originally specced (§5.15.8, §6.2.4, §5.14.13); the fourth (Gap 4, migration custody handover) is RESOLVED-AS-WITHDRAWN — the operation does not exist. See "## Resolution (commit 11.5)" below. **Correction (2026-06-18):** of the three originally specced, §5.15.8 standing-pair creation was subsequently reclassified as **single-context async creation — not a saga** (a 2-member MLS group is one context; replica sync is MLS + the event-log consistency layer, not a saga journal). Only **two** live sagas remain — cross-context tool invocation (§6.2.4) and broadcast hosting handshake (§5.14.13). See spec §5.15.8 and ADR-049 §3/§3a.

**Context.** ADR-049 commit 11 migrates the non-saga standing-pair, tool,
and broadcast handlers to the actor shape. The 4 cross-context saga
use cases as originally enumerated (standing-pair create, migration,
cross-context tool invocation, broadcast hosting handshake) were
deferred to commit 11.5 because the current spec did not fully define
the wire-level protocols needed to execute the 2-phase Prepare+Commit
FSM end to end. *(Historical — see **Status** above and the Resolution
below: only **two** are live sagas (cross-context tool invocation and
broadcast hosting handshake); "migration" is the cross-identity custody
handover, **WITHDRAWN** — it is not a saga and does not exist; and
standing-pair creation was reclassified as single-context async creation,
also not a saga.)*

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

> **Superseded — see Resolution Gap-1 (2026-06-18).** Standing-pair creation is **not** a two-phase-commit saga: a 2-member MLS group is **one** context (single-context async creation), so there is no Prepare-A / Prepare-B / Commit / Abort decomposition to specify. Replica synchronization is MLS (epoch-ordered Commits + the bootstrapping Welcome) plus the event-log consistency layer; the consent gate is applied by the joining peer on Welcome receipt. The `CreationReceipt` / `StandingPairCreate` / `InitiateStandingPairCreate` apparatus described below is removed. See spec §5.15.8 and ADR-049 §3 / §3a. The present-tense two-phase body below is the original problem statement, retained for historical provenance only.

**What's missing.** The spec (§5.12.6 plus the
`standing_helpers::generate_standing_context_id` derivation) defines
the `standing_context` get-or-create flow but, prior to §5.15.8, does
not specify (note: the original "§5.15.7" citation here was phantom —
§5.15.7 is *Send-Sequence Reservation*, not standing-pair creation):
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

**What's missing.** The spec (§6.2) defines tool invocation within a
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

> **RESOLVED-AS-WITHDRAWN — see "Resolution (commit 11.5)" below. This operation does not exist; the cross-identity custody handover is a security violation (§5.11A.6) and `SagaInput::ContextMigration` / `ContextMigrationPrepared` are slated for deletion in a separate code-correctness PR. The present-tense text below is the original problem statement, retained for historical provenance only.**

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

> **Superseded — see "Resolution (commit 11.5)" below: RESOLVED by ADR-049 §3a. The wait model is **block-until-terminal** for both live sagas — §6.2.4 cross-context tool invocation and §5.14.13 broadcast hosting handshake (supervisor-minted `SagaId`; **no** async/poll `saga_state` query — that option was contemplated only for the now-withdrawn Gap-4 custody handover). (Corrected 2026-06-18: standing-pair creation, §5.15.8, is **not** a saga — it is single-context async creation reached via the `standing_context` get-or-create path, so the saga count is **two**, not three.) The present-tense text below — including the "likely async" and `saga_state(id)` poll option — is the original problem statement, retained for historical provenance only.**

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

Commit 11.5 MUST land — not commit 12 — if any of these use cases needs
to go to production. (Superseded by the Resolution below: Gap 4 is
WITHDRAWN, so the criteria cover **3 spec gaps** — **2 sagas**
(cross-context tool invocation, broadcast hosting handshake) plus the
§5.15.8 single-context-async standing-pair spec, **not** 4 — and there
is no `saga_state` export, the async/poll wait model having been
withdrawn with Gap 4 per ADR-049 §3a.)

1. A spec update (.docs/specs/ or a new ADR) filling in the **3** spec
   gaps (Gaps 1–3) with canonical wire formats and state-machine tables —
   Gap 1 being the §5.15.8 single-context-async standing-pair spec (not
   a saga) and Gaps 2–3 the two live sagas. (Gap 4 is withdrawn, not
   specced; Gap 5 is the FFI surface, item 4 below.)
2. Replacement of the **3** `reply_saga_deferred` placeholders in
   `handlers/{standing,tools,broadcast}.rs` with real dispatches —
   Prepare+Commit for the two sagas, the single-context-async
   `create` + `add_member` + Welcome path for standing-pair. (No
   migration handler — Gap 4 withdrawn.)
3. Per-use-case integration tests (covering all **3** variants) under
   `crates/scp-runtime/tests/actor_saga_*.rs`.
4. FFI bridge exports for `start_saga` **only** — block-until-terminal,
   with **no** `saga_state` status query (the async/poll wait model was
   the withdrawn Gap 4's; see ADR-049 §3a and the Gap 5 Resolution).
5. SDK wrappers for each supported language target.

## References

- ADR-049 — actor-per-context architecture
- Spec §5.12.6 (the contact graph; §5.12.4 is actually *Context Creation as a Runtime Operation*, not the contact graph)
- Spec §5.14.2 (broadcast contexts, hosting handshake) and §5.14.13 (broadcast hosting handshake saga)
- Spec §5.12.6 (contact graph) and §5.15.8 (standing-pair creation — single-context async, not a saga)
- Spec §6.2 (Context-to-Context Tool Interfaces / single-context tool invocation) and §6.2.4 (cross-context tool invocation saga)
- Spec §9.4.3 (saga journal secret handling)
- Spec §17.16 (saga journal API)
- `crates/scp-runtime/src/context/supervisor/supervisor.rs` — FSM + dispatch methods
- `crates/scp-runtime/src/context/supervisor/saga_prepared_state.rs` — prepared-state shapes
- `crates/scp-runtime/src/context/actor/handlers/{standing,tools,broadcast}.rs` — handler modules

## Resolution (commit 11.5)

The spec gaps are resolved as follows (the spec lands first per the
artifact-flow invariant; the Phase 2C implementation is a separate
downstream PR):

- **Gap 1 — Standing-pair 2-phase decomposition → RESOLVED by
  §5.15.8 (standing-pair creation — single-context async, not a saga).**

  > **Corrected (2026-06-18) — §5.15.8 is single-context async creation, NOT a saga.** The Gap-1 problem statement and the Prepare-A/Prepare-B/`CreationReceipt`/reserve-at-Prepare/consume-at-Commit/rollback machinery described below is the **original (superseded) framing**, retained for historical provenance only. A standing pair is **one** MLS context with two members (both parties derive the identical `derived_context_id`), so its creation is ordinary single-context async creation — `create` + `add_member` + Welcome, with the consent gate applied by the joining peer on Welcome receipt — synchronized by MLS + the event-log consistency layer, with **no** two-phase commit, **no** `CreationReceipt`, **no** reserve-not-consume, and **no** saga journal. See the rewritten spec §5.15.8 and ADR-049 §3/§3a; standing-pair creation is **not** among the live sagas.

  *(Original framing, superseded — see the correction above.)* Deterministic
  `derived_context_id` derivation (which also keys MLS group
  isolation via the provider's `Entry::Vacant` guard — no separate
  `group_id`), Prepare-A/Prepare-B exchange, the `CreationReceipt` canonical JCS
  field set (public plan-metadata only — no commitment), the
  Prepare-B consent gate plus KeyPackage reserve-at-Prepare /
  consume-at-Commit discipline, the rollback protocol, and the
  `register_standing_context` replay interaction (with `AlreadyExists`
  scoped to **verified-self-membership** under the deterministic
  `derived_context_id`, not an existence oracle).

- **Gap 2 — Cross-context tool invocation transport → RESOLVED by
  §6.2.4 (Cross-Context Tool Invocation Saga).** The
  `CrossContextToolInvoke` envelope (UCAN carried as an *index*, not
  bytes; re-bound to `caller_did` plus tool at resolution to foreclose
  confused-deputy escalation), Prepare/Commit directional flow, RAII
  reservation release on every terminal path, the §9.5.1 field-
  enumerated `CrossContextToolReceipt` signature, dual event-log
  recording, and the signed `CrossContextDivergenceMarker` on
  `NeedsRepair`.

- **Gap 3 — Broadcast hosting handshake protocol → RESOLVED by
  §5.14.13 (Broadcast Hosting Handshake Saga).** The
  `BroadcastHostingRequest` / `BroadcastHostingGrant` messages
  (§9.5.1-signed, bound to `subscriber_did` / broadcast author), the
  `BroadcastHostConfig` schema, freshness window plus nonce-dedup,
  removal of the `honor_key_epoch_advance` revocation-bypass knob
  (epoch-advance-or-fail-closed), the no-provenance-stripping
  `forwarding_policy` semantics, positive `expires_at_ms`, the
  aggregate amplification cap, and the `AcceptedHostSnapshotEntry`
  snapshot. The broadcast key is delivered out-of-band post-grant via
  the §5.14.2 HPKE pull — never in the handshake.

- **Gap 4 — Migration CustodyHandover envelope → RESOLVED-AS-WITHDRAWN.**
  The operation **does not exist.** Cross-identity custody handover
  (transferring a context's `mls_group_state` + `sender_key_material`
  to a *different* DID) fails on three independent grounds: (1) no use
  case survives — every cross-identity custody scenario is an MLS
  Update, remove-and-re-add, Welcome (join), or the §7.3.2.1's
  "Seed custody and admin rotation" paragraph (HPKE seed re-wrap),
  never a bearer handover; (2) it contradicts the security model —
  §5.11A.6 calls transferring source key material to a destination a
  literal "(security violation)", and encryption-as-access-control
  means access is gained by *joining*, never by receiving group state
  out-of-band; (3) it is a category error against the saga abstraction
  — a saga coordinates atomicity across 2+ context-actors, but custody
  handover is a 1-context/2-identity operation, which SCP correctly
  models as single-context governance (§7.3.2.1's "Seed custody and
  admin rotation" paragraph re-wraps the participation signing seed to the incoming admin's `#0` via
  HPKE; §5.15.5 "governance never requires cross-context
  coordination"). `SagaInput::ContextMigration` has zero callers. The
  `SagaInput::ContextMigration` / `ContextMigrationPrepared` types and
  the §9.4.3 secret-bearing journal path are **to be deleted in the
  code task** — this gap is NOT specced. The downward correction lands
  in ADR-049 §3 (enumeration drops "context migration") and §4
  (withdrawn), §5.15.4 / §5.15.6 (no migration saga), and §9.4.3
  (re-scoped to "no live instance").

- **Gap 5 — FFI SagaId wire format → RESOLVED by ADR-049 §3a (FFI
  Saga Surface).** Both sagas (§6.2.4, §5.14.13) use the block-until-terminal wait
  model; standing-pair creation is **not** a saga (single-context async
  creation, §5.15.8 — corrected 2026-06-18) and follows the ordinary
  `standing_context` get-or-create path, not the saga wait model
  (the async/poll model contemplated here was only for the
  now-cut custody handover); `SagaId` is a UUIDv4 string at every
  bridge, always supervisor-minted and never caller-supplied; the
  `SCP-SAGA-*` error taxonomy maps each terminal state; drop-while-
  in-flight does not cancel (the saga is supervisor-owned and
  journal-durable). No `saga_state` export (block-until-terminal
  returns inline).

**Phantom-provenance fixes folded in:** the original Gap-1 "§5.15.7"
citation and the References "§5.15.7 (standing-pair creation)" /
"§5.12.4 (standing contexts / contact graph)" entries were all stale
(§5.15.7 is *Send-Sequence Reservation*; §5.12.4 is *Context Creation
as a Runtime Operation*). Corrected to §5.12.6 plus §5.15.8.
