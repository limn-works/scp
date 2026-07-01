# DEFERRED — ADR-049 commit 11.5: saga use-case wiring

**Status:** RESOLVED (commit 11.5). Three of the four saga use cases were originally specced (§5.15.8, §6.2.4, §5.14.13); the fourth (Gap 4, migration custody handover) is RESOLVED-AS-WITHDRAWN — the operation does not exist. See "## Resolution (commit 11.5)" below. **Correction (2026-06-18):** of the three originally specced, §5.15.8 standing-pair creation was subsequently reclassified as **single-context async creation — not a saga** (a 2-member MLS group is one context; replica sync is MLS + the event-log consistency layer, not a saga journal). **Correction (2026-06-25):** Gap 3 broadcast hosting handshake is now **RESOLVED-AS-WITHDRAWN** — it is a category error (not a saga: no harmful partial commit; and a phantom topology assuming content flows through an intermediate context, forbidden by §5.11A.6). Its §5.14.13 spec section, `broadcast/hosting_handshake.rs`, the `SagaInput::BroadcastHostingHandshake` variant, and `SCP-SAGA-13100..13102` are deleted. The **sole live saga** is now cross-context tool invocation (§6.2.4). See spec §5.15.8 and ADR-049 §3/§3a/§3b.

**Context.** ADR-049 commit 11 migrates the non-saga standing-pair, tool,
and broadcast handlers to the actor shape. The 4 cross-context saga
use cases as originally enumerated (standing-pair create, migration,
cross-context tool invocation, broadcast hosting handshake) were
deferred to commit 11.5 because the current spec did not fully define
the wire-level protocols needed to execute the 2-phase Prepare+Commit
FSM end to end. *(Historical — see **Status** above and the Resolution
below: only **one** is a live saga (cross-context tool invocation);
"migration" is the cross-identity custody handover, **WITHDRAWN** — it is
not a saga and does not exist; broadcast hosting handshake was **WITHDRAWN**
(2026-06-25) as a category error; and standing-pair creation was
reclassified as single-context async creation, also not a saga.)*

**What commit 11 DOES land** *(historical snapshot — the mechanism
names below describe the tree as it stood at commit 11; the
`ContextManager` and `MutationStateView` types were both deleted by the
later actor migration commits)*.
- Full `ContextCommand` sub-enum extension for standing / tools /
  broadcast — one variant per public method on the then-current
  `ContextManager` (excluding generic-executor methods that cannot
  cross the actor mailbox).
- Shim-callable handler implementations in
  `crates/scp-runtime/src/context/actor/handlers/{standing,tools,broadcast}.rs`,
  wired at the time through the since-deleted `MutationStateView`,
  delegating byte-identically to the since-deleted `ContextManager`.
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
  *(Superseded — see ADR-049 §3a, retained for historical provenance
  only. The instance-wide `saga_pending_guard` AtomicBool was replaced
  by per-participant-context-set reservation
  (`reserved_saga_contexts: Mutex<HashSet<String>>` in `supervisor.rs`):
  an instance-wide guard is exactly what §3a now **forbids** and
  `scripts/check-saga-gating-granularity.sh` enforces against. A saga is
  now rejected with `SagaBusy` only when its participant context set
  overlaps an in-flight saga's set — not whenever any saga is in
  flight — so disjoint sagas run concurrently.)*
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

**Status (resolved).** The saga apparatus is removed: the
`StandingCommand::InitiateStandingPairCreate` variant (and its
`NotImplemented` reply) no longer exists, and the two-phase
`CreationReceipt`-commitment / `StandingPairCreate` saga machinery has
been deleted — standing-pair creation is **not** a saga (see the Gap-1
Resolution blockquote above). Per §5.15.8 it is single-context async
creation (`create` + `add_member` + Welcome, with the consent gate
applied by the joining peer on Welcome receipt), reached via the
idempotent `standing_context` get-or-create path. The spec leads the
implementation, so this single-context-async creation path **is not yet
wired** (§5.15.8: "the standing-pair creation path is not yet wired") —
the saga-shaped `InitiateStandingPairCreate` variant and its `NotImplemented` reply are gone; the surviving not-yet-wired surface is the single-context-async creation path itself: the idempotent `standing_context` get-or-create path exists, but its full standing-pair creation protocol (peer KeyPackage fetch + `add_member` + Welcome + consent-on-receipt) remains unwired per §5.15.8, consistent with exit criterion 2 below.

## Gap 2 — Cross-context tool invocation transport

> **RESOLVED (2026-06-26).** The dead `ToolsCommand::InitiateCrossContextToolInvocation` mailbox variant that represented this "deferral" has been deleted. The §6.2.4 cross-context tool-invocation saga is produced supervisor-side by `Supervisor::start_cross_context_tool_invocation_saga`, not via the actor mailbox (its borrowed, non-`'static` `SagaSigningKeys` cannot move into a `'static` mailbox message). The saga's remaining surface — cross-node wire transport (the current path drives co-resident target actors in-process) — is tracked in the saga workstream. Its FFI export (ADR-049 §3a) has since shipped (see Gap-5 / exit criterion 4). The present-tense text below is the original problem statement, retained for historical provenance only.

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

**Resolution.** The saga is produced directly by
`Supervisor::start_cross_context_tool_invocation_saga` (running
supervisor-side); the dead `ToolsCommand::InitiateCrossContextToolInvocation`
mailbox variant and its `NotImplemented` reply have been deleted. Note:
`Supervisor::invoke_tool_with_economy` is, for a separate reason, not
a command variant — its generic `F: FnOnce(Value) -> Fut` executor closure
carries no `Send` bound and so cannot cross the actor mailbox; it runs
supervisor-side (FFI bridges invoke it inline).

## Gap 3 — Broadcast hosting handshake protocol

> **RESOLVED-AS-WITHDRAWN (2026-06-25) — see "Resolution (commit 11.5)" below. Broadcast hosting handshake is a category error, not a saga: there is no harmful partial commit (the host's forwarding registry is benign on loss; B's accepted-host snapshot is a unilateral B-side write satisfiable by sequencing), and it assumes a PHANTOM TOPOLOGY in which content flows through an intermediate host context to that host's members — forbidden by §5.11A.6 (decrypt-then-re-encrypt violates context-isolation and encryption-as-access-control). Broadcast scale-out is a transport/CDN concern (relays re-serving the already-public `BroadcastEnvelope`). The §5.14.13 spec section, `broadcast/hosting_handshake.rs`, `SagaInput::BroadcastHostingHandshake`, and `SCP-SAGA-13100..13102` are deleted in this PR; see ADR-049 §3b. The present-tense text below is the original problem statement, retained for historical provenance only.**

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

**Status (withdrawn).** WITHDRAWN — there is no placeholder. The
`BroadcastCommand::InitiateBroadcastHostingHandshake` variant,
`SagaInput::BroadcastHostingHandshake`, `broadcast/hosting_handshake.rs`,
and the `SCP-SAGA-13100..13102` codes are all deleted; broadcast hosting
handshake is a category error, not a saga (see the Gap-3 Resolution
blockquote above and ADR-049 §3b). No `NotImplemented` reply remains.

## Gap 4 — Migration CustodyHandover envelope

> **RESOLVED-AS-WITHDRAWN — see "Resolution (commit 11.5)" below. This operation does not exist; the cross-identity custody handover is a security violation (§5.11A.6) and `SagaInput::ContextMigration` / `ContextMigrationPrepared` were removed in a separate code-correctness PR (the types are now deleted — no FSM routing, no secret-bearing journal path). The present-tense text below is the original problem statement, retained for historical provenance only.**

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

**Status (withdrawn).** WITHDRAWN — the `SagaInput::ContextMigration` /
`ContextMigrationPrepared` types are deleted, so there is no FSM routing
and no secret-bearing saga journal path. Context migration is a
single-context governance action — `GovernanceAction::ProposeContextMigration`
/ `CancelContextMigration`, with read-state via the
`GovernanceCommand::MigrationState` query — **not** a saga (see the Gap-4
Resolution blockquote above and ADR-049 §3 / §9.4.3). No `NotImplemented`
dispatch remains.

## Gap 5 — FFI SagaId wire format (block-until-terminal vs async)

> **Superseded — see "Resolution (commit 11.5)" below: RESOLVED by ADR-049 §3a. The wait model is **block-until-terminal** for the sole live saga — §6.2.4 cross-context tool invocation (supervisor-minted `SagaId`; **no** async/poll `saga_state` query — that option was contemplated only for the now-withdrawn Gap-4 custody handover). (Corrected 2026-06-18: standing-pair creation, §5.15.8, is **not** a saga — single-context async creation reached via the `standing_context` get-or-create path. Corrected 2026-06-25: broadcast hosting handshake, formerly §5.14.13, is **WITHDRAWN** as a category error — so the saga count is **one**.) The present-tense text below — including the "likely async" and `saga_state(id)` poll option — is the original problem statement, retained for historical provenance only.**

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

**Status (resolved).** RESOLVED — the FFI saga surface is shipped. Each
bridge (PyO3, UniFFI, napi) exposes the block-until-terminal public method
`tool_invoke_cross_context_saga` for the sole live saga (§6.2.4). This is
the public FFI entry; it drives the supervisor's internal
`start_cross_context_tool_invocation_saga` and returns only after the saga
reaches a terminal state. On the committed terminal it returns a
`SagaResult` struct carrying the supervisor-minted `SagaId` (UUIDv4 string —
the gap's subject) plus the target's signed receipt bytes and the captured
tool-output bytes (every non-committed terminal raises a typed saga error
instead); the `crates/scp-ffi/common/src/saga_errors.rs` module and the
`SCP-SAGA-*` taxonomy map each terminal state to a language-native error.
There is **no** `saga_state` status query (the async/poll wait model was
withdrawn with Gap 4). See the Gap-5 Resolution blockquote above and
ADR-049 §3a.

## Commit 11.5 exit criteria

Commit 11.5 MUST land — not commit 12 — if any of these use cases needs
to go to production. (Superseded by the Resolution below: Gap 4 AND Gap 3
are WITHDRAWN, so the criteria cover **2 spec gaps** — **1 saga**
(cross-context tool invocation) plus the §5.15.8 single-context-async
standing-pair spec, **not** 4 — and there is no `saga_state` export, the
async/poll wait model having been withdrawn with Gap 4 per ADR-049 §3a.)

> **Status — mostly satisfied as of the resolutions above.** This list is
> the frozen definition-of-done, retained verbatim. Met: criterion 1 (both
> spec gaps landed — §5.15.8 single-context-async standing-pair and §6.2.4
> cross-context tool-invocation saga); criterion 4 (the FFI saga export —
> `tool_invoke_cross_context_saga`, block-until-terminal, in all three
> bridges); criterion 5 (SDK wrappers for each language target); and the
> saga side of criterion 3 (the §6.2.4 integration tests). **Pending:** the
> single-context-async standing-pair **wiring** — criterion 2's full
> standing-pair creation protocol (peer KeyPackage fetch + `add_member` +
> Welcome + consent-on-receipt) on the idempotent `standing_context`
> get-or-create path, plus its criterion-3 test — remains unwired by design
> (the spec leads; §5.15.8 records "the standing-pair creation path is not
> yet wired," so there is no live divergence to reconcile).

1. A spec update (.docs/specs/ or a new ADR) filling in the **2** spec
   gaps (Gaps 1–2) with canonical wire formats and state-machine tables —
   Gap 1 being the §5.15.8 single-context-async standing-pair spec (not
   a saga) and Gap 2 the one live saga. (Gaps 3–4 are withdrawn, not
   specced; Gap 5 is the FFI surface, item 4 below.)
2. Wiring the single-context-async standing-pair creation path into a
   real dispatch — get-or-create via `standing_context` + peer KeyPackage
   fetch + `add_member` + Welcome + consent-on-receipt. (No `tools`
   handler placeholder: the one live saga,
   §6.2.4 cross-context tool invocation, is produced supervisor-side by
   `start_cross_context_tool_invocation_saga`, not via an actor-mailbox
   handler. No migration or broadcast-hosting handler — Gaps 3–4
   withdrawn.)
3. Per-use-case integration tests under
   `crates/scp-runtime/tests/actor_saga_*.rs`. (The `actor_saga_*` glob is
   a filename convention, not a saga claim: the standing-pair entry is
   single-context async, not a saga — its test lives under that glob but
   the op it exercises is single-context async creation, not a saga.)
4. FFI bridge exports for `start_saga` **only** — block-until-terminal,
   with **no** `saga_state` status query (the async/poll wait model was
   the withdrawn Gap 4's; see ADR-049 §3a and the Gap 5 Resolution).
   (This covers the **one `start_*_saga` export** for the one live
   saga only: the standing-pair entry is single-context async and has
   **no** `start_*_saga` FFI export — it is reached via the
   `standing_context` get-or-create path, §5.15.8.)
5. SDK wrappers for each supported language target.

## References

- ADR-049 — actor-per-context architecture
- Spec §5.12.6 (the contact graph; §5.12.4 is actually *Context Creation as a Runtime Operation*, not the contact graph)
- Spec §5.14.2 (broadcast contexts) — the §5.14.13 broadcast-hosting-handshake-saga section was **WITHDRAWN** (2026-06-25) and deleted; see ADR-049 §3b
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

- **Gap 3 — Broadcast hosting handshake protocol → RESOLVED-AS-WITHDRAWN
  (2026-06-25).** The operation **is not a saga.** It fails the
  saga-admission criteria (ADR-049 §3b) on two grounds: (1) no *harmful*
  partial commit — the host's forwarding registry is benign on loss and
  B's accepted-host snapshot is a unilateral B-side write satisfiable by
  sequencing, so there is no both-or-neither cross-context atomicity to
  coordinate; (2) it assumes a **phantom topology** in which broadcast
  content flows *through* an intermediate host context to that host's
  members — forbidden by §5.11A.6, because relaying to the host's members
  would require a decrypt-then-re-encrypt stage that violates
  context-isolation and encryption-as-access-control. Broadcast scale-out
  is a transport/CDN concern: relays/CDNs re-serve the already-public
  encrypted `BroadcastEnvelope` (§5.14.5), granting no new access; only an
  entity that independently joins B as a §5.14.3 subscriber can read B's
  content. The §5.14.13 spec section, `broadcast/hosting_handshake.rs`,
  `SagaInput::BroadcastHostingHandshake`, and `SCP-SAGA-13100..13102` are
  **deleted** — this gap is NOT specced. See ADR-049 §3/§3a/§3b.

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
  coordination"). The `SagaInput::ContextMigration` /
  `ContextMigrationPrepared` types are **removed** — the type no longer
  exists anywhere in `crates/`, so the §9.4.3 secret-bearing journal
  path has no migration variant to route — this gap is NOT specced. The
  downward correction landed
  in ADR-049 §3 (enumeration drops "context migration") and §4
  (withdrawn), §5.15.4 / §5.15.6 (no migration saga), and §9.4.3
  (re-scoped to "no live instance").

- **Gap 5 — FFI SagaId wire format → RESOLVED by ADR-049 §3a (FFI
  Saga Surface).** The sole saga (§6.2.4) uses the block-until-terminal wait
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
