---
name: project-eventlog-committer-assigned-timestamp
description: Event-log convergence fix — committer-assigned leaf timestamps replace per-member now(); per-class sourcing rules + CommitMeta refactor + chokepoints
metadata:
  type: project
---

Event-log convergent leaf timestamp fix (branch feat/eventlog-unification-phase2-substrate). Spec commit `2ecfa23fb`, impl commit `88c856360` (on top of `bfa5baf73`).

**Problem:** runtime event log is convergent (RFC-6962 Merkle, leaf = SHA-256(0x00 || rmp_serde(Event))) but the append path stamped each member's local `SystemTime::now()` into the leaf `timestamp` — two honest members hashed different timestamps for the same commit-ordered event → divergent `merkle_root` at equal `eventCount` → §9.9.3 equal-count/equal-root false positive.

**Fix:** leaf timestamp is committer-assigned (the committing member's signed SCP envelope `created_at`), copied by every member (convergent by copy). Timer events use the pre-computed convergent deadline, never `now()`.

**Why:** §9.9.3 equivocation detection needs byte-identical leaves across honest members. Committer-assigned/deadline values are the only convergent sources.

**How to apply (per-class sourcing rules — reuse for any new append site):**
- Governance-executed leaves (all `execute_*` via the 3 dispatchers): `proposal.created_at` (signed, replicated, in shared state).
- Conflict leaves (GovernanceConflictDetected/Resolved in propose/vote inner): `proposal.created_at`.
- GovernanceFreezeExpired: `freeze_start + FREEZE_TIMEOUT_SECONDS` (module const, captured BEFORE resolution clears the freeze).
- Deferred ceiling/economic-policy application: `pending.effective_at`.
- ContextTombstoned: `migration.grace_period_end`.
- TTL ContextExpired/ContextClosed: `state.ttl.timer.deadline_unix_secs` threaded through `handle_ttl_expiry`/`finalize_close`/`try_ttl_expiry_cleanup`/`run_ttl_expiry_with_retries` (all gained a deadline param). ContextClosing (governance close): committer clock.
- Membership/commit-lifecycle (MemberJoined/Left, CommitBroadcasted/Pending, RecoveryEpochAdvanced, broadcast sub/unsub/block): committer's `deps.clock.now_secs()` (= outgoing commit envelope created_at). Broadcast subscribe already had a `timestamp` request param — use it.
- ContextCreated: creator-assigned creation time — added `creation_timestamp_secs` param to `builder::create_context`, passed `deps.clock.now_secs()` from `lifecycle_helpers::create_context`.
- Durable consequence leaves: convergent triggering-event timestamp = max-by-`event_sequence` of `consequence.evidence` (each `ConsequenceEvidence` has a convergent `timestamp`). Shared helper `scp_protocol::trust::consequence::convergent_consequence_timestamp` used by BOTH native (`governance_logic::convergent_consequence_timestamp` mirrors it) and the WASM/trait path (threaded through `LeafCtx.trigger_timestamp_secs` → `ConsequenceDispatcher::append_durable_consequence_leaf`).
- Receive path (`messaging_helpers::run_buffered_post_delivery`): inbound `msg.inner.timestamp / 1000` (ms→s). The `Some(event_name)` durable branch is currently dead but plumbed.

**Chokepoints:** receive-path envelope `created_at` = `messaging_helpers::deliver_incoming` `opened_envelope.inner.timestamp` (MILLISECONDS). Governance: `proposal.created_at` (seconds) flows via `execute_governance_action` → `dispatch_governance_action` (binds `let ts = proposal.created_at`) → sub-dispatchers.

**CommitMeta refactor:** adding `timestamp_secs` pushed 6 `execute_*` from 7→8 args (clippy `too_many_arguments`, threshold 7). Bundled the trailing `(pid: ProposalId, actor_did, timestamp_secs)` triplet into `pub struct CommitMeta<'a>` for ALL ~29 governance execute_/dispatcher functions; each destructures `let CommitMeta { .. } = meta;` at entry (execute_ that use the proposal id bind `pid: proposal_id`; others `pid: _`). This is the clean abstraction, not an `#[allow]`.

**Trait change:** `ConsequenceDispatcher::append_durable_consequence_leaf` gained a `trigger_timestamp_secs: u64` param (default no-op impl + WASM override + test impl).

**Out of scope (do NOT do):** adding currently-missing append calls (PaymentReceived durable, ProvenanceAttached, etc. — flagged by audit, NOT this work). The `wasm_native_full_governance_eventtype_parity_pending` test stays `#[ignore]` (~40 EventTypes WASM doesn't append — dedicated effort).

**Gotchas hit:** `cargo fmt --all` reflowed two unrelated pre-existing lines (wasm tools.rs, economy_helpers.rs) — benign. `golden_event_leaf_hash` KAT uses a FIXED timestamp in a hand-built Event (not via provider) → unaffected. scp-event-log checkpoint tests (84 pass/116 fail) are PRE-EXISTING baseline failures (`unsupported DID format: did:key:...` signature verification) — confirmed identical on pristine `bfa5baf73` via detached worktree; unrelated to this change. Full workspace build needs `allow_in_memory_custody` features (the CI clippy set) — bare `cargo build --workspace` fails on an unrelated `FfiKeyCustody::InMemory` feature gate.

**Tests strengthened:** `tests/eventlog_convergence.rs` + cross-impl block in `tests/wasm_conformance.rs` — members append with DISTINCT per-member clock skews (A +0, B +250) and still converge (committer-assigned); negative controls (`append_stream_with_local_timestamps[_shared]`) prove per-member-local stamping diverges at equal count.

Verification all green: full clippy (all features) exit 0, WASM clippy exit 0, workspace build (CI features) exit 0, eventlog_convergence 6/6, wasm_conformance 53/53 (+1 pre-existing ignore), scp-protocol consequence 48/48.
