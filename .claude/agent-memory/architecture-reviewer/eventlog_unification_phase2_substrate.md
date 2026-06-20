---
name: eventlog-unification-phase2-substrate
description: Phase 2 event-log substrate swap (HEAD bf9266777) — provider rewrite onto scp_event_log, single-tree convergence, the WASM emit-site/timestamp gap, and ADR-051 forward program
metadata:
  type: project
---

Phase 2 = the substrate swap following the ADR-011 amendment Phase 1 (see [[eventlog-unification-adr011]]). Reviewed at HEAD bf9266777.

**Architecture is SOUND — single source of truth achieved:**
- `MerkleEventLogProvider` (crates/scp-runtime/src/context/providers/event_log.rs) wraps ONE `scp_event_log::EventLog`. No second tree. The old `state.merkle_tree` twin / hash-chain head is DELETED (state.rs `ContextSnapshot::event_log_merkle_root` doc now says RFC 6962 `tree::root`, truncation-forgery CLOSED via genesis-rooted prefix verification — a real correctness UPGRADE over the prior open hardening item).
- Proof seam provably equivalent: concrete provider overrides `prove_event_inclusion/consistency` via `with_log` (own tree, no replay); trait default `rebuild_event_log_for_proof` (builder.rs:397) replays through the same `append_unsigned_event` → byte-identical tree.
- Trait is typed `EventType` everywhere; no `&str` append signature remains. Bridge-local `EventLogEntry` struct fully DELETED (0 refs); FFI common `filter_manager_entries` now operates on `scp_event_log::Event` with `event_type_label` (Debug form) the single surfaced-string source.
- Excluded events (MessageReceived/EquivocationDetected/PseudonymAnnounced) append ZERO canonical leaves — buffer-only `ContextEvent`s. Verified no append_event call sites for them.
- `anchored` boolean correctly wired into the SIGNED preimage (participation.rs:558 pushes the byte; receipt.rs:476) + propagated to Python/TS SDKs + pos/neg control tests. This is the ADR-051 §6 "interim anchoring is mechanical not prose" requirement done right.
- Frozen tags 0-35 pinned by test (tree.rs:1409), 36-75 unification variants (tag 59 retired for removed PseudonymAnnounced), all-distinct asserted.
- Consequence leaves derive timestamp from convergent `ctx.trigger_timestamp_secs`; `now_secs` used only for cooldown bookkeeping (local, never a leaf). `is_convergent_trigger` gates durability. Clean.
- Compiles clean (event-log+protocol checked); no todo!/unimplemented! introduced.

**RESIDUAL RISK (the honest Phase-2/later boundary — NOT a regression, declared in-code):**
1. WASM emit-site coverage incomplete vs native. `wasm_native_full_governance_eventtype_parity_pending` is an `#[ignore]`'d HONEST KNOWN-GAP panic test enumerating ~40 EventTypes WASM does NOT durably append (RoleAssigned, AccessRevoked, SpendApproved, ContextTombstoned, TtlExtended, SignerAdded, ThresholdModified, GovernanceProposalCreated/etc, AppBound). Two members on different platforms diverge the moment any occurs. Substrate is unified; cross-platform emit-site parity is the still-open dedicated effort.
2. WASM membership/lifecycle leaf TIMESTAMP source: `append_log_event` docstring (manager.rs:430-437) mandates committer-assigned envelope `created_at`, "NEVER crate::time::now_secs()". Governance proposal/vote sites DO source the signed artifact's `created_at` (convergent ✓). But ContextCreated/MemberJoined/MemberLeft/ContextClosing sites (1418,1502,1549,1728,1935,1988) pass `now_secs()` with a comment asserting it's the committer value — true ONLY for the acting member; WASM has no receive-side path that copies the committer's value when a *second* member appends the same membership leaf. Latent cross-member divergence on these leaves.

Both (1) and (2) are governed by the deferred-emit-site boundary (#A) and the ADR-051 forward program ("step 2"). Phase 2 = "step 1" (exclusion + substrate). Verdict was APPROVED with these as documented residual risks, not blockers — they are honestly marked in-code, not silent gaps.

ADR-051 (`.docs/adrs/ADR-051-...md`) is new this branch: causal-DAG application-event ordering. Well-reasoned, explicitly a SEPARATE forward program; rejects convergent-velocity-clock with full alternatives analysis. Not scope-creep — it's the documented home for the re-anchoring of the excluded per-author events.
