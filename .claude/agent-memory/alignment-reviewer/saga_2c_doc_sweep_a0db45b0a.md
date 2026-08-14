---
name: saga-2c-doc-sweep-a0db45b0a
description: ALIGNED doc-only sweep aligning restore-then-replay doc-comments with the pub(crate) restore_all_contexts seal + ADR-049 impl-sequencing note + PR-7/Phase-2D label scrub (worktree saga-2c, HEAD a0db45b0a, 2026-06-23)
metadata:
  type: project
---

# Saga 2C restore-then-replay DOC SWEEP (HEAD a0db45b0a) — ALIGNED, ZERO findings

Doc-only sweep, 14 files (+71/-57), commit `docs(saga): align restore-then-replay doc-comments with pub(crate) seal`. A prior commit narrowed `Supervisor::restore_all_contexts` `pub`→`pub(crate)`; this sweep fixes stale/ungrounded prose. NO production logic / witness / visibility / enforcement-assertion change (verified: supervisor.rs +21/-21 = label rewording only; README is a 1-line method-name swap in a `rust,ignore` block).

**Three review questions all ALIGNED:**

1. **ADR-049 §3 note** (`.docs/adrs/ADR-049-actor-per-context.md:59`) — "Startup ordering is enforced by construction; saga crash-recovery is inert in production until the durable journal is wired." APPROPRIATE for an ADR (not a spec): ADRs record *implementation sequencing/decisions*, specs are protocol-not-impl-state. Every technical claim VERIFIED against code:
   - `replay_unresolved_sagas(&self, restored: &RestoredContexts)` requires the witness (supervisor.rs:5614-5617). ✓
   - `RestoredContexts::new` module-private (142), mintable only via `restore_all_contexts`; feature-gated test hatch `new_inner`/for_test (146+). ✓
   - `restore_all_contexts` is `pub(crate)` (8038); `restore_on_startup` is `pub` (8089). ✓
   - `with_providers` (1354) hardcodes `Arc::new(NoopSagaJournal)` (1381); `with_providers_and_journal` (1411) takes caller journal; `ProtocolRepositorySagaJournal` is the durable backend. ✓
   - ALL 4 production bridges (PyO3 src/runtime.rs:1217, NAPI napi/runtime.rs:1007, UniFFI uniffi/runtime.rs:1306, common bridge_instance.rs:2877/4261) construct via `with_providers` — NONE via `with_providers_and_journal` → "inert in production today" is accurate. ✓
   Consistent with rest of ADR-049 (§3a normative-gate language is harmonious; the note is descriptive impl-state, doesn't contradict). Correctly grounds the ex-"PR-7/Phase 2D" labels into a real artifact (ADR-049 §17.16.4).

2. **Label scrub** — ALIGNED with no-ephemeral-refs-in-source spirit (`feedback_no_issue_refs_in_code`: #NNNN banned; "PR-7"/"Phase 2D" are the same class of ephemeral non-durable refs). Whole-repo grep for `PR-7`/`Phase 2D`/`Phase-2D` over `crates/` + `.docs/` = ZERO remaining (complete scrub). Replaced with durable ADR-049-citing wording ("a later phase of the ADR-049 saga work"). No artifact contradicted.

3. **`resume` "MUST NOT override" rephrase** — ACCURATE. Trait `BridgeInstanceCore::resume` (bridge_instance.rs:2544) is a DEFAULT body running core.resume → reconnect_transport_if_pending → restore_all_persisted_contexts; doc at 2535-2537 says bridges add a future `post_resume_hook`, not override. Per-bridge `Scp::resume`/`PyScp::resume` (uniffi/scp.rs:124, napi/scp.rs:306) are FFI-language WRAPPERS calling the default, not overrides. Old "per-bridge resume override" phrasing was genuinely stale.

4. **Whole-PR scope** — within §17.16.4 ordering-enforcement concern; feature diff (origin/main...HEAD, 33 files +3214/-168) = saga crash-recovery FSM + bridge bootstrap + RestoredContexts witness + broadcast hosting handshake + CI fuzz-nightly pin. Doc sweep adds ZERO scope creep; ADR note is descriptive, doesn't over-reach into spec/protocol territory.

**Pre-existing non-finding (NOT introduced/worsened):** README example calls `manager.restore_on_startup()` (and previously `manager.restore_all_contexts()`) but NEITHER is a `ContextManager` method — both are Supervisor-level (`restore_on_startup` = pub on Supervisor; the lifecycle_helpers `restore_all_contexts` is a FREE FN over `&Arc<Supervisor>`). The `rust,ignore` block is illustrative pseudocode; the `manager.` receiver predates this commit; the swap to `restore_on_startup` actually IMPROVES grounding (names the real public entry). Not a finding for this PR.

LESSON: an ADR impl-sequencing note ("enforced by construction; inert until wired") is APPROPRIATE in an ADR even though specs are protocol-not-impl — the spec/ADR split is exactly that ADRs carry decisions+sequencing. To clear it, VERIFY every named symbol/visibility/construction-path against code (replay sig requires witness, ctor is pub(crate)/module-private, ALL bridges use the inert path), and confirm the durable path (`with_providers_and_journal`/`ProtocolRepositorySagaJournal`) exists so "becomes live when..." isn't vaporware. For an ephemeral-label scrub, grep the WHOLE repo for every spelling and confirm zero survivors + that replacements cite a real artifact.
