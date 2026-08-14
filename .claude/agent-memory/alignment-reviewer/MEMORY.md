# Alignment Reviewer Memory

## Cross-cutting lessons
- [Two-dot diff / stale-base trap](feedback_two_dot_diff_stale_base_trap.md) — always three-dot; `git diff origin/main..HEAD` renders main's newer work as phantom deletions.
- [Early reviews 2026-02 + reusable patterns](early_reviews_2026_02_patterns.md) — archived Gate 1/3, ADR-022/025, PR #86/#118 verdicts; ADR-pseudocode-vs-code, PRD-path, bridge-stub, mock-integration patterns.

## Current / recent
- [SCP-RELAYRES-004 relay WRITE @5b89baada](relayres004_5b89baada.md) — confirming pass: prior 4 findings RESOLVED; 7 residual prose/artifact-flow (phantom `bound_relay_count()` 8× PRD/0× code; §10.4 miscitation self_host.rs:1406).
- [Relay-based DID resolution Model B (#482)](relay_resolution_modelb_482.md) — the PRD's shape and story split.
- [PR #2234 KEA fail-closed @432691d70](pr2234_kea_failclosed_432691d70.md) — BLOCKER: fail-closed KEA + executed-marker rollback (no `pid` idempotence) ⇒ retry double-rotates.
- [PR #2235 app-bound/unbound event log @f7392e538](pr2235_app_bound_unbound_eventlog.md) — ALIGNED, 2 WARNING. §8.4 lives in `08-products-and-apps-in-the-graph.md`, NOT 05-contexts. Stale base (18 behind).
- [Ceiling reconcile @1620de983 / @abdc11d80 / @3afb1ae06](ceiling_modify_reconcile_1620de983.md) — ModifyCeiling role/member reconciliation (§5.3.2).
- [SCP-OUT-046 streaming saga seal](scp_out_046_streaming_saga_seal.md) — outlet streaming saga seal review.

## Event log / ADR-011 / ADR-050
- [Phase-2 substrate final gate @3d96058f5](eventlog_phase2_final_gate_3d96058f5.md) — ALIGNED, 0 findings; review ONLY the incremental diff `4cad781e5...3d96058f5`, not the merge-base range.
- [Phase-2 substrate @dc18f5899](eventlog_unification_phase2_substrate.md) — APPROVE; migrates scp-runtime off the free-form `SCP-EXPORT-ENTRY:` hash chain onto RFC-6962 `scp_event_log::tree`.
- [EventType unification](adr011_eventtype_unification.md) · [amendment](adr011_eventtype_unification_amendment.md) · [@84c441c06](adr011_eventtype_unification_84c441c06.md)

## ADR-051 (causal-DAG app-event ordering)
- [Clockless reframe re-review](adr051_clockless_reframe_review.md) — CHANGES-NEEDED: one stale "median clock" ref at phase-2.md:912. Review the WORKTREE file, not main.
- [Causal-DAG review](adr051_causal_dag_review.md) — CHANGES-NEEDED: unqualified `paymentHistory` claim at 19-economic-governance.md:593.

## SDK coverage fail-closed + parity (long round series)
- [@341df72cc FINAL, rebased](sdk_coverage_failclosed_parity_341df72cc.md) — ALIGNED, 0 blocking. Pre-rotation custody ADR renumbered 051→**053**; gate ran 223 ops exit 0.
- [@0219e5c12](sdk_coverage_failclosed_parity_0219e5c12.md) · [@ed14e6c77](sdk_coverage_failclosed_parity_ed14e6c77.md) · [@44eaf5d05](sdk_coverage_failclosed_parity_44eaf5d05.md) · [@27d82895e](sdk_coverage_failclosed_parity_review.md) — earlier rounds, superseded.
- Key facts: §3.2.1 custody migration PRESERVES the DID; §9.12 + ADR-003 §4b `identity_migrate` creates a NEW DID. `evaluateTrust` is §7.2–7.5, NOT §9.3.

## SCP-1717 / SCP-1718 (identity migration, rounds 3-8)
- [Round-8 @6aa83a96d](scp1717_scp1718_round9.md) — ALIGNED, final. Kotlin deprecation WARNING→ERROR requires bumping test `@Suppress` DEPRECATION→DEPRECATION_ERROR in the same commit.
- [Round-7 @ad92b17ee](scp1717_scp1718_round8.md) · [Round-6 @98d91dcb4](scp1717_scp1718_round7.md) — superseded. Lesson: when an ADR renumbers invariants, parity-check every rustdoc step-list, CHANGELOG bullet, and test name.
- [Rounds 3-5](scp_1717_1718_review.md) — superseded.

## Phase 4 façade deletion
- [PR 4 round-3 @d569332d0](phase4_pr4_round3_review.md) — CLEAN PASS, shippable.
- [PR 4 façade deletion @2026-04-20](phase4_pr4_facade_deletion_review.md) — ALIGNED; ratchet 0/0/0/0, `DEFAULT_BRIDGE_INSTANCE` gone.
- [PR 4 earlier @2026-04-19](phase4_facade_delete_review.md) — SUPERSEDED, was MISALIGNED. Branch names mislead: verify free-fn counts and ratchet zeros.
- [PR #1735 PR-E enforcement hardening](pr_1735_pr_e_review.md) — ALIGNED; 2 cleanups.

## Topic files not yet indexed above
The directory holds ~230 per-review topic files named by subsystem + commit
(`adr049_*`, `adr052_*`, `adr055_*`, `adr057_*`, `adr062_*`, `saga_*`, `scp_out_*`,
`wasm_*`, `xctx_*`, `pr2141_*`, `ceiling_*`, `classs_*`, `spending_ucan_*`, …).
When picking up work in one of those areas, `ls` the directory and grep the
filenames for the ADR number, story ID, or commit SHA rather than expecting a
line here — the index intentionally stays short.
