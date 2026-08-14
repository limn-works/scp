---
name: eventlog-unification-phase1
description: ADR-011 EventType-unification Phase 1 review (feat/eventlog-unification-phase1) — 76-variant taxonomy + payload encoder + §25 KAT; APPROVED @658e1392 after CHANGES-NEEDED @d39e0a7ed
metadata:
  type: project
---

# ADR-011 EventType Unification Phase 1 @ `faf6c8ff7` (2026-06-17) — APPROVE, 0 blocking (re-confirm of `658e1392`)

Re-reviewed at HEAD `faf6c8ff7` (1 commit past `658e1392`). Findings IDENTICAL to `658e1392` below — all five checks clean, KAT Vectors 32/33 still pass (ran `cargo test -p scp-event-log --test test_vectors vector_3`, both green, root `0x39e50b87…`). Verified added-line issue-ref scan again: only `{marker:#04x}` (hex fmt, not a ref); `#586`/`#717`/`#1325` only on unmodified/context lines. Branch still touches ONLY `.docs/specs/25-test-vectors.md` downstream (62 ins / 1 del); ADR phase-2.md untouched. clippy -p scp-event-log clean.

---

# ADR-011 EventType Unification Phase 1 @ `658e1392` (2026-06-17) — APPROVE, 0 blocking

Re-review 4 commits past @d39e0a7ed. The earlier CHANGES-NEEDED field-name divergence is FIXED, plus a KAT renumber. Verified on the BRANCH tree (not main — see setup lesson below).

1. Variant fidelity: branch enum == ADR set IDENTICAL, count==76, no catch-all. (programmatic diff /tmp clean)
2. Payload: `ContextTombstonedPayload.destination_id` NOW correct (was destination_context_id; fixed in `f07a7de8`); zero stale `destination_context_id` in crate or .docs; 8 positional-rmp payload structs match ADR field lists exactly.
3. Classification (pruning.rs): all 76 classified once, exhaustive (no `_`), 44 structural + 32 operational; ContentKeysRotated/RecoveryEpochAdvanced=structural vs KeyEpochAdvance=operational (documented). Aligns ADR-030 §2c (phase-6.md:1850).
4. §25.8 KAT: typed-leaf KAT RENUMBERED 20/21→**32/33** (`658e1392`) to fix collision with §25.9 Key Continuity (which owns 20/21). Placeholder removed; vector list 5..33 contiguous & unique; §25.9 still 20/21. RAN `cargo test ... vector_3` — both PASS, tree::root `0x39e50b87...` computed via production tree::append path == both spec literals AND checkpoint.merkle_root. Honest/runtime-derived.
5. Artifact-flow: ADR untouched by branch (ADR amendment landed separately on origin/main via #1825 `e6493a2c8`; this branch is downstream realization — correct one-way flow). Only `#NNNN`-shaped match on added lines is `{marker:#04x}` (Rust hex fmt, not issue ref). Runtime test diffs in-scope: deduped local `compute_event_canonical_hash`/`event_type_tag` → canonical `tree::` pub fns (`15f674e3`, also dropped an issue ref). tree.rs: u16 tag + `SCP-EVENT-V1:` domain sep.

## CRITICAL REVIEW-SETUP LESSON (cost a near-false CHANGES-NEEDED)
MAIN worktree (`/Users/alec/Developer/limn/scp`) was on `main` @695f295a — NOT the target branch. Branch is in the AGENT worktree. `main` ALREADY had the 76-variant enum + payloads (merged ADR + prior work), so off-disk reads of lib.rs/payload.rs/pruning.rs LOOKED right but were main-state — masking that the spec renumber (32/33) was NOT on main (`git diff origin/main...HEAD -- spec` EMPTY; placeholder still at line 359 on main; vectors 32/33 absent).
**Why:** nearly flagged "Vectors 32/33 missing, placeholder present" when the branch had them.
**How to apply:** ALWAYS `git rev-parse --abbrev-ref HEAD` + confirm HEAD==stated SHA FIRST. If not on target branch, review via `git show "<branch>:path"` (quote whole arg — `$B:crates` mangles to `feat/...rates`) or cd into the worktree holding the branch. Also: the Read tool returned STALE lib.rs (old enum) while sed/grep showed the new enum — prefer sed/grep for authoritative on-disk worktree state.

---

## (Superseded) @ `d39e0a7ed` (2026-06-17) — CHANGES-NEEDED

Branch `feat/eventlog-unification-phase1`, worktree `agent-adeea63ae81780f7f`. Phase 1 = taxonomy + payload structs + §25 KAT only (NO emission changes, NO runtime migration, NO FFI/WASM tags — those are later phases per [[finding_runtime_eventlog_not_rfc6962]] sequencing).

**Diff:** lib.rs (+273) EventType 36→76 variants; payload.rs (NEW, 305) 8 per-variant structs + encode/decode_payload (positional rmp_serde); tree.rs (+237) event_type_tag now `pub`, exhaustive 76 tags 0..75; pruning.rs is_structural_event extended exhaustive; test_vectors.rs (NEW) Vectors 20-21; 25-test-vectors.md KAT fills deferred placeholder; 3 runtime _integration.rs files dedup local event_type_tag copies → call canonical.

**Verified TRUE:**
- Variant fidelity EXACT: programmatic ADR(phase-2.md:742-839)==impl(lib.rs:109-389), order-preserving, 0 set-diff, 76 count, no Other(String). TtlExtended (not TTL), RecoveryEpochAdvanced etc. correct.
- Tags: old 0-35 preserved (incl non-seq EconomicPolicyApplied=33), new 36-75 ADR-order, "MUST NOT change" comment.
- §25 KAT genuinely computed (not fabricated): vector_20 + vector_21 PASS via production append/canonical-hash/checkpoint path; regen pointer present; no §25 scope creep.
- Classification vs ADR-030 §2c (phase-6.md:1850) ALIGNED: exhaustive match (no `_`); ContentKeysRotated/RecoveryEpochAdvanced=structural vs KeyEpochAdvance=operational split documented "pending cryptographer confirmation" — honest.
- Artifact-flow direction correct (code realizes merged ADR; ADRs untouched).
- All 197 lib + 10 test_vectors pass + clippy clean ONLY with `--features testing` (did:key:<hex> helpers need it; 116 default-feature failures are pre-existing harness requirement, NOT a regression).

**BLOCKING finding (1):** `ContextTombstonedPayload.destination_context_id` (payload.rs:82, propagated lib.rs:292 + KAT) diverges from authoritative `destination_id` in BOTH ADR-011 amendment (phase-2.md:810) AND spec §5.11A.5 (05-contexts.md:576). NON-wire-affecting (positional MsgPack omits field names → no leaf-hash/KAT/convergence impact) but a real spec-vs-code fidelity divergence. Fix = rename field to `destination_id` (preferred, code→spec) OR fix spec first then code. ContextMigrationStarted also uses destination_id in §5.11A but has no payload struct this phase.

**Reusable pattern:** positional-MessagePack payload structs hide field-name drift from wire/KAT tests — name fidelity must be checked by reading the struct field idents against the spec/ADR variant-comment field list, not by running encode round-trips (which pass regardless of name). Cross-check EVERY payload field ident vs the upstream artifact's documented field list.
