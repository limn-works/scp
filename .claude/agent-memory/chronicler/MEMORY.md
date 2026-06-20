# Chronicler Memory

## Project Structure
- PRD lives at `.docs/prds/main.json` with 163 stories (SCP-001 through SCP-163)
- ADRs organized by phase: `phase-2.md`, `phase-3.md`, `phase-4.md`, `phase-5.md`, `phase-6.md`
- Specs at `.docs/specs/01-thesis.md` through `19-economic-governance.md`
- Standards at `.docs/standards/`

## PRD Schema
- Story keys: `id`, `title`, `status`, `priority`, `acceptanceCriteria`, `blockedBy`, `sources`, `files`, `description`, `details`, `actionItems`, `gate`, `result`, `severity`
- The `adrs` and `specRefs` fields exist but are empty for all stories
- Provenance tracked via `sources` field: array of `{file, section}` objects
- This is the canonical provenance mechanism for the project

## Provenance Patterns
- Implementation file headers include doc comments referencing spec sections and ADRs
- Each done story has populated `sources` linking to ADR and/or spec sections
- Loom subagents implement stories atomically; status.md tracks outcomes per iteration

## Key ADR Locations
- ADR-013 (PyO3): phase-3.md -- established the FFI bridge pattern
- ADR-021 (UniFFI): phase-4.md lines 616-774 -- written by SCP-059
- ADR-033 (Economic Governance): phase-3.md -- economic layer design
- ADR-029/030/031: phase-6.md -- offline/sync, pruning, multi-admin governance
- ADR-035 (HTTP Features): phase-2.md lines 1094-1190 -- dev API + broadcast projection

## PRD Files
- `.docs/prds/main.json` -- main PRD (SCP-001 through SCP-163)
- `.docs/prds/reachability.json` -- reachability stories (SCP-240, SCP-241)
- `.docs/prds/http-features.json` -- HTTP features (SCP-242 through SCP-249, gates gate-http-1 and gate-http-2)
- `.docs/prds/persistence.json` -- persistence layer (SCP-PERSIST-001 through SCP-PERSIST-072, 36 stories, 8 gates)

## Persistence Layer Review (2026-03-03)
- All 36 stories marked "done" but all 8 gates still "pending" -- gate statuses need updating
- ContextPersistence dyn trait is an implementation design decision not in spec or ADRs
- scp-platform crate tree in architecture.md is stale (missing sqlite/, filesystem/, syncable/, apple/)
- scp-transport/native/ tree in architecture.md is minimal (missing blob stores, combined, local_cache, relay_persistence)
- No lessons captured for persistence implementation (worktree merge strategy, clippy fixes, tempfile API changes)

## State File Conventions
- `.claude/state/current.md` -- active work + recently completed
- `.claude/state/blocked.md` -- items waiting on dependencies
- `.claude/state/planned.md` -- unblocked work ready to pick up

## Cross-Bridge Matrix (PR #1702, 2026-04-25)
- See [feedback_bridge_canonical_naming.md](feedback_bridge_canonical_naming.md) -- canonical name in bridge-aliases.json must already exist in all 4 bridges; otherwise file source-side rename
- See [feedback_enforcement_hook_matrix_expansion.md](feedback_enforcement_hook_matrix_expansion.md) -- ADD-only edits to bridge-aliases.json bypass the PreToolUse hook via dangerouslyDisableSandbox; only for additive diffs
- See [feedback_lockstep_enforcement.md](feedback_lockstep_enforcement.md) -- bridge-aliases.json wasm_required:true entries must equal WASM_REQUIRED_OPERATIONS in ffi_conformance.rs; aliases_json_is_in_sync_with_parity_operations test enforces. Edit both atomically.
- Lesson at `.docs/lessons/cross-bridge-canonical-naming.md` covers naming divergence (PyO3/UniFFI bare-verb vs NAPI/WASM noun-verb), inverse-coverage blind spot in bridge-symmetry harness, sibling-stem alignment, category-by-semantics rule, lockstep enforcement pattern

## Cross-Bridge Matrix Batch 2 (PR #1703, 2026-04-25)
- Branch `cross-bridge/1543-batch2-ratchet-promotion`. Added 6 ops (4 WASM-exempt per ADR-034). 5 new include_str! + 7 category coverage tests gated on per-bridge exemptions. Promoted 33 ops to wasm_required:true (96 of 134 total). All reviews CLEAN.
- Batch 3 next: ~60 real impl gaps in UniFFI economy/provenance/discovery/petnames/handle/scope/media + canonical reconciliation for 14 bare-verb vs noun-verb divergences.

## SCP-1717 Pre-Rotation Key Retention (2026-04-27)
- See [project_scp_1717_pre_rotation_retention.md](project_scp_1717_pre_rotation_retention.md) -- pre_rotation_key now retained on ScpIdentity; spec §9.7.4.1 #3/#5f and §9.12 cold-storage drift unresolved; ADR-003 phase-1.md struct text stale; CLAUDE.md Integration checklist owes item 6 for behavioral cross-bridge crypto invariants.
- Lesson at `.docs/lessons/behavioral-invariant-must-be-asserted-on-every-bridge.md` -- matrix-name parity is necessary but not sufficient; every bridge emitting a wire artifact must assert the cryptographic invariant on emitted bytes (SHA-256(revealed) == commitment recomputation per spec §3.7).
- Lesson at `.docs/lessons/hash-commitment-preimage-lifetime.md` -- generalizes pre-rotation key bug to all hash-then-reveal commitments (KeyPackage, sender key, MLS leaf); preimage must persist from t=commit to t=reveal on every reachable code path.

## ADR-051 Causal-DAG (2026-06-18)
- See [project_adr051_causal_dag.md](project_adr051_causal_dag.md) -- ADR-051 ordering/clock model + staging map; §25 taxonomy 76→75 is an off-by-one CORRECTION (actual EventType enum = 75 variants, no deletion); ADRs 046-051 standalone files, 001-045 inside phase-N.md; §23.16 anti-spam-local anchor is precision-nit not broken.
- See [project_adr051_doc_hygiene_review.md](project_adr051_doc_hygiene_review.md) -- CHANGES-NEEDED doc-hygiene pass: (1) bare `§5` token collides spec §5 (zero-idle, lines 19/96) vs ADR-internal §5 (closed-cut, lines 67/107); (2) line 21 claims §9.8.5 amended but it wasn't (09-security-model.md:747 still says SCP seq "in the Merkle event log entry"; line 121 lift-list omits §9.8.5 = internal contradiction). Taxonomy 75 consistent; no #NNNN; all Related: refs resolve.
## identity_migrate citation mismatch
- See [finding_identity_migrate_citation_mismatch.md](finding_identity_migrate_citation_mismatch.md) -- §3.2.1 = Custody Migration (preserves DID); identity_migrate creates a NEW DID via pre-rotation = §9.12/ADR-003 §4b. Python/TS SDKs cite the wrong section; don't conflate the two migration ops.

## Branch: sdk-coverage fail-closed (2026-06-20 review)
- See [project_branch_sdk_coverage_fail_closed.md](project_branch_sdk_coverage_fail_closed.md) -- ADR-051 (pre-rotation substrate isolation, Proposed) standalone file (consistent w/ ADR-046..050) + fail-closed check-sdk-coverage.py (listed in CLAUDE.md line 111) + capability matrix at .docs/standards/sdk-capability-matrix.json. REBASED 2026-06-20: merge-base now dabf13364, 27 branch commits, clean two-dot diff (no stale-base deletions). rotate_key exemption text CORRECTED this branch (was falsely "UniFFI does not export rotate_key"; bridge.rs:2178 DOES export it).
