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
