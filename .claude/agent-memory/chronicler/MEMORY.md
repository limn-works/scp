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

## State File Conventions
- `.claude/state/current.md` -- active work + recently completed
- `.claude/state/blocked.md` -- items waiting on dependencies
- `.claude/state/planned.md` -- unblocked work ready to pick up
