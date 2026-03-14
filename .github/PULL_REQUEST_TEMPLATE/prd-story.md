<!-- template: prd-story -->
## Story

<!-- story-id: PREFIX-NNN -->
| Field | Value |
|-------|-------|
| **ID** | `PREFIX-NNN` |
| **Issue** | #NNN |
| **PRD** | `file.json` |
| **Gate** | `gate-X` |
| **Priority** | P0 / P1 / P2 |
| **Severity** | critical / major / moderate / minor |

## Sources

Reference artifacts this story traces to (from `story.sources`):

- [ ] `.docs/specs/...` -- section heading
- [ ] `.docs/adrs/...` -- section heading

> Verified: source files exist and section headings match.

## Acceptance Criteria

<!-- ac:start -->
- [ ] _Copy each criterion from story.acceptanceCriteria verbatim_
<!-- ac:end -->

## Test Plan

| Type | File | Covers AC |
|------|------|-----------|
| unit | `path/to/test.rs` | AC 1, 2 |
| integration | `path/to/test.rs` | AC 3 |

- [ ] `cargo test --workspace` passes (with `DYLD_LIBRARY_PATH`)
- [ ] `cargo clippy --workspace --all-targets --features ...` clean
- [ ] Language-specific checks pass (if touching bindings)

## Files

### Expected (from story)
_List files from story.files_

### Added/Modified (in this PR)
_List actual files changed -- discrepancies flagged by CI_

## Dependencies

| Story | Status | Title |
|-------|--------|-------|
| _blockedBy entries_ | done / pending | _title_ |

> All dependencies must be `done` before this PR merges.

## Implementation Notes

_Architecture decisions, trade-offs, anything reviewers should know._

## Checklist

- [ ] All acceptance criteria met (every box above checked)
- [ ] No stubs remaining (`// Stub -- see PREFIX-NNN`)
- [ ] Tests added for every AC
- [ ] Sources verified against current spec/ADR content
- [ ] `python3.12 scripts/validate-prd.py` passes (if PRD file modified)
- [ ] Story status updated to `done` in PRD file
