---
name: audit
description: This skill should be used when the user asks to "audit the codebase", "review for gaps", "find wiring gaps", "check completeness", "staged review", "find stubs", "find dead code", "find missing implementations", "audit SDKs", "check spec compliance", "find bugs in the codebase", or wants a systematic top-down review of specs, ADRs, PRDs, and code for completeness, correctness, and quality issues.
argument-hint: "[section-or-crate] [--continue]"
---

# Staged Codebase Audit

Perform a systematic, top-down audit of the codebase: specs → ADRs → PRDs → code. Find real issues, validate them adversarially, and file detailed GitHub issues for everything confirmed.

## Arguments

Parse `$ARGUMENTS` for:

- **Section/crate** (optional): limit audit scope (e.g., `context`, `identity`, `scp-ffi`, `bindings/python`). If omitted, audit the entire codebase in stages.
- **`--continue`** (optional): resume from the last audit checkpoint saved in `.claude/agent-memory/audit/`.

## Cardinal Rules

1. **Read all related code.** Never accept grep/symbol search as complete research. Read every file, trace every call site, follow every import/export.
2. **Trace full provenance.** For every implementation, follow the chain: spec section → ADR decision → PRD story → code. If any link is broken, that's a finding.
3. **Never defer.** Nothing is "out of scope", "post-MVP", or "next phase." If it exists in the spec, it must exist in the code.
4. **Code first, issues second.** Start by reading the code — all of it. Only cross-reference open issues after findings are established.
5. **Validate adversarially.** Every finding gets a fresh agent dispatched to disprove it. Only confirmed findings become issues.

## Phase 1: Scope Enumeration

Before auditing anything, enumerate the full scope.

### 1.1 — Map the Repository

```bash
ls /Users/alec/Developer/limn/scp/
ls /Users/alec/Developer/limn/scp/crates/
ls /Users/alec/Developer/limn/scp/bindings/
ls /Users/alec/Developer/limn/scp/.docs/specs/
ls /Users/alec/Developer/limn/scp/.docs/adrs/
ls /Users/alec/Developer/limn/scp/.docs/prds/
```

### 1.2 — Build Audit Matrix

Create a tracking matrix: every spec section × every layer (core, FFI bridges, SDK wrappers, tests). Display it before proceeding.

### 1.3 — Determine Audit Order

If a section/crate argument was provided, audit only that scope. Otherwise, work through the codebase in this order:

1. **Specs** — read each spec file, extract every requirement
2. **ADRs** — read each ADR, extract every decision and constraint
3. **PRDs** — read each PRD, cross-reference story status vs code reality
4. **Rust core** (`crates/scp-core/`) — implementation completeness
5. **FFI bridges** (`crates/scp-ffi/`) — PyO3, UniFFI, NAPI
6. **SDK wrappers** (`bindings/`) — Python, TypeScript, Kotlin, Swift
7. **Cross-cutting** — tests, CI, error codes, standards compliance

## Phase 2: Staged Review

For each stage, dispatch a subagent with the appropriate specialization. Use worktree isolation for agents that may need to test code.

For the completeness/divergence stages below — missing implementations, spec drift, unwired code, inter-layer gaps, and artifact divergence — the `completionist` agent (`.claude/agents/completionist.md`) is the canonical specialization; dispatch it (via `subagent_type`) for spec/ADR/PRD-vs-code tracing and the layer-coverage matrix. For the *soundness* of the decisions the code embodies — expired premises, sunk-cost and status-quo reasoning, and cross-slice drift/rot — dispatch the `inquisitor` agent (`.claude/agents/inquisitor.md`); it interrogates whether a thing should exist at all, not merely whether it is fully wired. Reserve `general-purpose` for the adversarial validation pass in Phase 3.

### 2.1 — Spec Review

For each spec file in `.docs/specs/`:

1. Read the entire spec file
2. Extract every structured requirement (numbered items, "MUST"/"SHALL" language, defined behaviors)
3. For each requirement, trace to code:
   - Use `semantic_identifier_search` and `get_file_skeleton` to find implementations
   - Read the actual implementation code — do not trust function signatures alone
   - Check if the implementation matches the spec's exact semantics
4. Record findings: missing implementations, partial implementations, spec drift

### 2.2 — ADR Review

For each ADR file in `.docs/adrs/`:

1. Read the entire ADR
2. Extract every decision, constraint, and rejected alternative
3. Verify decisions are implemented as specified
4. Check that rejected alternatives are not accidentally present in code
5. Cross-reference with specs for consistency

### 2.3 — PRD Review

For each PRD file in `.docs/prds/`:

1. Read the PRD structure (gates, stories, dependencies)
2. For every story marked `done`:
   - Read every file listed in the story's `files` array
   - Check every acceptance criterion against actual code
   - If ANY criterion is not met, that's a finding: "falsely marked done"
3. For every story marked `pending` or `in-progress`:
   - Check if implementation actually exists (partially implemented but not tracked)
4. Run PRD validation: `python3.12 scripts/validate-prd.py`

### 2.4 — Rust Core Review

For each crate in `crates/`:

1. Read `lib.rs` / `mod.rs` to understand module structure
2. Use `get_file_skeleton` on every source file
3. Look for:
   - **Stubs**: `todo!()`, `unimplemented!()`, `// Stub`, `// TODO`, placeholder returns
   - **Dead code**: `#[allow(dead_code)]`, unused `pub` functions (no callers across crate boundary)
   - **Wiring gaps**: public functions without FFI bridge exports
   - **Security issues**: `unsafe` blocks, unchecked inputs, missing validation
   - **Bugs**: `let _ = Result` (silent error swallowing), integer overflow, race conditions
   - **Perf**: unnecessary clones, `String` where `&str` or `Cow` suffices, redundant allocations
   - **Duplicated code**: similar logic in multiple places that should be extracted

### 2.5 — FFI Bridge Review

For each bridge target (PyO3, UniFFI, NAPI):

1. Build coverage matrix: every public `scp-core` function × bridge export status
2. Read every bridge source file fully
3. Check that bridge functions correctly call core functions (not reimplementing logic)
4. Verify error mapping is complete (no swallowed errors)

### 2.6 — SDK Wrapper Review

For each SDK (Python, TypeScript, Kotlin, Swift):

1. Build coverage matrix: every FFI bridge function × SDK wrapper status
2. Read every wrapper source file
3. Check type mappings, error handling, async patterns
4. Verify tests exist for wrapped functions
5. Check that SDK-specific patterns are followed (see `.docs/scaffold/`)

### 2.7 — Cross-cutting Review

1. **Tests**: coverage gaps, tests that don't assert meaningful behavior
2. **CI**: jobs that should exist but don't, jobs that pass vacuously
3. **Error codes**: run `bash scripts/check-error-codes.sh`, verify canonical prefixes
4. **Standards**: check `.docs/standards/` compliance across all code

## Phase 3: Finding Validation

For every finding from Phase 2:

### 3.1 — Deduplication Check

```bash
gh issue list --repo limn-works/scp --state open --search "<finding keywords>" --limit 10
```

If a matching issue exists, note it. Consider enhancing it with new details.

### 3.2 — Adversarial Validation

For each finding, dispatch a fresh agent (subagent_type: "general-purpose") with a specific mission: **disprove this finding.**

Example prompts:
- Finding: "No implementation for X" → Agent: "Find the implementation of X in this codebase. Check all crates, bridges, and SDKs. Report what you find."
- Finding: "Function Y has no callers" → Agent: "Find all call sites for function Y across the entire codebase including tests, bridges, and SDKs."
- Finding: "Spec requirement Z not met" → Agent: "Verify whether spec requirement Z is implemented. Read the spec section and the code. Report evidence."

Only findings that survive adversarial validation proceed to Phase 4.

### 3.3 — Severity Classification

Classify each validated finding:

| Severity | Description |
|----------|-------------|
| `critical` | Security vulnerability, data loss, spec violation in core protocol |
| `major` | Missing implementation, broken wiring, falsely-done story |
| `moderate` | Partial implementation, missing test coverage, perf issue |
| `minor` | Dead code, style inconsistency, documentation drift |

## Phase 4: Issue Filing

For each validated, non-duplicate finding, file a GitHub issue.

### 4.1 — Issue Format

Every issue must contain enough detail for autonomous implementation. Structure:

```markdown
## Summary
[One-paragraph description of the finding]

## Evidence
[Specific files, line numbers, code snippets showing the gap]

## Expected Behavior
[What the spec/ADR/PRD requires]

## Actual Behavior
[What the code currently does or doesn't do]

## Root Cause
[Why this gap exists — missing wiring, incomplete implementation, spec drift, etc.]

## Reproduction / Verification
[How to verify the issue exists — commands, tests, code paths]

## Suggested Fix
[Specific implementation steps]

## Acceptance Criteria
[Machine-verifiable assertions that confirm the fix]

## Sources
[Links to spec sections, ADRs, PRD stories that define the requirement]
```

### 4.2 — Story-Structured Issues

Do NOT create PRD stories. File GitHub issues instead — but enforce PRD story structure in the issue body so findings are directly actionable by agents. Every issue body must include these sections (mirroring `.docs/standards/prd.md` fields):

```markdown
## Summary
[What and why — equivalent to story `description`]

## Priority
[P0/P1/P2 — per PRD standard: P0 blocking/foundational, P1 core, P2 polish]

## Severity
[critical/major/moderate/minor]

## Files
[List of files to create or modify — equivalent to story `files`]

## Acceptance Criteria
[Machine-verifiable assertions — same rules as PRD `acceptanceCriteria`:
 - Every criterion testable by grep/build/lint/test command
 - 1:1 mapping from source requirements
 - No vague language ("works correctly", "handles edge cases")
 - Conditional spec language becomes explicit test cases]

## Action Items
[Specific implementation steps — equivalent to story `actionItems`]

## Sources
[Backlinks to spec sections, ADRs, PRD stories — equivalent to story `sources`:
 - Format: `file` + `section` (exact heading in the file)
 - Every referenced file must exist
 - Every referenced section heading must exist in that file
 - If inferred from code (no upstream artifact), state that explicitly]

## Evidence
[Specific files, line numbers, code snippets showing the gap]

## Blocked By
[Other issue numbers or story IDs that must be resolved first, if any]
```

This structure ensures any issue can be converted to a PRD story or picked up by an execution agent without additional triage.

### 4.3 — Filing

```bash
gh issue create --repo limn-works/scp --title "<concise title>" --body "<detailed body>" --label "<severity>,<category>"
```

Use labels: `bug`, `enhancement`, `spec-drift`, `wiring-gap`, `dead-code`, `security`, `performance`.

## Phase 5: Checkpoint & Report

### 5.1 — Save Progress

After each stage completes, save a checkpoint:

```
.claude/agent-memory/audit/
├── checkpoint.md          # Current stage, findings so far
├── matrix.md              # Coverage matrix state
└── findings/              # Individual finding details
    ├── finding-001.md
    └── ...
```

`.gitignore` line 58 excludes `.claude/agent-memory/audit/`, so git never tracks
what this phase writes. These files list unfixed defects, and this repository is
public.

### 5.2 — Final Report

After all stages complete, produce a summary:

1. Total findings by severity and category
2. Issues filed (with links)
3. Issues enhanced (with links)
4. Coverage matrix gaps remaining
5. Recommendations for next steps

## Subagent Dispatch Strategy

- **Max 3 concurrent agents** to avoid rate limits
- Each agent gets ONE focused task (one spec section, one crate, one bridge)
- Agents that will modify files or run tests: use worktree isolation
- Read-only audit agents: no isolation needed
- Agent reports must include specific file paths and line numbers

## Reference Files

Consult these during audit:

- **`references/finding-categories.md`** — Detailed taxonomy of finding types with examples
- **`references/coverage-matrix-template.md`** — Template for building cross-layer coverage matrices
