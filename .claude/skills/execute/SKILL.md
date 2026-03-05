---
name: execute
description: This skill orchestrates complete PRD execution using parallel subagents with worktree isolation, completeness verification, per-story review, and full review roster. It should be used when the user says "execute a PRD", "run PRD", "begin executing", "execute stories", "run stories", "implement the PRD", "build the PRD", "start execution", "execute [prd-path]", or provides a PRD file path for full implementation.
argument-hint: "<prd-path> [story-ids...]"
---

# PRD Execution Orchestrator

Execute a complete PRD by orchestrating parallel subagents, each in an isolated worktree, with completeness verification, incremental review, and a full review sweep before pushing.

## Arguments

Parse `$ARGUMENTS` for:

- **PRD path** (required): path to a `.json` PRD file
- **Story IDs** (optional): specific story IDs to execute (e.g., `SCP-001 SCP-003`). If omitted, execute all `pending` and `in_progress` stories.

If `$ARGUMENTS` is empty, check `.loom/config.json` for a `prd` key. If that points to a directory, list `.json` files and ask which to use. If no PRD is found, ask the user.

## Phase 1: Analyze PRD

### 1.1 — Read PRD Structure

Read the PRD in waves using `jq` — never load the entire file at once:

```bash
jq '{project, description, gates}' <prd-path>
jq '[.stories[] | select(.status != "done" and .status != "cancelled") | {id, title, status, blockedBy, files, priority, severity}]' <prd-path>
```

### 1.2 — Build Execution Graph

From the pending/in-progress stories, compute **execution waves** — groups of stories that can run in parallel:

1. **Wave 0**: stories with empty `blockedBy` (or all blockers are `done`)
2. **Wave 1**: stories whose blockers are all in wave 0
3. **Wave N**: stories whose blockers are all in waves 0..N-1

Report the wave plan to the user before proceeding:

```
Execution plan:
  Wave 0 (parallel): SCP-001, SCP-002, SCP-003
  Wave 1 (parallel): SCP-004, SCP-005  (blocked by: SCP-001)
  Wave 2 (sequential): SCP-006  (blocked by: SCP-004, SCP-005)
  Total: 6 stories across 3 waves
```

If specific story IDs were provided, filter to only those stories (and validate their blockers are satisfied).

### 1.3 — Read Project Context

Before dispatching agents, gather context they will need:

- Read CLAUDE.md (project root and any relevant subdirectories)
- Read `.docs/standards/` relevant to the PRD's domain
- Search Vestige for patterns and decisions relevant to the stories' domains
- Identify the project's test command and CI pipeline

## Phase 2: Execute Stories

Process one wave at a time. Within each wave, launch all stories in parallel.

### 2.1 — Launch Implementation Subagents

For each story in the current wave, launch one subagent with `isolation: "worktree"`. Read `references/subagent-context.md` for the full prompt template. Every subagent must receive:

1. The **full story object** — read it from the PRD with `jq '.stories[] | select(.id == "STORY-ID")' <prd-path>`
2. **Project context** — CLAUDE.md contents, relevant standards, Vestige patterns
3. **Source artifacts** — list every file in the story's `sources` array; instruct the agent to read each one in full before writing code
4. **Explicit instructions** to: read CLAUDE.md, trace all artifact sources, use Vestige for lookup and memory, work only in the assigned worktree

Launch all subagents for the wave simultaneously. Do not poll or check on them — results arrive automatically.

### 2.2 — Verify Completeness

When a subagent returns claiming completion, **do not trust it.** Read `references/completeness-verification.md` for the full checklist. At minimum:

1. Read the story's `acceptanceCriteria` from the PRD
2. Check each criterion against the agent's reported work
3. Search for stubs, TODOs, and placeholder code in the modified files: `grep -rEn "TODO|FIXME|STUB|unimplemented|todo!|stub" <modified-files>`
4. Verify no `None`/`null` placeholders where the spec requires values
5. Check that all files listed in the story's `files` array were actually created or modified

If verification **fails** — the agent left gaps, stubs, or unaddressed criteria:

- **Do not launch a reviewer.** Launch a new implementation subagent (in a fresh worktree) with the original story plus explicit instructions about what was missed. Include the previous agent's output as context.
- Repeat verification on the new agent's output. Maximum 3 attempts per story.
- After 3 failures, mark the story as `blocked` with a note and move on.

If verification **passes**, proceed to per-story review (Phase 3).

### 2.3 — Wave Progression

After all stories in a wave are verified and reviewed:

1. Merge all worktree branches into the working branch (resolve conflicts using story context)
2. Run the project's test suite
3. If tests pass, proceed to the next wave
4. If tests fail, launch a fix subagent targeting the failures before proceeding

## Phase 3: Per-Story Review

As each story passes verification, launch a review subagent immediately. Read `references/review-protocol.md` for the full review procedure.

### 3.1 — Launch Review Subagent

Launch one review subagent per completed story. **No worktree isolation** — reviewers are read-only. The reviewer receives:

1. The full story object
2. The diff produced by the implementation agent
3. Instructions to read all source artifacts referenced by the story
4. The review checklist (acceptance criteria pass/fail, provenance, bugs, patterns)

### 3.2 — Process Review Findings

Review findings are binary: **ACTION** (must fix) or **LEARNING** (worth remembering).

**ACTION items**: Launch a fix subagent (with worktree isolation) to address them. After fixes, re-run tests. If tests fail, revert the fix commits. If fixes introduce new issues, review again and fix again — up to 3 review-fix cycles per story. After 3 cycles, escalate to the user.

**LEARNING items**: Save to Vestige immediately using `smart_ingest` or `codebase(action: "remember_pattern")`. Update project artifacts (`.docs/`, CLAUDE.md) if the learning represents a convention or constraint.

**Findings are not dismissible.** Read `references/review-protocol.md` §Forbidden Dismissals for the full list. No finding may be dismissed as "out of scope", "a nit", "pre-existing", "future enhancement", or any similar deflection. If a reviewer flags it, it gets fixed — period.

## Phase 4: Final Review

After ALL stories across ALL waves are implemented, verified, reviewed, and merged:

### 4.1 — Discover Review Agents

Read `.claude/agents/README.md` (or list `.claude/agents/*.md`) to identify the project's review agent roster. Default roster from CLAUDE.md:

- black-hat, red-hat, white-hat, security-reviewer, cryptographer
- bug-catcher, chronicler, alignment-reviewer, api-design-reviewer, simplifier

Use discretion to add or remove agents based on the PRD's content domain.

### 4.2 — Launch Full Roster Review

Launch **all selected review agents in parallel**, each reviewing the complete diff from the PRD's first commit to HEAD. Each reviewer operates in its domain — do not duplicate instructions. No worktree isolation (read-only).

### 4.3 — Process Final Findings

Same as Phase 3.2: fix ACTIONs, save LEARNINGs. Review-fix cycles continue until all findings are resolved (max 3 cycles). After all fixes, run the full test suite one final time.

## Phase 5: Push and PR

### 5.1 — Run CI Locally

Run the full CI pipeline locally before pushing. Identify the project's lint, format, and test commands from CLAUDE.md's toolchain table or the CI configuration. All checks must pass. Fix any failures before proceeding.

If CLAUDE.md defines language-specific commands (e.g., `cargo clippy`, `bun run lint`, `python3.12 -m ruff check`), run all of them — not just the primary language.

### 5.2 — Push and Open PR

Push the branch and open a PR using `gh pr create`. The PR title should summarize the PRD scope. The body should list all completed stories, key decisions, and review outcomes.

## Critical Rules

1. **Completeness over speed.** Every story must be 100% complete against its acceptance criteria. No stubs, no gaps, no deferred work.
2. **Do not trust agents.** Verify every claim of completion. Agents claim "done" when work remains — this is the expected failure mode.
3. **Worktree isolation is mandatory.** Every implementation subagent runs in its own worktree. No changes leak into the primary working tree until explicitly merged.
4. **Review only complete work.** Never launch a reviewer for a story that has stubs or unaddressed acceptance criteria. Fix first, review second.
5. **One story per agent.** No bundling. Each subagent implements exactly one story.
6. **Sources are truth.** When a story's `sources` reference spec files or ADRs, those documents govern. If the story text conflicts with the source, follow the source.
7. **Memory is continuous.** Instruct every subagent to read and write Vestige. Decisions, patterns, and gotchas discovered during execution must be persisted for future sessions.
8. **CI must pass before push.** Running lint, format, and test failures is never acceptable. Fix locally first.
9. **Every finding gets addressed.** Review feedback is never dismissed. No finding is "out of scope", "a nit", "pre-existing", or "for later." If a reviewer flags it, it gets fixed or the code gets changed. See `references/review-protocol.md` §Forbidden Dismissals.
10. **Review-fix cycles continue until clean.** If a fix introduces a new issue, review again and fix again — up to 3 cycles. Completeness means the final code is clean, not that one pass was attempted.

## Additional Resources

### Reference Files

For detailed templates and procedures, consult:
- **`references/subagent-context.md`** — Full prompt template for implementation subagents
- **`references/review-protocol.md`** — Detailed review process and agent roster
- **`references/completeness-verification.md`** — Verification checklist and stub detection
