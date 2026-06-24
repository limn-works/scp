# Review Protocol

This reference defines the review process for executed stories — both per-story incremental review (Phase 3) and full roster review (Phase 4).

## Per-Story Review (Phase 3)

### When to Launch

Launch a review subagent immediately after a story passes completeness verification. Do not batch reviews — start them as soon as possible to surface issues early.

### Review Subagent Prompt

```
Review the implementation of story {STORY_ID}: {STORY_TITLE}

Story:
{FULL_STORY_JSON}

Diff:
{GIT_DIFF_FOR_STORY_FILES}

Instructions:
1. Read CLAUDE.md at the project root
2. Read every file listed in the story's sources array — in full, not just referenced sections. Adjacent sections often contain applicable constraints.
3. Read .docs/ directories in the modified feature areas (ADRs, specs, conventions)
4. Read every line of the diff — do not skip files or skim hunks
5. For each modified file, read surrounding unchanged code to understand the full context

Review checklist:
- Does the diff satisfy EACH acceptance criterion? Report pass/fail per criterion with source citations.
- Does the code follow conventions from CLAUDE.md and .docs/?
- Are there acceptance criteria the implementation does not address?
- Does the code do what the story describes, or something subtly different?
- Does the diff include changes not related to this story?
- Are there bugs, edge cases, or correctness issues?
- Are there patterns worth remembering for future work?
- PROVENANCE: Can every changed hunk trace to a specific requirement or decision? Flag untraceable changes.
- THEMATIC: Beyond the literal checklist, does the implementation address the underlying design intent?

Output format — use exactly this structure:
STORY: {STORY_ID}
CRITERIA:
  - [PASS] <criterion text> — satisfied by <file>:<line-range>
  - [FAIL] <criterion text> — <explanation>
PROVENANCE:
  - <file>:<line-range> — traces to <requirement/decision reference>
  - <file>:<line-range> — NO PROVENANCE: <description>
ACTION:
  - <file>:<line-range> — <description of required fix>
LEARNING:
  - <description> — <why this matters>

Findings are binary: ACTION (must fix) or LEARNING (worth remembering). Do not classify severity. Everything actionable must be done.
```

### Review Agent Type

Use project-specific review agents if available (check `.claude/agents/`). For per-story review, a single `general-purpose` agent with the above prompt is sufficient.

## Full Roster Review (Phase 4)

### Agent Selection

Read `.claude/agents/README.md` to identify available review agents. The default roster:

| Agent | Domain | When to Include |
|-------|--------|-----------------|
| **black-hat** | Adversarial threat modeling | Always for security-sensitive code |
| **red-hat** | Offensive security, exploitation chains | When auth, crypto, or trust code is touched |
| **white-hat** | Defensive architecture, hardening | Always for infrastructure code |
| **security-reviewer** | Auth, secrets, injection, info leakage | Always |
| **cryptographer** | Crypto protocols, key management, signatures | When crypto code is touched |
| **bug-catcher** | Concurrency, crashes, logic errors | Always |
| **chronicler** | Documentation completeness, knowledge capture | Always |
| **alignment-reviewer** | Spec/roadmap alignment, intent verification | Always |
| **completionist** | Missing/mismatched implementations, unwired code, inter-layer gaps, artifact divergence | Always |
| **api-design-reviewer** | API quality, misuse resistance | When public APIs change |
| **simplifier** | Complexity, premature abstractions | Always |

Add or remove based on the PRD's domain:
- **architecture-reviewer** — for structural/module changes
- **performance-optimizer** — for data-heavy or async-heavy work
- **test-quality-reviewer** — when significant tests are added
- **dependency-safety-reviewer** — when dependencies change

### Full Roster Prompt

Each agent reviews the **complete diff** from the PRD's first commit to HEAD:

```bash
git log --oneline <base-commit>..HEAD
git diff <base-commit>..HEAD
```

Each agent receives:
1. The complete diff
2. A summary of all stories executed (IDs, titles, domains)
3. The PRD's description and gate structure
4. Instructions to review through their specific lens (domain from the agents table)
5. Instructions to read CLAUDE.md and relevant .docs/ before reviewing

Launch all roster agents simultaneously. No worktree isolation — reviewers are read-only.

### Full Roster Output Format

Same as per-story review: ACTION/LEARNING binary classification. Each agent reports findings in its domain.

## Conflicting Findings

When roster agents disagree (e.g., security-reviewer wants more defensive code, simplifier wants less code):

1. **Security wins over simplicity.** If a finding touches auth, crypto, input validation, or trust boundaries, the more conservative finding takes priority.
2. **Spec wins over opinion.** If one finding cites a specific spec section or ADR and the other does not, the spec-grounded finding takes priority.
3. **Escalate genuine tradeoffs.** If two findings are both spec-grounded and genuinely conflict, flag both for the user with the agents' reasoning. Do not silently resolve architectural tradeoffs.

## Processing Findings

### Reclassification Gate

Before processing, scan all LEARNING items. Reclassify as ACTION if any describe:
- Bugs, dead code, correctness errors
- Wrong API usage, unreachable paths
- Broken integration points
- Security vulnerabilities
- Spec violations

### ACTION Items

1. Group ACTIONs by affected file/story
2. Launch one fix subagent per group (with worktree isolation)
3. Each fix agent receives: original story, the ACTION items, and instructions to fix only the identified issues — no refactoring, no extras
4. After fix agents complete, merge fix branches
5. Run the full test suite
6. If tests pass, commit: `fix(<scope>): address review findings for <story-id>`
7. If tests fail, revert the fix commits — the original code was green. Log the failure.
8. **If fixes introduced new issues**, launch another review cycle on the fix diff. Repeat fix → review → fix up to **3 cycles** per story. After 3 cycles, escalate to the user — do not silently move on.

The goal is a clean final state, not a single pass. Completeness means the code that ships has no known issues, not that one review was attempted.

### LEARNING Items

For each LEARNING:

1. **Vestige** — save patterns, gotchas, or decisions useful to future sessions:
   - Code patterns: `codebase(action: "remember_pattern", ...)`
   - Decisions: `codebase(action: "remember_decision", ...)`
   - Gotchas: `smart_ingest(content: "...", tags: ["project", "gotcha"])`

2. **Artifacts** — update `.docs/`, CLAUDE.md, or inline comments if the learning represents a convention, constraint, or API behavior that should be documented permanently.

Every LEARNING must be stored somewhere. Do not discard findings.

## Forbidden Dismissals

Review findings — whether ACTION or LEARNING — **must never be dismissed.** The following reasoning patterns are explicitly forbidden when processing review feedback. If an agent or orchestrator catches itself reaching for any of these, stop and fix the finding instead.

### Forbidden phrases and reasoning

| Forbidden | Why it's wrong |
|-----------|---------------|
| "out of scope" | Everything that doesn't require a fresh design pass is in scope. |
| "future enhancement" | There is no future. Everything gets done now. |
| "after v1" / "not MVP" | There are no versions. The work is either done or not done. |
| "at a later time" | See above. Deferral is not an option. |
| "if we choose to" | The reviewer chose. By flagging it, they chose. |
| "would be nice to have" | If it's worth flagging, it's worth fixing. |
| "is a nit" | Nits get fixed. There is no severity classification — only ACTION and LEARNING. |
| "not from our changes" / "pre-existing" | If the review surfaces a pre-existing issue that the current changes interact with, touch, or should have caught — fix it. Do not leave known bugs adjacent to new code. The only exception is something that requires a fresh design pass. |
| "tracked separately" / "filed an issue" | Creating a tracking issue instead of doing the work is deferral with extra steps. Fix it now (unless it requires a design pass). |
| "known intentional gap" | There are no intentional gaps. If the gap is known, it should already be fixed. |
| "planned deferral" | These two words never belong next to each other in this order. Planned deferrals are forbidden. See completeness rules. |
| "updated the comment to note it" | Adding a comment about a problem is not fixing the problem. Fix the code, not the comment. |

### How to handle edge cases

- **Genuinely unrelated pre-existing bug** in an untouched file: This is the only case where "pre-existing" is valid. If the reviewer flagged it in a file that was not modified as part of this PRD, acknowledge the finding, save it as a LEARNING to Vestige, and move on. But if ANY of the PRD's changes touch that file or interact with the buggy code path — fix it.
- **Finding requires upstream spec change**: If a fix would contradict the spec, that means the spec needs updating first. Fix the spec, then fix the code. This is not deferral — it's the artifact flow (specs → code, never reverse).
- **Finding requires true design consideration**: This is the only acceptable reason to not do work from a piece of feedback. In this case, make a github issue with as much detail and as many artifact, source, and commit references as possible, the context that the need was uncovered in (what change was being made that surfaced the comment), the scope of the design, options, and a suggestion.
- **Finding is factually wrong**: If a reviewer's finding is based on a misunderstanding of the code or spec, dismiss it with a specific citation to the spec section or code that proves it wrong. "I disagree" is not a citation.
