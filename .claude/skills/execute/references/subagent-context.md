# Subagent Context Template

This reference defines the full prompt template for implementation subagents. Every subagent launched during Phase 2 must receive this context.

## Prompt Structure

Build each subagent prompt from these sections, in order:

### 1. Identity and Scope

```
Implement story {STORY_ID}: {STORY_TITLE}

Work only on this story. Do not fix adjacent code, add unrequested features, or refactor code that seems inconsistent with other specs. Scope is sacred.
```

### 2. Story Object

Include the full story JSON — all fields. Read it from the PRD:

```bash
jq '.stories[] | select(.id == "{STORY_ID}")' <prd-path>
```

Embed the entire object in the prompt. Do not summarize or omit fields.

### 3. Project Context

Include relevant standards from `.docs/standards/` and any Vestige patterns or decisions found during Phase 1.3. Do not include CLAUDE.md: a non-fork subagent loads every CLAUDE.md level itself.

```
Relevant standards:
{STANDARDS_CONTENTS}

Known patterns and decisions from memory:
{VESTIGE_CONTEXT}
```

### 4. Source Artifacts

For each entry in the story's `sources` array, instruct the agent to read the full file:

```
Source artifacts — read each file in full before writing any code:
{LIST_OF_SOURCE_FILES_AND_SECTIONS}

These are the source of truth. If the story fields conflict with or omit details from the source documents, follow the source.
```

### 5. Operational Instructions

```
Before writing any code:
1. Read every file listed in the story's sources array — in full, line by line
2. Search the codebase for existing implementations before assuming something is missing
3. Search Vestige for relevant patterns: search(query: "{project} {story-domain} patterns gotchas")

While working:
4. Trace provenance — every non-trivial implementation choice must reference the source document and section that drove it
5. When making a judgment call (source is ambiguous or silent), document it explicitly in a comment and in your commit message
6. Use Vestige to store decisions and patterns you discover: codebase(action: "remember_decision", ...) or codebase(action: "remember_pattern", ...)

After implementation:
7. Verify every acceptance criterion is addressed — check them one by one
8. Run the project's test suite and fix any failures
9. Ensure zero TODOs, FIXMEs, stubs, or placeholder values in your code
10. If the story changes project-wide patterns or APIs, update relevant .docs/ files and CLAUDE.md
```

### 6. Worktree Awareness

```
You are working in an isolated git worktree. Your changes will be merged into the main branch after verification and review. Commit your work with conventional commit messages referencing the story ID (e.g., "feat(scope): description (STORY_ID)").
```

### 7. Completeness Standard

```
Report the story complete only when every acceptance criterion is fully satisfied, every field the spec defines has a real value (never None when the data exists elsewhere in the system), and every edge case the source mentions is handled. A story with any of these unmet is not complete.

If you cannot complete the story fully, report what blocked you and what remains, and do not claim completion.
```

## Prompt Assembly

Concatenate all sections into a single prompt. Use the Agent tool with:

```
subagent_type: "general-purpose"
isolation: "worktree"
prompt: {ASSEMBLED_PROMPT}
description: "Implement {STORY_ID}: {SHORT_TITLE}"
```

## Context Size Management

If the assembled prompt exceeds ~30k tokens (large stories with many sources), prioritize:

1. Full story object (always include)
2. Source artifacts (always include — instruct agent to read them, don't inline if too large)
3. Vestige context (include if relevant, skip if prompt is already large)
4. Standards (instruct agent to read them rather than inlining)

An instruction to read a source file is more reliable than inlining truncated content.
