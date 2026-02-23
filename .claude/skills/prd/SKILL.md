---
name: prd
description: Generate a structured PRD from spec files, planning docs, or design sketches. Decomposes documents into atomic stories grouped into prioritized gates with dependency tracking.
argument-hint: "<files...> [--append] [--prefix PREFIX] [--max N]"
disable-model-invocation: true
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /prd

Generate a structured PRD (`.loom/prd.json`) from specification documents, planning sessions, design sketches, or any other input files.

## Arguments

Parse `$ARGUMENTS` for:

- **File paths**: one or more files to ingest (required unless `--append` with no files)
- **`--append`**: add stories to an existing PRD instead of replacing it
- **`--prefix PREFIX`**: story ID prefix (default: project directory name, uppercased, truncated to 5 chars)
- **`--max N`**: maximum number of stories to generate (default: no limit)

If `$ARGUMENTS` is empty or `help`, show usage and exit.

## Procedure

### Step 1: Read inputs

1. Read each specified file using the Read tool. If a path is a glob (contains `*`), expand it with Glob first.
2. If `--append` is set and `.loom/prd.json` exists, read it to understand existing stories (avoid duplicating work, continue ID numbering).
3. Read any existing codebase files that help contextualize the spec (look for `src/`, `lib/`, `package.json`, `Cargo.toml`, etc. — keep it lightweight, just enough to understand the tech stack and existing structure).

### Step 2: Decompose into PRD

Analyze the input documents and generate a complete PRD. The output is a single JSON object written to `.loom/prd.json`.

#### Schema

```json
{
  "project": "project-name",
  "description": "One-line project description.",
  "gates": [
    {
      "id": "gate-1",
      "name": "Human-readable gate name",
      "priority": "P0",
      "status": "pending",
      "stories": ["PREFIX-001", "PREFIX-002"]
    }
  ],
  "stories": [
    {
      "id": "PREFIX-001",
      "title": "Short imperative title",
      "gate": "gate-1",
      "priority": "P0",
      "severity": "critical",
      "status": "pending",
      "files": ["src/path/to/file.ts"],
      "description": "What this story accomplishes and why. Context for the implementer.",
      "acceptanceCriteria": [
        "Concrete, testable assertion 1",
        "Concrete, testable assertion 2"
      ],
      "actionItems": [
        "Specific implementation step 1",
        "Specific implementation step 2"
      ],
      "blockedBy": [],
      "details": {
        "protocolSection": "§2.3",
        "designUrl": "https://figma.com/..."
      }
    }
  ]
}
```

**Required fields** on every story: `id`, `title`, `gate`, `priority`, `severity`, `status`, `files`, `description`, `acceptanceCriteria`, `actionItems`, `blockedBy`, `details`.

- `severity`: `"critical"` | `"major"` | `"minor"` — used for prioritization within a gate
- `actionItems`: concrete implementation steps (what to do), complementing `acceptanceCriteria` (what to verify)
- `details`: object for arbitrary project-specific metadata. Always present (use `{}` when empty). Common keys: `protocolSection`, `designUrl`, `apiEndpoints`, `migrationSteps`, `currentBehavior`, `targetBehavior`, etc.

#### Generation rules

1. **Atomic stories** — each story must be completable by a single Claude Code subagent in one Loom iteration (~15-30 minutes of focused work). If a piece of work would take longer, split it.

2. **ID format** — `PREFIX-NNN` with zero-padded 3-digit numbers. Start at 001 (or continue from the highest existing ID if appending).

3. **Gates** — group stories into logical phases or categories. Each gate has a priority:
   - **P0**: Must be done first. Blocking, security-critical, or foundational.
   - **P1**: Important. Core functionality, significant features.
   - **P2**: Nice to have. Polish, cleanup, optimization.
   Order gates by priority, then by logical dependency.

4. **Dependencies** — set `blockedBy` arrays accurately. A story should only list IDs it truly cannot start without. Loom uses this to maximize parallelism — overly conservative dependencies serialize work unnecessarily.

5. **Files** — predict which files each story will create or modify. Use the existing codebase structure as a guide. This helps Loom's subagents find the right context quickly.

6. **Acceptance criteria** — concrete, testable assertions. Not "the feature works" but "POST /auth/login returns a 200 with a JWT when credentials are valid" or "the function returns an empty array when given no input". Each criterion should be verifiable by a test or manual check.

7. **No over-decomposition** — keep naturally coupled work together. Creating a model, its migration, and its route handler is one story, not three. A function and its unit tests belong in the same story.

8. **Critical path first** — arrange gates and story IDs so the critical path (longest dependency chain) uses the lowest numbers. This helps Loom prioritize correctly.

9. **Description richness** — the description should give the implementer enough context to work autonomously. Include relevant spec references, design decisions, constraints, and gotchas.

### Step 3: Write output

1. If `--append`:
   - Read the existing PRD
   - Merge new gates (add new ones, don't duplicate existing)
   - Append new stories (don't modify existing stories)
   - Write the merged result
2. Otherwise:
   - Write the complete PRD to `.loom/prd.json`

3. Validate the output:
   ```bash
   jq '.' .loom/prd.json > /dev/null
   ```

### Step 4: Report

Show a summary:

```
PRD generated: .loom/prd.json

  Stories:  47
  Gates:    6 (3×P0, 2×P1, 1×P2)
  Blocked:  12 stories have dependencies
  Root:     18 stories can start immediately

  Gate breakdown:
    gate-1  Core Infrastructure     P0  12 stories
    gate-2  Identity & Auth         P0   8 stories
    gate-3  Transport Layer         P0   7 stories
    gate-4  Context Management      P1   9 stories
    gate-5  Agent Framework         P1   6 stories
    gate-6  Polish & Documentation  P2   5 stories
```

If the story count exceeds `--max`, note which stories were omitted and suggest running `/prd --append` with the remaining scope.
