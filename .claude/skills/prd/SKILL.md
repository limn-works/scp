---
name: prd
description: Generate a structured PRD from spec files, planning docs, or design sketches. Decomposes documents into atomic stories grouped into prioritized gates with dependency tracking.
argument-hint: "<files...> [append] [prefix PREFIX] [max N]"
disable-model-invocation: true
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /prd

Generate a structured PRD (`.loom/prd.json`) from specification documents, planning sessions, design sketches, or any other input files.

## Arguments

Parse `$ARGUMENTS` for:

- **File paths**: one or more files to ingest (required unless `append` with no files)
- **`append`**: add stories to an existing PRD instead of replacing it
- **`prefix PREFIX`**: story ID prefix (default: project directory name, uppercased, truncated to 5 chars)
- **`max N`**: maximum number of stories to generate (default: no limit)

If `$ARGUMENTS` is empty or `help`, show usage and exit.

## Procedure

### Step 1: Read inputs

1. Read each specified file using the Read tool. If a path is a glob (contains `*`), expand it with Glob first.
2. If `append` is set and `.loom/prd.json` exists, read it to understand existing stories (avoid duplicating work, continue ID numbering).
3. Read any existing codebase files that help contextualize the spec (look for `src/`, `lib/`, `package.json`, `Cargo.toml`, etc. — keep it lightweight, just enough to understand the tech stack and existing structure).
4. **Preserve source contents verbatim.** For every source file read, retain the full text in working memory. You will copy relevant sections directly into story descriptions — do not paraphrase or summarize unless the original text is ambiguous. The source document is the specification; the PRD is a structured decomposition of it, not a rewrite.
5. Break excessively large files down into windows and assign to subagents, to avoid hitting token limits for your context window (~150k) or agent return windows (32k).

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
      "acceptanceCriteria": ["Concrete, testable assertion 1", "Concrete, testable assertion 2"],
      "actionItems": ["Specific implementation step 1", "Specific implementation step 2"],
      "blockedBy": [],
      "sources": [
        "specs/auth-design.md",
        { "file": "specs/api-spec.md", "section": "## Login Endpoint" }
      ],
      "details": {
        "protocolSection": "§2.3",
        "designUrl": "https://figma.com/...",
        "potentialPitfalls": "Ambiguous return types..."
      }
    }
  ]
}
```

**Required fields** on every story: `id`, `title`, `gate`, `priority`, `severity`, `status`, `files`, `description`, `acceptanceCriteria`, `actionItems`, `blockedBy`, `sources`, `details`.

- `severity`: `"critical"` | `"major"` | `"minor"` — used for prioritization within a gate
- `actionItems`: concrete implementation steps (what to do), complementing `acceptanceCriteria` (what to verify)
- `sources`: array of backlinks to the source documents this story was derived from. Each entry is either:
  - A string file path: `"specs/auth-design.md"` (the whole file is relevant)
  - An object with a section pointer: `{ "file": "specs/api-spec.md", "section": "## Login Endpoint" }`
  - If no external source exists (e.g. the story was inferred from codebase context), use `[]`.
- `details`: object for arbitrary project-specific metadata. Always present (use `{}` when empty). Common keys: `protocolSection`, `designUrl`, `apiEndpoints`, `migrationSteps`, `currentBehavior`, `targetBehavior`, etc. Also used for verbatim source subsections — see "Source preservation" below.

#### Generation rules

1. **Atomic stories** — each story must be completable by a single Claude Code subagent in one Loom iteration (~15-30 minutes of focused work). If a piece of work would take longer, split it and make a blocking sequence.
2. **ID format** — `PREFIX-NNN` with zero-padded 3-digit numbers. Start at 001 (or continue from the highest existing ID if appending).
3. **Gates** — group stories into logical phases or categories. Each gate has a priority:
   - **P0**: Must be done first. Blocking, security-critical, or foundational.
   - **P1**: Important. Core functionality, significant features.
   - **P2**: Polish, cleanup, optimization.
     Order gates by priority, then by logical dependency.
4. **Dependencies** — set `blockedBy` arrays accurately. A story should only list IDs it truly cannot start without. Loom uses this to maximize parallelism — overly conservative dependencies serialize work unnecessarily.
5. **Files** — predict which files each story will create or modify. Use the existing codebase structure as a guide. This helps Loom's subagents find the right context quickly.
6. **Acceptance criteria** — concrete, testable assertions derived directly from the source text. Not "the feature works" but "POST /auth/login returns a 200 with a JWT when credentials are valid" or "the function returns an empty array when given no input". Each criterion should be verifiable by a test or manual check. Every constraint, edge case, or behavioral requirement mentioned in the source must have a corresponding acceptance criterion — do not drop details during decomposition.
7. **No over-decomposition** — keep naturally coupled work together. Creating a model, its migration, and its route handler is one story, not three. A function and its unit tests belong in the same story.
8. **Critical path first** — arrange gates and story IDs so the critical path (longest dependency chain) uses the lowest numbers. This helps Loom prioritize correctly.
9. **Description richness** — the description should give the implementer enough context to work autonomously. Include relevant spec references, design decisions, constraints, and gotchas.
10. **Source preservation** — the implementer might never read the source document, and they should not have to. The story must be self-contained by copying source content directly into the story's structural fields. Follow these rules:
    - **`description`**: copy and paste the core source content that defines what this story is about. Use the source's own language — do not paraphrase.
    - **`acceptanceCriteria`**: every structured requirement, constraint, test case, or gate condition from the source becomes a 1:1 array entry. Do not merge multiple source requirements into one criterion.
    - **`actionItems`**: every implementation step, migration step, or ordered procedure from the source becomes a 1:1 array entry.
    - **`details`**: source subsections that don't map to a top-level key get copied as `{ "sectionName": "section content" }` entries. Use the source's section heading as the key.
    - When in doubt about where source content belongs, put it in `details` under a descriptive key rather than dropping it. Preserve lists exactly by converting them to arrays.
11. **Source backlinks** — every story derived from a source document must include at least one entry in `sources`. This creates a traceable chain from spec to implementation. If a story spans multiple source files or sections, include all of them.

#### Source preservation examples

**Example 1: Source paragraph → `description`**

Source file `specs/auth.md`, section `## Session Tokens`:
```
Session tokens are JWTs signed with RS256. They expire after 15 minutes
and must be refreshed using a separate refresh token endpoint. The refresh
token has a 7-day sliding window expiry. Tokens must include the user's
account ID, role, and tenant ID in the payload.
```

Story `description`:
```
"description": "Session tokens are JWTs signed with RS256. They expire after 15 minutes and must be refreshed using a separate refresh token endpoint. The refresh token has a 7-day sliding window expiry. Tokens must include the user's account ID, role, and tenant ID in the payload."
```

**Example 2: Source requirements list → `acceptanceCriteria` 1:1**

Source file `specs/auth.md`, section `## Validation Rules`:
```
- Passwords must be at least 12 characters
- Passwords must contain at least one uppercase, one lowercase, and one digit
- Passwords must not appear in the HIBP breached passwords database
- Failed login attempts are rate-limited to 5 per 10-minute window per IP
```

Story `acceptanceCriteria`:
```json
[
  "Passwords must be at least 12 characters",
  "Passwords must contain at least one uppercase, one lowercase, and one digit",
  "Passwords must not appear in the HIBP breached passwords database",
  "Failed login attempts are rate-limited to 5 per 10-minute window per IP"
]
```

**Example 3: Source subsections → `details`**

Source file `specs/api.md` contains:
```
## Rate Limiting
Requests are limited to 100/minute per API key. Burst allowance is 20
requests above the limit within a 5-second window. Exceeded requests
receive 429 with a Retry-After header.

## Error Format
All errors return JSON: { "error": { "code": "string", "message": "string", "details": {} } }
The `code` field uses UPPER_SNAKE_CASE identifiers. The `details` object is optional.
```

Story `details`:
```json
{
  "rateLimiting": "Requests are limited to 100/minute per API key. Burst allowance is 20 requests above the limit within a 5-second window. Exceeded requests receive 429 with a Retry-After header.",
  "errorFormat": "All errors return JSON: { \"error\": { \"code\": \"string\", \"message\": \"string\", \"details\": {} } }. The `code` field uses UPPER_SNAKE_CASE identifiers. The `details` object is optional."
}
```

**Example 4: Mixed source → distributed across fields**

Source file `specs/onboarding.md`, section `## Welcome Screen`:
```
The welcome screen displays the app logo, a tagline ("Your wallet, your keys"),
and two buttons: "Create Wallet" and "Import Wallet".

Requirements:
- Logo must be the SVG version at assets/logo.svg, rendered at 64x64
- Tagline uses the `heading2` text style from the design system
- "Create Wallet" is the primary CTA (filled button)
- "Import Wallet" is secondary (outline button)
- Screen must be accessible: all interactive elements need aria-labels
- Screen must support dark mode via the theme context

The screen animates in with a 300ms fade. The logo has a subtle
0.5s scale-up animation on first render.
```

Story fields:
```json
{
  "description": "The welcome screen displays the app logo, a tagline (\"Your wallet, your keys\"), and two buttons: \"Create Wallet\" and \"Import Wallet\".",
  "acceptanceCriteria": [
    "Logo must be the SVG version at assets/logo.svg, rendered at 64x64",
    "Tagline uses the heading2 text style from the design system",
    "\"Create Wallet\" is the primary CTA (filled button)",
    "\"Import Wallet\" is secondary (outline button)",
    "Screen must be accessible: all interactive elements need aria-labels",
    "Screen must support dark mode via the theme context"
  ],
  "details": {
    "animations": "The screen animates in with a 300ms fade. The logo has a subtle 0.5s scale-up animation on first render."
  },
  "sources": [
    { "file": "specs/onboarding.md", "section": "## Welcome Screen" }
  ]
}
```

### Step 3: Verify decomposition against sources

Before writing the PRD, perform a static verification pass to ensure nothing was lost in decomposition:

1. **Coverage check** — for each source file, walk through every section, paragraph, and requirement. Verify that each one maps to at least one story field (`description`, `acceptanceCriteria`, `actionItems`, or `details`). If a source requirement has no corresponding story, either add a story or add it to an existing story's criteria.

2. **Verbatim check** — for each story with `sources`, re-read the referenced source file and section. Confirm that the story's `description` uses the source's own language (not a paraphrase), that `acceptanceCriteria` entries map 1:1 to source requirements (not merged or summarized), and that source subsections appear in `details` under descriptive keys. If any content was paraphrased or condensed, replace it with the original text.

3. **Nuance check** — look for conditional language in the source ("unless", "except when", "only if", "must not") and verify these constraints appear as explicit acceptance criteria. Nuances and edge cases are the most common casualties of decomposition.

4. **Completeness check** — verify that the total set of acceptance criteria across all stories fully covers the source specification. No source requirement should be represented only in a `description` or `details` field — if it is testable, it must also appear as an acceptance criterion.

If any gaps are found, fix them before proceeding.

### Step 4: Write output

1. If `append`:
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

### Step 5: Report

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

If the story count exceeds `max`, note which stories were omitted and suggest running `/prd append` with the remaining scope.
