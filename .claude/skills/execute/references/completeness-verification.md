# Completeness Verification

This reference defines how to verify that an implementation subagent actually completed its story. Agents routinely claim completion when work remains — verification is the critical gate.

## Verification Checklist

Run every check in order. A story passes only if ALL checks pass.

### 1. Acceptance Criteria Audit

Read the story's `acceptanceCriteria` array from the PRD. For each criterion:

1. Identify what file(s) and code should satisfy it
2. Read the relevant code
3. Determine: is this criterion fully satisfied, partially satisfied, or unaddressed?

A partially satisfied criterion is a failure. "Mostly works" is not done.

Record the result for each:
```
  [PASS] "POST /api/x returns 200 with JWT" — implemented in src/routes/auth.rs:42-67
  [FAIL] "Rate limited to 5 per 10-min window" — rate limiter imported but not wired to endpoint
  [MISS] "Tokens include tenant ID" — no evidence of tenant_id in JWT claims
```

If ANY criterion is FAIL or MISS, verification fails.

### 2. Stub and Placeholder Detection

Search modified files for indicators of incomplete work:

```bash
grep -rEn "TODO|FIXME|STUB|HACK|XXX|PLACEHOLDER" <modified-files>
grep -rEn "unimplemented!|todo!|unreachable!|panic!" <modified-files>  # Rust
grep -rEn "NotImplementedError|pass  #|raise NotImplementedError" <modified-files>  # Python
grep -rEn "throw new Error.*not implemented|// stub" <modified-files>  # TypeScript
```

Any match is a verification failure unless the stub references a DIFFERENT story ID (e.g., `// Stub — see SCP-999` where SCP-999 is not the current story).

### 3. Placeholder Value Detection

Search for values that should be real but are set to defaults or None:

```bash
grep -rEn "None  #|= None|: None|null,|undefined,|\"\",|\.\.Default::default\(\)" <modified-files>
```

**Warning: this search produces many false positives** in legitimate code (`Option<T>` returns, `match` arms, TypeScript optional parameters). Evaluate each match against the story's acceptance criteria and source specs before classifying it as a gap. A `None` return from a function that genuinely has no value is correct; a `None` field that the spec says should be populated from data elsewhere in the system is a gap.

This catches the most common failure mode: agents set fields to `None` as "placeholders" when the data is available.

### 4. File Coverage Check

Compare the story's `files` array against what the agent actually modified:

```bash
git diff --name-only <agent-branch>
```

- Files in the story's list but NOT modified: possible gap (agent forgot to create/modify them)
- Files modified but NOT in the story's list: possible scope creep (agent touched files outside the story)

Investigate both. The story's file list is a prediction — it may be wrong. But unexplained gaps are verification failures.

### 5. Test Existence Check

If the story's acceptance criteria are testable (most are), verify that tests exist:

```bash
grep -rn "test.*{STORY_FUNCTION_NAME}\|describe.*{STORY_MODULE}" <test-directories>
```

If the project has a test convention and the story adds new functionality, the absence of tests is a verification failure.

When tests are found, read the test body to verify it exercises the acceptance criterion meaningfully. Trivial assertions like `assert!(true)`, empty test functions, or tests that only check the existence of a type without testing behavior do not satisfy this check.

### 6. Build and Test

Run the project's build and test commands:

```bash
# Adapt to the project's toolchain
cargo build --workspace
cargo test --workspace
```

Build failures or test failures are verification failures.

## When Verification Fails

### Relaunch Decision

If verification fails, do NOT launch a reviewer. Instead:

1. Compile a specific list of what failed:
   - Which acceptance criteria are FAIL or MISS
   - Which stubs or placeholders were found (file:line)
   - Which files are missing
   - Which tests failed

2. Launch a new implementation subagent with:
   - The original story object
   - The previous agent's branch as a starting point (so it doesn't redo completed work)
   - The explicit failure list with instructions to address each item
   - A strengthened completeness warning

3. Include in the relaunch prompt:
   ```
   The previous implementation attempt was incomplete. Address these specific gaps:

   {FAILURE_LIST}

   The original story and its acceptance criteria are the specification. Every criterion must be fully satisfied. Every placeholder and stub must be replaced with real implementation. Do not claim completion unless every item above is resolved.
   ```

### Attempt Limits

Maximum 3 implementation attempts per story. After 3 failures:

1. Mark the story as `blocked` in the PRD
2. Add a `result` field explaining what was attempted and what remains
3. Save the failure context to Vestige for future sessions
4. Move on to the next story

Do not let a single difficult story block the entire PRD execution.

## Common Failure Modes

### Mode 1: "Structural Scaffolding"

The agent creates the right file structure but leaves function bodies empty or with `todo!()`. This passes a build check but fails acceptance criteria.

**Detection**: Stub detection (check 2) catches explicit markers. For implicit stubs (empty function bodies), read each new function and verify it has real logic.

### Mode 2: "Happy Path Only"

The agent implements the main flow but skips error handling, edge cases, and conditional behavior specified in the acceptance criteria.

**Detection**: Acceptance criteria audit (check 1) catches this when criteria are specific enough. For criteria like "handles X error", verify the error path exists in code.

### Mode 3: "None Placeholder"

The agent wires most fields but sets some to `None`/`null` when the data exists elsewhere in the system. The code compiles and basic tests pass, but the spec requires those values.

**Detection**: Placeholder value detection (check 3). Cross-reference against acceptance criteria and the story's source spec sections.

### Mode 4: "Scope Avoidance"

The agent does adjacent work (refactoring, adding utilities) but avoids the hard part of the story. Progress looks real but the core requirement is unaddressed.

**Detection**: Acceptance criteria audit (check 1). Focus on the hardest/most-specific criteria first — these are the ones agents skip.

### Mode 5: "Claimed Done, Obvious Gaps"

The agent reports "all criteria met" but a quick read shows obvious omissions. This is the most common mode.

**Detection**: Always read the agent's actual output and cross-reference against criteria. Never take "done" at face value.
