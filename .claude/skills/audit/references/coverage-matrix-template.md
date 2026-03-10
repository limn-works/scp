# Coverage Matrix Template

Use this template to build cross-layer coverage matrices during audits. Fill every cell — empty cells are findings.

## Spec → Code Matrix

For each spec file, track which requirements are implemented and where.

```
| Spec Requirement | Core Rust | PyO3 Bridge | UniFFI Bridge | NAPI Bridge | WASM Bridge | Python SDK | TS SDK | Kotlin SDK | Swift SDK | Tests |
|-----------------|-----------|-------------|---------------|-------------|-------------|------------|--------|------------|-----------|-------|
| §X.Y.Z Req 1   | ✓ file:ln | ✓ file:ln   | ✓ file:ln     | ✓ file:ln   | ✓ file:ln   | ✓ file:ln  | ✓      | ✓          | ✓         | ✓     |
| §X.Y.Z Req 2   | ✓         | ✗ MISSING   | ✓             | ✗ MISSING   | N/A         | ✗          | ✗      | ✓          | ✓         | ✗     |
```

## Function Export Matrix

Track which core functions are exported through each bridge.

```
| Core Function           | Module      | PyO3 | UniFFI | NAPI | WASM | Notes |
|------------------------|-------------|------|--------|------|------|-------|
| create_context()       | context     | ✓    | ✓      | ✓    | ✓    |       |
| validate_capability()  | governance  | ✓    | ✗      | ✗    | N/A  | Gap   |
```

## SDK Wrapper Matrix

Track which bridge functions have SDK wrappers.

```
| Bridge Function     | Python SDK | TS SDK | Kotlin SDK | Swift SDK | Notes |
|--------------------|------------|--------|------------|-----------|-------|
| ffi_create_context | ✓          | ✓      | ✓          | ✓         |       |
| ffi_validate_cap   | ✗ MISSING  | ✗      | ✓          | ✓         | Gap   |
```

## PRD Story Verification Matrix

For each done story, track AC completion.

```
| Story ID | Title              | AC Count | ACs Met | ACs Unmet | Status  | Verified |
|----------|--------------------|----------|---------|-----------|---------|----------|
| SCP-001  | Create context     | 5        | 5       | 0         | done    | ✓        |
| SCP-042  | Trust validation   | 7        | 5       | 2         | done    | ✗ FALSE  |
```

## How to Fill the Matrix

### Step 1: List All Items

1. Parse spec files for requirement statements (MUST, SHALL, REQUIRED)
2. List all `pub fn` / `pub async fn` in core crates
3. List all exported functions per bridge
4. List all SDK wrapper functions
5. List all PRD stories with status

### Step 2: Cross-Reference

For each item in the left column, search for its counterpart in each layer column. Use:
- `semantic_identifier_search` for function names
- `grep` for string patterns
- `get_file_skeleton` for module structure
- Direct file reads for implementation verification

### Step 3: Mark Cells

- `✓` — implemented and verified (include file:line reference)
- `✗` — missing (this is a finding)
- `N/A` — not applicable (e.g., WASM can't do certain operations per ADR-034)
- `~` — partial implementation (this is a finding)
- `?` — could not determine (needs investigation)

### Step 4: Extract Findings

Every `✗`, `~`, or `?` cell is a potential finding. Investigate and validate each one.

## Matrix Storage

Save completed matrices to `.claude/agent-memory/audit/matrix.md` for cross-session continuity. Update the matrix as findings are validated or resolved.
