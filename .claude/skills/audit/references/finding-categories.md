# Finding Categories

Detailed taxonomy of finding types for staged codebase audits.

## 1. Wiring Gaps

Implementations that exist but are not connected to their consumers.

### Rust Core → FFI Bridge

A public function in `scp-core` that has no corresponding export in any FFI bridge (`crates/scp-ffi/`).

**How to detect:**
1. List all `pub fn` / `pub async fn` in `scp-core` modules
2. For each, search for calls in `crates/scp-ffi/src/` (PyO3), `crates/scp-ffi/uniffi/` (UniFFI), `crates/scp-ffi/napi/` (NAPI), `crates/scp-ffi/wasm/` (WASM)
3. Missing from ALL bridges = wiring gap

**Example finding:**
```
scp-core::context::roles::validate_capability_ceiling() is pub but not exported
through any FFI bridge. The function exists and works but is inaccessible to SDKs.
```

### FFI Bridge → SDK Wrapper

An FFI bridge function that has no corresponding wrapper in the language SDK.

**How to detect:**
1. List all exported functions per bridge
2. For each, search the corresponding `bindings/` directory
3. Missing from SDK = wiring gap

### Adapter Not Registered

A trait implementation that exists but is never registered with the runtime or provider.

**How to detect:**
1. Find all `impl SomeTrait for SomeStruct` patterns
2. Check if the struct is ever instantiated and passed to a constructor/builder
3. Not used = dead adapter

## 2. Incomplete Story Implementations

Stories marked `done` in PRDs where acceptance criteria are not fully met in code.

**How to detect:**
1. Parse PRD JSON for stories with `"status": "done"`
2. For each story, read every file in `files` array
3. Check each acceptance criterion against actual code behavior
4. Any unmet criterion = falsely marked done

**Common patterns:**
- Function exists but returns placeholder/default values
- Test file exists but tests are `#[ignore]`d
- Code compiles but logic is incomplete (e.g., always returns `Ok(())`)
- One variant of an enum handled, others silently dropped

## 3. Missing Acceptance Criteria

Spec requirements that have no corresponding acceptance criterion in any PRD story.

**How to detect:**
1. Extract MUST/SHALL/REQUIRED statements from specs
2. Search all PRD stories' `acceptanceCriteria` arrays
3. Unmatched requirements = coverage gap

## 4. Stubs

Code that signals incompleteness.

**Markers to search for:**
- `todo!()` — Rust panic macro
- `unimplemented!()` — Rust panic macro
- `// Stub` — Convention marker
- `// TODO` — Common marker
- `// FIXME` — Common marker
- `throw new Error("not implemented")` — TypeScript
- `raise NotImplementedError` — Python
- `fatalError("not implemented")` — Swift
- `TODO()` — Kotlin

**Note:** Clippy denies `todo!()` and `unimplemented!()` in this project. Stubs that bypass this (e.g., returning empty defaults instead of panicking) are harder to detect and more dangerous.

## 5. Duplicated Code

Similar logic implemented in multiple locations.

**Common duplication sites:**
- WASM bridge reimplements core algorithms (intentional per ADR-034, but must stay in sync)
- Multiple FFI bridges have similar boilerplate
- Test utilities duplicated across test files
- Error mapping logic repeated per module

**How to detect:**
1. Read related modules side by side
2. Look for functions with similar structure/logic
3. Check if extraction into a shared utility is warranted

## 6. Security Issues

**Priority categories:**
- **Input validation gaps**: Data crossing trust boundaries without validation
- **Error information leakage**: Internal errors exposed to callers with too much detail
- **Cryptographic misuse**: Wrong algorithm, insufficient key size, predictable nonces
- **Access control bypass**: Operations permitted without proper capability checks
- **Silent error swallowing**: `let _ = result` on security-critical operations

**How to detect:**
1. Trace all data entry points (FFI boundaries, network, file I/O)
2. Check for validation at each boundary
3. Review error handling for information leakage
4. Audit all `unsafe` blocks
5. Check crypto operations against spec requirements

## 7. Bugs

**Common bug patterns in this codebase:**
- `let _ = Result` — silently swallowing errors (the #1 recurring defect)
- Off-by-one in bounded collections
- Race conditions in concurrent code (check Mutex usage patterns)
- Integer overflow in size calculations
- Missing null/empty checks on deserialized data
- Stale enum match arms after new variants are added

## 8. Performance Optimizations

**What to look for:**
- `String` parameters where `&str` or `Cow<'_, str>` suffices
- Unnecessary `.clone()` calls
- Repeated serialization/deserialization
- `Vec` allocations in hot paths where iterators suffice
- Missing `#[inline]` on small, frequently-called functions
- `format!()` for simple string building

## 9. Dead Code

**Types:**
- Functions with `#[allow(dead_code)]` — explicitly suppressed warnings
- `pub` functions with zero callers outside their module
- Modules declared in `mod.rs` but never used
- Feature-gated code where the feature is never enabled
- Test utilities that no test calls

**How to detect:**
1. Search for `#[allow(dead_code)]`
2. For `pub` functions, search for callers across the entire workspace
3. Check `pub mod` declarations vs actual usage
4. Review Cargo.toml features vs code usage

## 10. Spec Drift

Code that was correct when written but the spec has since changed, or code that never matched the spec.

**How to detect:**
1. Read spec section
2. Read corresponding code
3. Compare semantics, not just structure
4. Check git blame for spec changes after code was written

**Common spec drift patterns:**
- Enum variants in code don't match spec's defined set
- Field names differ between spec and implementation
- Validation rules in code are looser than spec requires
- Default values differ from spec defaults
