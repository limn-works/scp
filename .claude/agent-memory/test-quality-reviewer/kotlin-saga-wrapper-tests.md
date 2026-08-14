# Kotlin §6.2.4 Saga Wrapper Tests (ToolSagaTest.kt)

PR-6c slice 4/4: SDK wrapper for tool_invoke_cross_context_saga. 9 tests.

## Load-bearing analysis (reusable patterns)
- **`lastSagaArgs` positional-forwarding assert IS load-bearing.** Stub records all 9 args into a `List<String>` in order BEFORE throwing; bridge forwards positionally; test passes all-distinct values (1L/2L/distinct strings). Any same-typed swap (handles 1↔2) or reorder is caught; dropped param impossible (fixed interface arity). This is the highest-ROI test in such wrapper suites — replicate it.
- **Typed-error construction tests (`ScpException.Saga*(...)` + field asserts) are contract-pins, NOT vacuous codegen re-test** — acceptable because Kotlin SDK surfaces generated UniFFI types DIRECTLY (no remap layer). Same precedent as CustodyType.rawValue. The `null retryAfterMs` variant is highest-value (pins null≠0 semantic).
- **e2e catch `e.message!!.contains("code=")` is non-vacuous**: every generated `ScpException.Saga*` `message` getter emits `"msg=…, code=…, …"`. Pins a TYPED exception (not generic RuntimeException/NPE) reached the catch. But CANNOT prove per-argument positional fidelity (a non-saga Validation/Permission rejection also satisfies it) — test self-documents this and defers positional assurance to Rust/integration. Honest scoping.

## Coverage gap (minor)
- No positive assert that null `ucanProofId` forwards via `lastSagaArgs`. Stub records `ucanProofId.toString()` → literal "null" (mildly ambiguous).

## Environmental gotcha — Kotlin SDK gradle test build
- `./gradlew :scp-kt:test` runs `generateUniffiBindings` → `scripts/generate-uniffi-kotlin.sh` which compiles the **MAIN checkout's** Rust crates (absolute path /Users/alec/Developer/limn/scp/crates/...), NOT the worktree's. If the main checkout has uncommitted WIP Rust that doesn't compile, cdylib regeneration fails and blocks ALL Kotlin SDK tests — even in an isolated worktree whose own crates are clean.
- `-x generateUniffiBindings` does NOT work around it: the generated `internal/` dir is only registered as a Kotlin source set when the task runs, so compileKotlin then fails with unresolved UniFFI references (petname*, sqlite*, etc.).
- Stale incremental target/ can spuriously report `no method named remove_member found for ContextRoleState` — a direct `cargo build -p scp-runtime` in the worktree clears/rebuilds clean. Don't attribute such errors to the PR.
