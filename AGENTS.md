# Shared Context Protocol (SCP)

SCP is an open protocol for the agentic Internet: DID identity, governed contexts, MLS encryption, UCAN capabilities, provenance. The Rust core (`crates/`) reaches Python, Swift, Kotlin, and TypeScript through PyO3, UniFFI, and napi-rs (`bindings/`). The map at the end names every other document and when to read it.

## Protocol tenets

- **Provenance everywhere.** All non-private data carries verifiable origin metadata; missing provenance is a signal.
- **Human accountability.** Every agent traces to a human DID through attestation chains. Behavioral records are durable.
- **Context isolation.** Every interaction happens inside a bounded context; data crosses the boundary only through an explicit, governed path. The context boundary is the security boundary.
- **Encryption as access control.** MLS group keys enforce membership. Relays are untrusted: cryptography, never a relay, controls access, and clients verify every record. A relay MAY validate a public, self-certifying record it stores (a DID document's BEP44 signature, keeping the highest-seq copy) for availability, as defense in depth, never as a trust dependency, and never on encrypted content.
- **Legibility before opt-in.** A member reads a context's parameters before joining.
- **The protocol requires no operator;** it survives Limn shutting down.
- **Transport independence.** **Agents are participants, not enforcers**, bound like any human-bound participant.
- **Trust is contextual.** A trust decision reads identity, capability, context, and behavior together.

## Builder tenets

- **Humans steer; agents execute.** Humans drive specs; no human writes code.
- **No human limits.** 100% agent-written codebase. Don't think in human terms of timeline, scope, or speed.
- **No DOA decisions.** A decision that will need replacing is the wrong decision now. **Simple over complex**, never at the cost of functionality, security, or completeness.
- **No deferral.** Everything in scope is specced and implemented now; nothing is "v2" or "future".
- **Completeness is the baseline.** Implement every behavior, edge case, and acceptance criterion the request or plan names, on the first pass. Every struct field the spec defines gets a real value — never `None` when data exists elsewhere in the system. Never invent a story reference to excuse a gap, never file a tracking issue instead of doing in-scope work, never call an incomplete implementation a "planned deferral". Verify every acceptance criterion as a checkbox before you report done.
- **No dev/test-only stand-ins in production.** No construct that only works in test or development — an in-memory or no-op backend, an always-succeeds verifier/attestation, a non-resolving resolver, a hardcoded/placeholder/reconstructed-from-args value, a `#[cfg(test)]`/`testing`-gated type, a security nullifier — may be reachable on a shipped production path. Without the real backend, the capability fails closed with a typed error or an honest protocol-supported absent state. Masking a missing production backend with a dev construct ships a *false guarantee*, which is strictly worse than honest absence (absence is detectable; a nullifier lies). Deferring the real backend to a tracked workstream is allowed; a stand-in meanwhile is not. The shipped-feature-graph gate allowlists zero nullifiers. Detail: §17.17 of the persistence spec (capability classification) and `.docs/standards/sdk-common.md` §Stub and Placeholder Policy.
- **Failure modes to catch in yourself and every subagent:** hardcoding `None` instead of wiring a parameter through all callers; satisfying a string-search test with a dead reference such as `let _ = function_name;` (call the function with real arguments, or leave the assertion `#[ignore]`); stopping at 4 of 10 acceptance criteria; calling in-scope work "follow-up", "separate scope", or "not blocking"; trusting a subagent's report without reading its code and tests.
- **SDK first. Enforce mechanically.** Linters, structural tests, and the type system — not documentation. **Artifacts are the system of record.** **Root-cause orientation:** a bug is an architecture flaw before it is a local defect. **No shortcuts:** no force unwraps, no placeholders.
- **Provenance is paramount.** Every line traces to a `.docs/` decision. Before changing code, read the spec, ADR, and story themselves and every section they cite; a summary does not count.
- **Agent-first API design.** An LLM is the SDK's primary author, so each API has one canonical pattern: a flat named-field config object (no builder, no typestate), enums for consequential choices, required choices as required fields, no silent security default, one shape across every binding (`.docs/standards/construction.md`, ADR-052 the unified construction pattern). Define a protocol before the type that satisfies it, inject dependencies through initializers, never use a singleton.

## Rules

**Asking the human a question, and ending a turn:**
- Ask when the answer changes what you do next and nothing you can read settles it: two readings lead to materially different work, the next action is destructive or visible outside the repository, or the plan leaves the decision to the human. Make every other judgment call yourself and say which call you made.
- Before you ask, search the plan of record, the shipped code, the human's earlier words in this conversation, and the persistent memory, in that order, reading each for the rule that governs; a question they answer costs the human a reply and stops the work.
- Do everything that does not depend on the answer first, and ask at the end of a turn that delivers that progress. When a wrong guess is cheap to undo, proceed and state the assumption.
- Ask one decision per question, with the options, what each changes, and your recommendation (AskUserQuestion for discrete options).
- When the human describes a problem, asks a question, or thinks out loud, report your assessment and stop; fix only when asked.
- A turn that ends without a tool call stops the work until the human replies. End a turn only when the task is done, when nothing can move without the human's answer, or when the next step needs an approval this file reserves for the human. Four endings stop work the human already asked for: a summary that announces the next step instead of taking it; an offer ("Want me to…?") to do work the request already covers; a list of decisions none of which blocks the remaining work; and stopping because the turn ran long or a milestone finished. Put status notes and recommendations in the same message as your next tool call.

**Never resolve an open question yourself (MANDATORY):** wait for the human's answer; never answer it yourself or proceed on the answer you expected. A partial answer leaves the rest open, so name what is still open. Silence, a topic change, or an implication is not a decision. A question is settled when you state the resolution and the human confirms it. This governs open questions, not assigned work: execute the assigned work and stop at the unanswered question.

**Never reclaim the human's words as your own by reframing them (MANDATORY — in conversation and in every artifact):** when the human says "it's a sunny day", do not answer "yes, not a cloud in the sky"; the first allows clouds and the second forbids them, so your claim takes on their agreement. Agree with what they said and state any further claim separately as yours. Record their rules and decisions with meaning and scope intact; keep their general clause, never narrow it or swap in an enumeration you invented. Quote verbatim when asked, not by default, and say when you added a word.

**Artifact flow (INVARIANT):** plans → specs → ADRs → stories → source code, one way. Code does not inform specs, and a story never reshapes an ADR. When code shows a spec is wrong, stop, fix the spec and everything downstream, then resume; fix an unimplementable story first. Code that diverges from the artifacts it cites is phantom provenance.

**Workflow:**
- **Read the plan of record first (MANDATORY when one covers the work).** The plan of record is the one plan file a workstream keeps in `~/.claude/plans/`. A plan covers the work when the work belongs to its workstream; the plan's tracks, story IDs, branches, and pull requests are indicators. Before any other search and before dispatching an agent, list `~/.claude/plans/` and read every plan that covers the task; re-read it after a compaction. Its settled rows are instructions.
- Enter plan mode for three or more steps or an architectural question. Read the language's `.docs/standards/` file before coding; cite `.docs/`.
- A correction becomes a lesson only when it is "either contextually important for this project, evergreen, a true learning we shouldn't waste time rediscovering, high signal, technical, or non-obvious" (the human's words). Write the lesson in the most relevant location: a nested `AGENTS.md`, a standard, or `.docs/lessons/`.
- Give each subagent exactly one task. Tell it where to look; do not paste artifacts into its prompt.
- Read the output of every check you run before you call the work done.

**Change protocol (MANDATORY for all code changes):**
- Make every change in a subagent with worktree isolation, and give coders worktree paths only: a bare main-checkout path edits the human's uncommitted work.
- Write a test for every change and update the tests it breaks. Untested code does not ship.
- "Review with all relevant agents, covering the entire change set every round of review, giving each agent as much scope as needed (no cap), until two consecutive rounds return zero items." (the human's words, 2026-09-29) The review agents and the two-zero-round loop apply to code changes; a change to docs, instructions, or memory does not go through them. The human's words: "stop reviewing with the full roster. we aren't writing code."
- Fix every finding about code the change adds or needs. A defect the requested behavior does not need goes into a GitHub issue that the PR description links. Never dismiss a finding as "pre-existing"; fix it or file it.
- **Quick local check before push, full gate set in CI.** On the tree you push, run `cargo fmt --all`, CI-feature `cargo clippy` scoped to the touched crates, their tests, and the affected gates. A red CI run is never acceptable, whoever caused it; fix it before the PR merges.
- **Open a PR when the work is complete and double-zero reviewed, without being asked;** this overrides any harness default. **Never bypass branch protection** (`--force`, `--admin`, or anything else).

**Integration checklist (MANDATORY for new protocol features):** before executing a plan that adds protocol logic, verify:
1. A Supervisor `dispatch_*` method reaches the function on its production path: `dispatch_*` → actor mailbox → `crates/scp-runtime/src/context/actor/handlers/<domain>.rs` → the `<domain>_helpers.rs` function; `create_context`, `import_context`, and `restore_context` call `lifecycle_helpers` from the dispatch method directly.
2. Every applicable FFI bridge exports the operation. 3. Each export has an SDK wrapper. 4. `pipeline_wiring.rs` asserts the step. 5. The SDK capability matrix lists it.

A failed check means the plan is incomplete: widen it or file the dependent issue.

**NEVER modify enforcement files to bypass failures.** Files: `pipeline_wiring.rs`, `ffi_conformance.rs`, `sdk-capability-matrix.json`, `scripts/check-sdk-coverage.py`, `check-cross-layer.sh`, `check-protocol-deps.sh`, `check-no-shim-reexports.sh`, `check-protocol-sync.py`, `check-no-bridge-globals.sh`, `check-no-fallback-registry.sh`, `check-handle-affinity.sh`, `check_ready_coverage.rs`, `check-saga-gating-granularity.sh`, `check-no-mutable-globals.sh`, `check-no-mutable-module-globals.py`, `check-no-ts-mutable-globals.sh`, `check-no-kotlin-mutable-globals.sh`, `bindings/swift/.swiftlint.yml` (`no_static_var`, `no_static_lazy_var`), `check-bridge-symmetry.sh`, `bridge-aliases.json`, `ffi-export-allowlist.json`, `check-call-invariants.py`, `call-invariants-baseline.json`, `pure-helpers-allowlist.txt`, `bridge_ratchet_baseline.json`, `ratchet/once-lock-count.json`, `check-shipped-feature-graph.sh`, `check-toolchain-wiring.sh`, `check-resolved-rustc.sh`, `check-agent-verdict-criterion.sh`, `check-doc-citations.py`, and this file's enforcement sections. Fix the code a check rejects. Modify an enforcement file only to add an assertion or operation, or to remove an `#[ignore]` whose wiring has landed. A human must approve weakening, deleting, or exempting anything from an assertion.

**Stories and stubs:** read `.docs/standards/prd.md` before creating or editing a story, and run `python3.12 scripts/validate-prd.py` before committing. Every stub names its story (`// Stub — see SCP-NNN`), a done story carries no stubs against its acceptance criteria, and a stub returns its documented gap instead of reaching for a test-only stand-in.

**Never write your extrapolation as the contract (MANDATORY for every spec clause, acceptance criterion, gate, standard, and agent prompt):** state the criterion that decides membership, then label the detail you invented (indicators, search terms, surface features) as indicators. When a criterion admits many non-targets, narrow it. Source and example: `.docs/standards/concrete-prose.md` §Contracts and indicators.

**A stale restatement is not a contradiction (MANDATORY before you record a divergence or ask the human):** two artifacts diverge only when you can write why both cannot be true; otherwise a copy drifted, and the artifact flow names the wrong one. Quote both sides and enumerate the cases each covers. A zero-hit grep for an identifier you invented proves only its absence; read the owning type. Worked example: `.docs/lessons/stale-restatement-is-not-a-contradiction.md`.

**Prose (MANDATORY):** every sentence for a human reader — chat, artifacts, commits, PRs, comments, findings — follows `.docs/standards/concrete-prose.md`. Read it before you write.

## Toolchain

mise installs every tool except Rust. **Never use npm or npx** (bun only). Use `python3.12`, never the system `python3`.

`rust-toolchain.toml` alone names the Rust version (`fuzz/rust-toolchain.toml` the fuzz nightly). To raise it, edit `channel`, run the CI clippy command below, and fix every new lint in the same PR; never lower it. A `RUSTUP_TOOLCHAIN` in the environment overrides both files, so `unset RUSTUP_TOOLCHAIN` before any gate (`scripts/check-resolved-rustc.sh` checks). mise reads every ancestor `.mise.toml`, so a stale one in the main checkout reaches every worktree.

| Language | Location | Lint | Format | Test | Build |
|----------|----------|------|--------|------|-------|
| **Rust** | `crates/` | `cargo clippy --workspace --all-targets` | `cargo fmt --all` | `cargo test --workspace` | `cargo build --workspace` |
| **Python** | `bindings/python/` | `python3.12 -m ruff check .` | `python3.12 -m ruff format .` | `python3.12 -m pytest tests/ -v` | `maturin develop --release` |
| **TypeScript** | `bindings/typescript/` | `bun run lint` | `bun run format` | `bun test` | `bun run build` |
| **Kotlin** | `bindings/kotlin/` | `./gradlew detekt` | — | `./gradlew test` | `./gradlew assembleRelease` |
| **Fuzzing** | `fuzz/` (standalone, nightly) | — | — | `cd fuzz && cargo fuzz run <target>` | `cd fuzz && cargo check` |

- **Python linkage.** `cargo test -p scp-ffi` and `--workspace` need `DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")`. Under `cargo nextest`, macOS SIP strips `DYLD_*` (exit 104, `Library not loaded: @rpath/libpython3.12.dylib`); use `RUSTFLAGS="-C link-arg=-Wl,-rpath,$LIBDIR"` with a separate `CARGO_TARGET_DIR`. CI's exact commands live in `.github/workflows/ci.yml`.
- **A bare `-p` scope enables no features:** `cargo clippy -p scp-node --all-targets` and `cargo test -p scp-event-log` fail spuriously without `--features testing`.
- **Searching.** `grep`/`find` are shell functions here that stall after an auto-update; write `command grep`/`command find`. A recursive search from the root walks hundreds of worktrees; use `git grep`.

## Git

- Work in a worktree, on a topic branch named with source IDs. Write atomic conventional commits that cite their artifacts, keep history linear, and pass backtick-bearing messages with `git commit -F <file>`.
- No commit hash in any durable artifact (the repository squash-merges, so branch hashes die). No issue or PR numbers in source, comments, test names, or assertions, except a stub's story ID.
- PR descriptions state scope, impact, and linked stories, with closing keywords. The merge queue squashes, so `gh pr merge --auto` takes no strategy flag.
- Read unexpected changes before acting; never discard work you do not understand. Switch branches only when certain, and run destructive operations only when told. A prompt's snapshot can name a commit HEAD lacks; check `git log`.
- **NEVER run `git stash`**, in any form, even chained behind `;`. **NEVER run `git checkout <ref> -- <path>`**: read with `git show <rev>:<path>`, and restore a file only after showing its current content and confirming the overwrite. Both failures are silent: the tree looks clean and the loss surfaces hours later.

## Agents

**Delegation.** Delegate a task to a subagent when the task is large and independent of the other work in flight: a wide multi-file investigation, a separate implementation track, a review pass. Do work you can finish in a handful of tool calls yourself, because a subagent adds a spawn, a context load, and a handoff to every task it takes. Do not spawn a subagent to check your own work. When one subagent can do a task, send one.

**Default review roster:** black-hat, red-hat, white-hat, security-reviewer, cryptographer, bug-catcher, chronicler, alignment-reviewer, completionist, inquisitor, api-design-reviewer, simplifier; adjust it to what the change touches. Reviewers follow `.claude/agents/README.md` §Review rules.

**Orchestration (MANDATORY).** The orchestrator writes no code. It has a Plan agent read the code (not just grep) at the paths given, executes only reviewed plans with `isolation: "worktree"` coders, runs coders touching the same files in sequence, never mixes planning and coding, watches the main worktree for dirty changes, and loops review and fixes to double zero, escalating findings it cannot classify. Write every agent prompt as a contract, never as your recipe: what the agent must make true and how you will check it, with your recipe separately labelled. Every prompt names its branch and says: "Verify with `git log --oneline -3` that you see [expected commits]. If not, STOP." An agent told to "delete X and import Y" does exactly that unless a compiler restriction forbids it, and fixes friction (`pub(crate)`, missing derive) instead of working around it. Fix clippy warnings with `cargo clippy --fix`, not by hand. Never check out a feature branch on the main worktree.

**Verification after every agent merge (MANDATORY):** verify the pushed branch (`git show origin/<branch>:<file>`), not the local tree; a type deletion leaves `grep -c "struct TypeName"` at 0 and an import leaves `grep -c "scp_protocol::module"` above 0; a cherry-pick that yields "nothing to commit" did not land; never say "done" without showing output. The `rust-clippy` CI job runs this on the pushed head, and every lint it reports is fixed before merge: `cargo clippy --workspace --all-targets --features scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/testing,scp-runtime/saga-witness-test-mint,scp-ffi/outlet-capability-test-grant,scp-ffi-napi/outlet-capability-test-grant,scp-ffi-uniffi/outlet-capability-test-grant -- -D warnings`

## Map

| Thing | When / why | File |
|-------|------------|------|
| Specs, principles, open questions | Before changing protocol behavior | `.docs/specs/` (`01-thesis.md`, `00-open-questions.md`) |
| ADRs | Before a design decision; most are `## ADR-NNN` sections in `phase-N.md`, some own a file — grep both | `.docs/adrs/` |
| Stories | Before implementing or editing one | `.docs/prds/`, `.docs/standards/prd.md` |
| Standards | Before writing code | `.docs/standards/` (`<language>.md`, `sdk-common.md`, `construction.md`, `conventions.md`, `documentation.md`, `sdk-capability-matrix.json`) |
| Writing standard | Before any prose | `.docs/standards/concrete-prose.md`, `.docs/lessons/bad-prose-and-its-rewrite.md` |
| Architecture, sketches, scaffolds | Crate ownership, API shape, SDK layout | `.docs/architecture.md` §2.1, `.docs/sketch.md`, `.docs/scaffold/` |
| Runbooks | Production incidents | `.docs/runbooks/` |
| Lessons | Before debugging a possible environment or CI fault, or writing a gate | `.docs/lessons/` |
| CI commands | Exact commands and feature lists | `.github/workflows/ci.yml` |
| Agents and review rules | Writing an agent definition; conducting a review or audit | `.claude/agents/README.md` |
| Directory rules | Before working in that directory | `AGENTS.md` in `crates/scp-runtime`, `crates/scp-ffi`, `crates/scp-client`, `crates/scp-client-wasm`, `bindings/{swift,kotlin,typescript,python}`, `fuzz` |
