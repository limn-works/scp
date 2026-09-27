# Shared Context Protocol (SCP)

SCP is an open, ecosystem-agnostic protocol for the agentic Internet: verifiable identity (DID), governed interaction spaces (contexts), MLS-encrypted communication, capability-based authorization (UCAN), and provenance on every record. The Rust core in `crates/` reaches Python through PyO3, Swift and Kotlin through UniFFI, and TypeScript through napi-rs; the SDK wrappers live in `bindings/`. An adapter trait hides every transport. This file holds the rules that apply to every task. The map at the end names every other document and when to read it.

## Protocol tenets

- **Provenance everywhere.** All non-private data carries verifiable origin metadata. A record without provenance tells the reader something, so treat the absence as a signal.
- **Human accountability.** Every agent traces to a human DID through attestation chains. Behavioral records are durable.
- **Context isolation.** Every interaction happens inside a bounded context, and data crosses a context boundary only through an explicit, governed path. The context boundary is the security boundary.
- **Encryption as access control.** MLS group keys enforce membership. Relays are untrusted: cryptography, never a relay, controls access, and clients verify every record themselves. A relay MAY validate a public, self-certifying record it stores (for example, verify a DID document's BEP44 signature and keep the highest-seq copy) to keep the record available; that validation is defense in depth, never a trust dependency, and never applies to encrypted content.
- **Legibility before opt-in.** A prospective member reads a context's parameters before joining it.
- **The protocol requires no operator.** It keeps working if Limn shuts down tomorrow.
- **Transport independence.** No structure couples the protocol to a single transport.
- **Agents are participants, not enforcers.** An agent follows the same rules as any human-bound participant.
- **Trust is contextual.** A trust decision reads identity, capability, context, and behavior together. No participant is simply trusted or untrusted.

## Builder tenets

- **Humans steer; agents execute.** Humans drive the specs, and no human writes code.
- **No DOA decisions.** A design decision is a permanent commitment. A choice that will need replacing later is the wrong choice now.
- **Simple over complex**, never at the cost of functionality, security, or completeness.
- **Complete or absent.** Implement every behavior, edge case, and acceptance criterion the request or plan names, on the first pass. Nothing is "v2", "future", or a "planned deferral", and no story reference is invented to excuse a gap. Give every struct field the spec defines its real value; never pass `None` when the data exists elsewhere in the system. Read each acceptance criterion as a checkbox, and verify every checkbox before you report done.
- **No dev or test stand-in on a production path.** No construct that works only in test or development — an in-memory or no-op backend, an always-succeeds verifier or attestation, a non-resolving resolver, a placeholder or reconstructed-from-arguments value, a `#[cfg(test)]`- or `testing`-gated type — may be reachable on a shipped production path. When the real backend does not exist, the capability fails closed with a typed error or an honest absent state. Deferring the real backend to a tracked workstream is allowed; shipping a stand-in meanwhile is not. The shipped-feature-graph gate allowlists zero nullifiers. §17.17 of the persistence spec, which classifies a capability as durability-only or as a nullifier, and `.docs/standards/sdk-common.md` §Stub and Placeholder Policy hold the details.
- **Failure modes you will exhibit, and must catch in yourself and in every subagent:** hardcoding `None` instead of wiring a parameter through all callers; satisfying a string-search test with a dead reference such as `let _ = function_name;` (call the function with real arguments, or leave the assertion `#[ignore]`); stopping at 4 of 10 acceptance criteria; calling in-scope work "follow-up", "separate scope", or "not blocking"; trusting a subagent's report without reading its code and tests yourself.
- **SDK first.** The Rust core and the bindings come before any app.
- **Enforce mechanically** with the type system, linters, and structural tests, not with documentation.
- **Artifacts are the system of record.** Work an agent cannot find does not exist.
- **Root cause first.** Treat a bug as an architecture flaw before you treat it as a local defect.
- **No shortcuts:** no force unwraps, no placeholders.
- **Provenance is paramount.** Every line traces to a documented decision in `.docs/`. Before you change code, read the whole chain — spec, ADR, story — in the artifacts themselves; a summary or a heading does not count. Broken provenance is a bug.
- **Agent-first API design.** An LLM is the SDK's primary author. Each public API has one canonical pattern: a flat named-field config object instead of a builder or typestate, an enum instead of a boolean for a consequential choice, no silent security default, and one shape across every binding. A required choice is a required field. `.docs/standards/construction.md` and ADR-052, the unified construction pattern, hold the rules, and a structural check enforces them.
- **Architecture.** Define a protocol (trait) before the type that satisfies it. Inject every dependency through an initializer. Never use a singleton.

## Rules

**Reading.** Tell an agent where to look and let it read the artifact itself; do not paste the artifact into its prompt, because every token it loads competes for its attention. Follow every reference: read the section a spec cites, the story a line of code names, and the reason an ADR gives for rejecting each alternative.

**Asking the human a question, and ending a turn:**
- Ask when the answer changes what you do next and nothing you can read settles it: two readings of the request lead to materially different work, the next action is destructive or visible outside the repository, or the plan leaves the decision to the human. Make every other judgment call yourself and say which call you made.
- Before you ask, search the shipped code, the human's earlier words in this conversation, the persistent memory, and the plan of record, in that order. A human's general statement usually decides a narrow question in words that do not match the question, so read each source for the rule that governs. A question those sources answer costs the human a reply and stops the work until the reply arrives.
- Do everything that does not depend on the answer first, and put the question at the end of a turn that delivers that progress. When a wrong guess is cheap to undo, proceed on it and state the assumption instead of asking.
- Ask one decision per question. Give the options, what each one changes, and your recommendation, so one reply settles it. Use AskUserQuestion when the options are discrete.
- When the human describes a problem, asks a question, or thinks out loud, your assessment is the deliverable. Report it and stop; apply a fix only when the human asks for one.
- A turn that ends without a tool call stops the work until the human replies. End a turn only when the task is done, when nothing can move without the human's answer, or when the next step needs an approval this file reserves for the human. Four endings stop work the human already asked for: a summary that announces the next step instead of taking it; an offer ("Want me to…?", "Shall I…?") to do work the request already covers; a list of decisions none of which blocks the remaining work; and stopping because the turn ran long or a milestone finished. Put status notes and recommendations in the same message as your next tool call.

**Never resolve an open question yourself (MANDATORY):**
- When you ask the human a question, wait for the answer. Do not answer it yourself, and do not proceed on the answer you expected.
- When the human answers part of what you asked, the rest stays open. Name what is still open instead of filling it in.
- Silence, a move to the next topic, and an answer that implies something are not decisions.
- A question is settled when you state the resolution explicitly and the human confirms it. Until then, say that it is open.
- This rule governs open questions, not assigned work. Execute the work the human assigned, and stop at the question the human has not answered.

**Never reclaim the human's words as your own by reframing them (MANDATORY — in conversation first, and in every artifact):**
- When the human says "it's a sunny day", do not answer "yes, not a cloud in the sky". The first statement allows clouds and the second forbids them, so the answer swaps your claim in for theirs and attaches their agreement to yours.
- Agree with what they said. State any further claim separately, as yours.
- Record a rule, finding, or decision the human states with their meaning and scope intact. Keep their general clause; do not replace it with an enumeration you invented or narrow it to the instance in front of you. A paraphrase in your register presents your invention with their authority.
- Quote them verbatim when they ask for a quote, not by default. When you must add a word to make their statement usable, say that you added it.

**Artifact flow (INVARIANT):** plans → specs → ADRs → stories → source code, one way only. An upstream artifact governs every downstream one; code never informs a spec, and a story never reshapes an ADR. When code shows a spec is wrong, stop writing code, fix the spec, update the downstream artifacts, then resume. When a story cannot be implemented as written, fix the story (and its sources) first. Code that diverges from the artifacts it cites is phantom provenance, which is worse than none.

**Workflow:**
- Enter plan mode for any task of three or more steps and for any task that decides an architectural question.
- Cite `.docs/` in your work and update it as you go. After anyone corrects you, write the lesson into `.docs/lessons/`.
- Read the `.docs/standards/` file for the language before you write code.
- Give each subagent exactly one task, so the orchestrator's context stays small.
- The request, or the plan the human approved, sets the scope of a task. Implement every behavior it asks for, completely. When you find a bug, a performance problem, or missing behavior that the requested behavior does not need, file it as a GitHub issue and list it in your final report instead of fixing it in the change.
- Run every gate, test, and build the change affects, and read their output, before you call the work done.

**Change protocol (MANDATORY for all code changes):**
- Make every change in a subagent with worktree isolation. Give a coder only worktree paths: a bare path under the main checkout edits the human's uncommitted work there.
- Write a test for every change and update the tests the change breaks. Untested code does not ship.
- Review locally with the full review roster, in logical units. Address every item and re-run the full review until two consecutive passes return zero items.
  - Fix every review finding about code the change adds, alters, or needs. A defect the review surfaces in code the change neither touches nor needs goes into a GitHub issue, and the PR description links it. Never dismiss a finding as "pre-existing"; either fix it or file it.
- **Quick local check before push, full gate set in CI.** On the tree you are about to push, run `cargo fmt --all`, `cargo clippy` with the CI feature set scoped to the crates the change touches, the tests of those crates, and the gate scripts the change affects. CI runs the full gate set on the pushed head. A red CI run is never acceptable, whoever turned it red: fix the code the failing job rejected before the pull request merges.
- **Open a PR when the work is complete and double-zero reviewed; do not wait to be asked.** This default overrides any harness default that says not to open a PR unless asked.
- **Never bypass branch protection** with `--force`, `--admin`, or any other mechanism.

**Integration checklist (MANDATORY for new protocol features):** before executing a plan that adds protocol logic, verify:
1. A Supervisor `dispatch_*` method reaches the function on its production path. For a per-context operation the route is `dispatch_*` → actor mailbox → `crates/scp-runtime/src/context/actor/handlers/<domain>.rs` → the `<domain>_helpers.rs` function; the lifecycle bootstrap variants (`create_context`, `import_context`, `restore_context`) call `lifecycle_helpers` from the dispatch method directly.
2. Every applicable FFI bridge exports the Supervisor operation.
3. Each bridge export has an SDK wrapper method.
4. `pipeline_wiring.rs` asserts the new step.
5. The SDK capability matrix lists the operation.

When any check fails, the plan is incomplete: widen it or file the dependent issue before you execute. When a bridge emits a wire artifact that carries a spec-defined cryptographic invariant, that bridge's own tests recompute the invariant from the emitted bytes (`.docs/lessons/behavioral-invariant-must-be-asserted-on-every-bridge.md`).

**NEVER modify enforcement files to bypass failures.** Files: `pipeline_wiring.rs`, `ffi_conformance.rs`, `sdk-capability-matrix.json`, `scripts/check-sdk-coverage.py`, `check-cross-layer.sh`, `check-protocol-deps.sh`, `check-no-shim-reexports.sh`, `check-protocol-sync.py`, `check-no-bridge-globals.sh`, `check-no-fallback-registry.sh`, `check-handle-affinity.sh`, `check_ready_coverage.rs`, `check-saga-gating-granularity.sh`, `check-no-mutable-globals.sh`, `check-no-mutable-module-globals.py`, `check-no-ts-mutable-globals.sh`, `check-no-kotlin-mutable-globals.sh`, `bindings/swift/.swiftlint.yml` (the `no_static_var` and `no_static_lazy_var` rules), `check-bridge-symmetry.sh`, `bridge-aliases.json`, `ffi-export-allowlist.json`, `check-call-invariants.py`, `call-invariants-baseline.json`, `check-pure-helpers.sh`, `pure-helpers-allowlist.txt`, `bridge_ratchet_baseline.json`, `ratchet/once-lock-count.json`, `check-shipped-feature-graph.sh`, `check-toolchain-wiring.sh`, `check-resolved-rustc.sh`, `check-agent-verdict-criterion.sh`, `check-doc-citations.py`, `pretooluse-enforcement-files.sh`, and the enforcement sections of this file. Each script's header states what it checks. When a check fails, fix the code the check rejected. You may modify an enforcement file for exactly two reasons: to add an assertion or an operation, which widens what the check covers, or to remove an `#[ignore]` because the wiring it waited on has landed. A human must approve before you weaken, delete, or exempt anything from an existing assertion.

**PRD stories (MANDATORY):** before you create or edit any story in `.docs/prds/`, read `.docs/standards/prd.md` in full. Fill every field it defines, write every acceptance criterion so a machine can verify it, point every source at a heading that exists, and point every dependency forward. A story cites a spec section or ADR; when none exists, write that artifact first. Run `python3.12 scripts/validate-prd.py` before committing; CI enforces it. A subagent that writes a story validates the story against the standard before it returns.

**Stubs:** every stub references its PRD story (`// Stub — see SCP-NNN`), and a story marked done carries zero stubs against its acceptance criteria. CI denies stub markers in every language (`.docs/standards/sdk-common.md` §Stub and Placeholder Policy). A stub returns its documented gap on its own path; it never reaches for a test-only stand-in to appear functional.

**Never write your extrapolation as the contract (MANDATORY for every spec clause, acceptance criterion, gate, standard, and agent prompt):** a contract states the criterion a reader applies to decide whether something qualifies. Write the criterion, then keep the operational detail you invented (candidate indicators, search terms, surface features) under a label that calls it indicators. Test each criterion by asking how many non-targets it admits; when it admits many, narrow it or demote the text to indicators under a criterion you still have to write. `.docs/standards/concrete-prose.md` §Contracts and indicators gives the source and a worked example.

**A stale restatement is not a contradiction (MANDATORY before you record a divergence or take a question to the human):** two artifacts diverge only when you can write the sentence stating why both cannot be true. Otherwise you found a copy that drifted from its source, and the artifact flow names which copy is wrong. Quote both sides in full and enumerate the cases each covers; a restatement usually dropped a condition its source carried. A grep that finds no hits for an identifier you invented proves only that the identifier is absent; read the type that owns the capability. `.docs/lessons/stale-restatement-is-not-a-contradiction.md` works an example.

**Prose (MANDATORY):** every sentence you write for a human reader — chat, specs, ADRs, stories, commit bodies, PR descriptions, code comments, review findings, READMEs — follows `.docs/standards/concrete-prose.md`. Read it before you write prose.

## Toolchain

mise installs every tool except Rust (`.mise.toml`). **Never use npm or npx**; use bun for JS and TS. System `python3` is Xcode's 3.9; use `python3.12`.

`rust-toolchain.toml` is the one place the repository names a Rust version, and `fuzz/rust-toolchain.toml` names the nightly the fuzz crate needs; every other consumer derives the version from those files. To raise a pin, edit `channel`, run the CI clippy command below, and fix everything the new release reports in the same pull request. Never lower a pin to silence a lint. A `RUSTUP_TOOLCHAIN` in the environment overrides both files, so run `unset RUSTUP_TOOLCHAIN` before any gate; `scripts/check-resolved-rustc.sh` compares the resolved compiler with the pin. mise loads `.mise.toml` from every ancestor directory, and every worktree under `.claude/worktrees/` sits inside the main checkout, so a stale `.mise.toml` there reaches every worktree. `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md` records the outage behind these rules.

| Language | Location | Package manager | Lint | Format | Test | Build |
|----------|----------|-----------------|------|--------|------|-------|
| **Rust** | `crates/` | cargo (workspace) | `cargo clippy --workspace --all-targets` | `cargo fmt --all` | `cargo test --workspace` (Python linkage below) | `cargo build --workspace` |
| **Python** | `bindings/python/` | pip + maturin | `python3.12 -m ruff check .` | `python3.12 -m ruff format .` | `python3.12 -m pytest tests/ -v` | `maturin develop --release` |
| **TypeScript** | `bindings/typescript/` | **bun** | `bun run lint` (biome) | `bun run format` (biome) | `bun test` | `bun run build` (tsup) |
| **Kotlin** | `bindings/kotlin/` | Gradle 8.x | `./gradlew detekt` | — | `./gradlew test` | `./gradlew assembleRelease` |
| **Fuzzing** | `fuzz/` (standalone, not a workspace member) | cargo-fuzz (nightly) | — | — | `cd fuzz && cargo fuzz run <target>` | `cd fuzz && cargo check` |

**Gotchas:**
- **Rust/Python linkage.** `cargo test -p scp-ffi` and `cargo test --workspace` need `DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")`. Under `cargo nextest`, macOS SIP strips every `DYLD_*` variable and the run exits 104 with `Library not loaded: @rpath/libpython3.12.dylib`; bake the path in with `RUSTFLAGS="-C link-arg=-Wl,-rpath,$LIBDIR"` and a separate `CARGO_TARGET_DIR`. CI's test commands and feature lists live in `.github/workflows/ci.yml`; take them from there, not from the table above.
- **A bare `-p` scope enables no features.** `cargo clippy -p scp-node --all-targets` fails on an example that uses a `testing`-gated item, and `cargo test -p scp-event-log` reports spurious `did:key` signature failures. Add `--features testing` before you call either a defect.
- **Searching.** In this shell `grep` and `find` are functions that exec the Claude binary and can stall after an auto-update; write `command grep` and `command find`. A recursive search from the repository root walks hundreds of worktrees under `.claude/worktrees/`, so use `git grep` or name the directories.
- **Kotlin:** JDK 17 (zulu), Gradle 8.x, and Kotlin 2.x come from mise; run `eval "$(mise env)"` first.
- **TypeScript:** `bun run check` runs `tsc --noEmit`. Biome handles lint and format.
- **Fuzzing:** run every fuzz command from inside `fuzz/`, where rustup applies the nightly pin; from the repository root rustup resolves stable and cargo-fuzz refuses to run. Never add `fuzz/` to the root `Cargo.toml` members.

## Git

- Branch in a worktree for any non-trivial change. Name branches by topic, with source IDs when they exist.
- Write conventional commits that cite their artifacts. Keep each commit atomic and revertable, and keep history linear. Pass a message containing backticks with `git commit -F <file>`, because the shell substitutes backticks inside `-m "…"`.
- Write no commit hash into a durable artifact (plan, lesson, spec, ADR, story, code comment): the repository squash-merges, so a branch hash stops resolving when the branch lands. Keep issue and PR numbers out of source code, comments, test names, and assertion messages; commit messages and PR descriptions carry them. A stub's story ID is the one exception.
- PR titles and descriptions state scope, impact, and linked stories, with closing keywords ("closes #42"). The repository merges through a merge queue that squashes, so `gh pr merge --auto` takes no strategy flag.
- When you find unexpected changes, stop and read them before you act. Never discard work you do not understand. Switch branches only when you are certain, and run a destructive git operation only when told to.
- **NEVER run `git stash`** in any form, for any reason, including chained behind `;`.
- **NEVER run `git checkout <ref> -- <path>`.** Read another revision's file with `git show <rev>:<path>`. To restore a file, show its current content first, confirm the overwrite is intended, then write.
- Both bans are unconditional because both failures are silent: the tree looks clean afterwards, so the destroyed work surfaces hours later or reads as a code finding when a grep returns baseline content.
- A task prompt's environment snapshot can name a commit the worktree's live HEAD lacks. Check `git log --oneline -3` before you branch from a pinned base.

## Agents and review

Agents give focus, expertise, and parallel work. `.claude/agents/README.md` lists the roster and when each agent applies.

**Delegation.** Delegate a task to a subagent when the task is large and independent of the other work in flight: a wide multi-file investigation, a separate implementation track, a review pass. Do work you can finish in a handful of tool calls yourself, because a subagent adds a spawn, a context load, and a handoff to every task it takes. Do not spawn a subagent to check your own work. When one subagent can do a task, send one.

**Default review roster:** black-hat, red-hat, white-hat, security-reviewer, cryptographer, bug-catcher, chronicler, alignment-reviewer, completionist, inquisitor, api-design-reviewer, simplifier. Add or remove agents to fit what the change touches.

**Take every finding seriously.** Assume a reviewer is right until evidence from the specs or the code proves otherwise. Dismiss a finding only when it is objectively false; a nit, a defense-in-depth suggestion, an incorrect comment, or a spec gap with any merit improves the code. When a review surfaces a real issue, fix it and update the artifacts it touches.

**Review the class, not the instance.** Alec stated this rule on 2026-08-30: "when you find an issue in one section that's liable to exist in another, immediately check for it in every possible area. don't wait and allow churn. use findings to be a proactive reviewer; don't rely on checks and be purely reactive." A reviewer that finds a defect searches every other place the same defect can occur — the other bridges, the other SDK wrappers, the other call sites, the twin function one module over — and reports every site in one finding. A passing check says nothing about the sites it does not read, so look for what no check covers.

**Read to the frontier, then stop.** A reviewer reads the diff, expands along the edges the change perturbs (callers when what a caller observes changes; every consumer of a changed wire format or signed preimage; implementors of a changed trait), and stops at every node whose observable contract the change leaves unchanged. A held finding lifts that bound for the defect it names. A frontier that does not close within the reading budget is itself a finding: report "unbounded blast radius".

**Guard against over-engineering and non-convergent enforcement.** A gate, validator, or linter is defense in depth. Before you add or grow one, confirm that it is closed by construction (a positive whitelist of permitted shapes, never a denylist chasing one more spelling), that it does not re-check in weaker form a property the type system or cryptography already enforces, and that its cost matches its benefit. When more than about three review passes on one artifact each surface a new spelling of the same bypass, the approach does not converge: stop and reframe it. The simplifier flags this class as a blocker. `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` records the case.

**Scar-tissue defense (MANDATORY on every design or architecture artifact, unprompted).** Internal consistency is not correctness. On every design artifact the roster attacks the design and its premises, and treats each of these as a blocker, never as a residual note:
- **Deferral dressed as a decision** — "known limitation", "out of scope", "follow-up", "tracked separately". A deferral is valid only when a stated external constraint, such as a compiler restriction, blocks the work.
- **An inherited premise treated as authorized** — a constraint copied from an issue, ADR, or comment that no human decided. Trace every load-bearing constraint to its author.
- **An invariant weakened to fit a workaround** — a spec MUST carved out, a gate exempted, type safety relaxed. Fix the root cause instead.
- **A misnomer or accidental status quo perpetuated** — challenge the primitive itself (the feature flag, the dependency edge, the trait shape, the name).
- **Building on an unsettled upstream** — a story or ADR that depends on a Proposed ADR, or that answers an upstream open question from downstream.

Validate a contested design against external convention in primary sources before accepting an internally consistent compromise. The inquisitor and a design-primitive challenge join the roster for every architecture artifact.

## Orchestration (MANDATORY)

The orchestrator writes no code. It plans, dispatches, keeps chunked work coherent with the plan, and triages review findings.

1. **Plan first.** Send a Plan agent the paths to the plan sections, issues, and code it must read, and tell it to read code, not just grep. Authorize execution only after the plan is reviewed.
2. **Execute in isolation.** Send coders with `isolation: "worktree"`. Run at most two or three coders at once, and run coders that touch the same files one after another. Never mix phases: plan fully, review the plans, then code. Watch the main worktree, and investigate any dirty change on it before you take a destructive action.
3. **Review.** Give reviewers what was intended, what to look for, and what to read. Never discard a finding silently; escalate to the human when you cannot tell whether it is actionable.
4. **Fix and re-review** until two consecutive passes return zero findings.

**Agent prompts.** Write every agent prompt as a contract, never as your recipe: state what the agent must make true and how you will check it, then give your recipe (files to read, greps, symbols to trace) separately under a label. An agent that receives only a recipe satisfies the recipe and reports success. Every definition in `.claude/agents/` except `README.md` opens with a `## Verdict criterion` section, which `scripts/check-agent-verdict-criterion.sh` checks for shape only; a reviewer of a definition still decides whether that section states a criterion. Every prompt names its starting branch and says: "Verify with `git log --oneline -3` that you see [expected commits]. If not, STOP." Tell every subagent to read this file.

**Agent rules.** When the plan says "delete X and import Y", the agent deletes X and imports Y; only a compiler-level restriction justifies keeping a local reimplementation. When an agent hits friction (a `pub(crate)` type, a missing derive or method), it fixes the impediment rather than working around it. Fix clippy warnings with `cargo clippy --fix` or an agent, not by hand. Never check out a feature branch on the main worktree.

**Verification after every agent merge (MANDATORY):**
- Verify against the pushed remote branch (`git show origin/<branch>:<file>`), never the local working directory.
- For a type deletion, `grep -c "struct TypeName" <file>` returns 0; for an import, `grep -c "scp_protocol::module" <file>` returns more than 0.
- A cherry-pick that resolves to "nothing to commit" did not land; investigate.
- The `rust-clippy` job of `.github/workflows/ci.yml` runs this command on the pushed head, and every lint it reports is fixed before the pull request merges: `cargo clippy --workspace --all-targets --features scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/testing,scp-runtime/saga-witness-test-mint,scp-ffi/outlet-capability-test-grant,scp-ffi-napi/outlet-capability-test-grant,scp-ffi-uniffi/outlet-capability-test-grant -- -D warnings`
- Never say "done" without showing the verification output.

**Scope of an audit.** When asked to verify, audit, or review "everything", list the repository root and write down, before you start, every layer you will check: the Rust core, the FFI bridges, the SDK wrappers, tests, specs, and CI. Justify every exclusion. When you compare implementations across bridges, SDKs, or platforms, build the full operations × targets matrix first; an empty cell is a finding. A Rust function without an FFI export, or an export without a wrapper, or a wrapper without tests, is unfinished.

## Map

| Thing | When / why to read it | File |
|-------|-----------------------|------|
| Specs | Before you implement or change protocol behavior; a spec states what MUST be true | `.docs/specs/` |
| Protocol principles | When a design question turns on a tenet above | `.docs/specs/01-thesis.md` |
| Open protocol questions | Before you settle a protocol question; gaps between spec and code go here or in an issue, never into a spec | `.docs/specs/00-open-questions.md` |
| ADRs | Before a design decision, and to learn why an alternative was rejected. Most ADRs are `## ADR-NNN` sections inside `phase-N.md`; some have their own `ADR-NNN-*.md` file. Grep both before calling a citation broken | `.docs/adrs/` |
| PRD stories | Before you implement or edit a story | `.docs/prds/`, with `.docs/standards/prd.md` |
| Language standards | Before you write code in that language | `.docs/standards/<language>.md` |
| Cross-SDK rules: stubs, error codes, placeholders | Before you touch a binding or an error code | `.docs/standards/sdk-common.md` |
| Construction pattern | Before you add or change a public constructor or config object | `.docs/standards/construction.md` |
| Naming and documentation conventions | Before you name a public item or write doc comments | `.docs/standards/conventions.md`, `.docs/standards/documentation.md` |
| SDK capability matrix | When an operation gains or loses a binding | `.docs/standards/sdk-capability-matrix.json` |
| Writing standard | Before you write any prose; the two lessons show the rules applied | `.docs/standards/concrete-prose.md`, `.docs/lessons/bad-prose-and-its-rewrite.md`, `.docs/lessons/a-rule-written-in-the-present-tense-reads-as-already-done.md` |
| Architecture and crate layout | To find which crate owns a concern and how crates depend on each other | `.docs/architecture.md`, section 2.1 Crate Structure |
| API sketches | To see the intended shape of an operation across SDKs | `.docs/sketch.md` |
| SDK build blueprints | Before you scaffold or restructure an SDK | `.docs/scaffold/` |
| Operator runbooks | When diagnosing a production incident, such as a saga that needs repair | `.docs/runbooks/` |
| Lessons | Before you debug a failure that could be an environment or CI fault, and before you write a gate; each title names its trap | `.docs/lessons/` |
| Toolchain pin | Before you touch `rust-toolchain.toml`, a workflow's Rust setup, or a Dockerfile | `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md` |
| CI lane routing | Before you edit a workflow's paths filter | `.docs/lessons/route-a-changed-file-to-every-lane-it-decides.md` |
| Writing a gate | Before you add or change a check script | `.docs/lessons/coverage-gates-must-fail-closed.md`, `.docs/lessons/a-green-check-that-asserted-nothing.md`, `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` |
| Shared cargo target directory | When builds block on a lock or a disk fills | `.docs/lessons/the-shared-target-directory-has-one-lock.md` |
| Cross-SDK behavior | When one SDK's constraint tempts you to impose it on another, or bridge names diverge | `.docs/lessons/per-sdk-idiom-not-cross-language-dogma.md`, `.docs/lessons/cross-bridge-canonical-naming.md` |
| CI commands | For the exact commands and feature lists CI runs | `.github/workflows/ci.yml` |
| Agent roster | To choose an agent for a task or a review | `.claude/agents/README.md` |
| Agent memory | An agent's own recorded findings, loaded by that agent | `.claude/agent-memory/<agent>/MEMORY.md` |
| Context+ MCP | Before you use Context+ to map code; records which tools work on this codebase | `.claude/CONTEXTPLUS_MCP.md` |
| Vestige MCP | Long-term memory: search it before a decision, save rulings and fixes to it, tag memories `always`, `prefer`, `avoid`, or `never` | `~/.claude/CLAUDE.md` (user-level) |
| Runtime (actor-per-context) | Before you change `scp-runtime` | `crates/scp-runtime/AGENTS.md` |
| FFI bridges (PyO3, napi-rs, UniFFI) | Before you change a bridge | `crates/scp-ffi/AGENTS.md` |
| In-browser client | Before you change `scp-client` or its tests | `crates/scp-client/AGENTS.md` |
| Browser wasm surface | Before you test a `#[wasm_bindgen]` function | `crates/scp-client-wasm/AGENTS.md` |
| Swift SDK | Before you change `bindings/swift/` | `bindings/swift/AGENTS.md` |
| Kotlin and Android SDK | Before you change `bindings/kotlin/` | `bindings/kotlin/AGENTS.md` |
| TypeScript SDK | Before you change `bindings/typescript/` | `bindings/typescript/AGENTS.md` |
| Python SDK | Before you write a Python validator | `bindings/python/AGENTS.md` |
| Fuzzing | Before you add or change a fuzz target | `fuzz/AGENTS.md`, `fuzz/README.md` |
