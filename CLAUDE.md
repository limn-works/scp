# Shared Context Protocol (SCP)

## Vision

SCP is an open, ecosystem-agnostic infrastructure protocol — open infrastructure for the agentic Internet: cryptographically verifiable identity (DID), governed interaction spaces (contexts), trustworthy communication (MLS encryption), capability-based authorization (UCAN), and transparent provenance. All interaction happens within contexts — bounded, encrypted, governed spaces where membership is enforced by cryptography, not infrastructure. Rust core with bindings via PyO3 (Python), UniFFI (Swift, Kotlin), napi-rs (TypeScript). Transport abstracted behind an adapter trait (SCP native relay + 17 adapters). Build phases defined in `.docs/adrs/`.

### Protocol tenets

- **Provenance everywhere.** All non-private data carries verifiable origin metadata. When a record carries no provenance, that absence tells a reader something, so treat it as a signal rather than as missing information.
- **Human accountability.** Every agent traces to a human DID through attestation chains. Behavioral records are durable.
- **Context isolation.** Every interaction happens inside a bounded context. A participant moves data across a context boundary only through an explicit, governed path. The context boundary is the security boundary.
- **Encryption-as-access-control.** MLS group keys enforce membership. Relays are untrusted: access control is cryptographic (never relay-enforced) and clients verify every record independently, so correctness never depends on a relay. A relay MAY validate *public, self-certifying* records it stores (e.g. verify a DID document's BEP44 signature and keep the highest-seq copy) for availability/anti-suppression — defense-in-depth, never a trust dependency, and never applies to encrypted content. 'Untrusted,' not 'does zero validation,' is the invariant.
- **Legibility before opt-in.** A prospective member reads a context's parameters before joining it, so the protocol makes informed consent mechanical.
- **Protocol requires no operator.** The protocol must keep working if Limn shuts down tomorrow.
- **Transport independence.** No structural coupling to any single transport.
- **Agents are participants, not enforcers.** Same rules as any human-bound participant.
- **Trust is contextual.** A trust decision reads identity, capability, context, and behavior together. No participant is simply trusted or untrusted.

### Builder tenets

- **No human limits.** 100% agent-written codebase. Don't think in human terms of timeline, scope, or speed. Consider code to be free and time to be infinite.
- **No DOA decisions.** Design decisions are permanent commitments. If it needs replacing later, it's the wrong choice now.
- **Simple over complex.** Never at the expense of functionality, security, or completeness.
- **No deferral.** Everything gets specced and implemented now. Nothing is "v2" or "future."
- **No stubs, no partial work.** Stubbing or partial implementations are forbidden. Only ever implement things to completion on the first pass.
- **No dev/test-only stand-ins in production.** No construct that only works in test or development — an in-memory or no-op backend, an always-succeeds verifier/attestation, a non-resolving resolver, a hardcoded/placeholder/reconstructed-from-args value, a `#[cfg(test)]`/`testing`-gated type, a security nullifier — may EVER be reachable on a shipped production path to mask an unfinished real implementation or stub for prod. If the real backend isn't built, the capability **fails closed** (a typed error, or an honest protocol-supported absent state) — it does NOT silently fall back to the dev stand-in. Masking a missing production backend with a dev construct ships a *false guarantee*, which is strictly worse than the capability being honestly absent (absence is detectable; a nullifier lies). Deferring the *real backend* to a tracked workstream is allowed; shipping a stand-in for it in the meantime is not. Prove absence mechanically — the shipped-feature-graph ⊆-allowlist gate admits durability-only features and **zero nullifiers, no exceptions** (no "documented," "tracked," or "legible" allowlisted nullifier edge). See `.docs/specs/17-persistence-and-storage.md` §17.17 (capability selection / durability-vs-nullifier classification) and `.docs/standards/sdk-common.md` §Stub and Placeholder Policy.
- **Completeness is the baseline.** Every feature, every edge case, every acceptance criterion — implemented fully or not at all. Maximum breadth. Partial implementations are failures. Every struct field the spec defines must have a real value — never `None` when data exists elsewhere in the system. Never fabricate story references to justify gaps. Never create tracking issues instead of doing the work. Never call an incomplete implementation a "planned deferral." When a gap is caught, fix it immediately — do not rationalize it.
- **Do the work. All of it.** When an issue has 10 acceptance criteria, implement all 10. Not 4 and call it "partial closing." Not 6 and argue the rest is "separate scope." Read every acceptance criterion as a literal checkbox. Verify every checkbox before reporting done. The plan defines scope — you do not get to reduce it. Subagents will cut corners, hardcode `None`, game string-search tests with dead references, and report success. You MUST verify their output against the actual acceptance criteria, not their self-reports. When you catch yourself thinking "this can be deferred" — that is the signal you are about to fail. Do. The. Work.
- **You do not make scope decisions.** The plan makes scope decisions. The issues define acceptance criteria. Your job is mechanical execution: read the checklist, implement every line, verify every line. Known failure modes you WILL exhibit and MUST guard against:
  - **Hardcoding `None` instead of wiring parameters.** When a function needs a real value, you will be tempted to pass `None` and move on. Don't. Wire the parameter through all callers.
  - **Gaming enforcement tests with dead references.** `let _ = function_name;` passes a string search but calls nothing. This is fraud. Call the function with real arguments or leave the assertion `#[ignore]`.
  - **Counting acceptance criteria and stopping early.** "4 of 10 met" is not progress — it's failure. You will feel done at 4. You are not. Do the other 6.
  - **Rationalizing gaps as "separate scope."** If the plan says to do it, it is in scope. Period. "Follow-up," "tracked separately," "not blocking," "can be deferred" — these are all lies you tell yourself to stop working. The plan already scoped the work. Execute it.
  - **Treating agent dispatches as expensive.** They are free. Time is infinite. Code is free. Dispatch as many agents as needed. Never trim scope to reduce iterations.
  - **Trusting subagent self-reports.** Subagents are liars. They report success while leaving work incomplete. ALWAYS verify against the actual acceptance criteria by reading the code yourself. grep for the function call. Read the test. Check the checkbox.
- **SDK first.** Rust core + bindings before any app.
- **Enforce mechanically.** Linters, structural tests, and the type system — not documentation.
- **Artifacts are the system of record.** If an agent can't find it, it doesn't exist.
- **Root-cause orientation.** Bugs are architecture flaws first, local defects second.
- **No shortcuts.** No force unwraps, no placeholders, no "good enough."
- **Provenance is paramount.** Every line traces to a documented decision. Chain: `.docs/` sources → `.docs/prds/` stories (or GitHub comments, feature-local artifacts). Before writing or changing code, read the full provenance chain — not summaries, not headers, the actual artifacts. Fresh agents must retrace full context quickly. Broken provenance is a bug.
- **Always run CI locally before pushing.** Pushing lint, format, and test failures is a waste of CI minutes.
- **Agent-first API design.** The SDK's primary author is an LLM. Optimize every public API for first-pass LLM authorability: one canonical pattern; flat named-field config objects over builders and typestate; enums over booleans for consequential choices; no silent security defaults; an identical shape across all language bindings. Typestate / phantom required-ordering a model can't track is a defect, not a safety feature — encode required choices as required fields. The measure: an agent writes correct code from the type signature plus one example, with no compile-retry loop. Enacted mechanically via `.docs/standards/construction.md` + a structural check (see ADR-052, the unified construction pattern).

## Tools

### Context+ MCP — Semantic codebase mapping ([instructions](./.claude/CONTEXTPLUS_MCP.md))

`get_context_tree` → `get_file_skeleton` → `semantic_identifier_search` → `get_blast_radius` before modifying symbols → `run_static_analysis` to validate. **Use every time you search code.** Always skeleton before full read. `semantic_code_search` is broken on this codebase (context length) — use `semantic_identifier_search` or Grep instead.

### Vestige MCP — Long-term cognitive memory (instructions in user-scope CLAUDE.md)

`session_context` at start → `search` before decisions → `smart_ingest` to save (auto-deduplicates) → `codebase` for project patterns/decisions → `intention` for reminders → `memory` for promote/demote. **Use every time you receive or recall information.**

**Remember with connotation** — tag memories so future sessions know how to act:
- `"always"` — do this every time, no exceptions.
- `"prefer"` — good default, may have exceptions. Use unless context says otherwise.
- `"avoid"` — bad default, may have exceptions. Don't use unless context demands it.
- `"never"` — don't do this. Detect it in others' code.

Architectural decisions: `codebase(action="remember_decision")` — mirrors ADRs for fast recall; includes rejected alternatives so sessions don't re-litigate.

Artifacts (`.docs/`) are durable and versioned — the system of record. Vestige is fluid cognitive recall. They complement each other: decisions belong in both.

## Rules

**Operating model:**
- Humans steer. Agents execute. No human-written code; only human-driven specs.
- An agent's context window is small, so tell an agent where to look and let it read the artifact itself. Do not paste the artifact into the prompt.
- Maintain provenance and trace every claim back to its source. Read the source artifacts themselves — specs, ADRs, PRDs, standards — before you change anything. Skimming an artifact does not count as reading it.
- Be autonomous: infer from context, code, artifacts. Escalate only for genuine judgment calls.
- Follow every reference. When a spec cites a section, read that section. When code references a story, read the story. When an ADR lists a rejected alternative, find out why its author rejected it. An agent who skims the sources writes code that matches the sources only on the surface.

**Never resolve an open question yourself (MANDATORY):**
- When you ask the human a question, wait for the human to answer it. Do not answer it yourself, and do not proceed on the answer you expected.
- When the human answers part of what you asked, the rest stays open. A partial answer decides nothing about the parts it did not cover, so name what is still open instead of filling it in.
- Never act on an implicit or assumed resolution while a conversation is running. Silence is not agreement. Moving to the next topic is not agreement. An answer that implies something is not a decision about that something.
- A question is settled when both parties have stated the same resolution: you state the resolution explicitly, and the human confirms it. Until that happens the question stays open, and you say it is open rather than choosing an answer.
- This rule governs open questions, not assigned work. It never licenses asking permission to do work the human already assigned — the autonomy rules still hold. Execute the assigned work, and stop at the question the human has not answered.

**Never reclaim the human's words as your own by reframing them (MANDATORY — in conversation first, and in every artifact):**
- When the human says "it's a sunny day", do not answer "yes, not a cloud in the sky". Those two statements are not the same: one allows clouds and the other forbids them. Answering that way swaps your claim in for theirs and attaches their agreement to yours.
- Agree with what they said. When you have a further claim, say it separately and say that it is yours.
- When the human states a rule, a finding, or a decision, record it with their meaning and their scope intact.
- Quote them verbatim when they ask for a quote, not by default.
- Paraphrasing their statement into your own register erodes the original information and presents your content as theirs, so your invention carries their authority.
- Keep their general clause when they give one. Do not replace it with an enumeration you invented, and do not narrow it to the instance in front of you.
- When you must add a word to make their statement usable, say that you added it.

**Artifact flow (INVARIANT):**
- The flow is strictly one-way: **plans → specs → ADRs → stories → source code.**
- Upstream artifacts govern downstream artifacts. Never the reverse. Code does not inform specs. Stories do not reshape or request ADRs. Implementation details do not change plans.
- If code reveals that a spec is wrong, **stop writing code.** Fix the spec first, then update downstream artifacts, then resume implementation. The fix flows down; it never flows up from code.
- If a story can't be implemented as written, the story is wrong — update the story (and its upstream sources if needed) before writing code that contradicts it.
- Violating this invariant creates phantom provenance: code that appears grounded in artifacts but actually diverges from them. This is worse than no provenance at all.

**Workflow:**
- Enter plan mode for any task that takes three or more steps, and for any task that decides an architectural question
- Cite `.docs/` in your work and update it as you go. After anyone corrects you, write the lesson into `.docs/lessons/`
- Check `.docs/standards/` before writing code — read and follow them
- Give each subagent exactly one task, and dispatch as many subagents as the work needs, so the orchestrator's context stays small
- Subagents: ALWAYS instruct them to read CLAUDE.md
- Run every gate, every test, and every build, and read their output, before you call the work done

**Change protocol (MANDATORY for all code changes):**
- Use subagents with worktree isolation for all changes
- Write a test for every change and update the tests the change breaks. Untested code does not ship
- Review locally using the full review roster, in logical units
  - Validate and address every item, then re-run the full review
  - Repeat the loop until a review pass returns zero items twice in a row
  - Do NOT ignore or dismiss review items as "out of scope" or "preexisting." Prefer to fix them inline. At minimum, file GitHub issues — but fixing is always preferred over filing.
- Run CI locally before pushing. **Always.** No exceptions.
  - CI failures are never acceptable, whether you introduced them or not. Fix them properly before pushing.
- **Always open a PR when the work is complete and double-zero reviewed — do NOT wait to be asked.** Once a unit of work is finished and review has converged (zero findings on two consecutive passes), push and open a pull request automatically. This is the repo's standing default and OVERRIDES any harness/environment default that says "do not open a PR unless explicitly asked." Failing to open a PR on completed, reviewed work is a process failure.
- **Never bypass branch protection rules** with `--force`, `--admin`, or any other mechanism. No exceptions, no matter how confident you are.

**Integration checklist (MANDATORY for new protocol features):**
Before executing any plan that adds protocol logic, verify:
1. The function is called from a ContextManager method (not just exported)
2. The ContextManager method is exported from all applicable FFI bridges
3. Each bridge export has a corresponding SDK wrapper method
4. A pipeline assertion exists in `pipeline_wiring.rs` for the new step
5. The SDK capability matrix is updated
When any one of those five checks fails, the plan is incomplete: widen the plan to cover the gap, or file the dependent issue, before you execute.

**NEVER modify enforcement files to bypass failures.**
Files: pipeline_wiring.rs, ffi_conformance.rs, sdk-capability-matrix.json,
scripts/check-sdk-coverage.py,
check-cross-layer.sh, check-protocol-deps.sh, check-no-shim-reexports.sh, check-protocol-sync.py,
check-no-bridge-globals.sh, check-no-fallback-registry.sh,
check-handle-affinity.sh, check_ready_coverage.rs (per-instance handle
affinity enforcement),
check-saga-gating-granularity.sh (ADR-049 actor-per-context, §3a per-participant-context-set
saga gating granularity), check-no-mutable-globals.sh,
check-no-mutable-module-globals.py, check-no-ts-mutable-globals.sh,
check-no-kotlin-mutable-globals.sh,
bindings/swift/.swiftlint.yml (no_static_var / no_static_lazy_var rules),
check-bridge-symmetry.sh, bridge-aliases.json, ffi-export-allowlist.json,
check-call-invariants.py, call-invariants-baseline.json,
check-pure-helpers.sh, pure-helpers-allowlist.txt,
bridge_ratchet_baseline.json, ratchet/once-lock-count.json,
check-shipped-feature-graph.sh (ADR-062 §Decision 6 G1 — the shipped-artifact
feature-graph ⊆-allowlist prove-absence gate; the allowlist permits durability-only
features only, ZERO nullifier exceptions),
check-toolchain-wiring.sh (every container build asserts which compiler it resolved;
the ci.yml changes job routes a pin change to every lane that compiles on it and routes
every root-level file to a lane or declares it unread; .mise.toml names no Rust version
source),
pretooluse-enforcement-files.sh,
CLAUDE.md (enforcement sections).
When a check fails, fix the code that the check rejected. You may modify an enforcement file for exactly two reasons:
- You are adding a new assertion or a new operation, which widens what the check covers
- You are removing an `#[ignore]` because the wiring it waited on has landed, which promotes a dormant assertion to an enforced one
A human must approve before you weaken an existing assertion, delete one, or exempt anything from one.

**Architecture:**
- Define a protocol before you write the type that satisfies it. Inject every dependency through an initializer. Never reach for a singleton
- Give every public API one happy path a reader can find from the type signature alone, and optimize that signature for an LLM author (see the Agent-first API design tenet)

**PRD stories (MANDATORY):**
- **Before creating, editing, or updating any story in `.docs/prds/`**, read `.docs/standards/prd.md` in full. No exceptions.
- Fill every field the standard defines. Write every acceptance criterion so a machine can verify it. Point every source at a heading that exists in a file that exists. Point every dependency forward, never backward.
- The artifact flow applies to stories: stories reference specs and ADRs, never the reverse. If a story can't cite a spec section or ADR, it needs one written first.
- Run `python3 scripts/validate-prd.py` before committing PRD changes. CI enforces this.
- A subagent that writes a story validates the story against the standard before it returns. Two audits shipped defective stories because neither audit checked its own output, and that failure is why this standard exists.

**Stubs:**
- Every stub must reference a PRD story ID (`// Stub — see SCP-NNN`)
- A story marked "done" carries zero stubs against its acceptance criteria
- CI enforces: Rust (`clippy::todo/unimplemented = "deny"`), Kotlin (detekt `ForbiddenComment`), Python (ruff `FIX`), Swift (SwiftLint `todo`), TypeScript (ESLint `no-warning-comments`)
- See `.docs/standards/sdk-common.md` §Stub and Placeholder Policy
- **No dev/test-only stand-in may mask a missing production implementation (see the builder tenet).** A stub returns a documented, story-referenced gap on its own path; it does NOT reach for a test-only nullifier (in-memory custody/DHT/attestation, no-op verifier, placeholder value) to *appear* functional in production. Prod fails closed until the real backend lands. The prove-absence gate allowlists zero nullifiers — deferring a real backend to a tracked issue never authorizes shipping a stand-in for it.

**Never write your extrapolation as the contract (MANDATORY for every spec clause, acceptance criterion, gate, standard, and agent prompt):**
Mike Caulfield names this failure in "I finally understand why LLMs suck at writing prompts" (https://mikecaulfield.substack.com/p/i-finally-understand-why-llms-suck): a model asked to write a prompt "write[s] the intermediate prompt as the contract prompt." Two different things get written in the same authoritative register:
- A **contract** states the criterion a reader applies to decide whether something qualifies.
- An **intermediate extrapolation** is the operational detail a model invents so it can act on a request the contract states too vaguely: candidate indicators, search terms, surface features that often accompany the target.
Caulfield asked a model to characterize the director Chris Columbus and got "warm, sentimental mainstream family entertainment; plucky kids and harried parents in cozy suburban or holiday settings; broad comic set-pieces softened by earnest heart and reassuring resolution." That paragraph reads as a definition, but it matched roughly one film in ten across continents and centuries, and the model itself later judged two of its three top matches indefensible. The paragraph lists things that often accompany a Columbus film. It never states what makes a film a Columbus film.
- **Write the criterion, then label the indicators as indicators.** State what decides membership. Keep the operational detail you invented, because a reader needs it to act, but mark it as evidence that suggests the target rather than as the test that defines the target.
- **Test every criterion you write by asking how many non-targets it admits.** When a criterion admits many things you did not mean, you wrote search candidates. Narrow the criterion, or demote the text to an indicator list under a criterion you then have to write.
- **This failure produces a defect this repo already fights.** A denylist gate that chases one more spelling of a bypass is an indicator list presented as a criterion, which is why the "Guard against over-engineering" rule requires a positive whitelist closed by construction.

**Prose (MANDATORY):** every sentence you write for a human reader follows `.docs/standards/concrete-prose.md`. Read that file before you write prose. It governs chat responses, specs, ADRs, PRD stories, commit bodies, pull-request descriptions, code comments, review findings, README text, and artifact copy.

### Toolchain

All tools via [mise](https://mise.jdx.dev/) (see `.mise.toml`). **Never use npm or npx** — bun only for JS/TS. System `python3` is Xcode 3.9 — **do not use it**; use `python3.12`.

**`rust-toolchain.toml` is the one place this repository names a Rust version.** Every other consumer derives the version from that file, so no two files can disagree: `cargo` and `rustup` read it natively, and rustup installs the channel, components, and targets it names on first use; `Dockerfile` and the container recipe in `templates/personal-relay/README.md` copy the file into the image before any cargo command, and their base tags name a Debian release and no Rust version. `fuzz/rust-toolchain.toml` names the nightly the standalone fuzz crate needs; run every fuzz command from inside `fuzz/` and rustup applies that file, so no command names the channel, and `.github/workflows/fuzz.yml` — whose commands run from the repository root — reads the channel out of the file in one job. To raise either version: edit `channel`, run the CI clippy command from the Orchestrator verification protocol below, and fix everything the new release reports in that same pull request. Never lower the pin to make a new lint disappear.

**mise installs every tool except Rust, and `.mise.toml` names no Rust version.** mise exports one `RUSTUP_TOOLCHAIN` for the whole repository, and that variable overrides a toolchain file entirely, so it cannot give `fuzz/` a nightly while the workspace compiles on stable. rustup resolves both, per directory, and README.md lists rustup among the prerequisites. A `RUSTUP_TOOLCHAIN` exported into your shell from anywhere still overrides both files, so `scripts/hooks/pre-commit` compares `rustc --version` against the pin before it runs cargo, and `fuzz/build.rs` fails the fuzz build when that crate resolves a compiler its own file does not name. `scripts/check-toolchain-wiring.sh` checks the three properties a derivation cannot supply: that every container build carries the ASSERT-PINNED-RUSTC block, which makes the build compare the compiler it resolved against the copied-in pin, since the base tag no longer names a compiler; that the `dorny/paths-filter` wiring in `.github/workflows/ci.yml` routes a pin change to every lane that compiles on it and routes every root-level file to a lane or declares that no compile reads it, since the `ci` aggregator job counts a skipped job as a pass; and that `.mise.toml` names no Rust version source. See `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md`, which records the merge-queue outage that a floating `@stable` caused.

| Language | Location | Package Manager | Lint | Format | Test | Build |
|----------|----------|----------------|------|--------|------|-------|
| **Rust** | `crates/` | cargo (workspace) | `cargo clippy --workspace --all-targets` | `cargo fmt --all` | `cargo test --workspace` (needs `DYLD_LIBRARY_PATH` below) | `cargo build --workspace` |
| **Python** | `bindings/python/` | pip + maturin | `python3.12 -m ruff check .` | `python3.12 -m ruff format .` | `python3.12 -m pytest tests/ -v` | `maturin develop --release` |
| **TypeScript** | `bindings/typescript/` | **bun** (not npm) | `bun run lint` (biome) | `bun run format` (biome) | `bun test` | `bun run build` (tsup) |
| **Kotlin** | `bindings/kotlin/` | Gradle 8.x | `./gradlew detekt` | — | `./gradlew test` | `./gradlew assembleRelease` |
| **Fuzzing** | `fuzz/` (standalone, not workspace) | cargo-fuzz (**nightly only**) | — | — | `cd fuzz && cargo fuzz run <target>` | `cd fuzz && cargo check` |

**Language-specific gotchas:**

- **Rust/Python linkage:** `cargo test -p scp-ffi` and `cargo test --workspace` require `DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")`
- **Kotlin:** JDK 17 (zulu), Gradle 8.x, Kotlin 2.x — all via mise. Run `eval "$(mise env)"` first.
- **TypeScript:** `bun run check` runs `tsc --noEmit` for type checking. Biome handles both lint and format.
- **PRD validation:** `python3.12 scripts/validate-prd.py` — run before committing PRD changes.
- **Fuzzing:** `fuzz/` is a standalone crate — never add it to root `Cargo.toml` members. Run every fuzz command from inside `fuzz/`: rustup applies the toolchain file of the directory a command runs in, and `fuzz/rust-toolchain.toml` names the nightly cargo-fuzz needs, so no command names a version. A command run from the repository root resolves the stable pin instead, and cargo-fuzz refuses to run on it. List targets: `cd fuzz && cargo fuzz list`. See ADR-045, the fuzzing infrastructure decision, and `fuzz/README.md`.

### Git

- Worktrees for non-trivial changes or when you're not already in one
- Topical branch names with source ids when available
- Conventional commits referencing artifacts/sources. Atomic, revertable — never bundle unrelated changes
- PR titles and descriptions: describe scope, impact, and linked tickets/stories. Use closing keywords ("closes #42")
- Always open a PR when work is complete and double-zero reviewed — do not wait to be asked (see the Change protocol). Opening the PR is part of finishing the work, not a separate step that requires permission.
- Clean, linear history
- Unexpected changes: back off, read, understand before acting. Never discard without understanding first
- No stashing/branch switching unless 100% confident. No destructive git ops unless told to or integrated upstream

## Agents

Use eagerly for focus, expertise, and parallelization. See `.claude/agents/README.md` for the full roster.

Default review agents: @"black-hat (agent)", @"red-hat (agent)", @"white-hat (agent)", @"security-reviewer (agent)", @"cryptographer (agent)", @"bug-catcher (agent)", @"chronicler (agent)", @"alignment-reviewer (agent)", @"completionist (agent)", @"inquisitor (agent)", @"api-design-reviewer (agent)", @"simplifier (agent)". Use discretion to add or remove based on review contents.

**Reviews are not rubber stamps.** Read every finding. If a reviewer flags something, understand the concern fully before dismissing it. Assume reviewers are right until you can prove otherwise with evidence from specs or code. Act on review feedback — don't acknowledge and move on. When a review surfaces a real issue, fix it and update the relevant artifacts.

**Take every finding seriously.** Only dismiss things that are categorically, objectively false or truly non-issues. Even slight suggestions — defense in depth, cleanup, clarity, incorrect comments, spec gaps, learnings — if there's any merit to them at all, whether in literal content or in spirit, take them seriously and use them to improve the code. Don't dismiss things because they seem out of scope, are nits, or appear generally not actionable. Only dismiss things that are absolutely not actionable because they are wrong.

**Guard against over-engineering and non-convergent enforcement.** Mechanical checks (gates, validators, linters) are defense-in-depth, not the primary guarantee. Before adding or growing one, confirm: (a) it is *sound and bounded* — closed by construction (a positive whitelist of permitted shapes), not an ever-expanding denylist chasing "one more spelling"; (b) it does not redundantly re-check, in weaker source-text/AST/runtime form, a property the type system or another compile-time/cryptographic mechanism already enforces soundly — such redundancy is negative value, not defense-in-depth; (c) its cost (lines, complexity, review cycles) is proportionate to its marginal benefit. **Review-pass count is a convergence signal:** if more than ~3 review passes on one artifact keep surfacing "a new spelling of the same bypass," the *approach* is non-convergent — stop and reframe, do not grind. The @"simplifier (agent)" is charged with flagging this class as a BLOCKER; take it as seriously as a correctness finding. See `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`.

**Scar-tissue defense (MANDATORY — applied by default on every design/architecture artifact, not on request).** Internal consistency is NOT correctness. A documented residue, a perpetuated misnomer, an "out of scope" note, a spec `MUST` weakened with a carve-out, an inherited scope-boundary — every one of these is *internally consistent*, which is exactly why ordinary review passes them. They are scar tissue: locally-reasonable compromises that calcify into an incoherent whole. The reviewer's job is to attack the **design and its premises**, not verify the artifact's coherence. On every design artifact the roster MUST, unprompted, hunt and challenge:
- **Deferral dressed as a decision** — "document the residue," "known limitation," "out of scope," "follow-up," "tracked separately," "interface-ready future work," "#NNNN handles it." Default answer per the no-deferral tenet: fix it now. A deferral is valid only if a *real* external constraint blocks it (a compiler restriction, a genuinely separate specced feature), stated explicitly.
- **Inherited premise treated as authorized** — a scope boundary or constraint copied from an issue/ADR/comment that no human actually decided. Trace every load-bearing constraint to its author. "It was in the issue" is not authorization.
- **Invariant weakened to fit a workaround** — a spec `MUST` carved out, a gate exempted, type-safety relaxed to accommodate a compromise. The workaround is wrong; fix the root cause. Weakening an invariant to fit code is the artifact-flow inversion, generalized.
- **Misnomer / accidental status-quo perpetuated** — a name that lies about what it gates, a coupling copied because "that's how it's done," a wrong-but-consistent primitive. Challenge the primitive itself (the feature flag, the dependency edge, the trait shape, the taxonomy, the name), not just its internal consistency.
- **Building on an unsettled upstream** — a story/ADR that depends on a `Proposed` (not `Accepted`) ADR, or that resolves an upstream artifact's open question from downstream. Upstream must be settled first; downstream never decides upstream's open questions.

**Validate contested design against external convention** (primary sources) before accepting an internally-consistent compromise. **Orchestrator rule:** scar-tissue findings are blockers, never "residual notes" — do not demote a premise/design finding to a nit or a follow-up. The inquisitor plus a design-primitive challenge are a *mandatory default* part of the review roster for any architecture artifact, charged against the substance (not process-meta).

### Orchestration protocol (MANDATORY)

The orchestrator never writes code. It manages execution, maintains plan alignment, and triages review feedback.

**For every work item:**

1. **Plan first.** Send a Plan agent with full context: master plan excerpts, file references, issue numbers, code to read. Instruct agents to READ CODE — not just grep. Use Explore agents too if needed. Use Vestige memory. Do not authorize execution until the plan is reviewed and signed off.
2. **Execute with isolation.** Send coder agents with worktree isolation (`isolation: "worktree"`). Provide all context from the approved plan. Monitor the main worktree — if dirty changes appear on main, investigate before any destructive action.
3. **Review thoroughly.** After coder completes, review changes with subagents. Give reviewers full context: what was intended, what to look for, what to read. When triaging feedback: real issues are real regardless of "pre-existing" or "out of scope" — but stay focused. If unsure whether a finding is actionable, escalate to the human. Never silently discard findings.
4. **Fix and re-review.** Actionable findings go back to coder agents. After fixes, re-review. Repeat until zero findings twice in a row (double-zero rule).

**Parallelization rules:**
- **Planning agents in parallel: OK.** Planning large swaths keeps work aligned across implementation agents.
- **Coder agents: conservative.** Max 2-3 coding agents at once.
- **Never mix phases.** Don't run planners, explorers, and coders simultaneously. Plan fully → review plans → then code.
- Doing fewer things right > doing more things fast.

**Orchestrator responsibilities:**
- Maintain coherence across chunked work items — ensure consistency between chunks.
- Validate that agent output aligns with the plan and referenced issues.
- Keep context lean — delegate, don't accumulate.

**Orchestrator verification protocol (MANDATORY after every agent merge):**
- Verify against the PUSHED REMOTE branch (`git show origin/branch:file`), never the local working directory. Local state may be on a different branch.
- For type deletions: `grep -c "struct TypeName" <file>` must return 0.
- For imports: `grep -c "scp_protocol::module" <file>` must return >0.
- Run the exact CI clippy command with ALL features before pushing: `cargo clippy --workspace --all-targets --features scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/testing,scp-runtime/saga-witness-test-mint,scp-ffi/outlet-capability-test-grant,scp-ffi-napi/outlet-capability-test-grant,scp-ffi-uniffi/outlet-capability-test-grant -- -D warnings`
- If a cherry-pick resolves to "nothing to commit," the changes DID NOT LAND. Investigate.
- Never say "done" without showing verification output.

**Agent execution rules (MANDATORY):**
- **Write every agent prompt as a contract, never as your recipe.** State what the agent must make true, and state how you will check it. Then, separately and labelled as such, give the recipe you would have followed: the files to read, the greps to run, the symbols to trace. An agent that receives only a recipe satisfies the recipe and reports success, which is how `let _ = function_name;` came to satisfy a string-search test while calling nothing. The same rule governs the standing agent definitions in `.claude/agents/`: each one states its verdict criterion, and its review dimensions serve that criterion as evidence rather than replacing it.
- Every agent prompt must specify which branch to start from. Include: "Verify with `git log --oneline -3` that you see [expected commits]. If not, STOP."
- Never checkout migration/feature branches on the main worktree. All branch work happens in worktrees. Main worktree stays on main.
- When the plan says "delete X and import Y," agents MUST delete X and import Y. No excuses. "Different serde format," "different field types," "architectural mismatch" are NOT valid reasons to keep local reimplementations when there are zero consumers. The only valid reason is a compiler-level mechanical restriction.
- When an agent hits friction (type is `pub(crate)`, missing derive, missing method), fix the impediment — don't work around it by keeping the reimplementation.
- Don't manually edit code to fix clippy warnings. Use `cargo clippy --fix` or dispatch an agent.
- Parallel coding agents that touch the same files WILL conflict. Run them sequentially, not in parallel.

## Scope discipline

**When asked to verify, audit, or review "everything," enumerate the full scope FIRST:**
1. `ls` the repo root. Every top-level directory is in scope unless explicitly excluded.
2. List what you're going to check BEFORE you start checking it. Show the list. If a directory exists and you're not planning to check it, that's a gap — flag it or justify the exclusion.
3. The system has layers. Rust core (`crates/`) is one layer. FFI bridges (`crates/scp-ffi/`) are another. Language SDK wrappers (`bindings/`) are a third. Tests, specs, and CI are more. Never audit one layer and call it complete.
4. When comparing coverage across implementations (bridges, SDKs, platforms), build a MATRIX first — all operations × all targets. Fill every cell. Empty cells are findings.
5. "Done" means done at every layer. A Rust function without an FFI export is half-done. An FFI export without a language wrapper is half-done. A wrapper without tests is half-done.

## Project Map

```
.claude/             # Operating instructions and tools
├── agents/          # Agent definitions (see agents/README.md)
├── agent-memory/    # Per-agent persistent memory
└── skills/          # /-commands

.docs/               # Project knowledge (root instance + per-feature local instances)
├── architecture.md  # Engineering blueprint — phases, SDK strategy, crate layout
├── sketch.md        # API surface sketches — pseudocode for all operations
├── adrs/            # Architecture Decision Records (phase-1 through phase-6)
├── lessons/         # Evergreen learnings, grouped by topic
├── planning-sessions/
├── runbooks/        # Operator runbooks (incident diagnosis + remediation)
├── scaffold/        # Per-language SDK build blueprints
├── specs/           # Product specs — what to build
└── standards/       # Coding and workflow standards. NON-NEGOTIABLE

crates/              # Rust workspace — the protocol core
├── scp-protocol/    # Pure sync protocol types (no tokio, compiles for wasm32)
├── scp-runtime/     # Async orchestration (Supervisor actor-per-context, MLS, providers)
├── scp-core/        # Facade re-exporting scp-protocol + scp-runtime
├── scp-ffi/         # FFI bridges — 3 targets, one codebase
│   ├── src/         #   PyO3 (Python) — the REFERENCE bridge (100% coverage target)
│   ├── uniffi/      #   UniFFI (Swift, Kotlin)
│   └── napi/        #   napi-rs (Node.js/Bun → TypeScript)
├── scp-identity/    # Native DID subsystem — DID-method, resolution/publication/lifecycle
├── scp-dht/         # Native DHT transport leaf — DhtClient/DhtRecord/InMemory/Pkarr + BEP44 helpers (ADR-057 in-browser client, task T1c-a)
├── scp-clock/       # Clock port (wall-clock time) — wasm-safe capability leaf
├── scp-crypto/      # Ed25519 signature verification — wasm-safe capability leaf
├── scp-did/         # DID data model (DID, SigningKeyId, DidDocument, proofs, attestation) — wasm-safe
├── scp-mls/         # Synchronous MLS state machine — wasm-safe, shared by node + browser (ADR-057 in-browser client)
├── scp-client/      # Single-threaded in-browser participant driver over scp-mls (ADR-057 in-browser client)
├── scp-client-wasm/ # wasm-bindgen browser surface over scp-client (ADR-057 in-browser client)
├── scp-transport/   # Relay, adapters, blob storage
├── scp-node/        # Application node binary (relay + HTTP + identity)
├── scp-platform/    # Platform abstractions (KeyCustody, Storage, DeviceAttestation)
├── scp-media/       # Media key derivation, signaling
├── scp-event-log/   # Merkle event log
├── scp-testing/     # Conformance macros, E2E tests, test adapters
└── scp-relay/       # Standalone relay binary

bindings/            # Language SDK wrappers — the developer-facing API
├── python/          # scp_sdk package (wraps PyO3 bridge)
├── typescript/      # @limn-works/scp-ts (wraps NAPI bridge; browser = in-browser SCP client over scp-client-wasm, keys on-device per ADR-057, the in-browser client)
├── swift/           # SCP Swift package (wraps UniFFI bridge)
└── kotlin/          # scp-kt (wraps UniFFI bridge) — Android extensions
```
