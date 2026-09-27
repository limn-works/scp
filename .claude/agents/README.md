# Agent Model

This project uses specialized agents for different architectural concerns. Each agent owns a vertical slice of responsibility.

## Every agent definition is a contract

An agent file must say, in one sentence, what the agent has to confirm before it reports a verdict. The rest of the file tells the agent where to look. An agent that has run every check in the file still has to confirm that one thing, and the file must say so.

An agent handed a checklist and no criterion completes the checklist and reports success. That is how `let _ = function_name;` came to satisfy a string-search test while calling nothing.

Every definition in this directory carries both requirements in a `## Verdict criterion` section, placed directly under the frontmatter and above every other section, so an agent reading the file top-down meets the criterion before the recipe. The section holds two labelled lines:
1. `**Criterion:**` — the criterion, in one sentence the agent can quote back. "INCOMPLETE if any acceptance criterion has no code behind it" is a criterion. "Check for stubs, check for `None`, check the matrix" is a recipe.
2. `**Indicators, not the criterion.**` — the sentence that labels the rest of the file as the place to look. Write "these dimensions are where gaps usually hide, not the definition of a gap," so an agent that exhausts the list still knows it has not yet met the criterion.

`scripts/check-agent-verdict-criterion.sh` fails the build when a definition omits the section, buries it under another section, drops either label, or leaves a label with no sentence after it. The gate reads that structure and never the meaning of the sentences, so a reviewer still applies the test in the paragraph above: a criterion states what decides the verdict, and a recipe states where to look. A `**Criterion:**` line that lists dimensions passes the gate and fails the review.

Write every agent definition to `.docs/standards/concrete-prose.md`, the writing standard that governs all prose in this repository, and rewrite to it every sentence you edit in one.

## Review rules

Every review agent follows these rules; the root `AGENTS.md` points here.

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

**Scope of an audit.** When asked to verify, audit, or review "everything", list the repository root and write down, before you start, every layer you will check: the Rust core, the FFI bridges, the SDK wrappers, tests, specs, and CI. Justify every exclusion. When you compare implementations across bridges, SDKs, or platforms, build the full operations × targets matrix first; an empty cell is a finding. A Rust function without an FFI export, or an export without a wrapper, or a wrapper without tests, is unfinished.

## Agents

| Agent | Responsibility | File |
|-------|---------------|------|
| **Architect** | Crate boundaries, protocol definitions, dependency graph, architecture decisions | `architect.md` |
| **Backend** | Rust services, runtime, storage, and relay implementation | `backend.md` |
| **Chronicler** | Documentation, knowledge capture, AGENTS.md updates | `chronicler.md` |
| **Review Agents** | | |
| **Adversarial Expert** | Ship/no-ship judgement from a paid outside skeptic's stance | `adversarial-expert.md` |
| **Black Hat** | Worst-case adversary modelling, abuse of legitimate features | `black-hat.md` |
| **Red Hat** | Offensive exploitation chains, attack-surface mapping | `red-hat.md` |
| **White Hat** | Defensive architecture, hardening, security invariants | `white-hat.md` |
| **Cryptographer** | MLS, AEAD, key management, signatures, Merkle, HPKE, UCAN, DID | `cryptographer.md` |
| **SDK Coverage Verifier** | Capability-matrix entries: public, callable, semantically correct | `sdk-coverage-verifier.md` |
| **Styler** | Conventions, naming, code organization | `styler.md` |
| **Bug Catcher** | Concurrency, crashes, logic errors, subtle defects | `bug-catcher.md` |
| **Simplifier** | Complexity, premature abstractions, change atomicity | `simplifier.md` |
| **Lint Diagnostics** | Compiler errors/warnings, build verification | `lint-diagnostics.md` |
| **Architecture Reviewer** | Completeness, scalability, maintainability, ADR compliance | `architecture-reviewer.md` |
| **Alignment Reviewer** | Intent verification, product/spec/roadmap alignment | `alignment-reviewer.md` |
| **Completionist** | Missing/mismatched implementations, unwired code, inter-layer gaps, artifact divergence | `completionist.md` |
| **Inquisitor** | Premise/decision soundness, sunk-cost & status-quo challenges, cross-slice coherence, drift/rot | `inquisitor.md` |
| **API Design Reviewer** | API quality, discoverability, misuse resistance, devx | `api-design-reviewer.md` |
| **Security Reviewer** | Auth, secrets, injection, info leakage | `security-reviewer.md` |
| **Performance Optimizer** | Blocking operations, memory leaks, hot paths, lock contention | `performance-optimizer.md` |
| **Test Quality Reviewer** | Test coverage ROI, behavior vs implementation, flakiness | `test-quality-reviewer.md` |
| **Tester** | Test execution, pass/fail reporting | `tester.md` |
| **Dependency Safety Reviewer** | Dependencies, breaking changes, observability | `dependency-safety-reviewer.md` |

## When to use which agent

The "Default review roster" paragraph in the Agents section of the root `AGENTS.md` names the review roster that runs on every code change. The table below names the condition under which each agent applies.

| Agent | Condition |
|-------|----------|
| **Architect** | A change creates a crate or module, adds a dependency edge, or defines a protocol that no ADR yet governs |
| **Backend** | Implementation work in the Rust runtime, storage, relay, or node crates |
| **Chronicler** | A decision, a correction, or an artifact change needs recording in `.docs/` or `AGENTS.md` |
| **Black Hat** | Protocol changes, trust assumptions, any feature an attacker could turn against a participant |
| **Red Hat** | Security-sensitive changes where you need the exploitation chain, not the vulnerability list |
| **White Hat** | New defensive controls, hardening work, security-invariant definitions |
| **Cryptographer** | Any change touching a cryptographic construction, key lifecycle, or proof |
| **Styler** | Convention changes, naming changes, new patterns |
| **Bug Catcher** | Changes to concurrency, persistence, error paths, or merge-conflict resolutions; debugging a crash |
| **Simplifier** | Any change under review; complexity audits |
| **Lint Diagnostics** | A build or lint run whose output would crowd the requesting agent's context |
| **Architecture Reviewer** | Structural changes, new modules, protocol modifications, pattern-setting changes |
| **Alignment Reviewer** | A change that implements a spec or PRD story, or alters scope |
| **Completionist** | Protocol logic spanning core, bridges, and SDKs; story-closing changes; spec, ADR, or PRD edits; any "done" claim |
| **Inquisitor** | Changes that establish or perpetuate a decision, patterns copied from existing code, "already built" arguments, design and architecture artifacts |
| **API Design Reviewer** | New protocols, public interface changes, module boundaries |
| **Security Reviewer** | Auth, UCAN, and DID code, secrets handling, untrusted-input parsing, error responses |
| **Performance Optimizer** | Hot paths, async flows, lock-holding code, allocation-heavy code |
| **Test Quality Reviewer** | Test files added or modified |
| **Tester** | A test-suite run whose output would crowd the requesting agent's context |
| **Dependency Safety Reviewer** | Changes to `Cargo.toml`, `Cargo.lock`, or a binding's package manifest; public API breaks |
| **Adversarial Expert** | Before building on unreviewed foundation code, or when you need a ship/no-ship call |
| **SDK Coverage Verifier** | Changes under `bindings/` or to `sdk-capability-matrix.json` |
