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

Every review agent also follows "Review the class, not the instance" in the Agents and review section of `AGENTS.md`: it searches the sibling sites before it writes a finding and reports every site it found as one finding. That statement in `AGENTS.md` is the authoritative one, so no agent definition repeats it.

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

The "Default review roster" paragraph in the Agents and review section of `AGENTS.md` names the review roster that runs on every code change. The table below names the condition under which each agent applies.

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
