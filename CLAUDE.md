# Shareable Context Protocol (SCP)

## Vision

Software is shifting from something we labor to craft into something manufactured on demand. We are early in this transition, but the trajectory is clear: production-ready apps built entirely by agents in hours or days — work that would have taken teams weeks or months, at a fraction of the cost. These apps are being commissioned by non-technical people operating agentic flows like OpenClaw, not by engineers writing code. Everything points to a world in the near future where software is on-demand, disposable, and highly personal. Agents will soon be building an overwhelming majority of the world's software. Without a guarantee that these ephemeral clients can exchange durable state, and without a strong, agent-optimized protocol for doing so, the result is fragmented apps saved only by monolithic solutions from established enterprises like Apple, Google, and Meta. SCP is the open, functional answer — not just an ethical alternative to platform lock-in, but the functionally preferable one: no opinions, easy adoption, collective contribution, and unlimited integration.

SCP (Shareable Context Protocol) is an open, ecosystem-agnostic infrastructure protocol that provides the social layer for software built by and for AI agents: cryptographically verifiable identity (DID), governed interaction spaces (contexts), trustworthy communication channels (MLS encryption), capability-based authorization (UCAN), and transparent provenance. App generation is becoming trivial — agents increasingly build ephemeral, personalized software on demand. What remains hard is the connective tissue between these clients and the humans and agents using them: identity, trust, relationships, and accountability. SCP is that connective tissue. The core is implemented in Rust with language bindings via PyO3 (Python), UniFFI (Swift, Kotlin), and wasm-bindgen (TypeScript). Client SDKs handle identity management, context participation, encryption, and transport — everything a client needs to join and interact within contexts. Server SDKs handle relay operation, message routing, and storage — everything needed to run SCP infrastructure. Both are optional and independent: a client can connect to any conforming relay, and relay operators need no knowledge of client implementations. All interaction happens within contexts — bounded, encrypted, governed spaces where membership is enforced by cryptography, not infrastructure. Transport is fully abstracted behind an adapter trait with an SCP native relay as the canonical reference and 17 additional adapters (Nostr, Matrix, libp2p, Hyperswarm, WebSocket, etc.). The build follows phased delivery defined in `.docs/adrs/`.

### Protocol tenets

- **Provenance everywhere.** All non-private data carries verifiable origin metadata. Every message, tool output, attestation, and cross-context data transfer is traceable to its source. The absence of provenance is itself a signal.
- **Human accountability.** Every agent can be traced to a human DID through attestation and delegation chains. The protocol provides the mechanism; contexts decide the requirement. Unattested DIDs are valid participants. Behavioral records are durable — actions have consequences that persist across contexts.
- **Context isolation.** All interaction happens within bounded contexts. Cross-context data flow is explicit and governed. This is the security boundary.
- **Encryption-as-access-control.** Context membership is enforced cryptographically through MLS group keys. Relays are untrusted dumb pipes; the math enforces access, not infrastructure.
- **Legibility before opt-in.** Every context's parameters — capability ceiling, governance, roles, tools, TTL, memory scope — are visible before joining. No hidden terms. Informed consent is mechanical.
- **Protocol requires no operator.** Every mechanism must work if no one runs centralized infrastructure. If Limn disappears tomorrow, SCP works exactly as designed.
- **Transport independence.** No structural coupling to any single transport. The protocol drives transport choice, not the reverse.
- **Agents are participants, not enforcers.** Agents use contexts and tools like any other participant. The protocol doesn't distinguish between a sophisticated autonomous agent and a simple passthrough — both are human-bound participants with the same rules.
- **Trust is contextual.** Trust is a function of identity, capability, context, and behavior — not a binary property. Alice might trust Bob in one context but not another. The protocol enables that granularity.

### Builder tenets

- **No deferral.** Everything discussed gets specced and implemented. Nothing is "v2" or "future." Metadata privacy, sender-side key layer, transport independence — all implemented now.
- **No DOA decisions.** Don't ship into something you plan to abandon. Design decisions are permanent commitments, not stepping stones. If it needs replacing later, it's the wrong choice now.
- **Simple over complex.** Prefer elegant, low-overhead solutions — but never at the expense of functionality, security, or completeness.
- **Completeness is the baseline.** Plan and execute at maximum breadth. Use time to improve and expand post-completion, not to reach the completed state.
- **SDK first.** Ship Rust core + language bindings before any app. The agent ecosystem is the audience.
- **Enforce mechanically.** Invariants are enforced by linters, structural tests, and the type system — not by documentation. Documentation drifts; automation doesn't.
- **Artifacts are the system of record.** All knowledge — decisions, patterns, constraints, product context — lives in-repo as discoverable artifacts. If an agent can't find it, it doesn't exist.
- **Root-cause orientation.** Bugs come from poor decisions upstream. Treat them first as architecture flaws, second as local defects. Don't patch around bad foundations — fix or replace them.
- **No shortcuts.** The best solution is the right one. No force unwraps, no placeholder implementations, no "good enough." Ship excellent, complete, production-ready code.
- **Provenance is paramount.** Every line of code must trace back to a documented decision. Typically this will be: source(s) in ~/.docs/ > story in .docs/prds/. But it may be more complex, involving comments in GitHub or feature-local .docs/ artifacts. No matter how long the chain, provenance must be maintained so that full context is retraceable for every line of code, and fresh agents with no memory can obtain it quickly and easily.

## Available Tools

### Context+ MCP

**What it is**
Semantic codebase mapping for context-optimized information retrieval.

**How it works**
`get_context_tree` → `get_file_skeleton` → `semantic_code_search` / `semantic_identifier_search` → `get_blast_radius` before modifying symbols → `propose_commit` to write → `run_static_analysis` to validate.

**When to use**
Every time you search the codebase.

[Instructions](./.claude/CONTEXT_MCP.md)

### Vestige MCP

**What it is**
Long-term cognitive memory for agents.

**How it works**
`session_context` at start → `search` before decisions → `smart_ingest` to save (auto-deduplicates) → `codebase` for project patterns/decisions → `intention` for reminders → `memory` for promote/demote. Memories decay via spaced repetition; searching strengthens recall.

**When to use**
Every time you receive or recall information.

Instructions are already available from the user-scope CLAUDE.md file.

### Loom Plugin

**What it is**
Autonomous development loop with parallel execution.

**How it works**
User provides a source → command dispatches parallel subagents → runs tests → commits green code → repeats. State and logs persist in `.loom/`. Supports worktrees and auto-opening PRs.

**When to use**
When instructed to via one of the slash commands.

[Instructions](./.claude/LOOM_PLUGIN.md)

## Rules

**Operating model:**
- Humans steer. Agents execute. No human written code; only human driven specs.
- Context is scarce — give agents a map, not a manual. Monolithic artifacts rot
- Provenance must always be maintained, and always be traced back. Everything along the provenance chain must be kept up to date. All sources along the chain should read and referenced before making changes or decisions.
- Be autonomous: infer from context, code, artifacts. Escalate only for genuine judgment calls

**Workflow:**
- Plan mode for all non-trivial tasks (3+ steps or architectural decisions)
- Aggressively reference and update `.docs/`; add lessons after any correction
- Check `.docs/standards/` before writing code — read and follow them
- Subagents: use liberally, one task each, keep main context clean
- Verify all gates, tests, and builds pass before deciding you are done

**Architecture:**
- Protocol-first design; inject through initializers; no singletons
- APIs: self-evident, one happy path

**Stubs:**
- Every stub must reference a PRD story ID (`// Stub — see SCP-NNN`)
- Stories marked "done" must have zero stubs against their acceptance criteria
- Each language enforces via CI: Rust (`clippy::todo/unimplemented = "deny"`), Kotlin (detekt `ForbiddenComment`), Python (ruff `FIX`), Swift (SwiftLint `todo`), TypeScript (ESLint `no-warning-comments`)
- See `.docs/standards/sdk-common.md` §Stub and Placeholder Policy

### Toolchain

All project tools are managed via [mise](https://mise.jdx.dev/) (see `.mise.toml`). The system `python3` is Xcode's Python 3.9 — **do not use it**. Always use `python3.12` for anything Python-related (tests, maturin, pip). Key commands:
- `cargo test -p scp-ffi` requires: `DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") cargo test -p scp-ffi`
- `cargo test --workspace` includes scp-ffi — set `DYLD_LIBRARY_PATH` or it will fail to link
- Kotlin/Android: JDK 17 (zulu), Gradle 8.x, Kotlin 2.x — all via mise
- WASM: `wasm-pack` via cargo, `wasm32-unknown-unknown` target installed

### Git

- Use worktrees for non trivial changes or when you're not already in one
- Use topical branch names. Include source ids if available (ticket or issue number/name/source)
- Write conventional commits and reference artifacts and sources in title and body
- Write topical PR titles and descriptions. Actually describe the scope and impact of the changes, along with detailed info about the tickets/issuse/stories/artifacts that pertain to the PR. When closing issues, use keywords ("closes #42") so that GitHub auto-updates their status.
- Always create atomic, revertable commits. Do not bundle unrelated changes into a single commit
- Keep a clean and linear history
- When you see unexpected changes, back off. Assume that another human or agent is also working in the repo. Read them to understand what's going on before doing anything. Never discard without doing those steps first
- Avoid stashing or changing branches unless you are 100% confident in your understanding of the current state, or you were told to
- Never use destructive git operations unless told to, or if you are 100% confident that they have been integrated upstream

## Agents

Use agents eagerly for focus, expertise, and parallelization — especially code reviews. See `.claude/agents/README.md` for the full roster.

## Project Map

### Agentic harness & artifacts:

.claude/             # Claude's project-wide operating instructions and tools
├── agents/          # 21 agent definitions — 8 core specialists + 13 reviewers (see agents/README.md)
├── agent-memory/    # Per-agent persistent memory (each dir maps to an agent)
└── skills/          # Skills (/-commands executable by the user and Claude)

.docs/               # Project knowledge — one root instance, additional local instances per feature (may have different contents)
├── architecture.md  # Engineering blueprint — build phases, SDK strategy, crate layout
├── sketch.md        # API surface sketches — pseudocode for all protocol operations
├── adrs/            # Architectural Decision Records — how to build (phase-1, phase-2, phase-3)
├── lessons/         # Evergreen learnings, one per file, grouped by topic (e.g. lessons/swift/)
├── planning-sessions/ # Historical planning session records
├── scaffold/        # Global and per-language SDK operational setup plans (covers *how*, not *what*)
├── specs/           # Product and project specifications — what to build (includes open questions)
└── standards/       # Coding and workflow standards. NON-NEGOTIABLE

### Memory

In addition to permanent context provided by artifacts, you have access to an MCP server for memory called "vestige". Liberally read and write to this memory during all operation modalities, and ensure subagents do the same.

### Agent Reviews

These agents should generally be used:

- @"black-hat (agent)"
- @"red-hat (agent)"
- @"white-hat (agent)"
- @"security-reviewer (agent)"
- @"cryptographer (agent)"
- @"bug-catcher (agent)"
- @"chronicler (agent)"
- @"alignment-reviewer (agent)"
- @"api-design-reviewer (agent)"
- @"simplifier (agent)"

You should use discretion to add or remove agents from this roster based on the review contents.
