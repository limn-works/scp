# Social Context Protocol (SCP)

## Vision

Software is shifting from something we labor to craft into something manufactured on demand. We are early in this transition, but the trajectory is clear: production-ready apps built entirely by agents in hours or days — work that would have taken teams weeks or months, at a fraction of the cost. These apps are being commissioned by non-technical people operating agentic flows like OpenClaw, not by engineers writing code. Everything points to a world in the near future where software is on-demand, disposable, and highly personal. Agents will soon be building an overwhelming majority of the world's software. Without a guarantee that these ephemeral clients can exchange durable state, and without a strong, agent-optimized protocol for doing so, the result is fragmented apps saved only by monolithic solutions from established enterprises like Apple, Google, and Meta. SCP is the open, functional answer — not just an ethical alternative to platform lock-in, but the functionally preferable one: no opinions, easy adoption, collective contribution, and unlimited integration.

SCP (Social Context Protocol) is an open, ecosystem-agnostic infrastructure protocol that provides the social layer for software built by and for AI agents: cryptographically verifiable identity (DID), governed interaction spaces (contexts), trustworthy communication channels (MLS encryption), capability-based authorization (UCAN), and transparent provenance. App generation is becoming trivial — agents increasingly build ephemeral, personalized software on demand. What remains hard is the connective tissue between these clients and the humans and agents using them: identity, trust, relationships, and accountability. SCP is that connective tissue. The core is implemented in Rust with language bindings via PyO3 (Python), UniFFI (Swift, Kotlin), and wasm-bindgen (TypeScript). Client SDKs handle identity management, context participation, encryption, and transport — everything a client needs to join and interact within contexts. Server SDKs handle relay operation, message routing, and storage — everything needed to run SCP infrastructure. Both are optional and independent: a client can connect to any conforming relay, and relay operators need no knowledge of client implementations. All interaction happens within contexts — bounded, encrypted, governed spaces where membership is enforced by cryptography, not infrastructure. Transport is fully abstracted behind an adapter trait with an SCP native relay as the canonical reference and 17 additional adapters (Nostr, Matrix, libp2p, Hyperswarm, WebSocket, etc.). The build follows phased delivery defined in `.docs/architecture.md` §6, with Architecture Decision Records in `.docs/adrs/`.

### Protocol tenets

- **Provenance everywhere.** All non-private data carries verifiable origin metadata. Every message, tool output, attestation, and cross-context data transfer is traceable to its source. The absence of provenance is itself a signal.
- **Human accountability.** Every agent traces to a human DID. No anonymous actors. Actions have consequences that persist across contexts.
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

## Rules

**Operating model:**
- Humans steer. Agents execute. No human written code
- Context is scarce — give agents a map, not a manual. Monolithic artifacts rot
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

## Agents

Use agents eagerly for focus, expertise, and parallelization — especially code reviews. See `.claude/agents/README.md` for the full roster.

## Project Map

### Agentic harness & artifacts:

**Loom loop rules for success:**
- **Atomic stories.** One subagent, one iteration (~15-30 min). Coupled work (model + migration + route) stays together; unrelated work does not.
- **Machine-verifiable acceptance criteria.** Not "it works" but "POST /api/x returns 200 with a JWT". If you can't write a test for it, Loom can't verify it.
- **File isolation for parallelism.** Stories that touch the same files cannot run in the same batch. Set `blockedBy` for true data dependencies only.
- **Green tests are a hard gate.** Never commit failing code. Failures go to status.md for the next iteration. 3 fix attempts max per iteration.
- **Context is scarce.** Read prd.json in jq waves of 10. Use dedicated tools (Read, Grep, Glob) not shell. status.md is the only cross-iteration continuity — write it thoroughly.
- **Search before building.** Always search the codebase before assuming something is missing.
- **Scope is sacred.** Implement only the assigned story. Don't "fix" adjacent code or add unrequested features.

.loom/               # Autonomous dev loop — dispatches parallel subagents from a PRD
├── loom.sh          # Main loop script — starts/stops iterations, manages tmux panes
├── prompt.md        # Autonomous iteration instructions (story selection, execution, commit)
├── directive.md     # Single-task mode instructions (execute one directive, signal result)
├── prd.json         # Structured stories with gates (P0/P1/P2), deps, acceptance criteria
├── status.md        # Current iteration state (read at start, written at end of each cycle)
├── prd.sh           # Standalone PRD generator (wraps claude -p)
├── loom-status.sh   # Status display — parses logs and status.md for summary
├── stop.sh          # Graceful stop signal
├── specs/           # Reference specs and ticket tracking for Loom
└── hooks/           # Guard rails: stop signals, interactive blocking, subagent limits

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
