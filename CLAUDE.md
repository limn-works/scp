# Shareable Context Protocol (SCP)

## Vision

SCP is an open, ecosystem-agnostic infrastructure protocol — the social layer for software built by and for AI agents: cryptographically verifiable identity (DID), governed interaction spaces (contexts), trustworthy communication (MLS encryption), capability-based authorization (UCAN), and transparent provenance. All interaction happens within contexts — bounded, encrypted, governed spaces where membership is enforced by cryptography, not infrastructure. Rust core with bindings via PyO3 (Python), UniFFI (Swift, Kotlin), wasm-bindgen (TypeScript). Transport abstracted behind an adapter trait (SCP native relay + 17 adapters). Build phases defined in `.docs/adrs/`.

### Protocol tenets

- **Provenance everywhere.** All non-private data carries verifiable origin metadata. The absence of provenance is itself a signal.
- **Human accountability.** Every agent traces to a human DID through attestation chains. Behavioral records are durable.
- **Context isolation.** All interaction within bounded contexts. Cross-context data flow is explicit and governed. The security boundary.
- **Encryption-as-access-control.** MLS group keys enforce membership. Relays are untrusted dumb pipes.
- **Legibility before opt-in.** Context parameters visible before joining. Informed consent is mechanical.
- **Protocol requires no operator.** Must work if Limn disappears tomorrow.
- **Transport independence.** No structural coupling to any single transport.
- **Agents are participants, not enforcers.** Same rules as any human-bound participant.
- **Trust is contextual.** Function of identity, capability, context, and behavior — not binary.

### Builder tenets

- **No deferral.** Everything gets specced and implemented now. Nothing is "v2" or "future."
- **No DOA decisions.** Design decisions are permanent commitments. If it needs replacing later, it's the wrong choice now.
- **Simple over complex.** Never at the expense of functionality, security, or completeness.
- **Completeness is the baseline.** Every feature, every edge case, every acceptance criterion — implemented fully or not at all. Maximum breadth. Improve post-completion, not to reach completion. Partial implementations are failures.
- **SDK first.** Rust core + bindings before any app.
- **Enforce mechanically.** Linters, structural tests, and the type system — not documentation.
- **Artifacts are the system of record.** If an agent can't find it, it doesn't exist.
- **Root-cause orientation.** Bugs are architecture flaws first, local defects second.
- **No shortcuts.** No force unwraps, no placeholders, no "good enough."
- **Provenance is paramount.** Every line traces to a documented decision. Chain: `.docs/` sources → `.docs/prds/` stories (or GitHub comments, feature-local artifacts). Before writing or changing code, read the full provenance chain — not summaries, not headers, the actual artifacts. Fresh agents must retrace full context quickly. Broken provenance is a bug.

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

### Loom Plugin — Autonomous dev loop ([instructions](./.claude/LOOM_PLUGIN.md))

User provides a directive → dispatches parallel subagents → runs tests → commits green code → repeats. State and logs at `.loom/`. Use when given one of the / commands.

## Rules

**Operating model:**
- Humans steer. Agents execute. No human-written code; only human-driven specs.
- Context is scarce — give agents a map, not a manual
- Provenance must always be maintained and traced back. Read the actual source artifacts — specs, ADRs, PRDs, standards — before making changes. Skimming is not reading.
- Be autonomous: infer from context, code, artifacts. Escalate only for genuine judgment calls.
- Go deep on references. When a spec cites a section, read that section. When code references a story, read the story. When an ADR lists alternatives, understand why they were rejected. Surface-level understanding produces surface-level code.

**Artifact flow (INVARIANT):**
- The flow is strictly one-way: **plans → specs → ADRs → stories → source code.**
- Upstream artifacts govern downstream artifacts. Never the reverse. Code does not inform specs. Stories do not reshape or request ADRs. Implementation details do not change plans.
- If code reveals that a spec is wrong, **stop writing code.** Fix the spec first, then update downstream artifacts, then resume implementation. The fix flows down; it never flows up from code.
- If a story can't be implemented as written, the story is wrong — update the story (and its upstream sources if needed) before writing code that contradicts it.
- Violating this invariant creates phantom provenance: code that appears grounded in artifacts but actually diverges from them. This is worse than no provenance at all.

**Workflow:**
- Plan mode for all non-trivial tasks (3+ steps or architectural decisions)
- Aggressively reference and update `.docs/`; add lessons after any correction
- Check `.docs/standards/` before writing code — read and follow them
- Subagents: use liberally, one task each, keep main context clean
- Verify all gates, tests, and builds pass before deciding you are done

**Architecture:**
- Protocol-first design; inject through initializers; no singletons
- APIs: self-evident, one happy path

**PRD stories (MANDATORY):**
- **Before creating, editing, or updating any story in `.docs/prds/`**, read `.docs/standards/prd.md` in full. No exceptions.
- Every field in the standard is required. Every acceptance criterion must be machine-verifiable. Every source must trace to an actual heading in an actual file. Every dependency must be forward-only.
- The artifact flow applies to stories: stories reference specs and ADRs, never the reverse. If a story can't cite a spec section or ADR, it needs one written first.
- Run `python3 scripts/validate-prd.py` before committing PRD changes. CI enforces this.
- Subagents creating stories must self-validate against the standard before returning. Two audits missed quality issues because no one checked their own output — that failure mode is why this standard exists.

**Stubs:**
- Every stub must reference a PRD story ID (`// Stub — see SCP-NNN`)
- Stories marked "done" must have zero stubs against their acceptance criteria
- CI enforces: Rust (`clippy::todo/unimplemented = "deny"`), Kotlin (detekt `ForbiddenComment`), Python (ruff `FIX`), Swift (SwiftLint `todo`), TypeScript (ESLint `no-warning-comments`)
- See `.docs/standards/sdk-common.md` §Stub and Placeholder Policy

### Toolchain

All tools via [mise](https://mise.jdx.dev/) (see `.mise.toml`). **Never use npm or npx** — bun only for JS/TS. System `python3` is Xcode 3.9 — **do not use it**; use `python3.12`.

| Language | Location | Package Manager | Lint | Format | Test | Build |
|----------|----------|----------------|------|--------|------|-------|
| **Rust** | `crates/` | cargo (workspace) | `cargo clippy --workspace --all-targets` | `cargo fmt --all` | `cargo test --workspace` (needs `DYLD_LIBRARY_PATH` below) | `cargo build --workspace` |
| **Python** | `bindings/python/` | pip + maturin | `python3.12 -m ruff check .` | `python3.12 -m ruff format .` | `python3.12 -m pytest tests/ -v` | `maturin develop --release` |
| **TypeScript** | `bindings/typescript/` | **bun** (not npm) | `bun run lint` (biome) | `bun run format` (biome) | `bun test` | `bun run build` (tsup) |
| **Kotlin** | `bindings/kotlin/` | Gradle 8.x | `./gradlew detekt` | — | `./gradlew :scp-sdk-kotlin:test :scp-sdk-kotlin-android:testDebugUnitTest` | `./gradlew assembleRelease` |
| **WASM** | `crates/scp-ffi/wasm/` | cargo | `cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown` | `cargo fmt` | conformance via `cargo test -p scp-core --test wasm_conformance` | `wasm-pack build crates/scp-ffi/wasm --target bundler` |

**Language-specific gotchas:**

- **Rust/Python linkage:** `cargo test -p scp-ffi` and `cargo test --workspace` require `DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")`
- **Kotlin:** JDK 17 (zulu), Gradle 8.x, Kotlin 2.x — all via mise. Run `eval "$(mise env)"` first. Release unit tests fail (pre-existing ProGuard issue); CI only runs `assembleRelease` + `jar`, no test task.
- **WASM:** Cannot depend on scp-core (tokio multi-thread). Re-implements algorithms locally. See ADR-034.
- **TypeScript:** `bun run check` runs `tsc --noEmit` for type checking. Biome handles both lint and format.
- **PRD validation:** `python3.12 scripts/validate-prd.py` — run before committing PRD changes.

### Git

- Worktrees for non-trivial changes or when you're not already in one
- Topical branch names with source ids when available
- Conventional commits referencing artifacts/sources. Atomic, revertable — never bundle unrelated changes
- PR titles and descriptions: describe scope, impact, and linked tickets/stories. Use closing keywords ("closes #42")
- Clean, linear history
- Unexpected changes: back off, read, understand before acting. Never discard without understanding first
- No stashing/branch switching unless 100% confident. No destructive git ops unless told to or integrated upstream

## Agents

Use eagerly for focus, expertise, and parallelization. See `.claude/agents/README.md` for the full roster.

Default review agents: @"black-hat (agent)", @"red-hat (agent)", @"white-hat (agent)", @"security-reviewer (agent)", @"cryptographer (agent)", @"bug-catcher (agent)", @"chronicler (agent)", @"alignment-reviewer (agent)", @"api-design-reviewer (agent)", @"simplifier (agent)". Use discretion to add or remove based on review contents.

**Reviews are not rubber stamps.** Read every finding. If a reviewer flags something, understand the concern fully before dismissing it. Assume reviewers are right until you can prove otherwise with evidence from specs or code. Act on review feedback — don't acknowledge and move on. When a review surfaces a real issue, fix it and update the relevant artifacts.

## Project Map

```
.claude/             # Operating instructions and tools
├── agents/          # 21 agent definitions (see agents/README.md)
├── agent-memory/    # Per-agent persistent memory
└── skills/          # /-commands

.docs/               # Project knowledge (root instance + per-feature local instances)
├── architecture.md  # Engineering blueprint — phases, SDK strategy, crate layout
├── sketch.md        # API surface sketches — pseudocode for all operations
├── adrs/            # Architecture Decision Records (phase-1 through phase-6)
├── lessons/         # Evergreen learnings, grouped by topic
├── planning-sessions/
├── scaffold/        # Per-language SDK build blueprints
├── specs/           # Product specs — what to build
└── standards/       # Coding and workflow standards. NON-NEGOTIABLE
```
