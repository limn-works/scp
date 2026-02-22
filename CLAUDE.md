# Social Context Protocol (SCP)

This is a fully agentic code base. 100% of code is written by AI. None of it is written by humans. Humans are creating the product decisions, guidelines, and specifications; writing documentation and guidelines for implementing them in conversation with AI. AI is taking that input and turning it into actionable items to give to itself to execute and write code. With this in mind, understand that:
- There is no such thing as MVP, or a partial state of completion, or the next iteration. The most valuable thing that can be done is specc'ing out things to completion and executing them to completion
- Deferring work is almost always harmful unless there's no other choice. It is almost never helpful or strategically advisable
- Tests and gates are of the utmost importance to verify that work is functional, correct, and bug-free
- Artifacts of all sorts are extremely important for persisting information across contexts
- Context rot and drift are some of the most insidious problems that can cause issues with the code over time, and should be avoided at all costs

## Rules

These shape every interaction. Violations cause damage.

**Operating model:**
- Humans steer. Agents execute. No human written code
- Context is scarce — give agents a map, not a manual. Monolithic artifacts rot
- Enforce invariants mechanically (linters, structural tests, type system), not via documentation
- Abandon classical notions of scope, timeline, MVP, and next-iterations that are derived from human limitations. When agents write 100% of the code, it becomes cheap and malleable. Completeness is the baseline requirement. By default, always execute and plan at maximum currently established breadth to achieve completeness.

**Code quality:**
- Enterprise grade, battle-ready, prinicpal quality, defect free
- Bugs typically come from poor decisions upstream due to bad architecture or assumptions. Treat them first as such, and as local defects second. Find root causes, and do not be afraid to abandon and rewrite things that don't are problematic (be sure to update artifacts when you do).
- Do not leave work for todos, the next version/iteration, or later, unless you have been explicitly told to. Everything is to be done to completion, regardless of what you think about the scope.
- The best solution is the right one; no shortcuts just to move on.
- Be autonomous: infer from context, code, artifacts. Escalate only for genuine judgment calls.
- APIs: self-evident, one happy path. 

**Workflow:**
- Plan mode for all non-trivial tasks (3+ steps or architectural decisions)
- Aggressively reference content in `.docs/`
- Repository is the system of record — always capture and update knowledge in relevant `.docs/` before session ends
- After any correction or remediated error (human or agent): add a lesson to the relevant `.docs/lessons/`
- Subagents: use liberally, one task each, keep main context clean
- No TODOs, FIXMEs, placeholders, or "good enough." Ship excellent, complete, production ready code
- Verify all gates, tests, and builds pass before deciding you are done

**Architecture:**
- Layers: UI → Domain → AI → Data → Network. Dependencies flow down only
- Protocol-first design; inject through initializers; no singletons

## Standards

When writing code, always check for applicable docs at the root `.docs` directory, and any relevant local `.docs` directories that may be present. If there are relevant files in `standards/`, you must ALWAYS read and FOLLOW them.

## Agents

Use agents eagerly. Any time a relevant agent/s can provide focus and expertise, as well as a chance to parallelize work, use it/them — espescially for code reviews.

See `agents/README.md` for the full roster, triggers, and coordination.

## Project Map

### Agentic harness & artifacts:

.ralph/              # Agentic coding loop for tasks of any size. Only one at root.
├── prd.json         # tk
├── tk/              # tk
└── tk/              # tk

.claude/             # Claude's project-wide operating instructions and tools. Only one at root.
├── agent-memory/    # Agent-specific memories (each dir maps to an agent)
├── agents/          # Agent definitions for specialized work
└── skills/          # Slash command definitions

.docs/               # One project-wide version at root, with any number of additional versions local to features.
├── adrs/            # ADRs (how to build)
├── lessons/         # Evergreen learnings (one per file)
├── specs/           # Product/project specs (what to build)
└── standards/       # Coding and workflow standards. NON-NEGOTIABLE
