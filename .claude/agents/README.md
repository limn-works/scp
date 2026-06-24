# Agent Model

This project uses specialized agents for different architectural concerns. Each agent owns a vertical slice of responsibility.

## Agents

| Agent | Responsibility | File |
|-------|---------------|------|
| **Architect** | Structure, protocols, patterns, standards | `architect.md` |
| **Data** | Persistence, models, queries, caching | `data.md` |
| **Frontend** | UI views, components, design system, navigation | `frontend.md` |
| **Network** | API transport, auth, sync, offline | `network.md` |
| **AI** | Prompts, context, response parsing, model selection | `ai.md` |
| **Backend** | Backend systems, APIs, services, server-side architecture | `backend.md` |
| **Designer** | Product design, visual design, UX, animations, brand | `designer.md` |
| **GFX** | Shaders, GPU rendering, visual effects, creative coding | `gfx.md` |
| **Chronicler** | Documentation, knowledge capture, CLAUDE.md updates | `chronicler.md` |
| **Review Agents** | | |
| **Styler** | Conventions, naming, code organization | `styler.md` |
| **Bug Catcher** | Concurrency, crashes, logic errors, subtle defects | `bug-catcher.md` |
| **Simplifier** | Complexity, premature abstractions, change atomicity | `simplifier.md` |
| **Lint Diagnostics** | Compiler errors/warnings, build verification | `lint-diagnostics.md` |
| **Architecture Reviewer** | Completeness, scalability, maintainability, ADR compliance | `architecture-reviewer.md` |
| **Alignment Reviewer** | Intent verification, product/spec/roadmap alignment | `alignment-reviewer.md` |
| **Completionist** | Missing/mismatched implementations, unwired code, inter-layer gaps, artifact divergence | `completionist.md` |
| **Frontend Reviewer** | Interactions, a11y, brand, design system, i18n | `frontend-reviewer.md` |
| **API Design Reviewer** | API quality, discoverability, misuse resistance, devx | `api-design-reviewer.md` |
| **Security Reviewer** | Auth, secrets, injection, info leakage | `security-reviewer.md` |
| **Performance Optimizer** | N+1 queries, blocking ops, memory leaks, hot paths | `performance-optimizer.md` |
| **Test Quality Reviewer** | Test coverage ROI, behavior vs implementation, flakiness | `test-quality-reviewer.md` |
| **Tester** | Test execution, pass/fail reporting | `tester.md` |
| **Dependency Safety Reviewer** | Dependencies, breaking changes, migrations, observability | `dependency-safety-reviewer.md` |

## When to Spin Up Which Agent

| Agent | Triggers |
|-------|----------|
| **Architect** | New modules, dependencies, unclear patterns, interface definitions |
| **Data** | Model changes, persistence, migrations, queries |
| **Frontend** | UI views, components, interactions, navigation |
| **Network** | API transport, auth, sync, offline handling |
| **AI** | Prompts, context management, response parsing, model selection |
| **Backend** | Backend systems, API design, services, server-side architecture, 0-1 builds |
| **Designer** | New features needing design specs, visual polish, UX flows, brand alignment |
| **GFX** | Shaders, GPU rendering, visual effects, performance-critical visuals |
| **Chronicler** | After significant changes, artifact/doc changes, permanent instructions, implementation learnings |
| **Review — always on code:** | |
| **Styler** | After writing code, during refactoring, convention changes |
| **Bug Catcher** | After writing/modifying code, debugging crashes, concurrency-heavy changes |
| **Simplifier** | After implementing features, overcomplicated code, complexity reviews |
| **Lint Diagnostics** | After writing/modifying code, verifying builds compile |
| **Architecture Reviewer** | Structural changes, new modules, protocol mods, any pattern-setting change |
| **Alignment Reviewer** | Non-trivial feature work, any change that could diverge from spec/roadmap |
| **Completionist** | Protocol logic spanning core/bridges/SDKs, story-closing changes, spec/ADR/PRD edits, any "done" claim |
| **Review — when relevant:** | |
| **Frontend Reviewer** | Views, components, navigation, any user-facing surface |
| **API Design Reviewer** | New protocols, public interface changes, service APIs, module boundaries |
| **Security Reviewer** | Auth flows, network code, secrets handling, input processing, error responses |
| **Performance Optimizer** | Database queries, async flows, data-heavy features, rendering perf |
| **Test Quality Reviewer** | When test files are added or modified |
| **Tester** | After code changes to verify tests pass |
| **Dependency Safety Reviewer** | Package/dependency changes, model changes, migrations, public API changes |

## Coordination Principles

1. **Protocol-First Communication**
   - Agents communicate through protocols defined by Architect
   - No agent reaches into another's implementation details

2. **Clear Ownership**
   - Each agent owns its domain completely
   - When work crosses boundaries, document needs and hand off
   - Architect resolves ownership ambiguity

3. **Cross-Domain Work**
   - Initiating agent documents: what it needs, expected interface, constraints
   - Receiving agent implements within its domain
   - Architect validates cross-cutting concerns

## Bootstrap Order

When initializing or adding major features:
1. **Architect** — Structure, protocols, module boundaries
2. **Data** — Models and persistence
3. **Network** — API transport layer
4. **AI** — Intelligence layer (if needed)
5. **Designer** — Visual specs and UX flows (if needed)
6. **Frontend** — Navigation shell and design system
7. Feature implementation using appropriate agents (GFX for graphics-heavy work)

## Quick Reference

### Adding a Dependency
1. Consult Architect for approval and integration pattern
2. Update dependency injection approach if needed
3. Document in relevant agent file

### Resolving Conflicts
- Ownership unclear -> Architect decides
- Pattern inconsistency -> Architect standardizes
- Cross-layer concern -> Architect defines abstraction

## See Also

- Individual agent files for detailed responsibilities
