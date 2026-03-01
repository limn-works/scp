## Loom — Autonomous Development Loop

Loom is installed as a Claude Code plugin (`alecmarcus/loom`). It runs Claude Code in a continuous loop: read tasks from a PRD, dispatch parallel subagents, run tests, commit green code, repeat.

```
.loom/               # Per-project Loom state (plugin provides scripts, hooks, and skills)
├── prd.json         # Structured stories with gates (P0/P1/P2), deps, acceptance criteria
├── status.md        # Current iteration state (read at start, written at end of each cycle)
└── logs/            # Per-iteration logs
```

**Skills:** `/loom:start`, `/loom:init`, `/loom:setup`, `/loom:prd`, `/loom:status`, `/loom:stop`, `/loom:kill`, `/loom:preview`

### Rules for success

**Stories must be atomic.** Each story is executed by a single subagent in one iteration (~15-30 min). If it can't be done in one shot, split it. Coupled work (model + migration + route) stays together; unrelated work does not.

**Acceptance criteria must be machine-verifiable.** Not "it works" but "POST /api/x returns 200 with a JWT". If you can't write a test for it, Loom can't verify it.

**Parallelism requires file isolation.** Stories that touch the same files cannot run in the same batch. Set `blockedBy` for true data dependencies; leave it empty otherwise to maximize parallelism.

**Green tests are a hard gate.** Loom never commits failing code. Test failures are recorded in status.md and become top priority for the next iteration. After 3 failed fix attempts within one iteration, Loom stops and records the state.

**Context is the scarcest resource.** Read prd.json in jq waves of 10. Never cat entire files. Use dedicated tools (Read, Grep, Glob) instead of shell commands. status.md is the only continuity across loop restarts — write it thoroughly.

**Search before building.** Subagents must search the codebase before assuming something is missing. Reimplementing existing code is a common failure mode.

**Scope is sacred.** Implement only the assigned story. Do not "fix" adjacent code, add unrequested features, or refactor code that seems inconsistent with other specs.

[GitHub](https://github.com/alecmarcus/loom)
