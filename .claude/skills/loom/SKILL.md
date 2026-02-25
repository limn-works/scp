---
name: loom
description: Start the Loom autonomous development loop, or set up integrations from remote guides. Launches a tmux session that continuously reads tasks from a PRD, dispatches parallel subagents, runs tests, and commits passing code.
argument-hint: "[setup <query>] | <prompt> | [dry-run|github|linear|slack|notion|sentry <prompt>] [resume <directory>] [wt|worktree <true|false>] [pr <true|false>] | status | stop | kill"
disable-model-invocation: true
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, WebFetch
---

# /loom

Route `$ARGUMENTS` to the correct handler. Read **only** the file you need — do not read both.

| If `$ARGUMENTS`... | Read and follow |
|---------------------|-----------------|
| starts with `setup` | `.claude/skills/loom/setup.md` — pass everything after `setup` as the query |
| anything else (or empty) | `.claude/skills/loom/exec.md` — pass `$ARGUMENTS` unchanged |
