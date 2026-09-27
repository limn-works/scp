# Memory stores in SCP

This file says where each kind of fact is written, and when an agent reads each store. Each fact goes to exactly one store. Write facts in your own words; Flex holds every message verbatim. A short exact phrase of Alec's is useful as an anchor, because a keyword search for it in Flex finds the source message. Vestige is the working recall layer and Flex the perfect-retrieval layer; they are used together. Claude Code's auto-memory is turned off and never written. SCP has its own Vestige store, which the `vestige` MCP server opens for any session in this repository or one of its worktrees; `~/.claude/CLAUDE.md` gives the tool mechanics and holds the rules that apply to all projects.

## Where each fact goes

| Fact | Store |
|------|-------|
| A design decision (protocol, architecture, or API), and the reasoning about it that deserves to be checked in and shared: the concrete why this and not that | The repository: the spec, ADR, or standard that owns it, per the artifact flow in the root `AGENTS.md` |
| A lesson that passes the lesson rule in the root `AGENTS.md` Workflow section, including a bug's root cause and fix | The repository: a nested `AGENTS.md`, a standard, or `.docs/lessons/` |
| A workstream's tracks, work items, status, and the scope and sequencing Alec settles for it | The plan of record: the workstream's one plan file in `~/.claude/plans/` |
| Anything else a future session would otherwise re-derive or get wrong: how code or a subsystem works, what an investigation found, an approach that failed and why, an environment trap, the informal process by which a decision was reached, an item waiting on Alec, and a standing rule or permanent operational request Alec explicitly gives as one | Vestige, through `smart_ingest`, in the agent's own words, dated |
| What was said and decided in a conversation | Flex holds every session transcript without an agent writing anything. For a salient point, an agent may also write a summary to Vestige. |
| A reminder Alec asks for (do X when Y) | Vestige (`intention`), which surfaces it when the trigger matches |
| Anything a repository artifact already states, secrets, debug output, session narration | Nowhere |

## When to read each store

| Store | Read it |
|-------|---------|
| **Plan of record** (`~/.claude/plans/`) | **Mandatory, before every other store, when a plan covers the work.** A plan covers the work when the work belongs to its workstream; the plan's tracks, story IDs, branches, and pull requests are indicators. List the directory and read each covering plan at the start of the task, before dispatching an agent, before asking Alec a question, and after a compaction. |
| **Repository** (`.docs/`, nested `AGENTS.md`) | When the root `AGENTS.md` map names the document for the task, and before any design decision. |
| **Vestige** (MCP `mcp__vestige__*`) | At session start and after a compaction, through `session_start`. With `recall`: at the start of every task, with the task's subject as the query; before editing a crate, module, or file, with its name as the query; before debugging an error, with the error text as the query; before asking Alec a question. |
| **Flex** (MCP `mcp__flex__flex_search`, cell `claude_code`) | When Vestige returns nothing relevant. When the question is about something that happened in a conversation. Before stating what Alec decided or why, because the artifacts paraphrase him. After a compaction, to recover what the digest and the summary dropped. |
| **Agent memory** (`.claude/agent-memory/<agent>/`) | Only the subagent of that type reads and writes its own directory. |
