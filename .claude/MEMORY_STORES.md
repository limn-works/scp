# Memory stores in SCP

This file says where each kind of fact is written, and when an agent reads each store. Each fact goes to exactly one store. `~/.claude/CLAUDE.md` gives the Vestige tool mechanics.

## Where each fact goes

| Fact | Store |
|------|-------|
| A design decision: protocol, architecture, or API, with its rationale and rejected alternatives | The repository: the spec, ADR, or standard that owns it, per the artifact flow in the root `AGENTS.md` |
| A lesson that passes the lesson rule in the root `AGENTS.md` Workflow section | The repository: a nested `AGENTS.md`, a standard, or `.docs/lessons/` |
| A workstream's tracks, work items, status, and the scope and sequencing Alec settles for it | The plan of record: the workstream's one plan file in `~/.claude/plans/` |
| A standing rule Alec explicitly gives as one: a rule that holds for all future tasks and that no plan or repository artifact records yet | A memory file, in the agent's own words, dated, without quoting Alec |
| A permanent operational request Alec explicitly gives as one: a correction of a mistake a session has made before or would plausibly repeat | A memory file, in the agent's own words, dated, without quoting Alec |
| An environment trap that cost time, or an item waiting on Alec | A memory file |
| A bug's root cause and fix that does not pass the lesson rule | Vestige |
| What was said and decided in a conversation | Flex holds every session transcript without an agent writing anything. For a salient point, an agent may also write a summary to Vestige. |
| A reminder Alec asks for | Vestige (`intention`) |
| Anything a repository artifact already states, secrets, debug output, session narration | Nowhere |

## When to read each store

| Store | Read it |
|-------|---------|
| **Plan of record** (`~/.claude/plans/`) | **Mandatory, before every other store, when a plan covers the work.** A plan covers the work when the work belongs to its workstream; the plan's tracks, story IDs, branches, and pull requests are indicators. List the directory and read each covering plan at the start of the task, before dispatching an agent, before asking Alec a question, and after a compaction. |
| **Repository** (`.docs/`, nested `AGENTS.md`) | When the root `AGENTS.md` map names the document for the task, and before any design decision. |
| **Memory files** (`~/.claude/projects/-Users-alec-Developer-limn-scp/memory/`) | The harness loads the `MEMORY.md` index into every session. Open a file when its index line names the topic at hand. |
| **Vestige** (MCP `mcp__vestige__*`) | At session start (`session_context`). At the start of every task, with the task's subject as the query. Before editing a crate, module, or file, with its name as the query. Before debugging an error, with the error text as the query. Before asking Alec a question. |
| **Flex** (MCP `mcp__flex__flex_search`, cell `claude_code`) | When Vestige returns nothing relevant. When the question is about something that happened in a conversation. Before stating what Alec decided or why, because the artifacts paraphrase him. After a compaction, to recover what the summary dropped. |
| **Agent memory** (`.claude/agent-memory/<agent>/`) | Only the subagent of that type reads and writes its own directory. |
