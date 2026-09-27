# Memory stores in SCP

This file says which memory store holds which kind of fact, and when an agent reads or writes each store. Alec ruled on 2026-08-31 that agents use every store together: Vestige is working memory, Flex serves historical accuracy, information recovery, and citations, and the memory files hold the agent's version of events. `~/.claude/CLAUDE.md` gives the Vestige tool mechanics (queries, tags, `smart_ingest`, promote and demote).

## Matrix

| Store | Holds | Read it | Write it |
|-------|-------|---------|----------|
| **Plan of record** (`~/.claude/plans/`, one plan file per workstream) | The workstream's tracks, numbered work items, status, and every decision Alec settled for it | **Mandatory, before every other store, when a plan covers the work.** A plan covers the work when the work belongs to its workstream; the plan's tracks, story IDs, branches, and pull requests are indicators. List the directory and read each covering plan at the start of the task, before dispatching an agent, before asking Alec a question, and after a compaction. | Before dispatching the first agent on new work: add the work as a track. When Alec settles a decision in conversation: write it into the plan at once. When a ruling changes a row: replace the row in place. |
| **Vestige** (MCP `mcp__vestige__*`) | Working memory: Alec's rulings and preferences, design decisions, bug root causes and fixes, code patterns, the state of each workstream | At session start (`session_context`). At the start of every task, with the task's subject as the query. Before editing a crate, module, or file, with its name as the query. Before debugging an error, with the error text as the query. Before any decision or answer an earlier session may have settled. Before asking Alec a question. | When Alec explicitly gives a standing rule or a permanent operational request as one (see below): at once, in your own words with its meaning and scope intact, dated, without quoting him. After a bug fix: error, root cause, fix, files. After a design decision: rationale and rejected alternatives. When Alec asks for a reminder: `intention`. |
| **Flex** (MCP `mcp__flex__flex_search`, cell `claude_code`) | The indexed transcripts of past sessions, including Alec's exact words | When a Vestige search returns nothing relevant. When the question is about something that happened. Before stating what Alec decided or why, read his exact words there, because the artifacts paraphrase him. After a compaction, to recover what the summary dropped. | Agents do not write to Flex. |
| **Memory files** (`~/.claude/projects/-Users-alec-Developer-limn-scp/memory/`) | The main session's version of events: Alec's rulings, how Alec wants the work done, environment traps, open items awaiting Alec | The harness loads the `MEMORY.md` index into every session. Open a file when its index line names the topic at hand. | When Alec explicitly gives a standing rule or a permanent operational request as one (see below): write it here and in Vestige. When an item starts or stops waiting on Alec. When an environment trap costs time. |
| **Agent memory** (`.claude/agent-memory/<agent>/`) | One subagent type's own lessons | The subagent of that type reads its own directory. | The subagent of that type writes its own directory. The main session writes none of them. |
| **Repository lessons and rules** (`.docs/lessons/`, nested `AGENTS.md`, `.docs/standards/`) | Lessons that pass the lesson rule in the root `AGENTS.md` Workflow section, and rules every agent must follow | When the root `AGENTS.md` map names the document for the task. | When a correction passes the lesson rule. The change goes through a pull request. |

## Where a fact goes

- **A decision Alec settles about what a workstream builds:** the plan of record at once, or the spec. Not memory.
- **A standing rule Alec explicitly gives as one** (a rule that holds for all future tasks and that no plan, spec, ADR, or `AGENTS.md` records yet): Vestige and a memory file. When it passes the lesson rule, also the repository.
- **A permanent operational request Alec explicitly gives as one** (a correction of a mistake a session has made before or would plausibly repeat): Vestige and a memory file. When it passes the lesson rule, also the repository.
- **A bug's root cause and fix:** Vestige. When it passes the lesson rule, also `.docs/lessons/`.
- **A design decision:** Vestige. A protocol decision also needs its spec or ADR, per the artifact flow in the root `AGENTS.md`.
- **Anything a repository artifact already states:** nowhere else.
- **Secrets, debug output, session narration:** nowhere.
