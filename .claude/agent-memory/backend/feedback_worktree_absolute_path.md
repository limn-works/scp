---
name: Worktree absolute-path discipline
description: Always prefix file ops with the worktree absolute path, never bare /Users/alec/Developer/limn/scp/ which is the MAIN worktree
type: feedback
---

When working inside a worktree, ALL file reads and edits must use the worktree path, e.g. `/Users/alec/Developer/limn/scp/.claude/worktrees/agent-XXXX/crates/...`, NOT `/Users/alec/Developer/limn/scp/crates/...`.

**Why:** `/Users/alec/Developer/limn/scp/` is the MAIN worktree and it sits on `main`. Edits there pollute main with uncommitted changes and contradict orchestration protocol ("Never checkout migration/feature branches on the main worktree"). On commit 12c.9e.1 I spent several tool calls editing the main worktree by mistake because prompt context mentioned the short path — all edits had to be `git checkout --`-reverted before redoing them in the actual worktree.

**How to apply:** Before every Read/Edit/Write/Bash-write, verify the path begins with the worktree prefix. Check `pwd` at session start; it names the worktree. If a file path looks like `/Users/alec/Developer/limn/scp/crates/...`, rewrite it to `/Users/alec/Developer/limn/scp/.claude/worktrees/agent-XXX/crates/...`.
