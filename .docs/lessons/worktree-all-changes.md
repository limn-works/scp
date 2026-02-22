# Worktree Workflow: All Changes in the Worktree

**Problem**: When using git worktrees for feature work, artifact updates (ticket files, state files) were done in the main repo instead of the worktree. This leaves the worktree dirty with uncommitted changes, preventing clean removal.

**Rule**: Do ALL work in the worktree, including:
- Code changes
- Ticket/state file updates
- Any other artifact modifications

Commit everything together in the worktree, merge to main, then the worktree is clean for removal.
