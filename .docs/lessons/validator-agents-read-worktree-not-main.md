# Validator subagents in worktrees read their working tree, not `origin/main`

**Source:** the Orchestrator verification protocol in CLAUDE.md.

## What happened

During the fuzzing infrastructure review, validator subagents dispatched into a worktree
branch reported that certain files "do not exist" — files that had already been merged to
`origin/main` days earlier. The agents were reading their own working tree (the feature branch
worktree), which did not contain those files because the feature branch predated the merge.

This produced false-positive review findings: the agent flagged real, correct code as missing.

## Why this happens

When an agent is dispatched into a worktree (e.g., `docs/fuzzing-chronicles`), its working
directory is the worktree root. `Read`, `Grep`, and `Glob` tool calls resolve relative to that
directory. If the working tree branch was created from `origin/main` before a particular commit
landed, files from that commit do not appear in the worktree.

The agent has no automatic awareness of what is on `origin/main` vs. the local worktree. It
sees what is on disk.

## The rule

**Validators must always verify findings against `origin/main`, not their local working tree.**

For any claim of the form "file X does not exist" or "function Y is not called":

```sh
# Check against origin/main, not local disk
git show origin/main:path/to/file.rs | grep "function_name"

# Or: fetch the file content from origin/main explicitly
git show origin/main:.docs/lessons/<name>.md
```

The orchestrator verification protocol in `CLAUDE.md` already mandates this for post-merge
verification:

> Verify against the PUSHED REMOTE branch (`git show origin/branch:file`), never the local
> working directory. Local state may be on a different branch.

The same principle applies to review agents dispatched into worktrees that may be on different
branches.

## How to prevent false positives

When dispatching a review agent:

1. **Tell the agent which branch to treat as canonical.** "The authoritative state for
   production code is `origin/main`. If a file or function appears to be missing, verify with
   `git show origin/main:<path>` before reporting it as a finding."

2. **Instruct the agent to rebase if in doubt.** If the worktree branch is stale relative to
   `origin/main`, rebase before reviewing: `git rebase origin/main`.

3. **Orchestrator post-review verification.** After receiving review findings, the orchestrator
   must distinguish between: (a) findings about the PR's own changes, which are correctly
   evaluated against the worktree; and (b) findings about pre-existing production code, which
   must be verified against `origin/main`.

## Related false-positive pattern: cherry-pick "nothing to commit"

A related pattern from `CLAUDE.md`:

> If a cherry-pick resolves to "nothing to commit," the changes DID NOT LAND. Investigate.

This is the inverse: the orchestrator believed changes landed (because they were on a local
branch) when they had not yet been pushed or merged. Both patterns stem from conflating local
state with remote/canonical state.

## Related

- `CLAUDE.md` §"Orchestrator verification protocol" — verify against remote, not local
- `.docs/lessons/worktree-all-changes.md` — related worktree pitfalls
- `CLAUDE.md` §"Agent execution rules" — branch verification at agent start
