---
name: two-dot-diff-stale-base-trap
description: On a branch that is behind main, `git diff origin/main..HEAD` shows main's newer commits as deletions the branch never made; confirm scope against the merge base before flagging a deletion
metadata:
  type: feedback
---

A two-dot diff `origin/main..HEAD` compares the branch tip with main's current tip. When the
branch forked from an older main, every commit main gained since then appears in that diff as
a deletion or reversion on the branch side. Such phantoms look like alarming scope changes
("this branch deletes 50 EventType variants", "reverts the event-log unification").

**How to apply,** before flagging any deletion or reversion:
1. Compare `git merge-base origin/main HEAD` with `git rev-parse origin/main`. If they
   differ, the branch is stale.
2. `git log --oneline HEAD..origin/main` lists the main-only commits whose changes will
   masquerade as deletions.
3. Read the branch's own changes with the three-dot form `git diff origin/main...HEAD`,
   which diffs from the merge base.
4. For each file you would flag, `git diff "$(git merge-base origin/main HEAD)"..HEAD --stat -- <file>`;
   empty output means the branch never touched it.

In the incident that taught this, a branch about 19 commits behind main appeared to delete the
reconnect path, revert an EventType expansion, and soften a spec clause; it had touched none of
those files. The real finding was the staleness itself: the branch needed a rebase that kept
main's work.
