---
name: two-dot-diff-stale-base-trap
description: When reviewing a branch via `git diff origin/main..HEAD`, a stale branch base renders main's NEWER commits as phantom deletions/reversions — always confirm scope against merge-base..HEAD before flagging
metadata:
  type: feedback
---

When asked to review a branch and given a `git diff origin/main..HEAD` (two-dot) command, that diff conflates the branch's real changes with everything main added since the branch's base. A branch that is many commits behind main shows main's newer work as **deletions/reversions** — which look like alarming scope changes (e.g. "this branch deletes 50 EventType variants", "removes reconnect", "reverts the event-log unification").

**Why:** Two-dot `A..B` = "what's in B but not A" only when B is up to date with A. If B forked from an older A, the diff shows B-minus-current-A, so current-A's new commits appear as removals on B's side.

**How to apply:** Before flagging any deletion/reversion as a branch finding:
1. `git merge-base origin/main HEAD` and compare to `git rev-parse origin/main`. If they differ, the branch is stale.
2. Check `git log --oneline HEAD..origin/main` — commits listed are main-only work the branch lacks; their changes will masquerade as deletions in the two-dot diff.
3. Get the branch's ACTUAL contributions with `git diff <merge-base>..HEAD` (three-dot `origin/main...HEAD` also works — it diffs from the merge-base).
4. For any file you'd flag, run `git diff <merge-base>..HEAD --stat -- <file>`. Empty output = the branch never touched it; the "change" is stale-base noise.

Real incident: branch `fix/sdk-coverage-fail-closed-and-parity` (merge-base 0c8f0b06, main at dabf1336, ~19 commits behind) appeared to delete reconnect/heartbeat, revert event-log EventType expansion (#1827), re-add `signing_key_id` to Event, and soften spec §9.4.1 capability-proof enforcement. ALL phantom — the branch touched none of those files. Its real scope was SDK parity (trust/economy/identity TS+Py), a fail-closed check-sdk-coverage.py gate, and ADR-051.

The actionable branch-level finding in that case was the staleness itself: rebasing onto current main is required, and the branch must NOT drop main's reconnect entry / event-log work during the rebase.

Related: [[two-dot-diff-stale-base-rebase]] (orchestrator's "verify two-dot diff before merge" in root MEMORY.md is the merge-time version of this same trap).
