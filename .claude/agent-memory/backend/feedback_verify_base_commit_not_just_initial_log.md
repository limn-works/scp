---
name: feedback-verify-base-commit-not-just-initial-log
description: A task's "git log shows X" gate can be satisfied by the pre-prompt snapshot while the live worktree HEAD is one commit STALE; verify HEAD with a live git call before branching
metadata:
  type: feedback
---

Before branching for a task that pins a base commit, run a LIVE `git rev-parse HEAD` / `git log --oneline -1` and compare to the required SHA. Do not trust the `git log` snapshot embedded in the task prompt's environment block.

**Why:** On the eventlog-unification Phase 2 task, the prompt's gate said "verify `git log` shows `1c0ccbc7d` (#1827); if not STOP." The prompt's pre-baked status snapshot DID show `1c0ccbc7d` at the top, but the live worktree HEAD was actually `695f295ac` — exactly one commit earlier (the version-bump commit, parent of #1827). `git checkout -b` therefore cut my branch from the wrong base, missing the entire Phase 1 substrate (payload.rs, the 76-variant EventType, event_type_tag tags 36-75). Symptom: `crates/scp-event-log/src/payload.rs` was a 0-byte UNTRACKED file, and `lib.rs` had only 35 EventType variants. Compounding confusion: the worktree FILESYSTEM had a later checkout of some scp-event-log files (greps "found" the 76 variants) while git HEAD did not — an inconsistent worktree.

**How to apply:** (1) `git rev-parse HEAD` live, compare to the pinned SHA, before any branch op. (2) If a "Phase 1 primitive" the task swears is present is missing on disk, check `git merge-base --is-ancestor <pinnedSHA> HEAD` and `git log --oneline -1 origin/main` — the pinned commit may be origin/main's tip but NOT an ancestor of your stale local HEAD. (3) Fix = if your branch has zero own commits (`git log <base>..HEAD` empty) and no modified tracked files, `git reset --hard origin/main` is safe and non-destructive. Remove stray 0-byte untracked files that would collide first. (4) After reset, re-establish ground truth on every primitive file — earlier reads may have mixed stale-filesystem and HEAD content.
