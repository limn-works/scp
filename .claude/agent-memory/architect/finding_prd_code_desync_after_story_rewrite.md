---
name: finding-prd-code-desync-after-story-rewrite
description: A story rewritten mid-branch goes stale when a later commit on the same branch changes the design — re-verify every acceptance-criterion grep against HEAD; never trust the story's premise or a reviewer's line numbers.
metadata:
  type: feedback
---

A PRD story rewritten in the middle of a branch is stale by default: commits that land after
the rewrite change the design the story specifies, and nothing re-syncs it. Because stories
govern code, a later agent executing the stale story regresses the fix the branch shipped. On
the relay-DID branch (#482) one commit rewrote the stories and the next deleted the one-shot
relay latch they specified; a sibling story had also copied a premise an earlier commit had
already fixed.

**How to apply:**
- Before editing a story, run its acceptance-criterion greps against HEAD. `git grep <sym>
  HEAD -- crates/` returning only PRD hits means the symbol does not exist.
- Print the story and assert on the actual string before overwriting it
  (`assert "..." in ac[2]`); a coordinator's or reviewer's index or line number can be wrong.
- A premise fixed in one story is usually copied into its siblings. After correcting one,
  grep the whole PRD for the retracted symbol names.
- Record the correction in the artifact (`details.retracted_premise`,
  `details.delivered_by_NNN` with file evidence, `details.rejected_design`), not only in the
  commit message. The next agent reads the story, not the log.
- Marking a story `done` requires verifying every acceptance criterion. Chase the test each
  criterion names; a name-grep can miss it.
- zsh applies history modifiers to `$M:c…`, so `git show $M:crates/...` mangles the path.
  Write `git show "${M}:crates/..."`, and quote pathspecs in `git grep ... -- "$PATHS"`.
