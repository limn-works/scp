---
name: finding-prd-code-desync-after-story-rewrite
description: A story rewritten mid-branch goes stale the moment a later commit on the SAME branch changes the design — re-verify every AC grep against HEAD, never trust the story or the reviewer's line numbers.
metadata:
  type: feedback
---

A PRD story rewritten in the middle of a branch is stale by default: commits landing
AFTER the rewrite change the very design the story specifies, and nothing re-syncs it.
Because the artifact flow is one-way (stories govern code), the stale story is
authoritative — a later agent executing it will REGRESS the fix the branch shipped.

**Why:** On the #482 relay-DID branch, `4f6c247d3` rewrote the stories and
`36358fc17` (next commit) deleted the one-shot relay latch they specified. Three
independent reviewers found the contradiction. Separately, SCP-RELAYRES-008's stated
root cause ("`publish` returns `Result<(), _>` so no caller can build the frame";
"`self_did_republish_entry` reconstructs the triple off the DHT") was fully fixed by
an earlier commit on the same branch — two of its ACs were already satisfied, and one
of its sibling stories (005) had copied the same dead premise into its sequencing
rationale.

**How to apply:**
- Before editing any story, run its ACs' greps against HEAD yourself. `git grep <sym>
  HEAD -- crates/` returning only PRD hits means the symbol is phantom.
- Never trust a coordinator's or reviewer's AC index / line number — print the story
  and assert on the actual string before overwriting (`assert "..." in ac[2]`).
- A premise fixed in one story is usually copied into siblings. After correcting one,
  sweep the whole PRD for the same claim (grep the retracted symbol names).
- Record the correction IN the artifact — `details.retracted_premise`,
  `details.delivered_by_NNN` with file evidence, `details.rejected_design` — not just
  in the commit message. The next agent reads the story, not the log.
- Marking a story `done` requires verifying every AC, not the load-bearing ones. Chase
  the test the AC names; a comment pointing at "the on-disk restart test in
  `store::credentials`" found the test a name-grep had missed.
- zsh applies parameter modifiers, so `git show $M:crates/...` mangles the path — use
  `git show "${M}:crates/..."`, and quote pathspecs in `git grep ... -- "$PATHS"`.

Related: [[decision-readiness-gate-vs-observability-accessor]],
[[finding_phantom_provenance_issue_number_is_the_prd]]
