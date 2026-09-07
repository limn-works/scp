---
name: finding-phantom-provenance-issue-number-is-the-prd
description: A code comment citing an issue number as the owner of unfinished work is not provenance until a STORY covers it — grep the PRD, not just the issue number
metadata:
  type: feedback
---

When code justifies a gap with "#NNNN owns this end to end. No separate issue tracks it", verify
that a **story** covers it — not that the issue number exists.

**Why:** `crates/scp-node/src/self_host.rs` justified a permanently-dormant relay republish arm
with exactly that sentence pointing at **#482**. #482 *is* `.docs/prds/relay-did-resolution.json`,
and grepping that PRD for "relay-client binding", "bootstrap relay", and "§18.5.1" returned zero
hits across all five stories. The work was owned by no artifact while reading as fully sourced —
worse than no provenance, because the citation suppresses the question.

**How to apply:** on any review of a deferral comment naming an issue/ADR/PRD:
- Resolve the citation to the actual artifact and grep it for the *specific capability* named in
  the comment, not for the issue number.
- If nothing covers it, the deferral is unauthorized: per the one-way artifact flow the story must
  be written **before** the code descends from it.
- Same failure shape in reverse: `.docs/prds/reachability.json` SCP-239/SCP-240 are marked `done`
  with acceptance criteria ("publishes to identity's own relays AND bootstrap relays", "queries
  sent to identity's known relays first, then bootstrap relays") that no code has ever satisfied —
  a `done` status is a claim to re-verify, not a fact.

Related: [[decision-blockedby-cannot-start-not-cannot-finish]].
