---
name: finding-phantom-provenance-issue-number-is-the-prd
description: A code comment citing an issue number as the owner of unfinished work is not provenance until a story in that artifact covers the named capability — grep the artifact, not the number.
metadata:
  type: feedback
---

When code justifies a gap with "#NNNN owns this end to end", verify that a story covers the
capability, not that the issue number exists.

**Why:** `crates/scp-node/src/self_host.rs` once justified a dormant relay republish arm by
pointing at #482. #482 is `.docs/prds/relay-did-resolution.json`, and a grep of that PRD for
"relay-client binding", "bootstrap relay", and "§18.5.1" returned zero hits across its five
stories. No artifact owned the work while the comment read as fully sourced, and the citation
suppressed the question.

**How to apply:** on any review of a deferral comment that names an issue, ADR, or PRD:
- Resolve the citation to the artifact and grep it for the specific capability the comment
  names.
- If nothing covers it, the deferral is unauthorized: the story must be written before the
  code descends from it.
- The same failure runs in reverse: a story marked `done` whose acceptance criteria no code
  satisfies (SCP-239/SCP-240 in `.docs/prds/reachability.json` were found this way). A `done`
  status is a claim to re-verify.
