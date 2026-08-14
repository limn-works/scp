---
name: scar-tissue-accepted-pending-status
description: "Accepted (pending human sign-off)" is a novel intermediate ADR status = scar tissue; an ADR is Proposed until the human accepts
metadata:
  type: project
---

An ADR that self-promotes its Status to **"Accepted (…final human sign-off pending…)"** is scar
tissue, not a legitimate state. Seen in ADR-054 accept amendment (branch
`docs/adr-054-accept-substrate-residence`, commit 90b6388d6, 2026-07-14).

**Why:** CLAUDE.md operating model is "Humans steer, agents execute; only human-driven specs."
ADR acceptance is a *human* decision. An agent writing "Accepted" before the human signs off
invents a novel intermediate status to paper over the missing decision — the exact "No DOA
decisions" failure mode. The parenthetical hedge ("human accepts on review") proves the author
knew acceptance wasn't theirs to give; the bare token "Accepted" overrides the hedge in any
grep/index scan, and the ADR's own Alternatives line ("acceptance authorizes the implementation
workstream") means a downstream executing agent will read "Accepted" as authorization to start
coding before the human has accepted.

**How to apply:** Flag any ADR/spec Status that is a hybrid/conditional acceptance. The honest
states are `Proposed` (design complete, recommended for acceptance) until the human accepts,
then a clean `Accepted (date)`. Resolving open questions (OQ2/OQ3 etc.) does NOT require
self-accepting — those resolutions land fine under `Proposed`. Correct text:
"Proposed — design complete, recommended for acceptance; awaiting human sign-off."
Related: the amend-without-delete convention (retain prior content + dated Amendment note) is
sound here; the Status hybrid is the only scar. See [[MEMORY]].
