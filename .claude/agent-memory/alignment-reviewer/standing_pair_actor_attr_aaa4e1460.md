---
name: standing-pair-actor-attr-aaa4e1460
description: Standing-Pair v2 one-line actor-attribution fix @ aaa4e1460 — ALIGNED, ship, 0 findings
metadata:
  type: project
---

# Standing-Pair v2 actor-attribution one-line fix @ `aaa4e1460` — ALIGNED, ship, 0 findings

Branch `spec/standing-pair-not-a-saga-v2`. HEAD = prior-ALIGNED [[standing-pair-order-align-c81fcce95]] + EXACTLY ONE commit. DOCS-ONLY, 05-contexts.md only (+1/-1).

**The fix:** §5.15.8 collision-resolution `did_lo`-ignores bullet (`:1848`). Before: "so **its** later destroy equivocates against no peer" with "its" wrongly bound to `did_lo`. After: "so **`did_hi`'s** later destroy of that orphan equivocates against no peer (`did_lo` having never observed it)."

**Why correct:** `did_lo` is the normative SURVIVOR — `:1846` "all other Welcomes are ignored", `:1851` "the survivor… ignores every inbound Welcome". It NEVER destroys. The destroyer is `did_hi` (`:1849` "joins `did_lo`'s and then destroys its self-created group"). Prior wording self-contradicted the next bullet. Corrected text also makes the equivocation-safety argument sound: only `did_lo` could observe `did_hi`'s orphan, and it built no state from it → `did_hi`'s destroy equivocates against no peer.

**Verified:** (1) no residual "its later destroy"/`did_lo`-as-destroyer phrasing anywhere (grep clean; `:1855`/`:1887` correctly assign destroy to the `did_hi` party). (2) "orphan" vocab matches existing `:1855`/`:1887` "destroys its orphan" — no drift. (3) no new §-cross-ref, no raw #NNNN in added lines. (4) HEAD is c81fcce95 + this one commit, nothing else.

**Why ALIGNED:** pure clarity/correctness fix removing a genuine internal actor contradiction; corpus-consistent; cross-refs resolve. Verdict ALIGNED, nothing actionable, ship.

LESSON: actor-attribution fix in a multi-party normative section → after confirming the edited line, grep the WHOLE section for any OTHER place the wrong actor is bound to the same verb (survivor-never-destroys is an invariant: any "did_lo destroys" anywhere is a bug). Confirm corrected vocabulary ("orphan") matches established term used in sibling restatements.
